"""
LangGraph Agent: Bộ điều hợp Client LLM

CHỨC NĂNG:
- Giao tiếp với Local LLM (Gemma 9B) thông qua OpenAI-compatible endpoint (llama.cpp server).
- Sử dụng OpenAI API format (OpenAI-compatible endpoint tại port 5000).
- Triển khai cơ chế Retry, Exponential Backoff, và xử lý Timeout để đảm bảo
  Agent không bị crash khi model đang bận tính toán.
"""

import json
import logging
import os
import re
import time
from typing import Any

try:
    import openai  # type: ignore
except ImportError:
    raise ImportError("Thiếu thư viện yêu cầu: hãy chạy pip install openai")

import yaml  # type: ignore

from src.agent import token_monitor

logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "system_settings.yaml")
try:
    with open(CONFIG_PATH) as f:
        _config = yaml.safe_load(f)
except Exception:
    _config = {}

YAML_BASE_URL = _config.get("llm", {}).get("base_url", "http://127.0.0.1:5000/v1")

# Endpoint tương thích với OpenAI (llama.cpp server)
API_BASE_URL = os.getenv("LLM_API_BASE", YAML_BASE_URL)
API_KEY = os.getenv("LLM_API_KEY", "sk-placeholder-local-only")  # Giá trị giữ chỗ cho Local LLM

# Tham số cấu hình cho Security Agent
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.1  # Nhiệt độ thấp = suy luận nhất quán (deterministic), ít ảo tưởng
# Seed cố định -> với cùng prompt + temp thấp, llama.cpp cho output TẤT ĐỊNH (tái lập).
# None = không cố định (bỏ qua). Đọc từ config llm.seed.
DEFAULT_SEED = _config.get("llm", {}).get("seed", 42)
# Tên model đọc từ env LLM_MODEL_FILE (đồng bộ với model thực tế llama.cpp đang nạp
# và tự khớp khi hot-swap qua scripts/switch_model.sh). llama.cpp bỏ qua tên này khi
# chỉ nạp 1 model, nhưng giữ đồng bộ để chính xác và tương thích đa-model.
DEFAULT_MODEL = os.getenv(
    "LLM_MODEL_FILE",
    _config.get("llm", {}).get("model", "gemma-2-9b-it-Q6_K.gguf"),
)


class LLMClient:
    def __init__(self, base_url: str = API_BASE_URL, max_retries: int = 3, timeout: int = 300):
        """
        Khởi tạo OpenAI Client trỏ về Local LLM server.
        """
        self.client = openai.OpenAI(base_url=base_url, api_key=API_KEY, timeout=timeout)
        self.max_retries = max_retries

    def invoke(
        self,
        messages: list[dict[str, str]],
        temperature: float = DEFAULT_TEMPERATURE,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        response_format: dict[str, Any] | None = None,
        seed: int | None = DEFAULT_SEED,
    ) -> str:
        """
        Gọi LLM với cơ chế thử lại (Retry).

        Args:
            messages: Danh sách dict [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
            temperature: Độ sáng tạo của mô hình. 0.1 cho Phân tích Bảo mật.
            max_tokens: Số lượng token đầu ra tối đa.
            response_format: Định dạng đầu ra (vd: {"type": "json_object"} nếu mô hình hỗ trợ)

        Trả về:
            Văn bản đầu ra từ LLM.
        """
        retries = 0
        backoff = 2  # Bắt đầu với 2 giây chờ

        if os.getenv("MOCK_LLM") == "1":
            return json.dumps(
                {
                    "reasoning": "Mock reasoning from MOCK_LLM=1. Detected anomaly matching MITRE TTPs and NIST containment phases.",
                    "action": "BLOCK_IP",
                    "confidence": 0.99,
                    "extracted_iocs": [{"type": "ip", "value": "192.168.1.100"}],
                }
            )

        # Cổng quan sát ngữ cảnh (TRƯỚC khi gọi): ước lượng token input, cảnh báo nếu sát trần.
        token_monitor.preflight_check(messages, max_tokens)

        for retries in range(self.max_retries + 1):
            try:
                # Gọi API
                kwargs: Any = {
                    "model": DEFAULT_MODEL,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }

                # Seed cố định -> output tất định (tái lập) với cùng prompt + temp thấp.
                if seed is not None:
                    kwargs["seed"] = seed

                # llama.cpp API hỗ trợ JSON mode cho một số model
                if response_format:
                    kwargs["response_format"] = response_format

                response: Any = self.client.chat.completions.create(**kwargs)  # type: ignore

                # Ghi token THẬT do server trả về (prompt/completion) để quan sát & tinh chỉnh.
                token_monitor.record_usage(getattr(response, "usage", None))

                # Trả về văn bản
                return response.choices[0].message.content

            except openai.APITimeoutError as e:
                logger.warning(f"LLM Timeout (attempt {retries + 1}/{self.max_retries}): {e}")
                if retries == self.max_retries:
                    raise
            except openai.APIConnectionError as e:
                logger.error(f"LLM Connection Error: {e}. Is LLM server running on port 5000?")
                if retries == self.max_retries:
                    raise
            except openai.RateLimitError:
                logger.warning(
                    f"LLM Rate Limit (attempt {retries + 1}/{self.max_retries}): Model is busy."
                )
                if retries == self.max_retries:
                    raise
            except openai.APIStatusError as e:
                logger.error(f"LLM API Status Error (e.g. 500 Internal Server Error): {e}")
                # Trả về chuỗi rỗng để kích hoạt lớp Hard Fallback (AWAIT_HITL)
                return ""
            except Exception as e:
                logger.error(f"LLM Unexpected Error: {e}")
                raise  # Các lỗi khác (vd: code logic error) thì fail fast luôn

            # Cơ chế thử lại (Retry)
            retries += 1
            if retries <= self.max_retries:
                logger.info(f"Retrying in {backoff} seconds...")
                time.sleep(backoff)
                backoff *= 2  # Exponential backoff (2, 4, 8s...)

        return ""

    def parse_llm_response(self, raw: str) -> dict:
        """
        Parse JSON an toàn từ LLM output với cơ chế dự phòng (Fallback).
        Ngăn chặn crash hệ thống khi Gemma 9B ảo tưởng (ví dụ: markdown fences,
        trailing commas, hoặc chữ text kẹp chung với JSON).
        """
        # Loại bỏ các khung markdown (fences) nếu có
        clean = re.sub(r"```json|```", "", raw).strip()
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            logger.warning(f"JSON Decode failed, attempting regex fallback. Raw: {raw[:100]}...")
            # Dự phòng: trích xuất khối JSON bằng biểu thức chính quy (regex)
            match = re.search(r"\{.*\}", clean, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass

            # Dự phòng cứng: trả về giá trị mặc định an toàn thay vì gây crash
            logger.error("All JSON parse attempts failed. Using safe default.")
            return {
                "action": "AWAIT_HITL",
                "confidence": 0.0,
                "error": "parse_failed",
                "raw": raw[:200],
            }

    def check_health(self) -> bool:
        """Ping API để kiểm tra model đã load xong chưa."""
        try:
            # Gửi một token đơn giản
            self.invoke([{"role": "user", "content": "Ping"}], max_tokens=2)
            return True
        except Exception:
            return False


# Thực thể duy nhất (Singleton)
llm_client = LLMClient()
