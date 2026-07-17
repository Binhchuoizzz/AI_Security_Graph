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

from typing import Literal

import yaml  # type: ignore
from pydantic import BaseModel, Field, ValidationError

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


class IOCModel(BaseModel):
    ioc_type: str = Field(..., description="Loại IOC, vd: ip, cve, url")
    value: str = Field(..., description="Giá trị của IOC")
    severity: str = Field(..., description="Mức độ nghiêm trọng của IOC")


class LLMDecision(BaseModel):
    # CHỈ `action` bắt buộc — đây là quyết định lõi và Literal ép ĐÚNG enum (giá trị lạ ->
    # ValidationError -> tuồn xuống salvage/fallback an toàn). Các trường làm giàu để
    # OPTIONAL + default: LLM cục bộ đôi khi bỏ sót mitre/nist nhưng action+reasoning vẫn
    # hợp lệ — KHÔNG hạ cấp cả quyết định rõ ràng xuống "parse_salvaged" chỉ vì thiếu enrich.
    action: Literal["BLOCK_IP", "ALERT", "LOG", "AWAIT_HITL"] = Field(
        ..., description="Hành động phân loại"
    )
    confidence: float = Field(default=0.0, description="Độ tin cậy từ 0.0 đến 1.0")
    mitre_technique: str = Field(default="N/A", description="Tên kỹ thuật MITRE")
    attack_method: str = Field(default="N/A", description="Phương thức tấn công")
    nist_control: str = Field(default="N/A", description="Kiểm soát NIST")
    reasoning: str = Field(default="", description="Lập luận phân tích")
    extracted_iocs: list[IOCModel] | None = Field(default=[], description="Các IOC trích xuất được")


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

                # Trả về văn bản. `content` có thể là None theo schema OpenAI (vd
                # finish_reason=length/content_filter, hay tool-call) → ép "" để
                # parse_llm_response KHÔNG ném TypeError và suy biến an toàn AWAIT_HITL.
                return response.choices[0].message.content or ""

            except openai.APITimeoutError as e:
                logger.warning(f"LLM Timeout (attempt {retries + 1}/{self.max_retries + 1}): {e}")
                if retries == self.max_retries:
                    raise
            except openai.APIConnectionError as e:
                logger.error(f"LLM Connection Error: {e}. Is LLM server running on port 5000?")
                if retries == self.max_retries:
                    raise
            except openai.RateLimitError:
                logger.warning(
                    f"LLM Rate Limit (attempt {retries + 1}/{self.max_retries + 1}): Model is busy."
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
            if retries < self.max_retries:
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
        parsed_dict = None
        try:
            parsed_dict = json.loads(clean)
        except json.JSONDecodeError:
            logger.warning(f"JSON Decode failed, attempting regex fallback. Raw: {raw[:100]}...")
            # Dự phòng: trích xuất khối JSON bằng biểu thức chính quy (regex)
            match = re.search(r"\{.*\}", clean, re.DOTALL)
            if match:
                try:
                    parsed_dict = json.loads(match.group())
                except json.JSONDecodeError:
                    pass

        if parsed_dict is not None:
            try:
                # Ép kiểu và kiểm duyệt qua Pydantic
                validated = LLMDecision(**parsed_dict)
                return validated.model_dump()
            except ValidationError as ve:
                logger.warning(f"Pydantic Validation failed: {ve}")
                # Nếu Pydantic báo lỗi cấu trúc (vd: missing reasoning, sai enum), chuyển xuống salvage

        # Nếu không có parsed_dict (JSON hỏng hoàn toàn) hoặc Pydantic fail
        # Cứu vãn từng TRƯỜNG từ JSON bị CẮT CỤT (thường do max_tokens) hoặc lệch định
        # dạng — thay vì mất trắng cả reasoning (đây là nguyên nhân #1 của thẻ hiển thị
        # "No reasoning provided / tin cậy 0%").
        salvaged = self._salvage_fields(clean)
        if salvaged.get("action") or salvaged.get("reasoning"):
            salvaged.setdefault("action", "AWAIT_HITL")
            salvaged.setdefault("confidence", 0.0)
            salvaged["error"] = "parse_salvaged"
            logger.warning("JSON parse failed nhưng đã vớt được trường qua regex.")
            return salvaged

        # Dự phòng cứng: trả về giá trị mặc định an toàn thay vì gây crash. GẮN reasoning
        # TRUNG THỰC để analyst hiểu (không để trống thành "No reasoning provided").
        logger.error("All JSON parse attempts failed. Using safe default.")
        return {
            "action": "AWAIT_HITL",
            "confidence": 0.0,
            "reasoning": (
                "⚠️ Không đọc được phản hồi LLM (JSON parse lỗi — thường do output bị cắt "
                "cụt theo max_tokens hoặc sai định dạng). Tự động leo thang AWAIT_HITL để "
                "người xác minh; Tier-1 (xác định) vẫn bảo vệ độc lập."
            ),
            "error": "parse_failed",
            "raw": raw[:200],
        }

    def _salvage_fields(self, text: str) -> dict:
        """Vớt action/confidence/reasoning/mitre_technique từ output LLM hỏng hoặc bị cắt cụt
        bằng regex từng trường — để không mất reasoning khi JSON không parse trọn vẹn."""
        out: dict = {}
        m = re.search(r'"action"\s*:\s*"([^"]+)"', text)
        if m:
            out["action"] = m.group(1).strip().upper()
        m = re.search(r'"confidence"\s*:\s*([0-9]*\.?[0-9]+)', text)
        if m:
            try:
                out["confidence"] = float(m.group(1))
            except ValueError:
                pass
        m = re.search(r'"mitre_technique"\s*:\s*"([^"]+)"', text)
        if m:
            out["mitre_technique"] = m.group(1).strip()
        # reasoning: ưu tiên chuỗi có dấu đóng; nếu bị cắt cụt (không có "), vớt phần còn lại.
        m = re.search(r'"reasoning"\s*:\s*"(.+?)"(?:\s*[,}]|$)', text, re.DOTALL)
        if m:
            out["reasoning"] = m.group(1).strip()
        else:
            m = re.search(r'"reasoning"\s*:\s*"(.+)$', text, re.DOTALL)
            if m:
                out["reasoning"] = m.group(1).strip().rstrip('"') + " …(bị cắt cụt)"
        return out

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
