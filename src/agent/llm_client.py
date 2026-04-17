"""
LangGraph Agent: LLM Client Wrapper

CHỨC NĂNG:
- Giao tiếp với Local LLM (Gemma 9B) thông qua Oobabooga Text-Generation-WebUI.
- Sử dụng OpenAI API format (do Oobabooga cung cấp OpenAI-compatible endpoint ở port 5000).
- Implement Retry logic, Exponential Backoff, và Timeout handling để đảm bảo
  Agent không bị crash khi model đang bận tính toán.
"""
import os
import time
import logging
import json
import re
from typing import List, Dict, Any, Optional

try:
    import openai
except ImportError:
    raise ImportError("Missing dependency: pip install openai")

logger = logging.getLogger(__name__)

# Oobabooga OpenAI-compatible endpoint
API_BASE_URL = os.getenv("LLM_API_BASE", "http://127.0.0.1:5000/v1")
API_KEY = "sk-111111111111111111111111111111111111111111111111"  # Dummy key for local

# Tuning parameters cho Security Agent
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.1  # Nhiệt độ thấp = suy luận deterministic, ít hallucination
DEFAULT_MODEL = "gemma-2-9b-it"


class LLMClient:
    def __init__(self, base_url: str = API_BASE_URL, max_retries: int = 3, timeout: int = 60):
        """
        Khởi tạo OpenAI Client trỏ về Local Oobabooga.
        """
        self.client = openai.OpenAI(
            base_url=base_url,
            api_key=API_KEY,
            timeout=timeout
        )
        self.max_retries = max_retries

    def invoke(self, 
               messages: List[Dict[str, str]], 
               temperature: float = DEFAULT_TEMPERATURE,
               max_tokens: int = DEFAULT_MAX_TOKENS,
               response_format: Optional[Dict[str, str]] = None) -> str:
        """
        Gọi LLM với Retry Logic.
        
        Args:
            messages: List of dict [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]
            temperature: Độ sáng tạo của model. 0.1 cho Security Analysis.
            max_tokens: Số token output tối đa.
            response_format: Định dạng output (vd: {"type": "json_object"} nếu model hỗ trợ)
            
        Returns:
            Text output từ LLM.
        """
        retries = 0
        backoff = 2  # Bắt đầu với 2 giây chờ

        while retries <= self.max_retries:
            try:
                # Gọi API
                kwargs = {
                    "model": DEFAULT_MODEL,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }
                
                # Oobabooga API hỗ trợ JSON mode cho một số model
                if response_format:
                    kwargs["response_format"] = response_format

                response = self.client.chat.completions.create(**kwargs)
                
                # Trả về text
                return response.choices[0].message.content

            except openai.APIConnectionError as e:
                logger.error(f"LLM Connection Error: {e}. Is Oobabooga running on port 5000?")
                if retries == self.max_retries:
                    raise
            except openai.APITimeoutError as e:
                logger.warning(f"LLM Timeout (attempt {retries+1}/{self.max_retries}): {e}")
                if retries == self.max_retries:
                    raise
            except openai.RateLimitError as e:
                logger.warning(f"LLM Rate Limit (attempt {retries+1}/{self.max_retries}): Model is busy.")
                if retries == self.max_retries:
                    raise
            except openai.APIStatusError as e:
                logger.error(f"LLM API Status Error (e.g. 500 Internal Server Error): {e}")
                # Trả về chuỗi rỗng để kích hoạt lớp Hard Fallback (AWAIT_HITL)
                return ""
            except Exception as e:
                logger.error(f"LLM Unexpected Error: {e}")
                raise  # Các lỗi khác (vd: code logic error) thì fail fast luôn

            # Retry logic
            retries += 1
            if retries <= self.max_retries:
                logger.info(f"Retrying in {backoff} seconds...")
                time.sleep(backoff)
                backoff *= 2  # Exponential backoff (2, 4, 8s...)

        return ""

    def parse_llm_response(self, raw: str) -> dict:
        """
        Parse JSON an toàn từ LLM output với Fallback Logic.
        Ngăn chặn crash hệ thống khi Gemma 9B hallucinate (ví dụ: markdown fences,
        trailing commas, hoặc chữ text kẹp chung với JSON).
        """
        # Strip markdown fences nếu có
        clean = re.sub(r'```json|```', '', raw).strip()
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            logger.warning(f"JSON Decode failed, attempting regex fallback. Raw: {raw[:100]}...")
            # Fallback: extract JSON block bằng regex
            match = re.search(r'\{.*\}', clean, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
            
            # Hard fallback: trả về safe default thay vì crash
            logger.error("All JSON parse attempts failed. Using safe default.")
            return {
                "action": "AWAIT_HITL", 
                "confidence": 0.0,
                "error": "parse_failed", 
                "raw": raw[:200]
            }

    def check_health(self) -> bool:
        """Ping API để kiểm tra model đã load xong chưa."""
        try:
            # Gửi một token đơn giản
            self.invoke([{"role": "user", "content": "Ping"}], max_tokens=2)
            return True
        except Exception:
            return False

# Singleton instance
llm_client = LLMClient()
