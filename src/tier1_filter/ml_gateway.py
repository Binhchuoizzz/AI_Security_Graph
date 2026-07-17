import logging
import os
import pickle
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class MLGateway:
    """
    Tier-1 ML Gateway (Cổng ML)
    Dời từ Tier-2 sang Tier-1 để giải quyết bài toán Head-of-Line (HOL) Blocking.
    Đánh giá nhanh feature số học bằng LightGBM + StandardScaler (76 features).
    Chỉ trả về quyết định khi tự tin > 90%.
    """

    def __init__(self):
        self.pipeline = self._load_pipeline()
        self.conf_threshold_block = 0.90
        self.conf_threshold_alert = 0.70

    def _load_pipeline(self) -> dict[str, Any] | None:
        try:
            model_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "ml_lab",
                "tier_2_model.pkl",
            )
            if not os.path.exists(model_path):
                logger.warning(f"[TIER-1 ML GATE] Không tìm thấy model tại {model_path}")
                return None
            with open(model_path, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            logger.error(f"[TIER-1 ML GATE] Lỗi load mô hình: {e}")
            return None

    def evaluate(self, log: dict) -> tuple[str | None, str | None, float]:
        """
        Đánh giá log, trả về (action, reasoning, confidence).
        Nếu action = None, tức là ML không đủ tự tin -> Fallback qua LLM.
        """
        if not self.pipeline or "model" not in self.pipeline:
            return None, None, 0.0

        features = self.pipeline.get("features", [])
        model = self.pipeline["model"]
        scaler = self.pipeline["scaler"]

        required = ["Flow Duration", "Total Fwd Packets", "Flow Pkts/s"]
        has_features = sum(1 for req in required if req in log and log[req] not in ["", None, 0])
        if has_features == 0 and "Source IP" in log:
            # Likely a payload-based log (DAPT/WAF), skip ML
            return None, None, 0.0

        # Pre-allocate X optimally
        X = []
        for f_name in features:
            val = log.get(f_name)
            if val in (None, ""):
                X.append(0.0)
            else:
                try:
                    X.append(float(val))
                except (ValueError, TypeError):
                    X.append(0.0)

        try:
            X_arr = np.array(X, dtype=float).reshape(1, -1)
            X_scaled = scaler.transform(X_arr)
            proba = model.predict_proba(X_scaled)[0]
        except Exception as e:
            logger.error(f"[TIER-1 ML GATE] Lỗi dự đoán: {e}")
            return None, None, 0.0

        confidence_benign = proba[0]
        confidence_attack = proba[1]

        action = None
        reasoning = None
        confidence = 0.0

        # Lưu ý: "Cổng ML" là marker để UI bắt được (từ component.py)
        if confidence_attack >= self.conf_threshold_block:
            action = "BLOCK_IP"
            reasoning = f"Phát hiện tấn công bởi Cổng ML Tier-1 (LightGBM). Độ tin cậy: {confidence_attack:.2%}"
            confidence = float(confidence_attack)
        elif confidence_attack >= self.conf_threshold_alert:
            action = "ALERT"
            reasoning = f"Cảnh báo rủi cao bởi Cổng ML Tier-1 (LightGBM). Độ tin cậy: {confidence_attack:.2%}"
            confidence = float(confidence_attack)
        elif confidence_benign >= self.conf_threshold_block:
            action = "LOG"
            reasoning = f"Xác nhận an toàn bởi Cổng ML Tier-1 (LightGBM). Độ tin cậy: {confidence_benign:.2%}"
            confidence = float(confidence_benign)

        return action, reasoning, confidence
