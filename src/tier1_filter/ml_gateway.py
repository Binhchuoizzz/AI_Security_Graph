import logging
import math
import os
import pickle
import warnings
from typing import Any

import numpy as np

from src.guardrails import decision_policy

logger = logging.getLogger(__name__)

# Model được fit trên DataFrame có tên cột; ở runtime ta truyền ndarray (nhanh hơn, không
# cần pandas mỗi sự kiện) -> sklearn phát UserWarning "X does not have valid feature names"
# cho MỖI lần predict, làm nghẽn log SOC. Chặn đúng cảnh báo VÔ HẠI này (giá trị dự đoán
# không đổi vì thứ tự feature đã khớp `features` trong pkl).
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
    module="sklearn",
)

# ── Ngưỡng LỚP BẢO MẬT Cổng ML (chống né-tránh / evasion) ─────────────────────
# StandardScaler biến mỗi feature thành z-score = (x - mean)/std. Kẻ tấn công có thể
# bơm giá trị CỰC ĐOAN (hoặc Inf/NaN) để đẩy z-score ra xa, lật nhãn ML hoặc ép ML
# im lặng (né BLOCK / tốn LLM). Ba tuyến phòng thủ (dùng mean_/scale_ của scaler, KHÔNG
# cần data train):
#   1) Sanitize: NaN/±Inf/không-parse-được -> thay bằng mean của feature (z-score ≈ 0).
#   2) Clamp: kẹp z-score về [-CLIP_SIGMA, CLIP_SIGMA] -> 1 feature cực đoan không thể
#      một mình chi phối dự đoán.
#   3) OOD abstain: nếu QUÁ NHIỀU feature lệch > OOD_SIGMA (input xa phân bố train, dấu
#      hiệu đối kháng/drift) -> KHÔNG tin ML, trả None để escalate LLM.
# Ngưỡng nới rộng để KHÔNG kích hoạt trên lưu lượng THẬT sạch (giữ nguyên bypass rate);
# chỉ bật với input bất thường.
CLIP_SIGMA = 8.0  # kẹp |z| tối đa (8 lần độ lệch chuẩn)
OOD_SIGMA = 6.0  # ngưỡng coi 1 feature là "lệch cực mạnh"
OOD_FRACTION = 0.30  # nếu > 30% feature vượt OOD_SIGMA -> abstain (escalate LLM)
# Phủ feature tối thiểu: model học 76 feature CICIDS. Log KHÔNG cùng phân bố (vd DAPT chỉ
# có ~1/76 feature) -> vector toàn-mean -> dự đoán VÔ NGHĨA. Yêu cầu tối thiểu MIN_COVERAGE
# feature thực-sự-có-mặt; thiếu -> abstain (escalate LLM) thay vì đoán bừa.
MIN_FEATURE_COVERAGE = 0.5


class MLGateway:
    """
    Tier-1 ML Gateway (Cổng ML)
    Dời từ Tier-2 sang Tier-1 để giải quyết bài toán Head-of-Line (HOL) Blocking.
    Đánh giá nhanh feature số học bằng LightGBM + StandardScaler (76 features).
    Quyết định theo 4 DẢI (C = độ tin cậy tấn công): C>=0.85 BLOCK · 0.65–0.85 ESCALATE(LLM) ·
    0.40–0.65 ALERT · <0.40 PASS/DROP — VÀ input phải vượt qua lớp bảo mật chống né-tránh
    (low-coverage / OOD-abstain / clamp) nếu không sẽ escalate LLM.
    """

    def __init__(self):
        self.pipeline = self._load_pipeline()
        # Ngưỡng lấy từ chính sách THỐNG NHẤT (chung với LLM) — 1 nguồn sự thật.
        # (giữ 2 thuộc tính này để hiển thị/tương thích; quyết định thực tế dùng classify_ml 4 dải).
        self.conf_threshold_block = decision_policy.ML_BLOCK_CONF
        self.conf_threshold_alert = decision_policy.ML_ALERT_CONF
        # Cache mean_/scale_ dạng ndarray để sanitize/OOD nhanh (đọc 1 lần).
        self._mean = None
        self._scale = None
        if self.pipeline and self.pipeline.get("scaler") is not None:
            sc = self.pipeline["scaler"]
            if hasattr(sc, "mean_") and hasattr(sc, "scale_"):
                self._mean = np.asarray(sc.mean_, dtype=float)
                self._scale = np.asarray(sc.scale_, dtype=float)

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

    def _build_raw_vector(self, log: dict, features: list) -> tuple[np.ndarray, int, int]:
        """Dựng vector feature THÔ + đếm ô sanitize (non-finite/hỏng) + ô có-mặt-hợp-lệ.

        Ô hỏng/thiếu -> thay bằng mean của feature (nếu có scaler) hoặc 0.0 (trung tính).
        Trả (X, n_sanitized, n_present)."""
        X = np.empty(len(features), dtype=float)
        n_sanitized = 0
        n_present = 0
        for i, f_name in enumerate(features):
            val = log.get(f_name)
            parsed = None
            if val is not None and val != "":
                try:
                    f = float(val)
                    if math.isfinite(f):
                        parsed = f
                except (ValueError, TypeError):
                    parsed = None
            if parsed is None:
                # Giá trị thiếu/hỏng/Inf/NaN -> dùng mean (z-score ≈ 0). Chỉ tính là
                # "sanitized" (dấu hiệu tấn công) khi ô CÓ dữ liệu nhưng không hợp lệ.
                n_sanitized += 1 if (val is not None and val != "") else 0
                X[i] = self._mean[i] if self._mean is not None else 0.0
            else:
                X[i] = parsed
                n_present += 1
        return X.reshape(1, -1), n_sanitized, n_present

    def evaluate(self, log: dict) -> tuple[str | None, str | None, float]:
        """Đánh giá log, trả (action, reasoning, confidence). action=None -> escalate LLM."""
        action, reasoning, confidence, _ = self.evaluate_detailed(log)
        return action, reasoning, confidence

    def evaluate_detailed(self, log: dict) -> tuple[str | None, str | None, float, dict]:
        """Như evaluate() nhưng trả thêm dict security để eval/test soi được phòng thủ.

        security = {skipped, sanitized(int), clamped(int), ood_fraction(float),
                    ood_abstain(bool), reason(str)}.
        """
        sec = {
            "skipped": False,
            "sanitized": 0,
            "clamped": 0,
            "ood_fraction": 0.0,
            "ood_abstain": False,
            "reason": "",
        }
        if not self.pipeline or "model" not in self.pipeline:
            sec["skipped"] = True
            sec["reason"] = "no_model"
            return None, None, 0.0, sec

        features = self.pipeline.get("features", [])
        model = self.pipeline["model"]
        scaler = self.pipeline["scaler"]

        required = ["Flow Duration", "Total Fwd Packets", "Flow Pkts/s"]
        has_features = sum(1 for req in required if req in log and log[req] not in ["", None, 0])
        if has_features == 0 and "Source IP" in log:
            # Log lớp-ứng-dụng thuần payload (DAPT/WAF) -> không đủ feature số, bỏ ML.
            sec["skipped"] = True
            sec["reason"] = "no_numeric_features"
            return None, None, 0.0, sec

        # ── LỚP BẢO MẬT 1: Sanitize (chặn NaN/Inf trước khi vào scaler) ──
        X_arr, n_sanitized, n_present = self._build_raw_vector(log, features)
        sec["sanitized"] = n_sanitized

        # ── LỚP BẢO MẬT 0: Phủ feature — vector toàn-mean (vd DAPT ~1/76) là dự đoán rác ──
        coverage = n_present / len(features) if features else 0.0
        sec["coverage"] = round(coverage, 4)
        if coverage < MIN_FEATURE_COVERAGE:
            sec["skipped"] = True
            sec["reason"] = "low_feature_coverage"
            logger.info(
                f"[TIER-1 ML GATE] Bỏ ML: chỉ {n_present}/{len(features)} feature có mặt "
                f"(< {MIN_FEATURE_COVERAGE:.0%}) -> escalate LLM. "
                f"src={log.get('Source IP') or log.get('src_ip')}"
            )
            return None, None, 0.0, sec

        try:
            X_scaled = scaler.transform(X_arr)
        except Exception as e:
            # Sau sanitize KHÔNG nên còn Inf; nếu vẫn lỗi -> abstain an toàn.
            logger.error(f"[TIER-1 ML GATE] Lỗi scale sau sanitize: {e}")
            sec["skipped"] = True
            sec["reason"] = "scale_error"
            return None, None, 0.0, sec

        # X_scaled CHÍNH LÀ z-score (StandardScaler). Dùng cho OOD + clamp.
        z = X_scaled[0]
        abs_z = np.abs(z)

        # ── LỚP BẢO MẬT 3: OOD abstain (input xa phân bố train -> không tin ML) ──
        n_ood = int(np.sum(abs_z > OOD_SIGMA))
        ood_fraction = n_ood / len(features) if features else 0.0
        sec["ood_fraction"] = round(ood_fraction, 4)
        if ood_fraction > OOD_FRACTION or n_sanitized > 0.5 * len(features):
            sec["ood_abstain"] = True
            sec["reason"] = "ood_abstain"
            logger.warning(
                f"[TIER-1 ML GATE][ML_OOD_ABSTAIN] Input xa phân bố train "
                f"({n_ood}/{len(features)} feature |z|>{OOD_SIGMA}, sanitized={n_sanitized}) "
                f"-> KHÔNG tin ML, escalate LLM. src={log.get('Source IP') or log.get('src_ip')}"
            )
            return None, None, 0.0, sec

        # ── LỚP BẢO MẬT 2: Clamp z-score (1 feature cực đoan không chi phối được) ──
        n_clamped = int(np.sum(abs_z > CLIP_SIGMA))
        sec["clamped"] = n_clamped
        if n_clamped > 0:
            X_scaled = np.clip(X_scaled, -CLIP_SIGMA, CLIP_SIGMA)
            logger.info(
                f"[TIER-1 ML GATE][ML_CLAMP] Kẹp {n_clamped} feature cực đoan về ±{CLIP_SIGMA}σ "
                f"(chống evasion). src={log.get('Source IP') or log.get('src_ip')}"
            )

        try:
            proba = model.predict_proba(X_scaled)[0]
        except Exception as e:
            logger.error(f"[TIER-1 ML GATE] Lỗi dự đoán: {e}")
            sec["skipped"] = True
            sec["reason"] = "predict_error"
            return None, None, 0.0, sec

        confidence_benign = float(proba[0])
        confidence_attack = float(proba[1])

        action = None
        reasoning = None
        confidence = 0.0

        # Cổng ML — 4 DẢI theo chính sách (C = confidence_attack):
        #   C>=0.85 BLOCK · 0.65–0.85 ESCALATE(LLM) · 0.40–0.65 ALERT · <0.40 PASS/DROP.
        # Lưu ý: "Cổng ML" là marker để UI bắt được (từ components.py).
        verdict = decision_policy.classify_ml(confidence_attack)
        if verdict == "BLOCK_IP":
            action = "BLOCK_IP"
            reasoning = f"Phát hiện tấn công bởi Cổng ML Tier-1 (LightGBM). Độ tin cậy: {confidence_attack:.2%}"
            confidence = confidence_attack
        elif verdict == "ALERT":
            action = "ALERT"
            reasoning = f"Cảnh báo rủi ro (low-priority) bởi Cổng ML Tier-1 (LightGBM). Độ tin cậy: {confidence_attack:.2%}"
            confidence = confidence_attack
        elif verdict == "DROP":
            # C < 0.40 -> PASS/audit log: dừng ngay ở Tier-1, KHÔNG tốn LLM (noise reduction thật).
            action = "DROP"
            reasoning = f"Xác nhận an toàn (PASS) bởi Cổng ML Tier-1 (LightGBM). Độ tin cậy: {confidence_benign:.2%}"
            confidence = confidence_benign
        # verdict == "ESCALATE" (0.65–0.85): giữ action=None -> đẩy LLM phân tích sâu.

        return action, reasoning, confidence, sec
