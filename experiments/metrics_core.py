"""Chỉ số đánh giá dùng chung — thuần Python, không phụ thuộc agent/LLM/RAG.

TÁCH RIÊNG có chủ đích, cùng khuôn với `action_scoring.py`: mọi script eval đều cần
những phép tính này, nhưng nếu để lẫn trong file eval thì chúng import cả agent + LLM
client + retriever, không unit-test được trong CI và không nơi nào dùng lại được.

BỐI CẢNH (vì sao cần từng nhóm hàm):

1. **MCC thay Accuracy.** Accuracy vô nghĩa trên dữ liệu lệch lớp, và benchmark của dự án
   lệch theo CẢ HAI chiều tuỳ tập: `ground_truth` phân tầng có ~94% tấn công (một hàm
   `return True` đạt accuracy 0,94), còn tập escalate của Tier-2 có ~98% lành tính (một
   hàm `return False` đạt 0,98). Cùng một hệ, đổi tập là accuracy nhảy từ 0,94 xuống 0,02
   — chỉ số biến động theo DỮ LIỆU hơn theo HỆ THỐNG thì không so sánh được. Hệ số tương
   quan Matthews dùng cả 4 ô nên chỉ cao khi hệ làm tốt ở CẢ hai lớp.

2. **Khoảng tin cậy.** Trước đây chỉ APT có Wilson CI; F1/precision/recall/action_accuracy
   đều là ước lượng điểm trần trụi. Với ablation n~160 và Tier-2 n=800, chênh lệch
   0,4391 vs 0,4435 giữa hai cấu hình HOÀN TOÀN có thể là nhiễu — không có CI thì không
   kết luận được gì. Bootstrap chạy trên kết quả ĐÃ LƯU nên không tốn thêm lượt gọi LLM.

3. **Bóc theo lớp.** Recall gộp 0,47 có thể là "bắt 100% DoS, 0% Infiltration". Bộ dữ liệu
   có 15 lớp tấn công nhưng trước đây `cicids_label` CHỈ dùng để lấy mẫu phân tầng, chưa
   bao giờ dùng để báo cáo — nên điểm mù không lộ ra.

4. **Gánh nặng cảnh báo.** Luận văn mở đầu bằng "SOC Alert Fatigue" nhưng lại đo bằng
   precision — đơn vị mà SOC không dùng. Quy về cảnh báo/giờ và cảnh báo/ca trực đóng lại
   đúng vòng lập luận đã mở.

5. **Neo bằng chứng thay "độ đầy đủ audit".** Chỉ số cũ đếm 5 trường trong dict do CHÍNH
   hệ sinh ra nên luôn đạt 100% — đó là kiểm tra schema, không phải phép đo. Prompt triage
   BẮT BUỘC mỗi luận điểm phải kèm ít nhất một giá trị `field=value` trích nguyên văn từ
   log; đo tỉ lệ tuân thủ điều đó mới là phép đo giải thích THẬT, và nó CÓ THỂ trượt.
"""

from __future__ import annotations

import math
import random
import re
from collections.abc import Callable, Sequence

# ==============================================================================
# 1. Chỉ số từ ma trận nhầm lẫn
# ==============================================================================


def mcc(tp: int, fp: int, tn: int, fn: int) -> float:
    """Hệ số tương quan Matthews ∈ [-1, 1] — thay thế Accuracy trên dữ liệu lệch lớp.

        MCC = (TP·TN − FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))

    Cách đọc:  +1 hoàn hảo · 0 = **không hơn đoán bừa** · −1 sai hệ thống.
    Tính chất quyết định: một hệ luôn hô "tấn công" (hoặc luôn hô "lành tính") cho MCC = 0
    BẤT KỂ tỉ lệ lớp — đúng thứ mà Accuracy và F1 không làm được.

    Mẫu số bằng 0 khi có một hàng/cột rỗng (hệ chỉ đoán một lớp) -> trả 0.0 theo quy ước.
    """
    num = (tp * tn) - (fp * fn)
    den = math.sqrt(float((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)))
    return round(num / den, 4) if den else 0.0


def balanced_accuracy(tp: int, fp: int, tn: int, fn: int) -> float:
    """Trung bình của recall trên lớp tấn công và recall trên lớp lành tính.

        BA = (TPR + TNR) / 2

    Đọc KÈM MCC: dễ diễn giải hơn ("đúng bao nhiêu % nếu hai lớp cân bằng") nhưng không
    phạt nặng bằng MCC khi hệ thiên hẳn về một lớp. Đoán bừa cho 0,5 — không phải 0.
    """
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0
    return round((tpr + tnr) / 2, 4)


def prf1(tp: int, fp: int, tn: int, fn: int) -> dict[str, float]:
    """Precision / Recall / F1 / Accuracy — bộ bốn cổ điển, gom một chỗ để khỏi chép lại.

    Accuracy VẪN được trả về nhưng phải đọc kèm `majority_baseline` (xem hàm dưới); nó có
    mặt để đối chiếu với tài liệu cũ, KHÔNG phải để trích làm kết luận.
    """
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    n = tp + fp + tn + fn
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(2 * p * r / (p + r), 4) if (p + r) else 0.0,
        "accuracy": round((tp + tn) / n, 4) if n else 0.0,
    }


def majority_baseline(n_positive: int, n_total: int) -> float:
    """Điểm của một stub hô "tấn công" cho MỌI đầu vào = tỉ lệ dương của tập.

    BẮT BUỘC in cạnh mọi accuracy. Giữ đúng ngữ nghĩa đang dùng ở
    `evaluate_tier2_decision.py` để không phá tính so sánh với số đã trích.
    """
    return round(n_positive / n_total, 4) if n_total else 0.0


def zero_r_accuracy(n_positive: int, n_total: int) -> float:
    """Accuracy của bộ phân loại hằng TỐT NHẤT (ZeroR) = max(tỉ lệ dương, tỉ lệ âm).

    Đây mới là mốc ĐÚNG để so với accuracy. `majority_baseline` (tỉ lệ dương) chỉ là mốc
    của stub luôn hô "tấn công" — trên tập ÁP ĐẢO LÀNH TÍNH thì stub khôn hơn là hô "lành
    tính", đạt accuracy bằng tỉ lệ âm. Nếu so accuracy với mỗi tỉ lệ dương, một hệ hô
    "lành tính" cho tất cả trên tập 98% benign sẽ "vượt mốc 0,02" và trông như có năng
    lực, trong khi thực chất nó không phân biệt được gì (MCC = 0).
    """
    if not n_total:
        return 0.0
    p = n_positive / n_total
    return round(max(p, 1.0 - p), 4)


def confusion_report(tp: int, fp: int, tn: int, fn: int) -> dict:
    """Gói đầy đủ 4 ô + mọi chỉ số dẫn xuất + mốc đối chứng. Dùng ở mọi script eval."""
    n = tp + fp + tn + fn
    base = prf1(tp, fp, tn, fn)
    acc = base["accuracy"]
    zero_r = zero_r_accuracy(tp + fn, n)
    return {
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "n_scored": n,
        **base,
        "mcc": mcc(tp, fp, tn, fn),
        "balanced_accuracy": balanced_accuracy(tp, fp, tn, fn),
        "majority_baseline": majority_baseline(tp + fn, n),
        "zero_r_accuracy": zero_r,
        "specificity": round(tn / (tn + fp), 4) if (tn + fp) else 0.0,
        # Cờ tự chẩn: accuracy không vượt được bộ phân loại HẰNG tốt nhất
        # -> chỉ số KHÔNG có năng lực phân biệt, đừng trích như một thành tích.
        "accuracy_beats_baseline": acc > zero_r,
    }


# ==============================================================================
# 2. Khoảng tin cậy
# ==============================================================================


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Khoảng tin cậy Wilson cho một TỈ LỆ k/n (mặc định 95%).

    Dùng cho recall/precision/specificity khi n NHỎ — đây chính là lý do "3/3 = 1,00"
    không được đọc là "hoàn hảo": Wilson cho cận dưới quanh 0,44 với n=3.

    Ưu điểm so với khoảng Wald thông thường: không bao giờ tràn ra ngoài [0,1] và vẫn có
    nghĩa khi k=0 hoặc k=n — đúng hai trường hợp hay gặp nhất ở n nhỏ.
    """
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / d
    return (round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4))


def bootstrap_ci(
    records: Sequence,
    statistic: Callable[[Sequence], float],
    n_resamples: int = 1000,
    alpha: float = 0.05,
    seed: int = 42,
) -> tuple[float, float]:
    """Khoảng tin cậy bootstrap phần trăm cho MỘT thống kê bất kỳ tính trên `records`.

    Dùng khi chỉ số không phải tỉ lệ đơn giản nên Wilson không áp được — F1, MCC,
    action_accuracy. Lấy mẫu lại CÓ HOÀN LẠI `n_resamples` lần, tính thống kê mỗi lần,
    rồi cắt phân vị.

    `seed` cố định -> **tất định**, chạy lại cho đúng số cũ. Chạy hoàn toàn trên kết quả
    ĐÃ LƯU nên KHÔNG tốn thêm lượt gọi LLM nào.

    Ví dụ:
        bootstrap_ci(list(zip(y_true, y_pred)), lambda s: f1_from_pairs(s))
    """
    n = len(records)
    if n < 2:
        return (0.0, 0.0)
    rng = random.Random(seed)
    stats: list[float] = []
    for _ in range(n_resamples):
        sample = [records[rng.randrange(n)] for _ in range(n)]
        try:
            stats.append(float(statistic(sample)))
        except (ZeroDivisionError, ValueError):
            continue  # mẫu suy biến (vd toàn một lớp) -> bỏ, không giết cả phép tính
    if not stats:
        return (0.0, 0.0)
    stats.sort()
    lo = stats[int((alpha / 2) * len(stats))]
    hi = stats[min(len(stats) - 1, int((1 - alpha / 2) * len(stats)))]
    return (round(lo, 4), round(hi, 4))


# ==============================================================================
# 3. Bóc theo lớp tấn công
# ==============================================================================


def per_class_report(
    records: Sequence[dict],
    label_key: str = "label",
    flagged_key: str = "flagged",
    threat_key: str = "is_threat",
) -> dict[str, dict]:
    """Recall (và số ca) cho TỪNG lớp tấn công, thay vì một con số gộp.

    Vì sao cần: recall gộp 0,47 có thể là "bắt 100% DoS, bỏ sót sạch Infiltration". Bộ dữ
    liệu có 15 lớp — không bóc ra thì không chứng minh được tính khái quát, và điểm mù
    không bao giờ lộ.

    Mỗi bản ghi cần: nhãn lớp, cờ hệ có gắn cờ không, và nhãn thật là tấn công hay không.
    Lớp LÀNH TÍNH cũng được báo, nhưng dưới dạng specificity (không phải recall).
    """
    groups: dict[str, list[dict]] = {}
    for r in records:
        groups.setdefault(str(r.get(label_key) or "unknown"), []).append(r)

    out: dict[str, dict] = {}
    for lbl, rows in sorted(groups.items()):
        n = len(rows)
        threats = [r for r in rows if r.get(threat_key)]
        benign = [r for r in rows if not r.get(threat_key)]
        caught = sum(1 for r in threats if r.get(flagged_key))
        passed = sum(1 for r in benign if not r.get(flagged_key))
        entry: dict = {"n": n, "n_threat": len(threats), "n_benign": len(benign)}
        if threats:
            entry["recall"] = round(caught / len(threats), 4)
            entry["recall_ci95"] = list(wilson_ci(caught, len(threats)))
            entry["missed"] = len(threats) - caught
        if benign:
            entry["specificity"] = round(passed / len(benign), 4)
            entry["false_positives"] = len(benign) - passed
        out[lbl] = entry
    return out


def weakest_classes(report: dict[str, dict], k: int = 3) -> list[tuple[str, float]]:
    """k lớp có recall THẤP NHẤT — điểm mù cần nêu thẳng ở mục Hạn chế của luận văn."""
    scored = [(lbl, e["recall"]) for lbl, e in report.items() if "recall" in e]
    return sorted(scored, key=lambda x: x[1])[:k]


# ==============================================================================
# 4. Hiệu năng vận hành
# ==============================================================================


def throughput(n_events: int, elapsed_seconds: float) -> float:
    """Sự kiện xử lý mỗi giây.

    Độ trễ MỖI SỰ KIỆN không trả lời được câu hỏi vận hành "hệ chịu được bao nhiêu EPS?"
    — đó là con số một SOC dùng để quyết định có triển khai được hay không. Tuyên bố trung
    tâm của luận văn là "làm suy luận LLM cục bộ khả thi", nên đây là chỉ số phải có.
    """
    return round(n_events / elapsed_seconds, 2) if elapsed_seconds > 0 else 0.0


def alert_burden(
    n_false_positives: int,
    n_total_alerts: int,
    elapsed_seconds: float,
    shift_hours: float = 8.0,
) -> dict[str, float]:
    """Quy tải cảnh báo về ĐƠN VỊ MÀ SOC THẬT DÙNG: cảnh báo/giờ và cảnh báo/ca trực.

    Precision 0,91 không cho analyst biết họ phải xử bao nhiêu cảnh báo rác mỗi ca. Luận
    văn mở đầu bằng nghịch lý mệt-mỏi-cảnh-báo thì phải đóng lại bằng chính đơn vị đó.

    LƯU Ý khi trích: con số này tỉ lệ thuận với TỐC ĐỘ PHÁT của benchmark, không phải tốc
    độ lưu lượng thật của một mạng doanh nghiệp. Phải nêu là "trên nhịp phát của benchmark",
    hoặc chuẩn hoá lại theo EPS mục tiêu trước khi so với số liệu ngành.
    """
    hours = elapsed_seconds / 3600.0 if elapsed_seconds > 0 else 0.0
    if hours <= 0:
        return {"alerts_per_hour": 0.0, "false_alerts_per_hour": 0.0, "alerts_per_shift": 0.0}
    return {
        "alerts_per_hour": round(n_total_alerts / hours, 2),
        "false_alerts_per_hour": round(n_false_positives / hours, 2),
        "alerts_per_shift": round(n_total_alerts / hours * shift_hours, 2),
        "false_alerts_per_shift": round(n_false_positives / hours * shift_hours, 2),
    }


# ==============================================================================
# 5. Chất lượng giải thích
# ==============================================================================

# `field=value`, `field="value"`, `field='value'` — đúng dạng mà prompt triage YÊU CẦU.
#
# Tên cột CICIDS CÓ khoảng trắng ("Total Fwd Packets") nên lớp ký tự của phần tên buộc
# phải cho phép space; hệ quả là nó nuốt luôn từ đứng trước trong văn xuôi ("with Total
# Fwd Packets"). Không siết regex được mà không làm hỏng tên cột nhiều từ, nên xử lý ở
# bước TRA CỨU: thử lần lượt các hậu tố của chuỗi tên (xem `_lookup_field`).
# Phần giá trị loại thêm backtick/ngoặc vuông-nhọn vì model hay bọc `field=value` trong
# markdown inline-code, khiến giá trị bắt được thành "22`" và không khớp gì cả.
_EVIDENCE_TOKEN = re.compile(r"([A-Za-z][\w /\.\-]{1,40})\s*=\s*([\"']?)([^\s\"',;)\]}`]{1,60})\2")
_VALUE_TRAILING = "`.,;:)]}\"'"


def _lookup_field(field: str, flat: dict[str, str]) -> str | None:
    """Tra giá trị thật của một tên trường bắt được từ văn xuôi.

    Thử từ CHUỖI ĐẦY ĐỦ rồi bỏ dần từ ở ĐẦU: "with Total Fwd Packets" -> "Total Fwd
    Packets" -> "Fwd Packets" -> "Packets". Lấy khớp DÀI NHẤT tìm được, nên "with" bị
    loại mà tên cột nhiều từ vẫn nguyên vẹn.
    """
    tokens = field.strip().split()
    for start in range(len(tokens)):
        key = "".join(tokens[start:]).lower().replace("_", "")
        if key in flat:
            return flat[key]
    return None


# Cụm "viện dẫn thẩm quyền" — lập luận rỗng mà prompt CẤM tường minh. Đếm riêng để thấy
# model có đang thay bằng chứng bằng lời khẳng định suông hay không.
_APPEAL_PHRASES = (
    "confirmed by mitre",
    "according to mitre",
    "as per nist",
    "based on best practice",
    "this is dangerous",
    "must be blocked",
    "clearly malicious",
)


def evidence_grounding(reasoning: str, log: dict) -> dict:
    """Lập luận có NEO vào bằng chứng thật trong log không? — thay `audit_completeness`.

    Chỉ số cũ đếm 5 trường trong dict do chính hệ sinh ra nên LUÔN đạt 100%: đó là kiểm
    tra schema, không phải phép đo chất lượng (một phép đo không thể trượt thì không đo
    được gì). Ở đây ta kiểm ĐÚNG điều prompt bắt buộc: mỗi luận điểm về hành vi phải kèm
    ít nhất một giá trị `field=value` **lấy nguyên văn từ log**.

    Trả:
      n_citations       — số cặp field=value trích được trong lập luận
      n_verified        — số cặp KHỚP giá trị thật trong log (chống bịa số)
      grounded          — có >=1 trích dẫn ĐÃ XÁC MINH
      n_appeals         — số cụm viện-dẫn-thẩm-quyền rỗng (prompt cấm)
    """
    text = str(reasoning or "")
    # So khớp không phân biệt hoa/thường và bỏ khoảng trắng, vì tên cột CICIDS có dấu cách
    # ("Total Fwd Packets") còn model hay viết liền hoặc gạch dưới.
    flat = {
        str(k).lower().replace(" ", "").replace("_", ""): str(v) for k, v in (log or {}).items()
    }

    n_cit = n_ver = 0
    for m in _EVIDENCE_TOKEN.finditer(text):
        field, value = m.group(1), m.group(3).rstrip(_VALUE_TRAILING)
        n_cit += 1
        actual = _lookup_field(field, flat)
        if actual is None or not value:
            continue
        # Số: so theo GIÁ TRỊ (1000 == 1000.0). Chuỗi: khớp con, không phân biệt hoa/thường.
        try:
            if math.isclose(float(actual), float(value), rel_tol=1e-6):
                n_ver += 1
                continue
        except (TypeError, ValueError):
            pass
        if value.lower() in actual.lower():
            n_ver += 1

    low = text.lower()
    return {
        "n_citations": n_cit,
        "n_verified": n_ver,
        "grounded": n_ver > 0,
        "n_appeals": sum(1 for p in _APPEAL_PHRASES if p in low),
    }


def evidence_grounding_rate(pairs: Sequence[tuple[str, dict]]) -> dict:
    """Tổng hợp `evidence_grounding` trên nhiều cặp (lập luận, log)."""
    if not pairs:
        return {"n": 0}
    per = [evidence_grounding(r, lg) for r, lg in pairs]
    n = len(per)
    n_grounded = sum(1 for p in per if p["grounded"])
    return {
        "n": n,
        "grounding_rate": round(n_grounded / n, 4),
        "grounding_rate_ci95": list(wilson_ci(n_grounded, n)),
        "mean_citations": round(sum(p["n_citations"] for p in per) / n, 2),
        "mean_verified_citations": round(sum(p["n_verified"] for p in per) / n, 2),
        "appeal_rate": round(sum(1 for p in per if p["n_appeals"] > 0) / n, 4),
    }


# ==============================================================================
# 6. Chi phí tài nguyên
# ==============================================================================

# Giá tham chiếu API thương mại ($/1 triệu token) — CHỈ để đối chiếu bậc độ lớn, không
# phải báo giá. Phải nêu rõ mốc thời gian khi trích vì giá thay đổi liên tục.
_REF_API_USD_PER_MTOK_IN = 3.0
_REF_API_USD_PER_MTOK_OUT = 15.0


def resource_cost(
    n_events: int,
    n_llm_calls: int,
    mean_prompt_tokens: float,
    mean_completion_tokens: float,
    gpu_vram_gb: float = 16.0,
) -> dict:
    """Chi phí xử lý quy về đơn vị so sánh được: token/1k sự kiện và $ tương đương API.

    VÌ SAO CẦN: luận điểm trung tâm là "suy luận LLM CỤC BỘ khả thi về vận hành". Vế
    "khả thi" có hai mặt — độ trễ (đã đo) và CHI PHÍ (chưa đo). Nếu không quy ra con số
    thì không trả lời được câu hỏi hiển nhiên của hội đồng: *"vì sao không gọi thẳng API
    thương mại cho nhanh?"*.

    Con số $ ở đây là CHI PHÍ TRÁNH ĐƯỢC (avoided cost) nếu cùng khối lượng đó chạy trên
    API thương mại — KHÔNG phải chi phí thực của hệ (hệ chạy cục bộ, chi phí biên ≈ điện
    năng). Đó chính là điều làm nó có sức thuyết phục: nó định giá phần việc mà kiến trúc
    hai tầng đã LOẠI BỎ khỏi tầng đắt tiền.

    Phải nêu kèm khi trích: giá API là mốc tham chiếu tại thời điểm viết, và VRAM là yêu
    cầu phần cứng tối thiểu để tái lập chứ không phải mức tiêu thụ đo được.
    """
    if n_events <= 0:
        return {"n_events": 0}
    tok_in = n_llm_calls * mean_prompt_tokens
    tok_out = n_llm_calls * mean_completion_tokens
    usd = (tok_in / 1e6) * _REF_API_USD_PER_MTOK_IN + (tok_out / 1e6) * _REF_API_USD_PER_MTOK_OUT
    return {
        "n_events": n_events,
        "n_llm_calls": n_llm_calls,
        "llm_call_rate": round(n_llm_calls / n_events, 4),
        "tokens_per_1k_events": round((tok_in + tok_out) / n_events * 1000, 1),
        "avoided_api_usd_per_1k_events": round(usd / n_events * 1000, 4),
        "gpu_vram_gb_required": gpu_vram_gb,
        "reference_api_pricing_usd_per_mtok": {
            "input": _REF_API_USD_PER_MTOK_IN,
            "output": _REF_API_USD_PER_MTOK_OUT,
        },
        "note": (
            "USD = chi phí TRÁNH ĐƯỢC nếu cùng khối lượng chạy trên API thương mại, không "
            "phải chi phí thực của hệ (chạy cục bộ). Giá API là mốc tham chiếu tại thời "
            "điểm đo; VRAM là yêu cầu tối thiểu để tái lập, không phải mức tiêu thụ đo được."
        ),
    }


# ==============================================================================
# 7. Độ đồng thuận giữa hai người/máy chấm
# ==============================================================================


def cohens_kappa(rater_a: Sequence, rater_b: Sequence) -> float:
    """Độ đồng thuận Cohen's κ giữa HAI người/máy chấm, đã trừ phần trùng do may rủi.

        κ = (Pₒ − Pₑ) / (1 − Pₑ)

    Vì sao luận văn cần: điểm LLM-as-Judge hiện dựa vào MỘT trọng tài duy nhất, không mẫu
    nào được người đối chiếu. Nếu Context Precision thấp, ta KHÔNG phân biệt được "agent
    kém" với "trọng tài kém". Cho người chấm một mẫu con rồi tính κ là cách rẻ nhất để
    biết điểm của trọng tài có đáng tin không.

    Thang quy ước (Landis & Koch): <0,20 rất kém · 0,21–0,40 kém · 0,41–0,60 vừa ·
    0,61–0,80 tốt · >0,80 rất tốt.
    """
    n = min(len(rater_a), len(rater_b))
    if n == 0:
        return 0.0
    a, b = list(rater_a)[:n], list(rater_b)[:n]
    observed = sum(1 for x, y in zip(a, b, strict=False) if x == y) / n
    cats = set(a) | set(b)
    expected = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    if math.isclose(expected, 1.0):
        return 1.0 if math.isclose(observed, 1.0) else 0.0
    return round((observed - expected) / (1 - expected), 4)


# ==============================================================================
# Hiệu chuẩn độ tin cậy — confidence có ĐÁNG TIN không?
# ==============================================================================


def brier_score(confidences: Sequence[float], outcomes: Sequence[bool]) -> float:
    """Sai số bình phương trung bình giữa độ tin cậy dự báo và kết cục thực tế.

        Brier = (1/n) · Σ (pᵢ − oᵢ)²      với oᵢ ∈ {0, 1}

    Đọc: 0,0 là hoàn hảo; 0,25 là mức của một hệ luôn hô 0,5; càng thấp càng tốt. Khác
    accuracy ở chỗ nó phạt cả sự QUÁ TỰ TIN: đoán đúng với p=0,55 tốt hơn đoán sai với
    p=0,95, và Brier phản ánh đúng thứ tự đó.
    """
    n = min(len(confidences), len(outcomes))
    if n == 0:
        return 0.0
    return round(sum((float(confidences[i]) - bool(outcomes[i])) ** 2 for i in range(n)) / n, 4)


def expected_calibration_error(
    confidences: Sequence[float], outcomes: Sequence[bool], n_bins: int = 10
) -> dict:
    """ECE — độ lệch trung bình giữa "hệ nói chắc bao nhiêu" và "hệ đúng bao nhiêu".

    Chia [0,1] thành `n_bins` khoảng, mỗi khoảng so ĐỘ TIN CẬY TRUNG BÌNH với TỈ LỆ ĐÚNG
    THỰC TẾ, rồi lấy trung bình có trọng số theo số mẫu::

        ECE = Σ_b (n_b / n) · |acc(b) − conf(b)|

    VÌ SAO LUẬN VĂN CẦN CHỈ SỐ NÀY. Chính sách 4 dải (BLOCK ≥0,85 · ESCALATE 0,65–0,85 ·
    ALERT 0,40–0,65 · DROP <0,40) là một đóng góp được tuyên bố, và nó đứng trên MỘT giả
    định chưa từng được kiểm: rằng con số `confidence` có ý nghĩa. Quét ngưỡng chỉ trả lời
    "chọn 0,85 có phải cherry-pick không"; nó KHÔNG trả lời "0,85 có thật sự nghĩa là đúng
    85% số lần không". ECE trả lời đúng câu đó, và nó CÓ THỂ TRƯỢT — một mô hình quá tự tin
    (hô 0,95 nhưng chỉ đúng 60%) cho ECE lớn, và khi đó ngưỡng BLOCK tự động đang đứng trên
    cát bất kể quét ngưỡng đẹp tới đâu.

    Trả thêm `bins` để vẽ được biểu đồ độ tin cậy (reliability diagram).
    """
    n = min(len(confidences), len(outcomes))
    if n == 0 or n_bins < 1:
        return {"ece": 0.0, "max_gap": 0.0, "n": 0, "bins": []}

    buckets: list[dict] = [
        {"lo": i / n_bins, "hi": (i + 1) / n_bins, "n": 0, "conf_sum": 0.0, "n_correct": 0}
        for i in range(n_bins)
    ]
    for i in range(n):
        p = min(max(float(confidences[i]), 0.0), 1.0)
        idx = min(int(p * n_bins), n_bins - 1)
        buckets[idx]["n"] += 1
        buckets[idx]["conf_sum"] += p
        buckets[idx]["n_correct"] += 1 if outcomes[i] else 0

    ece = 0.0
    max_gap = 0.0
    out_bins = []
    for b in buckets:
        if not b["n"]:
            continue
        conf = b["conf_sum"] / b["n"]
        acc = b["n_correct"] / b["n"]
        gap = abs(acc - conf)
        ece += (b["n"] / n) * gap
        max_gap = max(max_gap, gap)
        out_bins.append(
            {
                "range": [round(b["lo"], 2), round(b["hi"], 2)],
                "n": b["n"],
                "mean_confidence": round(conf, 4),
                "actual_accuracy": round(acc, 4),
                "gap": round(gap, 4),
                # Dấu của (acc − conf): âm = QUÁ TỰ TIN (nói chắc hơn thực lực) — chiều
                # nguy hiểm, vì nó đẩy ca sai vào dải tự động BLOCK.
                "overconfident": acc < conf,
            }
        )
    return {"ece": round(ece, 4), "max_gap": round(max_gap, 4), "n": n, "bins": out_bins}


def calibration_report(confidences: Sequence[float], outcomes: Sequence[bool]) -> dict:
    """Gói hiệu chuẩn đầy đủ: Brier + ECE + kiểm tra riêng dải tự động BLOCK.

    `high_conf_*` là phần đắt giá nhất trong thực tế: chỉ xét các ca có độ tin cậy ≥ 0,85
    (ngưỡng tự động BLOCK). Một lệnh chặn KHÔNG THỂ ĐẢO, nên sai ở dải này tốn kém hơn hẳn
    sai ở dải ALERT. ECE gộp có thể đẹp trong khi riêng dải cao vẫn hỏng.
    """
    n = min(len(confidences), len(outcomes))
    hi = [(float(confidences[i]), bool(outcomes[i])) for i in range(n) if confidences[i] >= 0.85]
    n_hi = len(hi)
    n_hi_correct = sum(1 for _, o in hi if o)
    return {
        "n": n,
        "brier": brier_score(confidences, outcomes),
        **expected_calibration_error(confidences, outcomes),
        "high_conf_n": n_hi,
        "high_conf_accuracy": round(n_hi_correct / n_hi, 4) if n_hi else None,
        "high_conf_accuracy_ci95": list(wilson_ci(n_hi_correct, n_hi)) if n_hi else None,
        "high_conf_mean_confidence": round(sum(c for c, _ in hi) / n_hi, 4) if n_hi else None,
    }


# ==============================================================================
# Ngăn chặn ở MỨC IP — "kẻ tấn công có bị chặn không, và sau bao nhiêu sự kiện?"
# ==============================================================================


def ip_containment(events: Sequence[dict]) -> dict:
    """Quy trách nhiệm ở mức ĐỊA CHỈ NGUỒN thay vì mức từng sự kiện.

    `events` là chuỗi theo ĐÚNG thứ tự luồng, mỗi phần tử::

        {"ip": str, "is_attack": bool, "blocked": bool}

    `blocked` = sự kiện này khiến hệ ra lệnh chặn (BLOCK_IP), không phải chỉ cảnh báo.

    VÌ SAO CẦN — và vì sao thiếu nó thì bộ chỉ số đang tự làm hại luận văn. Mọi chỉ số hiện
    có đều đếm theo SỰ KIỆN. Một kẻ tấn công gửi 500 flow bị đếm thành 500 sự kiện, nên nếu
    hệ chặn nó ở flow thứ 3 thì F1 mức-sự-kiện vẫn phạt đủ 497 lần còn lại. Vận hành thật
    thì đó là THÀNH CÔNG — kẻ tấn công đã bị cắt — nhưng thước đo ghi nhận là thất bại.
    Kiến trúc của hệ (uy tín IP, chặn-khi-thấy-lại, liên kết chiến dịch đa ngày) vận hành ở
    mức IP, nên phải có thước đo ở đúng mức đó.

    Bộ bốn chỉ số phải đọc CÙNG NHAU:
      * `containment_rate` — bao nhiêu IP tấn công rốt cuộc bị chặn;
      * `leak_rate`        — phần bù, tức "tỉ lệ IP lọt qua hệ thống";
      * `events_before_containment` — sự kiện lọt được TRƯỚC khi lệnh chặn có hiệu lực,
        tức THIỆT HẠI THỰC; chặn ở sự kiện thứ 2 khác hẳn chặn ở sự kiện thứ 400;
      * `benign_ip_false_block_rate` — đối trọng BẮT BUỘC. Không có nó thì một hệ chặn
        sạch mọi IP đạt containment 1,00 và trông như hoàn hảo.

    CẢNH BÁO ĐỌC SỐ: chỉ số này chỉ có nghĩa khi ĐỊNH DANH IP có nghĩa. Với dữ liệu mà địa
    chỉ nguồn là tổng hợp, nó đo CƠ CHẾ (lệnh chặn có bật và có dính không) chứ không đo độ
    khó. Hãy tách nhóm nguồn IP thật và IP tổng hợp khi báo cáo.
    """
    order: list[str] = []
    seen: set[str] = set()
    attack_seq: dict[str, list[bool]] = {}
    is_attacker: dict[str, bool] = {}
    blocked_at: dict[str, int | None] = {}

    for ev in events:
        ip = str(ev.get("ip") or "")
        if not ip:
            continue
        if ip not in seen:
            seen.add(ip)
            order.append(ip)
            attack_seq[ip] = []
            is_attacker[ip] = False
            blocked_at[ip] = None
        atk = bool(ev.get("is_attack"))
        if atk:
            is_attacker[ip] = True
            attack_seq[ip].append(True)
        if bool(ev.get("blocked")) and blocked_at[ip] is None:
            # Vị trí = số sự kiện TẤN CÔNG của IP này đã đi qua trước lệnh chặn.
            blocked_at[ip] = len(attack_seq[ip]) - (1 if atk else 0)

    attackers = [ip for ip in order if is_attacker[ip]]
    benign_only = [ip for ip in order if not is_attacker[ip]]
    contained = [ip for ip in attackers if blocked_at[ip] is not None]
    fb = [ip for ip in benign_only if blocked_at[ip] is not None]

    delays = sorted(blocked_at[ip] or 0 for ip in contained)
    n_atk, n_ben = len(attackers), len(benign_only)

    def _pct(vals: list[int], q: float) -> int | None:
        if not vals:
            return None
        return vals[min(int(q * len(vals)), len(vals) - 1)]

    return {
        "n_attacker_ips": n_atk,
        "n_benign_ips": n_ben,
        "n_contained": len(contained),
        "containment_rate": round(len(contained) / n_atk, 4) if n_atk else None,
        "containment_ci95": list(wilson_ci(len(contained), n_atk)) if n_atk else None,
        # Chính là con số "tỉ lệ IP lọt qua hệ thống".
        "leak_rate": round(1 - len(contained) / n_atk, 4) if n_atk else None,
        "events_before_containment": {
            "median": _pct(delays, 0.5),
            "p95": _pct(delays, 0.95),
            "max": delays[-1] if delays else None,
            "mean": round(sum(delays) / len(delays), 2) if delays else None,
        },
        "benign_ip_false_block_rate": round(len(fb) / n_ben, 4) if n_ben else None,
        "benign_ip_false_block_ci95": list(wilson_ci(len(fb), n_ben)) if n_ben else None,
        "n_benign_ips_blocked": len(fb),
    }


# ==============================================================================
# Chất lượng TRUY XUẤT — đo thẳng bộ RAG, không qua trung gian LLM
# ==============================================================================


def _rank_of(retrieved: Sequence[str], relevant: set) -> int | None:
    """Hạng 1-based của tài liệu liên quan ĐẦU TIÊN; None nếu không có trong danh sách."""
    for i, doc_id in enumerate(retrieved, start=1):
        if doc_id in relevant:
            return i
    return None


def retrieval_report(
    queries: Sequence[tuple[Sequence[str], set]], ks: Sequence[int] = (1, 3, 5, 10)
) -> dict:
    """Recall@k · MRR · nDCG@k trên tập truy vấn đã chạy.

    `queries` là chuỗi cặp `(danh sách id đã truy xuất theo THỨ TỰ HẠNG, tập id liên quan)`.

    VÌ SAO CẦN. Chất lượng truy xuất hiện chỉ được đo GIÁN TIẾP, qua điểm "Context
    Precision" mà một LLM khác chấm. Cách đó trộn ba thứ vào một con số: bộ truy xuất lấy
    đúng chưa, tác tử dùng ngữ cảnh khéo không, và trọng tài chấm có chuẩn không. Khi điểm
    thấp, ta KHÔNG biết phải sửa cái nào. Ba chỉ số dưới đây đo THẲNG bộ truy xuất, chạy
    offline trong vài giây và KHÔNG cần LLM — nên chúng cũng là cách rẻ nhất để chứng minh
    hiệu quả của RAG lai (FAISS + BM25 hợp nhất bằng RRF), vốn là một đóng góp được tuyên bố
    nhưng chưa từng có phép đo riêng.

    Ba chỉ số trả lời ba câu khác nhau, phải đọc cùng nhau:
      * `recall@k` — tài liệu đúng có LỌT vào k đầu không? (có/không)
      * `mrr`      — nó nằm ở hạng bao nhiêu? (1/hạng, trung bình) — nhạy với việc leo hạng
                     mà recall@k không thấy, vì hạng 5 lên hạng 1 vẫn giữ recall@5 = 1,0.
      * `ndcg@k`   — có tính CHIẾT KHẤU theo log vị trí, chuẩn của ngành truy xuất thông tin.

    Prompt chỉ nạp 3 đoạn hợp nhất đầu bảng, nên **recall@3 mới là con số vận hành**:
    tài liệu đúng nằm ở hạng 7 thì với LLM nó không tồn tại.
    """
    n = len(queries)
    if n == 0:
        return {"n_queries": 0, "recall_at_k": {}, "mrr": 0.0, "ndcg_at_k": {}, "n_found": 0}

    ranks: list[int | None] = [_rank_of(r, rel) for r, rel in queries]
    recall = {f"@{k}": round(sum(1 for r in ranks if r is not None and r <= k) / n, 4) for k in ks}
    mrr = round(sum((1.0 / r) if r else 0.0 for r in ranks), 4) / n
    # nDCG với MỘT tài liệu liên quan lý tưởng ở hạng 1 => IDCG = 1, nên DCG = 1/log2(1+hạng).
    ndcg = {
        f"@{k}": round(sum(1.0 / math.log2(1 + r) if (r and r <= k) else 0.0 for r in ranks) / n, 4)
        for k in ks
    }
    found = [r for r in ranks if r is not None]
    return {
        "n_queries": n,
        "n_found": len(found),
        "recall_at_k": recall,
        "recall_at_3_ci95": list(wilson_ci(sum(1 for r in ranks if r is not None and r <= 3), n)),
        "mrr": round(mrr, 4),
        "ndcg_at_k": ndcg,
        "median_rank_when_found": sorted(found)[len(found) // 2] if found else None,
        "miss_rate": round(1 - len(found) / n, 4),
    }
