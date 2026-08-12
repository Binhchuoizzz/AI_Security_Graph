"""Cổng BẰNG CHỨNG QUY KẾT: Tier-2 chỉ được khẳng định kỹ thuật khi có căn cứ.

BỐI CẢNH ĐO ĐƯỢC (lượt chạy 11/08/2026, 496.885 sự kiện, 553 lô Tier-2). Trước bản vá:

  * 336 lô chỉ sinh 44 truy vấn RAG phân biệt; 187 lô (55,7%) dùng CHUNG một chuỗi
    "high event frequency ... service http destination port 8080" — không mang tín hiệu
    tấn công nào. Với truy vấn đó RAG chỉ trả về được kỹ thuật tầng mạng, nên T1190 thậm
    chí không có mặt để LLM chọn.
  * T1571 "Non-Standard Port" chiếm 139/327 quy kết (42,5%), và 136/136 lô một-log bị chặn
    đều rơi vào bản ghi LÀNH — độ chính xác lệnh chặn 0,0%.
  * Lá chắn `OVERLY_GENERIC_TECHNIQUES` có tồn tại nhưng điều kiện là "payload RỖNG", mà
    lưu lượng web luôn có payload, nên nó chưa bao giờ bắn đúng nhóm nó nhắm tới.

Các test dưới đây khoá HÀNH VI (đầu vào -> đầu ra), không khoá văn bản mã nguồn: một test
kiểm `'chuỗi' in source` vẫn xanh trong khi hành vi đã hỏng — đúng cách mà lỗi trên lọt qua.
"""

import json

import pytest

from src.agent.attack_mapper import AttackMapperInput, _from_triage_anchor
from src.agent.nodes import batch_attack_vocabulary, build_rag_queries

UA = "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)"


def _log(payload="", uri="/tienda1/publico/anadir.jsp", reasons=None, **kw):
    """Một log HTTP kiểu CSIC 2010 đã qua Tier-1."""
    d = {
        "Source IP": "198.51.100.7",
        "Destination Port": 8080,
        "service": "http",
        "method": "POST",
        "uri": uri,
        "payload": payload,
        "user_agent": UA,
        "message": f"HTTP POST {uri}",
        "tier1_reasons": reasons
        if reasons is not None
        else ["Tần suất gửi yêu cầu cao: 1.00 req/s"],
        "tier1_action": "ESCALATE",
    }
    d.update(kw)
    return d


# ── 1. Lô KHÔNG có căn cứ thì không có từ vựng quy kết ────────────────────────────
def test_frequency_only_batch_yields_no_attack_vocabulary():
    """Lý do Tier-1 duy nhất là "tần suất cao" -> KHÔNG được suy ra kỹ thuật nào.

    Một ngưỡng bị vượt chỉ chứng minh khối lượng bất thường; DoS, C2 beaconing và rò rỉ dữ
    liệu đều khớp như nhau. Đây chính là 100% số lô đã bị chặn nhầm trong lượt đo.
    """
    assert batch_attack_vocabulary([_log(payload="idA=2")]) == []


def test_benign_ecommerce_form_yields_no_attack_vocabulary():
    """Biểu mẫu đăng ký hợp lệ (có `login=`/`password=`) KHÔNG phải brute force.

    Mẫu cũ `login=|pwd=|password=` khớp mọi biểu mẫu thương mại điện tử và bơm từ vựng
    "brute force" vào 70/336 lô, kéo theo cụm quy kết T1110.x cho lưu lượng lành.
    """
    form = "modo=registro&login=medeiros&password=r31u1tAMEnte&nombre=Francesca&B1=Registrar"
    assert batch_attack_vocabulary([_log(payload=form)]) == []
    tech_q, _ = build_rag_queries([_log(payload=form)])
    assert "brute force" not in tech_q.lower()


def test_repeated_authentication_does_become_brute_force_signal():
    """Nhưng LẶP LẠI thì có: >=3 lần gửi thông tin xác thực trong cùng một lô."""
    logs = [
        _log(payload=f"login=u{i}&password=p{i}", uri="/tienda1/publico/autenticar.jsp")
        for i in range(3)
    ]
    tech_q, _ = build_rag_queries(logs)
    assert "brute force" in tech_q.lower()


# ── 2. Chữ ký WAF của Tier-1 phải chảy vào truy vấn KỂ CẢ khi tier1_reasons thiếu ──
@pytest.mark.parametrize(
    "payload,uri,expect_term",
    [
        (
            "B2=%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--",
            "/tienda1/publico/vaciar.jsp",
            "sql injection",
        ),
        ("", "/tienda1/imagenes/1.gif.inc", "scanning"),
        (
            "B1=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "/tienda1/publico/anadir.jsp",
            "cross-site scripting",
        ),
    ],
)
def test_waf_signature_recovered_when_tier1_reasons_lack_it(payload, uri, expect_term):
    """Log leo thang qua đường z-score chưa từng đi qua nhánh chữ ký -> Tier-2 soi lại.

    `tier1_reasons` ở đây CỐ Ý chỉ có lý do tần suất, đúng như luồng thật: đây là đường mà
    257/336 lô đã đi, và là lý do truy vấn RAG mất sạch từ vựng tấn công.
    """
    lg = _log(payload=payload, uri=uri, reasons=["Tần suất gửi yêu cầu cao: 1.00 req/s"])
    voc = batch_attack_vocabulary([lg])
    assert voc, "chữ ký WAF phải được soi lại khi tier1_reasons không mang từ vựng tấn công"
    assert any(expect_term in v.lower() for v in voc), f"{expect_term!r} không có trong {voc}"
    tech_q, _ = build_rag_queries([lg])
    assert expect_term in tech_q.lower()


def test_tier1_signature_still_wins_when_present():
    """Có sẵn chữ ký trong `tier1_reasons` thì KHÔNG cần soi lại — giữ đường cũ."""
    lg = _log(reasons=["WAF: Phát hiện SQL Injection (SQLi) trong 'payload'"])
    voc = batch_attack_vocabulary([lg])
    assert any("sql injection" in v.lower() for v in voc)


# ── 3. Lá chắn T1571: payload CÓ MẶT không phải là bằng chứng cho C2 ──────────────
def test_t1571_with_web_attack_payload_is_downgraded():
    """REGRESSION: payload SQLi là bằng chứng CHỐNG LẠI cách đọc C2, không phải ủng hộ.

    Điều kiện cũ ("payload rỗng thì mới hạ cấp") giữ nguyên `resolved` cho đúng ca này —
    chế độ hỏng chiếm 42,5% quy kết trong lượt đo.
    """
    m = _from_triage_anchor(
        AttackMapperInput(
            attack_type="T1571 - Non-Standard Port",
            confidence=0.93,
            payload="B2=');waitfor delay '0:0:15';--",
        )
    )
    assert m is not None
    assert m.mitre_technique_id == "T1571", "vẫn GIỮ dự đoán để analyst thấy"
    assert m.mapping_status == "low_confidence", "nhưng phải buộc người xác minh"
    assert m.mapping_confidence <= 0.4


def test_t1571_technique_name_alone_is_not_self_corroborating():
    """Chuỗi "non-standard port" là TÊN của T1571 — không được tính là bằng chứng.

    Nhận nó thì lá chắn tự phản: model chỉ cần nêu tên kỹ thuật là tự chứng minh cho mình.
    """
    m = _from_triage_anchor(
        AttackMapperInput(attack_type="non-standard port detected", confidence=0.9, payload="idA=2")
    )
    if m is not None and m.mitre_technique_id == "T1571":
        assert m.mapping_status == "low_confidence"


# ── 4. Cổng chỉ được ĐÓNG với lành, không được đóng với tấn công thật ─────────────
def test_gate_separates_attack_from_benign_on_real_csic():
    """Đo trên CSIC 2010 THẬT, cỡ lô 10 (đúng cỡ lô Tier-2 dùng).

    Số chốt của lượt đo: lô tấn công giữ 97,6%, lô lành giữ 0,0%. Ngưỡng dưới đây nới rộng
    để không đỏ vì nhiễu mẫu, nhưng bất biến "0 báo nhầm" thì KHÔNG nới.
    """
    import ast
    import os

    path = "data/csic.json"
    if not os.path.exists(path):
        pytest.skip("cần data/csic.json (dựng bằng scripts/build_csic_dataset.py)")
    with open(path) as f:
        csic = json.load(f)

    def lab(e):
        v = e.get("_label")
        if isinstance(v, str):
            try:
                v = ast.literal_eval(v)
            except Exception:
                v = {}
        return v or {}

    atk = [e for e in csic if lab(e).get("expected_threat")][:3000]
    ben = [e for e in csic if not lab(e).get("expected_threat")][:3000]

    def keep_rate(pool, n=10):
        batches = [pool[i : i + n] for i in range(0, len(pool) // n * n, n)]
        return sum(1 for b in batches if batch_attack_vocabulary(b)) / max(1, len(batches))

    assert keep_rate(ben) == 0.0, "lô toàn lành KHÔNG được sinh từ vựng tấn công"
    assert keep_rate(atk) >= 0.90, "lô tấn công phải giữ được quyền quy kết"


# ==============================================================================
# TRUY VẤN RAG — hai lỗi làm chệch vector, đo trên lượt chạy 12/08/2026
# ==============================================================================
def test_auth_vocabulary_suppressed_when_batch_has_specific_signature():
    """Lô CÓ chữ ký cụ thể thì KHÔNG được nhét thêm cụm brute-force.

    HỒI QUY LỖI THẬT. "Lặp lại gửi thông tin xác thực" là tín hiệu HÀNH VI, cùng hạng với các
    cụm ngưỡng: nối nó cạnh một chữ ký cụ thể thì nó kéo tụt chữ ký ấy. CSIC nhúng payload
    CRLF/XSS vào chính form đăng ký nên `login=`/`password=` xuất hiện ở cả 10 log của lô,
    cụm brute-force luôn được thêm, và truy xuất trả về họ T1110. Quy kết luật CHẶT của ba
    lớp đó: T1071.001 0/39 · T1059.007 0/16 · T1083 0/14.
    """
    from src.agent.nodes import build_rag_queries

    logs = [
        {
            "Source IP": "203.0.113.5",
            "service": "http",
            "uri": f"/app/registro.jsp?modo=registro%0d%0aSet-cookie:+X=1&login=u{i}&password=p{i}",
            "payload": "",
            "tier1_reasons": ["WAF: Phát hiện CRLF / Response Splitting trong 'uri'"],
        }
        for i in range(10)
    ]
    q = build_rag_queries(logs)
    tq = str(q[0] if isinstance(q, (list, tuple)) else q).lower()
    assert "response splitting" in tq, "phải giữ chữ ký cụ thể của lô"
    assert "brute force" not in tq, (
        "cụm brute-force phải bị chặn khi lô đã có chữ ký cụ thể — nó kéo truy xuất sang T1110"
    )


def test_no_attack_term_names_a_different_technique():
    """Cụm từ vựng không được chứa NGUYÊN TÊN của kỹ thuật KHÁC với đáp án của chính nó.

    HỒI QUY LỖI THẬT. Cụm XSS từng là "cross-site scripting XSS **drive-by compromise** web
    client exploit" — "Drive-by Compromise" là tên của T1189. Truy vấn đó trả về
    [T1189, T1608.004, T1190, T1203, T1571], KHÔNG có T1059.007; bỏ hai từ ấy thì T1059.007
    lên hạng 1. Cùng cái bẫy với lá chắn T1571 từng tự chứng minh bằng chính tên mình.

    Test khoá ĐÚNG các cặp đã đo, không quét cả bảng: nhiều cụm CỐ Ý mang tên kỹ thuật đáp án
    của chúng (cụm SQLi chứa "exploit public-facing application" vì T1190 chính là đáp án).
    """
    from src.agent.nodes import _ATTACK_TERMS

    terms = dict(_ATTACK_TERMS)
    cam = {
        "xss": "drive-by compromise",
        "cross-site scripting": "drive-by compromise",
    }
    for khoa, cum_cam in cam.items():
        assert khoa in terms, f"mất khoá từ vựng {khoa!r}"
        assert cum_cam not in terms[khoa].lower(), (
            f"cụm {khoa!r} chứa tên kỹ thuật khác ({cum_cam!r}) -> truy xuất sẽ trả về "
            f"chính kỹ thuật đó thay vì đáp án"
        )
