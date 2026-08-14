"""Khoá bộ dựng badge của Dashboard — chống tái phát giá trị BỊA trên màn hình.

VÌ SAO CÓ TỆP NÀY. Cùng một logic badge từng có BA bản chép tay (thẻ cảnh báo, cụm HITL,
thẻ chặn Tier-1). Chúng trôi dạt khỏi nhau, và bốn giá trị bịa phải sửa HAI LẦN ở hai tệp
mới hết. Nay logic gom về `src/ui/components.py`; test này khoá cả hành vi lẫn việc không
ai chép lại bản thứ hai.

Bốn giá trị bịa đã bị loại (giữ tên ở đây làm mốc hồi quy):
  1. `Threat Memory: 13 sự cố (10 Block · 3 HITL/Audit) · Risk: 100.0/100` hardcode, kích
     hoạt một phần bởi việc chuỗi IP demo "198.51.100" xuất hiện trong target;
  2. `default_top5` độn 5 mã vào panel dán nhãn "Top-5 Ứng viên RAG Truy xuất (FAISS+BM25)"
     dù chúng chưa từng qua RAG;
  3. in `T1190 - Exploit Public-Facing Application` khi hệ thật sự trả `N/A`;
  4. `Live GPU (TTFT 0.3s)` — con số không đến từ phép đo nào.
"""

import ast
import inspect
import re
from pathlib import Path

import pytest

from src.ui import components as C

SRC_DIR = Path(__file__).resolve().parents[2] / "src" / "ui"


# ── parse_mitre_technique ──────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("Agent: SQLi [MITRE: T1190] Confidence: 0.9", "T1190"),
        ("[MITRE: T1059.007 [Tự suy luận]]", "T1059.007 [Tự suy luận]"),  # ngoặc lồng
        ("phát hiện AML.T0051 prompt injection", "AML.T0051"),
        ("chỉ có mã trần T1595.003 trong câu", "T1595.003"),
        ("không có mã kỹ thuật nào ở đây", "N/A"),
        ("", "N/A"),
    ],
)
def test_parse_mitre_technique(reason, expected):
    assert C.parse_mitre_technique(reason) == expected


def test_khong_ma_thi_khong_duoc_doan_thanh_t1190():
    """Lỗi cũ: N/A bị thay bằng T1190 — màn hình công bố kỹ thuật hệ chưa hề kết luận."""
    for reason in ("hệ không quy kết được", "unmappable", "Confidence: 0.31"):
        assert "T1190" not in C.parse_mitre_technique(reason)


def test_parse_mitre_tra_ve_nguyen_van_chu_khong_lam_sach():
    """Hàm này là bộ BÓC TÁCH, KHÔNG phải bộ lọc HTML — nơi gọi phải tự thoát chuỗi.

    Chuỗi reason do LLM sinh ra SAU KHI đã đọc payload của kẻ tấn công, nên mọi thứ nằm
    trong `[MITRE: ...]` đều là dữ liệu không tin cậy. Khoá hành vi ở đây để test dưới
    (`test_ma_mitre_khong_duoc_nhung_tho_vao_html`) có nghĩa thật.
    """
    doc = "[MITRE: <img src=x onerror=alert(1)>]"
    assert C.parse_mitre_technique(doc) == "<img src=x onerror=alert(1)>"


# ── Chống Stored XSS trên màn hình SOC ─────────────────────────────────────────────
# `<script>` chèn qua innerHTML thì trình duyệt KHÔNG chạy, nhưng thuộc tính bắt sự kiện
# (`onerror`, `onload`) thì CÓ. Nên "không thấy thẻ script" không phải là bằng chứng an toàn.
_NHUNG_VAO_CODE = re.compile(r"<code[^>]*>\{(?P<ten>[A-Za-z_][A-Za-z0-9_]*)\}</code>")


@pytest.mark.parametrize("ten_tep", ["app.py", "components.py"])
def test_ma_mitre_khong_duoc_nhung_tho_vao_html(ten_tep):
    """Mã kỹ thuật chỉ được vào HTML sau khi thoát chuỗi.

    Hồi quy thật: `render_alert_card` đã thoát (`components.py`), nhưng bảng HITL trong
    `app.py` dùng CÙNG hàm bóc tách mà quên rào — một payload khiến LLM viết
    `[MITRE: <img src=x onerror=...>]` vào reason là đủ để chạy mã trong trình duyệt của
    analyst khi họ mở thẻ. Cùng một hàm, hai nơi dùng, chỉ một nơi có rào.
    """
    text = (SRC_DIR / ten_tep).read_text(encoding="utf-8")
    for m in _NHUNG_VAO_CODE.finditer(text):
        ten = m.group("ten")
        # Phép gán có thể xuống dòng trong ngoặc: `x = (\n  html.escape(...)`
        da_thoat = re.search(rf"\b{ten}\s*=\s*\(?\s*html(?:_lib)?\.escape\(", text)
        assert ten.startswith("safe_") or da_thoat, (
            f"{ten_tep}: `{ten}` nhúng thô vào <code>…</code> dưới unsafe_allow_html. "
            "Thoát bằng html.escape() rồi đặt tên bắt đầu bằng `safe_` như phần còn lại của tệp."
        )


# ── build_threat_memory_badge ──────────────────────────────────────────────────────
def test_threat_memory_khong_co_du_lieu_thi_noi_la_khong_co():
    html = C.build_threat_memory_badge("Agent: cảnh báo thường, không có lịch sử")
    assert "chưa có điểm" in html
    for bia in ("100.0", "13 sự cố", "Risk:", "1 sự cố"):
        assert bia not in html, f"badge bịa lại giá trị {bia!r}"


def test_threat_memory_chi_hien_phan_parse_duoc():
    """Có sự cố nhưng KHÔNG có điểm uy tín ⇒ không được tự gắn Risk."""
    html = C.build_threat_memory_badge("IP này có 7 incidents 4 blocks")
    assert "7 sự cố" in html and "4 Block" in html and "3 HITL/Audit" in html
    assert "Risk:" not in html


def test_threat_memory_day_du():
    html = C.build_threat_memory_badge("5 incidents 5 blocks reputation score of 92.5/100")
    assert "5 sự cố (5 Block)" in html and "Risk: 92.5/100" in html
    assert "HITL/Audit" not in html  # 5-5=0 ⇒ không hiện phần dư


def test_threat_memory_khong_suy_tu_chuoi_ip_demo():
    """IP demo trong nội dung KHÔNG được tự sinh ra lịch sử uy tín."""
    html = C.build_threat_memory_badge("truy cập từ 198.51.100.15 tới cổng 22")
    assert "chưa có điểm" in html


# ── build_technique_codes_html ─────────────────────────────────────────────────────
def test_khong_co_ma_thi_an_han_khoi():
    assert C.build_technique_codes_html("không có mã nào") == ""


def test_khong_don_ma_cho_du_nam():
    """Lỗi cũ: độn default_top5 rồi dán nhãn 'RAG truy xuất'."""
    html = C.build_technique_codes_html("chỉ nêu T1190 thôi")
    assert html.count("<code") == 1
    for don in ("T1595.003", "T1059.007", "T1083", "T1046"):
        assert don not in html, f"vẫn độn {don}"
    assert "(1)" in html  # số hiện ra phải là số mã THẬT


def test_nhan_khong_duoc_noi_la_rag_truy_xuat():
    """Các mã này đọc từ chuỗi phán quyết, KHÔNG phải đầu ra của FAISS/BM25."""
    html = C.build_technique_codes_html("T1190 và T1083")
    assert "FAISS" not in html and "BM25" not in html and "Top-5" not in html


def test_khu_trung_va_cat_nam():
    html = C.build_technique_codes_html(" ".join(f"T1{i:03d}" for i in range(100, 110)) + " T1100")
    assert html.count("<code") == 5  # cắt đúng 5, không nhiều hơn


# ── build_origin_badge ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("reason", "mong_doi"),
    [
        ("PHÁN QUYẾT TÁI SỬ DỤNG từ ResponseCache", "Semantic Cache Hit"),
        ("suy luận mới trên GPU", "Live GPU"),
    ],
)
def test_origin_badge(reason, mong_doi):
    html = C.build_origin_badge(reason)
    assert mong_doi in html
    assert "TTFT" not in html, "badge nguồn không đo thời gian — không được gắn số"


# ── build_grounding_badge · build_guardrail_note ───────────────────────────────────
def test_grounding_theo_ma_ky_thuat():
    _, gr = C.build_grounding_badge("Agent: [MITRE: T1190]", "T1190")
    assert gr is True
    html, gr = C.build_grounding_badge("unmappable technique", "N/A")
    assert gr is False and "DEGRADED SAFEGUARD" in html


def test_guardrail_note_chi_hien_cho_await_hitl():
    assert C.build_guardrail_note(True, "T1190", "BLOCK_IP") == ""
    assert "AWAIT_HITL" in C.build_guardrail_note(True, "T1190", "AWAIT_HITL")


# ── build_tier1_block_badge ────────────────────────────────────────────────────────
def test_tier1_badge_khong_dan_nhan_phan_tram_cho_diem_luat():
    """`tier1_score` là bộ CỘNG DỒN không chặn trên (+50/+40/+30/+100/+z…).

    Bản cũ in `Risk: {score}/100` nên hai luật cùng khớp là ra "Risk: 150/100" — một phần
    trăm bất khả thi. Thang 0–100 là của `reputation_score` (Threat Memory), không phải của
    `tier1_score`.
    """
    html = C.build_tier1_block_badge(count=3, tier1_score=150)
    assert "/100" not in html
    assert "150" in html and "3 lần chặn" in html


def test_tier1_badge_khong_nhan_nham_la_threat_memory():
    """Nguồn là ring buffer `tier1_blocks.json` TTL 1h, không phải kho uy tín SQLite."""
    html = C.build_tier1_block_badge(count=1, tier1_score=20)
    assert "Threat Memory" not in html
    assert "Tier-1 Rule Engine" in html


def test_tier1_badge_khong_in_mot_bien_thanh_hai_so():
    """Bản cũ: `{count} sự cố ({count} Block)` — cùng một biến, trông như hai số độc lập."""
    html = C.build_tier1_block_badge(count=4, tier1_score=60)
    assert html.count("4") == 1


# ── Quét mã nguồn: không ai chép lại bản thứ hai ───────────────────────────────────
def _ma_thuc_thi(duong_dan: Path) -> str:
    """Trả mã ĐANG CHẠY, đã bỏ chú thích và docstring.

    Phải lọc bằng AST chứ không lọc dòng `#`: các tên bịa cũ CỐ Ý được nhắc lại trong
    docstring của `components.py` để ghi vết lỗi. Lọc thô sẽ báo động giả trên chính phần
    tài liệu hoá. `ast.unparse` bỏ chú thích sẵn; docstring thì gỡ tay.
    """
    cay = ast.parse(duong_dan.read_text(encoding="utf-8"))
    for nut in ast.walk(cay):
        if isinstance(nut, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            than = nut.body
            if (
                than
                and isinstance(than[0], ast.Expr)
                and isinstance(than[0].value, ast.Constant)
                and isinstance(than[0].value.value, str)
            ):
                than.pop(0)
                if not than:
                    than.append(ast.Pass())
    return ast.unparse(cay)


@pytest.mark.parametrize("ten_tep", ["app.py", "components.py"])
@pytest.mark.parametrize(
    "dau_hieu",
    [
        r"default_top5",
        r"TTFT\s*0\.3\s*s",
        r"13\s+sự\s+cố",
        r"['\"]198\.51\.100['\"]\s+in\b",
        r"T1190\s*-\s*Exploit Public-Facing Application",
        r"Top-5 Ứng viên RAG Truy xuất",
    ],
)
def test_khong_con_dau_hieu_gia_tri_bia(ten_tep, dau_hieu):
    ma = _ma_thuc_thi(SRC_DIR / ten_tep)
    assert not re.search(dau_hieu, ma), f"{ten_tep} bịa lại {dau_hieu!r}"


def test_app_khong_tu_dung_badge_ma_goi_bo_dung_chung():
    """Chống chép bản thứ hai: app.py phải GỌI components chứ không tự ghép chuỗi badge."""
    ma = (SRC_DIR / "app.py").read_text(encoding="utf-8")
    for ten in ("GROUNDED IN RAG", "DEGRADED SAFEGUARD", "Semantic Cache Hit"):
        assert ten not in ma, f"app.py chép lại badge {ten!r} — phải gọi components.build_*"


def test_render_alert_card_dung_bo_dung_chung():
    src = inspect.getsource(C.render_alert_card)
    for ham in (
        "build_grounding_badge",
        "build_origin_badge",
        "build_threat_memory_badge",
        "build_technique_codes_html",
        "build_guardrail_note",
    ):
        assert ham in src, f"render_alert_card không dùng {ham}"


def test_sidecar_tier1_ghi_cung_mot_hinh_dang():
    """Hai nhánh (Cổng ML và rule engine) phải cùng đi qua `_tier1_block_record`.

    Lỗi cũ: nhánh Cổng ML append thẳng `evaluated_log` (khoá "Source IP"), còn bên đọc
    `_get_tier1_blocks()` lọc bằng `b.get("ip")` ⇒ mọi IP do Cổng ML chặn bị bỏ lặng lẽ,
    không bao giờ hiện trên Dashboard.
    """
    ma = (Path(__file__).resolve().parents[2] / "src" / "streaming" / "subscriber.py").read_text(
        encoding="utf-8"
    )
    appends = re.findall(r"tier1_recent_blocks\.append\(\s*([^\n]*)", ma)
    assert len(appends) >= 2, "chờ ít nhất 2 chỗ append"
    for a in appends:
        assert "_tier1_block_record" in a or a.strip() == "", (
            f"append không qua _tier1_block_record: {a!r}"
        )


# ===========================================================================
# PHỄU + TẦNG QUYẾT ĐỊNH — chống tái phát bốn lỗi đo ngày 2026-08-03
# ===========================================================================


def test_pheu_khong_bi_tran_boi_ring_buffer():
    """Phễu phải đọc `offload_counts`, KHÔNG suy từ ring buffer 12 dòng.

    Lỗi cũ đo trên lượt chạy 10k: `t1_count = len(t1_blocks)` với
    `cached_get_tier1_blocks(show=12)` nên Tier-1 luôn hiện ≤ 12, trong khi
    `offload_counts["action:BLOCK_IP"]` = 4.083. Phễu vì thế vẽ Tier-1 nhỏ hơn Cổng ML —
    ĐẢO NGƯỢC câu chuyện xả tải.
    """
    from src.ui import components as C

    ghi: dict = {}

    def _bat(html, **kw):
        ghi["html"] = html

    goc = getattr(C.st, "markdown", None)
    C.st.markdown = _bat  # type: ignore[assignment]
    try:
        C.render_metrics_header(
            all_alerts=[],
            pending_rules=0,
            active_rules=0,
            total_raw_logs=10_000,
            t1_blocks=[{"ip": f"10.0.0.{i}"} for i in range(12)],  # ring buffer bị cắt còn 12
            offload_counts={
                "action:ESCALATE": 3_334,
                "escalated_to_llm": 1_411,
                "ml_gate_resolved": 1_923,
                "action:BLOCK_IP": 4_083,
            },
            blocks_by_tier={"tier1_rule": 3_865, "tier1_ml": 58, "tier2_llm": 160},
        )
    finally:
        if goc is not None:
            C.st.markdown = goc  # type: ignore[assignment]

    html = ghi.get("html", "")
    assert "6,666" in html, f"Tier-1 phải là 10000-3334=6666, không phải 12. HTML: {html[:400]}"
    # xả tải LLM = 1 - 1411/10000 = 85.9%
    assert "85.9%" in html, "phải hiện tỉ lệ XẢ TẢI LLM"


def test_phieu_chi_co_DUY_NHAT_mot_chi_so_phan_tram():
    """Phễu chỉ được in MỘT phần trăm — 'Xả tải LLM'.

    'Giảm nhiễu' (97,1%) là đại lượng KHÁC xả tải LLM (85,9%) và luôn cao hơn ~11 điểm.
    Khi hai con số đứng cạnh nhau trên cùng một thẻ, người đọc trích số nào cũng thấy
    "đúng" — đó là lý do bỏ hẳn nó khỏi phễu thay vì chỉ đổi nhãn.
    """
    # Quét MÃ ĐANG CHẠY, không quét chú thích: chú thích cố ý ghi lại nhãn cũ làm mốc hồi
    # quy, nên so trên văn bản thô sẽ tự báo động giả (đã vấp đúng lỗi này).
    ma = _ma_thuc_thi(Path(__file__).resolve().parents[2] / "src" / "ui" / "components.py")
    assert "Tier-1 Offloaded Rate" not in ma, (
        "nhãn cũ gộp hai đại lượng khác nhau vào một chữ — đã thay bằng 'Xả tải LLM'"
    )
    assert "Xả tải LLM" in ma
    assert "giảm nhiễu" not in ma, "phễu chỉ được có MỘT chỉ số phần trăm"


def test_audit_trail_ghi_tang_tuong_minh():
    """`_log_to_db` phải nhận và ghi cột `tier`; `get_audit_trail` phải trả nó về."""
    import src.response.executor as E

    assert "tier" in inspect.signature(E._log_to_db).parameters
    assert "tier" in inspect.signature(E.block_ip).parameters
    assert "tier" in inspect.signature(E.raise_alert).parameters
    ma = (Path(__file__).resolve().parents[2] / "src" / "response" / "executor.py").read_text(
        encoding="utf-8"
    )
    assert "ADD COLUMN tier TEXT" in ma, "thiếu migration cột tier"
    assert '"tier": r[6] or ""' in ma, "get_audit_trail không trả cột tier"


def test_phan_tab_uu_tien_cot_tier_hon_van_xuoi():
    """Bản ghi `tier=tier2_llm` mà lý do có chữ 'Tier-1' vẫn phải vào tab Tier-2.

    Đây chính là ca hỏng: câu lý do khi LLM chết chứa 'Tier-1 (xác định) vẫn bảo vệ độc lập'.
    """
    from src.guardrails.constants import TIER_LLM, TIER_ML, TIER_RULE

    ML_GATE_MARKERS = ("Cổng ML", "ML Tier 2", "Decision Tree")

    def _xep(alert: dict) -> str:
        t = str(alert.get("tier") or "")
        if t == TIER_ML:
            return "ml"
        if t == TIER_RULE:
            return "t1"
        if t == TIER_LLM:
            return "t2"
        r = alert.get("reason", "")
        if any(k in r for k in ML_GATE_MARKERS):
            return "ml"
        if "Tier 1" in r or "Tier-1" in r or "whitelist" in r.lower():
            return "t1"
        return "t2"

    bay = {"tier": TIER_LLM, "reason": "Máy chủ LLM không phản hồi. Tier-1 vẫn bảo vệ độc lập."}
    assert _xep(bay) == "t2", "cột tier phải THẮNG heuristic dò chuỗi"
    # bản ghi cũ (tier rỗng) vẫn rơi về heuristic — không đổi hồi tố
    assert _xep({"tier": "", "reason": "Tier-1 chặn"}) == "t1"
    assert _xep({"tier": "", "reason": "Cổng ML (LightGBM)"}) == "ml"

    ma = (Path(__file__).resolve().parents[2] / "src" / "ui" / "app.py").read_text(encoding="utf-8")
    assert 'alert.get("tier")' in ma, "app.py chưa đọc cột tier"


def test_loi_mat_ket_noi_khong_do_loi_cho_max_tokens():
    """LLM chết là sự cố HẠ TẦNG — thông điệp không được nhắc max_tokens/định dạng."""
    from src.guardrails.decision_policy import HITL_REASONS

    assert "llm_unavailable" in HITL_REASONS, "thiếu mã lý do riêng cho LLM không phản hồi"
    assert "max_tokens" not in HITL_REASONS["llm_unavailable"]

    ma_nodes = (Path(__file__).resolve().parents[2] / "src" / "agent" / "nodes.py").read_text(
        encoding="utf-8"
    )
    assert 'llm_unavailable_err = ""' in ma_nodes, "nodes.py chưa tách nhánh mất kết nối"
    assert '"error": "llm_unavailable"' in ma_nodes

    from src.agent.nodes import _degraded_reason

    txt = _degraded_reason({"error": "llm_unavailable"})
    assert "max_tokens" not in txt and "định dạng" not in txt, f"vẫn quy sai nguyên nhân: {txt}"
    assert "hạ tầng" in txt.lower()


def test_da_chan_roi_thi_khong_dem_lan_chan_thu_hai(tmp_path):
    """Chính sách: 2 ALERT -> 1 BLOCK, và đã chặn lần đầu thì KHÔNG có lần sau.

    Lỗi cũ đo trên lượt chạy 10k: `mark_ip_blocked` cộng `total_blocks` MỖI gói khớp chữ ký,
    nên `198.51.100.38` hiện `total_blocks = 24` trong khi sổ kiểm toán có ĐÚNG 0 lệnh chặn
    cho nó — con số trên Dashboard mâu thuẫn thẳng với chính sách.
    """
    from src.agent.threat_memory import ThreatMemoryStore

    tm = ThreatMemoryStore(db_path=str(tmp_path / "tm.db"))
    ip = "198.51.100.38"
    for _ in range(24):
        tm.mark_ip_blocked(ip)

    r = tm.get_ip_reputation(ip)
    assert r is not None
    assert r["total_blocks"] == 1, f"phải là 1 quyết định chặn, nhận {r['total_blocks']}"
    assert r["total_incidents"] == 1
    assert r["blocked_hits"] == 23, "23 gói đến SAU khi bị chặn phải nằm ở cột riêng"
    assert r["reputation_score"] == 100.0

    # Analyst gỡ chặn -> IP tái phạm mới được tính là lần chặn MỚI, và bộ đếm gói về 0.
    tm.reset_ip_reputation(ip)
    tm.mark_ip_blocked(ip)
    r2 = tm.get_ip_reputation(ip)
    assert r2 is not None
    assert r2["total_blocks"] == 2 and r2["blocked_hits"] == 0


def test_badge_threat_memory_doc_kho_khong_doc_van_xuoi():
    """Có bản ghi trong kho thì badge phải in số của kho, kể cả khi câu lý do không nhắc gì.

    Ca thật: `203.0.113.159` có `reputation_score=100, total_blocks=2` trong kho nhưng badge
    in "chưa có điểm" vì chỉ regex trên `raw_reason`.
    """
    from src.ui.components import build_threat_memory_badge

    reason = "[MITRE: T1190] The source IP issued HTTP GET requests to port 8080."
    assert "chưa có điểm" in build_threat_memory_badge(reason)

    kho = {"total_blocks": 1, "total_alerts": 0, "blocked_hits": 23, "reputation_score": 100.0}
    ra = build_threat_memory_badge(reason, kho)
    assert "1 lần chặn" in ra, ra
    assert "23 gói chặn tại chỗ" in ra, "gói chặn-tại-chỗ phải tách khỏi số lần chặn"
    # "uy tín" nghe như phẩm chất; đây là ĐIỂM rủi ro 0–100 nên gọi thẳng là "điểm".
    assert "điểm 100/100" in ra
    assert "uy tín" not in ra
    assert "chưa có điểm" not in ra


def test_dap_an_bo_du_lieu_doc_sidecar_khong_doc_log_tho():
    """Đáp án phải tra từ sidecar theo `gt_id`, và im lặng khi không có sidecar.

    Log thô đã bị loại mọi khoá nhãn trước khi vào Tier-1, chỉ `gt_id` (mã băm) được giữ.
    Nếu bộ dựng đáp án lỡ đọc nhãn TỪ log thô thì nó đang đọc thứ đáng ra không tồn tại —
    và sẽ im re trên mọi bản ghi thật.
    """
    import json as _json

    from src.ui import components as C

    ghi: list = []

    goc_md, goc_gt = C.st.markdown, C.get_ground_truth
    C.st.markdown = lambda h, **kw: ghi.append(h)  # type: ignore[assignment]
    C.get_ground_truth = lambda g: (  # type: ignore[assignment]
        {
            "unified_source": "csic",
            "wa_mitre": "T1595.003",
            "wa_expected_action": "BLOCK_IP",
            "gt_label": "Backup/Source File Probing",
            "expected_threat": True,
        }
        if g == "EV-abc123"
        else None
    )
    try:
        # log thô KHÔNG chứa nhãn nào, chỉ có gt_id -> vẫn phải ra đáp án đầy đủ
        C.render_ground_truth(_json.dumps({"gt_id": "EV-abc123", "Dst Port": 80}))
        assert ghi, "có gt_id khớp sidecar mà không in đáp án"
        html = ghi[0]
        assert "T1595.003" in html and "BLOCK_IP" in html and "TẤN CÔNG" in html, html

        ghi.clear()
        C.render_ground_truth(_json.dumps({"gt_id": "EV-khong-co", "Dst Port": 80}))
        assert not ghi, "không tra được nhãn thì phải IM, không bịa"

        ghi.clear()
        C.render_ground_truth(_json.dumps({"Dst Port": 80}))
        assert not ghi, "log thô không có gt_id thì phải IM"
    finally:
        C.st.markdown, C.get_ground_truth = goc_md, goc_gt  # type: ignore[assignment]


def test_khong_duoc_suy_so_lieu_bang_phep_tru_khac_don_vi():
    """Cấm suy số hiển thị bằng cách trừ hai đại lượng KHÁC ĐƠN VỊ.

    Ca thật đo trên Dashboard: `escalated_to_llm=1403` (đơn vị SỰ KIỆN) trừ
    `pending_llm_queue=562` (đơn vị LÔ) ra 841, trong khi Tier-2 mới phân tích xong 89.
    Sai gần 10 lần vì một lô ôm nhiều sự kiện.
    """
    ma = _ma_thuc_thi(Path(__file__).resolve().parents[2] / "src" / "ui" / "app.py")
    assert "_to_llm - int(pending_llm" not in ma and "_to_llm - pending_llm" not in ma, (
        "không được suy số hiển thị bằng phép trừ sự-kiện − lô"
    )
    assert "cached_count_blocks_by_tier" in ma, (
        "số lệnh chặn theo tầng phải đọc COUNT(*) trên chính bảng mà các tab nhật ký đọc"
    )


def test_subscriber_dem_du_ba_no_i_su_kien_that_thoat():
    """Ba chỗ sự kiện rời khỏi đường tới Tier-2 đều phải có bộ đếm, nếu không phễu hở.

    Không có ba bộ đếm này thì `escalated_to_llm` (1.403) lớn hơn hẳn nhật ký Tier-2 (89)
    mà không ai giải thích được phần chênh đi đâu.
    """
    ma = _ma_thuc_thi(Path(__file__).resolve().parents[2] / "src" / "streaming" / "subscriber.py")
    assert "tier2_suppressed" in ma, "sự kiện bị NÉN SPAM (pending_ai TTL) phải được đếm"
    assert "tier2_analysed" in ma, "sự kiện Tier-2 phân tích XONG phải được đếm tại chỗ"
    assert "ml_gate:" in ma, "Cổng ML phải tách bộ đếm theo hành động (DROP không vào sổ)"


def test_phieu_in_so_CHAN_chu_khong_in_so_su_kien_di_qua():
    """Hai thẻ giữa phễu phải in SỐ LỆNH CHẶN, không in bộ đếm sự kiện đi qua.

    Ca thật: phễu in `ml_gate_resolved`=1.881 và `escalated_to_llm`=1.403 cạnh hai tab nhật
    ký chỉ có 210 và 77 dòng — lệch cả chục lần, vì Cổng ML giải quyết phần lớn bằng nhánh
    DROP (không ghi sổ) còn phần sang Tier-2 thì bị nén spam và xếp hàng.
    """
    from src.ui import components as C

    ghi: dict = {}
    goc = C.st.markdown
    C.st.markdown = lambda h, **kw: ghi.__setitem__("html", h)  # type: ignore[assignment]
    try:
        C.render_metrics_header(
            all_alerts=[],
            pending_rules=0,
            active_rules=0,
            total_raw_logs=10_000,
            t1_blocks=[],
            offload_counts={
                "action:ESCALATE": 3_284,
                "escalated_to_llm": 1_403,
                "ml_gate_resolved": 1_881,
            },
            blocks_by_tier={"tier1_ml": 58, "tier2_llm": 160},
        )
    finally:
        C.st.markdown = goc  # type: ignore[assignment]

    html = ghi.get("html", "")
    assert ">58<" in html, f"phải in số Cổng ML ĐÃ CHẶN (58). HTML: {html[:400]}"
    assert ">160<" in html, "phải in số Tier-2 ĐÃ CHẶN (160)"
    assert "1,881" not in html and "1,403" not in html, (
        "bộ đếm SỰ KIỆN ĐI QUA không được lên phễu — nó không so được với nhật ký"
    )


def test_khong_dan_nhan_FPR_cho_ti_le_analyst_bac_bo():
    """`rejected/(approved+rejected)` KHÔNG phải False Positive Rate.

    FPR thật là FP/(FP+TN) trên toàn luồng, phải đo bằng benchmark có đáp án. Mẫu số ở đây
    là số LUẬT ĐỀ XUẤT đã được analyst xem — đại lượng khác hẳn. Và khi chưa ai duyệt luật
    nào, bản cũ in "0.0%" tức là khoe không có dương tính giả mà không có bằng chứng nào.
    """
    from src.ui import components as C

    ma = _ma_thuc_thi(Path(__file__).resolve().parents[2] / "src" / "ui" / "components.py")
    assert "False Positive Rate" not in ma, "nhãn sai bản chất — đây là tỉ lệ analyst bác bỏ"

    ghi: dict = {}
    goc = C.st.markdown
    C.st.markdown = lambda h, **kw: ghi.__setitem__("html", h)  # type: ignore[assignment]
    try:
        C.render_metrics_header(all_alerts=[], pending_rules=0, active_rules=0, live_fpr=None)
    finally:
        C.st.markdown = goc  # type: ignore[assignment]
    assert "0.0%" not in ghi.get("html", ""), "chưa đo được thì phải hiện '—', không hiện 0.0%"
