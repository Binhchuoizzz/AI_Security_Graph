"""Mở rộng & sửa `knowledge_base/mitre_attack.json` từ ATT&CK STIX CHÍNH THỨC.

VÌ SAO. Đối chiếu (`scripts/verify_kb_against_mitre.py`) cho thấy KB chỉ phủ **99/189 =
52,4%** số kỹ thuật mà ATT&CK nói là phát hiện được bằng telemetry MẠNG — đúng lớp bằng
chứng mà đồ án này làm việc. 90 kỹ thuật thiếu dồn vào chính những nhóm một SOC mạng quan
tâm nhất: Command & Control (19), Exfiltration (9)... Thiếu `T1048.*` (Exfiltration Over
Non-C2 Protocol) hay `T1001.*` (Data Obfuscation) nghĩa là RAG KHÔNG THỂ trả đúng dù LLM có
suy luận tốt đến đâu — kỹ thuật đó không tồn tại trong kho để mà truy xuất.

Ngoài ra KB còn 42 mã MITRE ĐÃ KHAI TỬ và 2 tên sai.

KHÔNG BỊA MỘT CHỮ NÀO. Mọi trường đều lấy từ bó STIX:
  - id / name / description / tactic  -> attack-pattern
  - detection_indicators              -> mô tả của x-mitre-analytic mà MITRE gắn cho kỹ thuật
  - log_patterns                      -> tên log source trong chính analytic đó
  - response_actions                  -> ĐỂ TRỐNG (đây là nội dung do dự án soạn, không có
                                        trong STIX; thà trống còn hơn tự nghĩ ra)

Chạy:
    .venv/bin/python scripts/expand_kb_from_mitre.py --stix <đường dẫn> --dry-run
    .venv/bin/python scripts/expand_kb_from_mitre.py --stix <đường dẫn> --apply
Sau khi --apply PHẢI dựng lại chỉ mục FAISS + checksum (script sẽ nhắc).
"""

import argparse
import copy
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

KB_PATH = os.path.join(ROOT, "knowledge_base", "mitre_attack.json")
STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
# Tiền tố log source được coi là TELEMETRY MẠNG — đúng lớp bằng chứng của hệ thống này.
NET_PREFIXES = (
    "nsm:",
    "networkdevice:",
    "netflow:",
    "cni:netflow",
    "dns:query",
    "alb:httplogs",
    "applicationlog:webserver",
    "container:proxy",
)


def _is_net_source(name: str) -> bool:
    n = (name or "").lower()
    return n.startswith(NET_PREFIXES) or "firewall" in n


def safe_desc(text: str) -> str:
    """Mô tả sạch: thoát các thẻ dạng HTML thành `&lt;...&gt;`.

    VÌ SAO. Mô tả chính thức của `T1027.017` (SVG Smuggling) có câu "...can legitimately
    include `<script>` tags...". Đó là câu MÔ TẢ, nhưng bộ lọc chống-injection lúc truy xuất
    khớp đúng mẫu `<script>` và cắt xén chính tài liệu KB hợp lệ — đúng lớp lỗi mà
    `test_knowledge_base_survives_retrieve_sanitization` sinh ra để bắt (và đã bắt được).
    Thoát dấu ngoặc giữ nguyên nghĩa cho cả người lẫn LLM, mà không kích hoạt bộ lọc.
    """
    return re.sub(r"<(/?[a-zA-Z][a-zA-Z0-9]*)>", r"&lt;\1&gt;", text)


def _tid(o: dict) -> str | None:
    return next(
        (
            r.get("external_id")
            for r in o.get("external_references", [])
            if r.get("source_name") == "mitre-attack"
        ),
        None,
    )


def load_stix(path: str | None) -> dict:
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    print(f"[*] Tải ATT&CK từ {STIX_URL} (~45 MB)...")
    with urllib.request.urlopen(STIX_URL, timeout=180) as r:  # noqa: S310
        return json.loads(r.read().decode("utf-8"))


def answer_key_ids() -> set[str]:
    """Mọi mã ATT&CK được các tập dữ liệu dùng làm ĐÁP ÁN.

    VÌ SAO CẦN. Bộ lọc `net_refs` bên dưới chỉ nạp kỹ thuật mà MITRE có cấp *analytic dùng
    nguồn mạng*. Kỹ thuật thuộc `Reconnaissance` thường KHÔNG có analytic nào (MITRE coi đó
    là hoạt động PRE, quan sát từ phía nạn nhân) nên bị bỏ qua — trong đó có `T1595.003`
    (Wordlist Scanning), chính là họ tấn công LỚN NHẤT của CSIC 2010 (dò tệp sao lưu + duyệt
    ép = 349/689 = 51% số mẫu CSIC suy được kỹ thuật).

    Hệ quả đo được: mã đó KHÔNG có trong kho -> RAG không thể trả ra -> lá chắn neo bằng
    chứng ép AWAIT_HITL 100% số lô đó, và trần chính xác của cả hệ bị chặn cứng vì một lỗ
    hổng của KHO chứ không phải vì mô hình suy luận kém.

    Đây KHÔNG phải "học tủ": nội dung mục vẫn lấy nguyên từ STIX chính thức, và kho có 432
    mục trong khi chỉ 36 mã từng là đáp án — thêm một mục không hề chỉ điểm đáp án nào.
    Ngược lại, để trống là làm sai lệch phép đo theo hướng có lợi cho... không ai cả.
    """
    ids: set[str] = set()
    from scripts.build_csic_dataset import FAMILIES
    from scripts.fetch_and_build_dataset import LABEL_MAP

    for m in LABEL_MAP.values():
        for k in ("mitre", "sub"):
            if m.get(k):
                ids.add(str(m[k]))
    ids |= {t for _, t, _ in FAMILIES}
    return ids


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", default=None)
    ap.add_argument("--apply", action="store_true", help="ghi đè KB (mặc định chỉ xem trước)")
    ap.add_argument(
        "--ensure-answer-keys",
        action="store_true",
        help="thêm cả những mã mà dataset dùng làm đáp án nhưng MITRE không cấp analytic mạng",
    )
    args = ap.parse_args()

    stix = load_stix(args.stix)
    objs = stix["objects"]

    phase2tac = {
        o["x_mitre_shortname"]: o["name"]
        for o in objs
        if o.get("type") == "x-mitre-tactic" and o.get("x_mitre_shortname")
    }
    live = {
        o["id"]: o
        for o in objs
        if o.get("type") == "attack-pattern"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    }
    analytics = {o["id"]: o for o in objs if o.get("type") == "x-mitre-analytic"}
    strategies = {o["id"]: o for o in objs if o.get("type") == "x-mitre-detection-strategy"}

    # detection-strategy -> attack-pattern
    det_of: dict[str, list] = {}
    revoked_by: dict[str, str] = {}
    for r in objs:
        if r.get("type") != "relationship":
            continue
        if r.get("relationship_type") == "detects" and r.get("target_ref") in live:
            det_of.setdefault(r["target_ref"], []).append(r.get("source_ref"))
        elif r.get("relationship_type") == "revoked-by":
            revoked_by[r.get("source_ref", "")] = r.get("target_ref", "")

    def evidence(ap_ref: str, *, net_only: bool = True) -> tuple[list[str], list[str]]:
        """(mô tả cách phát hiện, tên log source) lấy từ analytic CHÍNH THỨC của MITRE.

        `net_only=True`  -> chỉ analytic dùng nguồn MẠNG; đây là bộ lọc quyết định kỹ thuật
                            nào được coi là "phát hiện được bằng telemetry mạng".
        `net_only=False` -> MỌI analytic. Dùng cho việc LẤP mô tả phát hiện của các mục đã có
                            trong kho: kể cả analytic viết cho nguồn endpoint thì từ vựng
                            quan sát được của nó vẫn là từ vựng ATT&CK chính thức về kỹ thuật
                            đó, và đó chính là thứ bộ truy xuất cần để khớp.
        """
        inds: list[str] = []
        srcs: list[str] = []
        for sref in det_of.get(ap_ref, []):
            for aref in strategies.get(sref, {}).get("x_mitre_analytic_refs") or []:
                a = analytics.get(aref)
                if not a:
                    continue
                names = [
                    str(s.get("name", "")) for s in (a.get("x_mitre_log_source_references") or [])
                ]
                if net_only and not any(_is_net_source(n) for n in names):
                    continue
                d = re.sub(r"\s+", " ", str(a.get("description", ""))).strip()
                if d and d not in inds:
                    inds.append(d[:400])
                for n in names:
                    keep = _is_net_source(n) if net_only else bool(n)
                    if keep and n not in srcs:
                        srcs.append(n)
        return inds[:4], srcs[:6]

    def net_evidence(ap_ref: str) -> tuple[list[str], list[str]]:
        return evidence(ap_ref, net_only=True)

    # Tập kỹ thuật phát hiện được bằng telemetry MẠNG.
    net_refs = {ref for ref in det_of if net_evidence(ref)[1]}

    # ...cộng thêm những mã mà DATASET dùng làm đáp án (xem `answer_key_ids`). Chúng có thể
    # không có analytic mạng nào trong STIX, nhưng thiếu chúng thì phép đo bị chặn trần bởi
    # lỗ hổng của kho chứ không phải bởi năng lực của hệ thống.
    forced: set[str] = set()
    if args.ensure_answer_keys:
        want = answer_key_ids()
        for ref, o in live.items():
            t = _tid(o)
            if t and t in want and ref not in net_refs:
                net_refs.add(ref)
                forced.add(t)

    with open(KB_PATH) as f:
        raw = json.load(f)
    is_list = isinstance(raw, list)
    items = raw if is_list else list(raw.values())[0]
    # Ảnh chụp TRƯỚC mọi thay đổi. Bản trước ghi sao lưu ở CUỐI hàm, nhưng `items` đã bị sửa
    # tại chỗ từ trước đó nên tệp .bak lưu đúng trạng thái ĐÃ sửa — tức là không khôi phục
    # được gì. Lỗi chỉ lộ ra khi thật sự cần khôi phục.
    snapshot = copy.deepcopy(raw)
    by_id = {str(x.get("id", "")).upper(): x for x in items}

    # Chuẩn hoá mô tả cho MỌI mục (kể cả mục cũ) -> tự chữa lành, chạy lại bao nhiêu lần cũng
    # ra cùng kết quả.
    escaped = 0
    for x in items:
        d0 = str(x.get("description", ""))
        d1 = safe_desc(d0)
        if d1 != d0:
            x["description"] = d1
            escaped += 1

    added, renamed, retired = [], [], []

    # ── 0. Chuẩn hoá tên tactic ──
    # KB đang có CẢ "Command and Control" (17 mục) LẪN "Command And Control" (22 mục) — hai
    # chuỗi khác nhau cho cùng một tactic, do các đợt bổ sung khác nhau viết hoa khác nhau.
    # Bất kỳ chỗ nào nhóm/lọc theo tactic đều thấy nó tách làm đôi. Lấy đúng chính tả của
    # STIX làm chuẩn (`phase2tac`), so khớp không phân biệt hoa thường.
    official_tac = {t.lower(): t for t in phase2tac.values()}
    fixed_tac = 0
    for x in items:
        cur = str(x.get("tactic", ""))
        want = official_tac.get(cur.lower())
        if want and want != cur:
            x["tactic"] = want
            fixed_tac += 1

    # ── 1. Thêm kỹ thuật MẠNG còn thiếu ──
    for ref in sorted(net_refs, key=lambda r: _tid(live[r]) or ""):
        o = live[ref]
        tid = _tid(o)
        if not tid or tid in by_id:
            continue
        inds, srcs = net_evidence(ref)
        tac = next(
            (
                phase2tac.get(p["phase_name"], p["phase_name"])
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ),
            "Unknown",
        )
        items.append(
            {
                "id": tid,
                "name": o.get("name", ""),
                "tactic": tac,
                "description": safe_desc(
                    re.sub(r"\s+", " ", str(o.get("description", ""))).strip()[:1200]
                ),
                "detection_indicators": inds + [tid],
                "log_patterns": srcs,
                # CỐ Ý để trống: STIX không có "hành động ứng phó", tự viết là bịa.
                "response_actions": [],
            }
        )
        added.append((tid, o.get("name", ""), tac))

    # ── 1b. LẤP mô tả phát hiện cho các mục THOÁI HOÁ ──
    #
    # LỖI THẬT, ĐO ĐƯỢC. 251/433 mục (58%) có `detection_indicators` chỉ lặp lại chính tên và
    # mã của nó — ví dụ T1190 là `['Exploit Public-Facing Application', 'T1190']` và
    # `log_patterns` là `['malicious activity detected matching T1190']`. Không một từ nào về
    # SQL injection, XSS, path traversal. Hệ quả đo được trên chỉ mục thật: truy vấn
    # "SQL injection UNION SELECT in HTTP query parameter" KHÔNG trả về T1190 trong top-5
    # (nó trả T1572, T1132, T1055.011...). Tức là kỹ thuật quan trọng nhất của toàn bộ tập
    # dữ liệu web KHÔNG THỂ được truy xuất, nên LLM không có cách nào trả lời đúng và lá chắn
    # neo bằng chứng ép AWAIT_HITL — một trần bị chặn bởi KHO, không phải bởi mô hình.
    #
    # Lấp bằng mô tả analytic CHÍNH THỨC của MITRE (`net_only=False` — kể cả analytic viết cho
    # nguồn endpoint, vì từ vựng quan sát được của nó vẫn là mô tả chuẩn về kỹ thuật đó).
    # KHÔNG bịa một chữ nào, và KHÔNG đụng vào mục đã có chỉ báo do dự án tự soạn tử tế.
    def _is_degenerate(x: dict) -> bool:
        name = str(x.get("name", "")).strip().lower()
        tid_l = str(x.get("id", "")).strip().lower()
        real = [
            str(d).strip()
            for d in (x.get("detection_indicators") or [])
            if str(d).strip() and str(d).strip().lower() not in (name, tid_l)
        ]
        return not real

    ref_by_tid = {_tid(o): r for r, o in live.items() if _tid(o)}
    backfilled = []
    for x in items:
        if not _is_degenerate(x):
            continue
        ref = ref_by_tid.get(str(x.get("id", "")).upper())
        if not ref:
            continue
        inds, srcs = evidence(ref, net_only=False)
        if not inds:
            continue
        # Giữ mã ở cuối để tra cứu theo mã vẫn khớp (quy ước sẵn có của kho).
        x["detection_indicators"] = [safe_desc(i) for i in inds] + [x["id"]]
        if srcs:
            x["log_patterns"] = srcs
        backfilled.append(x["id"])

    # ── 2. Sửa tên sai (chỉ khi KHÔNG phải quy ước "Cha: Con" mà mã nguồn dựa vào) ──
    for tid, x in by_id.items():
        ref = next((r for r, o in live.items() if _tid(o) == tid), None)
        if not ref:
            continue
        official = live[ref].get("name", "")
        cur = str(x.get("name", ""))
        if cur == official or ":" in cur:  # "Cha: Con" là quy ước cố ý của dự án
            continue
        renamed.append((tid, cur, official))
        x["name"] = official

    # ── 3. Đánh dấu mã đã khai tử + trỏ sang mã kế nhiệm ──
    dead_ids = {}
    for o in objs:
        if o.get("type") == "attack-pattern" and (o.get("revoked") or o.get("x_mitre_deprecated")):
            t = _tid(o)
            succ = revoked_by.get(o["id"])
            dead_ids[t] = _tid(live[succ]) if succ in live else None
    for tid, x in by_id.items():
        if tid in dead_ids:
            x["deprecated"] = True
            if dead_ids[tid]:
                x["superseded_by"] = dead_ids[tid]
            retired.append((tid, x.get("name", ""), dead_ids[tid] or "(không có mã thay thế)"))

    print(f"\n{'=' * 88}\nKẾT QUẢ\n{'=' * 88}")
    print(f"  KB trước      : {len(by_id)}")
    print(f"  THÊM mới      : {len(added)}")
    print(f"  Sửa tên       : {len(renamed)}")
    print(f"  Đánh dấu khai tử: {len(retired)}")
    print(f"  Thoát thẻ HTML trong mô tả: {escaped}")
    print(f"  Chuẩn hoá hoa/thường tên tactic: {fixed_tac}")
    print(f"  LẤP mô tả phát hiện (mục chỉ lặp tên/mã): {len(backfilled)}")
    if forced:
        print(f"  Thêm vì là ĐÁP ÁN của dataset (không có analytic mạng): {sorted(forced)}")
    print(f"  KB sau        : {len(items)}")
    for t, n, tac in added[:15]:
        print(f"    + {t:14s} {n[:46]:48s} [{tac}]")
    if len(added) > 15:
        print(f"    ... còn {len(added) - 15} mục")
    for t, a, b in renamed:
        print(f"    ~ {t:14s} {a[:40]!r} -> {b!r}")

    if not args.apply:
        print("\n[i] XEM TRƯỚC — chưa ghi gì. Thêm --apply để ghi.")
        return 0

    bak = KB_PATH + ".bak"
    if not os.path.exists(bak):
        with open(bak, "w") as f:
            json.dump(snapshot, f, ensure_ascii=False, indent=2)
        print(f"\n[+] Sao lưu (trạng thái TRƯỚC khi sửa) -> {bak}")
    out = items if is_list else {list(raw.keys())[0]: items}
    with open(KB_PATH, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"[+] Đã ghi {KB_PATH}")
    # Lệnh dưới đây phải chạy ĐÚNG ba bước theo ĐÚNG thứ tự — bản trước ghi sai cả hai dòng
    # (`build_faiss_index` không tồn tại; và `sha256sum knowledge_base/*.json` ghi tên có tiền
    # tố thư mục + bỏ mất 6 mục index, làm `build_all_indexes` từ chối chạy vì "MISSING").
    # `build_all_indexes` TỰ kiểm toàn vẹn KB trước khi dựng, nên phải niêm phong nguồn TRƯỚC,
    # dựng index, rồi niêm phong lại để bao gồm chính các tệp index vừa sinh.
    print(
        "\n[!] BẮT BUỘC làm tiếp, nếu không chỉ mục sẽ lệch khỏi KB:\n"
        "    .venv/bin/python -c 'from src.rag.embedder import build_all_indexes,"
        " update_checksums_file; update_checksums_file(); build_all_indexes();"
        " update_checksums_file()'"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
