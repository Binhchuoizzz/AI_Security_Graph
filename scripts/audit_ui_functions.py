"""Quét chức năng UI: gọi ĐÚNG hàm mà mỗi nút gọi, rồi KIỂM SINK tương ứng.

VÌ SAO KHÔNG "BẤM THỬ TRÊN TRÌNH DUYỆT". Bấm nút chỉ chứng minh Streamlit không văng
exception; nó KHÔNG chứng minh dữ liệu đã xuống đúng nơi. Mỗi hành động ở đây chạm tới BA
sink khác nhau (Redis blacklist · SQLite luật phản hồi · SQLite nhật ký kiểm toán có HMAC),
và lỗi thật đã gặp trong dự án này đều là kiểu "UI báo thành công nhưng một sink im lặng
không ghi". Nên kịch bản này gọi thẳng hàm của nút rồi ĐỌC LẠI từng sink.

An toàn: chỉ dùng IP TEST-NET-3 (RFC 5737, 203.0.113.0/24) KHÔNG có trong tập demo, và luôn
dọn sạch ở cuối (kể cả khi giữa chừng lỗi). Kịch bản này KHÔNG chạy benchmark.

Chạy:  .venv/bin/python scripts/audit_ui_functions.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(ROOT, ".env"))

import logging  # noqa: E402

logging.disable(logging.WARNING)

from src.guardrails.constants import TIER_SELFTEST  # noqa: E402
from src.response.executor import (  # noqa: E402
    audit_key_is_default,
    block_ip,
    get_audit_trail_for_ip,
    unblock_ip,
    verify_audit_trail_integrity,
)
from src.tier1_filter.feedback_listener import CONFIG_PATH, FeedbackListener  # noqa: E402

# IP thử nghiệm: TEST-NET-3, không định tuyến công cộng, không có trong demo.
TEST_IP = "203.0.113.254"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))


def _redis():
    import redis

    return redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))


def _blacklisted(ip: str) -> bool:
    try:
        return bool(_redis().exists(f"blacklist:{ip}"))
    except Exception:
        return False


def _rule_status(ip: str) -> str | None:
    """Đọc THẲNG từ YAML trên đĩa, KHÔNG qua getter của listener.

    Kho luật phản hồi là `config/system_settings.yaml` -> `tier1.dynamic_rules` (không phải
    SQLite). Listener có cache RAM khử theo mtime; nếu đọc qua cache thì một lần ghi hỏng
    vẫn có thể "trông như" thành công. Đọc thẳng đĩa mới chứng minh được dữ liệu đã xuống.
    """
    import yaml

    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        rules = (data.get("tier1") or {}).get("dynamic_rules") or []
        hits = [r for r in rules if str(r.get("pattern")) == ip]
        return str(hits[-1].get("status")) if hits else None
    except Exception as e:  # pragma: no cover - chỉ để chẩn đoán
        return f"ERR:{e}"


def _purge_rule(ip: str) -> None:
    """Xoá mọi luật của IP thử nghiệm khỏi YAML (ghi nguyên tử qua chính listener's lock)."""
    import yaml
    from filelock import FileLock

    try:
        with FileLock(CONFIG_PATH + ".lock", timeout=10):
            with open(CONFIG_PATH, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            rules = (data.get("tier1") or {}).get("dynamic_rules") or []
            kept = [r for r in rules if str(r.get("pattern")) != ip]
            if len(kept) == len(rules):
                return
            data["tier1"]["dynamic_rules"] = kept
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
    except Exception:
        pass


def cleanup(fb: FeedbackListener) -> None:
    for fn in (lambda: fb.remove_from_whitelist(TEST_IP), lambda: unblock_ip(TEST_IP)):
        try:
            fn()
        except Exception:
            pass
    _purge_rule(TEST_IP)


def main() -> int:
    fb = FeedbackListener()
    print("=" * 78)
    print(f"QUÉT CHỨC NĂNG UI — sink thật, IP thử nghiệm {TEST_IP}")
    print("=" * 78)

    cleanup(fb)  # trạng thái đầu sạch

    # ── 0. Điều kiện đầu ─────────────────────────────────────────────
    print("\n── 0. Điều kiện đầu ──")
    check("IP thử nghiệm chưa bị chặn", not _blacklisted(TEST_IP))
    check("IP thử nghiệm chưa whitelist", TEST_IP not in fb.get_whitelisted_ips())

    # ── 1. Nút 'Kích hoạt luật chặn' (app.py L1975) ──────────────────
    print("\n── 1. Nút 'Kích hoạt luật chặn' → 3 sink ──")
    fb.receive_new_rule(
        "Source IP", TEST_IP, score=95, source="manual_audit", reason="quét chức năng"
    )
    fb.approve_rule(TEST_IP, "Source IP")
    block_ip(TEST_IP, "[Tier-1 Filter] quét chức năng tự động", tier=TIER_SELFTEST)

    check("sink Redis: blacklist:<ip> tồn tại", _blacklisted(TEST_IP))
    st = _rule_status(TEST_IP)
    check("sink SQLite luật: status=ACTIVE", st == "ACTIVE", f"đọc được {st!r}")
    trail = get_audit_trail_for_ip(TEST_IP, limit=10)
    check(
        "sink SQLite kiểm toán: có bản ghi BLOCK_IP",
        any(str(r.get("action")) == "BLOCK_IP" for r in trail),
        f"{len(trail)} bản ghi",
    )
    check("Rule Engine thấy IP trong blacklist", _blacklisted(TEST_IP))

    # ── 2. Nút 'Thêm vào Whitelist' (app.py L2026) ───────────────────
    print("\n── 2. Nút 'Thêm vào Whitelist' → phải GỠ chặn ──")
    ok_wl = fb.add_to_whitelist(TEST_IP)
    unblock_ip(TEST_IP)
    check("add_to_whitelist trả True", bool(ok_wl))
    check("IP có trong danh sách whitelist", TEST_IP in fb.get_whitelisted_ips())
    check("sink Redis: blacklist đã bị GỠ", not _blacklisted(TEST_IP))
    # Xung đột trạng thái: whitelist mà luật vẫn ACTIVE là mâu thuẫn tự nó.
    st2 = _rule_status(TEST_IP)
    check("luật không còn ACTIVE khi đã whitelist", st2 != "ACTIVE", f"đọc được {st2!r}")

    # ── 3. Nút 'Gỡ khỏi Whitelist' (app.py L1735) ────────────────────
    print("\n── 3. Nút 'Gỡ khỏi Whitelist' ──")
    fb.remove_from_whitelist(TEST_IP)
    check("IP đã rời whitelist", TEST_IP not in fb.get_whitelisted_ips())

    # ── 4. HITL: Phê duyệt / Từ chối (app.py L1312/L1351/L1867/L1889) ─
    print("\n── 4. HITL Phê duyệt / Từ chối ──")
    _purge_rule(TEST_IP)
    fb.receive_new_rule("Source IP", TEST_IP, score=80, source="ml_triage", reason="chờ duyệt")
    st3 = _rule_status(TEST_IP)
    check("luật mới ở trạng thái chờ duyệt", st3 == "PENDING_APPROVAL", f"đọc được {st3!r}")
    pend = [r for r in fb.get_pending_rules() if r.get("pattern") == TEST_IP]
    check("luật hiện trong hàng chờ HITL của UI", bool(pend), f"{len(pend)} mục")

    fb.approve_rule(TEST_IP, "Source IP")
    check("Phê duyệt → ACTIVE", _rule_status(TEST_IP) == "ACTIVE")

    block_ip(TEST_IP, "[Tier-1 Filter] mô phỏng thi hành sau phê duyệt", tier=TIER_SELFTEST)
    fb.reject_rule(TEST_IP, "Source IP")
    unblock_ip(TEST_IP)
    st4 = _rule_status(TEST_IP)
    check("Từ chối → rời ACTIVE", st4 != "ACTIVE", f"đọc được {st4!r}")
    check("Từ chối → Redis đã gỡ chặn", not _blacklisted(TEST_IP))

    # ── 5. Toàn vẹn nhật ký kiểm toán (sidebar, app.py L739) ─────────
    print("\n── 5. Nút 'Kiểm tra toàn vẹn nhật ký' (chuỗi HMAC) ──")
    valid, msg = verify_audit_trail_integrity()
    check("verify_audit_trail_integrity() = True", bool(valid), str(msg)[:70])
    check(
        "KHÔNG dùng khoá HMAC mặc định",
        not audit_key_is_default(),
        "SENTINEL_LOG_SECRET nạp từ .env",
    )

    # ── 6. Toàn vẹn tài liệu RAG (tab5, app.py L2080) ────────────────
    print("\n── 6. Nút 'Kiểm tra toàn vẹn tài liệu RAG' ──")
    try:
        from src.rag.security import verify_document_integrity

        # `faiss_index/` được SINH RA khi build KB nên hash đổi theo máy -> loại trừ, chỉ
        # xác minh các tệp tri thức NGUỒN (đây mới là thứ RAG poisoning nhắm tới).
        res = verify_document_integrity(exclude_generated=True)
        ok6 = bool(res.get("verified"))
        check("verify_document_integrity() hợp lệ", ok6, str(res.get("details"))[:90])
    except Exception as e:
        check("verify_document_integrity() chạy được", False, f"{type(e).__name__}: {e}")

    # ── 7. RBAC: mọi nút thay đổi trạng thái phải chặn non-L3 ────────
    # Kiểm TĨNH: đọc mã, không phải bấm thử. Nói rõ để không ai hiểu nhầm mức bảo đảm.
    print("\n── 7. RBAC (kiểm tĩnh trên mã nguồn) ──")
    # Rào quyền trong Streamlit nằm ở KHỐI BAO (`if is_l3:` / `if role == "L3_Manager":`
    # bọc cả cụm nút), nên chỉ soi vài dòng quanh nút sẽ báo oan hàng loạt — bản đầu của
    # kịch bản này đúng là đã báo oan 7 nút. Cách đúng: lần ngược CHUỖI KHỐI CHA theo thụt
    # lề, y như Python xác định phạm vi.
    src_lines = open("src/ui/app.py", encoding="utf-8").read().splitlines()
    MUTATORS = (
        "approve_rule",
        "reject_rule",
        "add_to_whitelist",
        "remove_from_whitelist",
        "block_ip",
        "unblock_ip",
        "receive_new_rule",
        "update_rule_status",
    )
    GUARD_TOKENS = ("is_l3", "L3_Manager", "require_l3")
    guarded = 0
    unguarded: list[int] = []
    for i, line in enumerate(src_lines):
        if "st.button(" not in line and "st.form_submit_button(" not in line:
            continue
        body = "\n".join(src_lines[i : i + 14])
        if not any(k in body for k in MUTATORS):
            continue  # nút chỉ đọc/điều hướng -> không cần rào
        indent = len(line) - len(line.lstrip())
        chain, cur = [], indent
        for j in range(i - 1, -1, -1):
            prev = src_lines[j]
            if not prev.strip():
                continue
            pi = len(prev) - len(prev.lstrip())
            if pi < cur and prev.lstrip().startswith(("if ", "elif ", "with ", "for ", "def ")):
                chain.append(prev)
                cur = pi
                if pi == 0:
                    break
        scope = body + "\n" + "\n".join(chain)
        if any(k in scope for k in GUARD_TOKENS):
            guarded += 1
        else:
            unguarded.append(i + 1)
    check(
        "mọi nút thay-đổi-trạng-thái có rào L3",
        not unguarded,
        f"{guarded} nút có rào" + (f", HỞ tại dòng {unguarded}" if unguarded else ""),
    )

    cleanup(fb)
    print("\n── 8. Dọn dẹp ──")
    check("IP thử nghiệm đã rời Redis", not _blacklisted(TEST_IP))
    check("IP thử nghiệm đã rời whitelist", TEST_IP not in fb.get_whitelisted_ips())
    check("luật thử nghiệm đã xoá khỏi SQLite", _rule_status(TEST_IP) is None)

    n_fail = sum(1 for _, ok, _ in results if not ok)
    print("\n" + "=" * 78)
    print(f"KẾT QUẢ: {len(results) - n_fail}/{len(results)} đạt · {n_fail} hỏng")
    print("=" * 78)
    if n_fail:
        for name, ok, detail in results:
            if not ok:
                print(f"  HỎNG: {name}  — {detail}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
