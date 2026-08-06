"""Kiểm BA cơ chế giảm tải của Tier-1 bằng kịch bản dựng sẵn (không dựa vào lượt chạy sống).

VÌ SAO CẦN KỊCH BẢN RIÊNG. Lượt chạy sống chỉ cho biết "tổng số lô Tier-2 giảm"; nó KHÔNG
chứng minh được cơ chế nào hoạt động, và nếu số không giảm thì cũng không chỉ ra hỏng ở đâu.
Ba cơ chế dưới đây là toàn bộ lý do kiến trúc "nhớ mặt" tồn tại, nên phải kiểm từng cái một
với đầu vào do ta kiểm soát:

  1. BLOCKLIST  — IP có reputation >= 70 bị chặn NGAY ở Tier-1, ĐỘC LẬP với điểm gói hiện
                  tại (gói lành từ IP xấu vẫn phải bị chặn). Đây là lớp BỀN (SQLite, không
                  TTL), khác lớp Redis blacklist chỉ sống 1 giờ.
  2. WHITELIST  — IP whitelist vẫn được phân tích ĐẦY ĐỦ (analyst còn quan sát được hành vi)
                  nhưng hành động cuối LUÔN là WHITELIST_DROP: không chặn, không leo thang,
                  và được MIỄN TRỪ reputation.
  3. CACHE      — khoá lớp-2 CỐ Ý bỏ IP ra ngoài để gộp flow cùng bản chất. Rủi ro kèm theo:
                  verdict của IP sạch bị tái dùng cho kẻ tái phạm. Phải chứng minh hai rổ
                  (có/không tiền sử) tách nhau.

An toàn: chỉ dùng IP TEST-NET (RFC 5737) không có trong tập demo; dọn sạch ở cuối.

Chạy:  .venv/bin/python scripts/audit_offload_mechanisms.py
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(ROOT, ".env"))

import logging  # noqa: E402
from datetime import datetime  # noqa: E402

logging.disable(logging.WARNING)

from src.agent.response_cache import ExactMatchResponseCache  # noqa: E402
from src.agent.threat_memory import ThreatMemoryStore  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

BAD_IP = "203.0.113.201"  # sẽ được gán reputation xấu
WL_IP = "203.0.113.202"  # sẽ được whitelist

# Trước 05/08/2026 script này CHỈ in ra màn hình. Hệ quả: chỉ số 1.l ("14/14 đạt") là chỉ số
# RQ1 duy nhất không có tệp bằng chứng — muốn đối chiếu thì phải chạy lại tại chỗ. Ghi JSON
# để nó đứng ngang hàng với mọi chỉ số khác.
OUT_JSON = os.path.join(ROOT, "experiments", "results", "offload_mechanisms_audit.json")

results: list[dict] = []
_group = "?"  # cơ chế đang kiểm; `check()` đóng dấu vào từng mục để tách được theo cơ chế


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append({"co_che": _group, "phep_kiem": name, "dat": ok, "chi_tiet": detail})
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))


def benign_log(ip: str) -> dict:
    """Gói HOÀN TOÀN LÀNH: không payload, cổng 443, lưu lượng nhỏ. Nếu gói này bị chặn thì
    chỉ có thể do tiền sử IP, không thể do nội dung — đúng thứ ta muốn chứng minh."""
    return {
        "Source IP": ip,
        "Destination Port": 443,
        "Protocol": 6,
        "Total Fwd Packets": 3,
        "Total Length of Bwd Packets": 1200,
        "Flow Duration": 1000,
        "service": "https",
    }


def main() -> int:
    print("=" * 78)
    print("KIỂM BA CƠ CHẾ GIẢM TẢI TIER-1")
    print("=" * 78)

    global _group
    mem = ThreatMemoryStore()
    mem.reset_ip_reputation(BAD_IP)

    # ── 1. BLOCKLIST: reputation >= 70 chặn on-sight ─────────────────
    _group = "BLOCKLIST"
    print("\n── 1. BLOCKLIST (reputation bền, không TTL) ──")
    eng = RuleEngine()
    before = eng.evaluate(benign_log(BAD_IP))
    check(
        "gói lành từ IP SẠCH: không bị chặn",
        before.get("tier1_action") != "BLOCK_IP",
        f"action={before.get('tier1_action')}",
    )

    mem.mark_ip_blocked(BAD_IP, "T1110")
    rep = mem.get_ip_reputation(BAD_IP) or {}
    check(
        "mark_ip_blocked đặt reputation=100",
        float(rep.get("reputation_score", 0)) >= 70,
        f"điểm={rep.get('reputation_score')}",
    )

    # Engine MỚI để không dính cache reputation trong RAM (TTL 5s).
    eng2 = RuleEngine()
    after = eng2.evaluate(benign_log(BAD_IP))
    check(
        "CÙNG gói lành đó từ IP XẤU: bị chặn",
        after.get("tier1_action") == "BLOCK_IP",
        f"action={after.get('tier1_action')}",
    )
    check(
        "lý do nêu rõ là do tiền sử (không phải nội dung gói)",
        any("tiền sử" in str(x) for x in (after.get("tier1_reasons") or [])),
        str((after.get("tier1_reasons") or [""])[-1])[:60],
    )
    # Đây là điểm mấu chốt của GIẢM TẢI: chặn xong thì KHÔNG được leo thang Tier-2 nữa.
    check("chặn ở Tier-1 => KHÔNG leo thang LLM", after.get("tier1_action") != "ESCALATE")

    # ── 2. WHITELIST: phân tích đủ nhưng luôn cho qua ────────────────
    _group = "WHITELIST"
    print("\n── 2. WHITELIST (miễn trừ, nhưng vẫn phân tích) ──")
    mem.mark_ip_blocked(WL_IP, "T1110")  # cố tình cho tiền sử XẤU...
    eng3 = RuleEngine()
    eng3.whitelist_ips = set(eng3.whitelist_ips) | {WL_IP}  # ...rồi whitelist
    wl = eng3.evaluate(benign_log(WL_IP))
    check(
        "IP whitelist có tiền sử xấu VẪN được cho qua",
        wl.get("tier1_action") == "WHITELIST_DROP",
        f"action={wl.get('tier1_action')}",
    )
    check("cờ is_whitelisted được gắn", bool(wl.get("is_whitelisted")))
    check(
        "KHÔNG chặn và KHÔNG leo thang",
        wl.get("tier1_action") not in ("BLOCK_IP", "ESCALATE"),
    )
    # Miễn trừ KHÔNG được đồng nghĩa với "nuốt lặng": vẫn phải có điểm/lý do để analyst xem.
    check(
        "vẫn được chấm điểm để analyst quan sát",
        wl.get("tier1_score") is not None,
        f"score={wl.get('tier1_score')}",
    )

    # ── 3. CACHE: hai rổ theo tiền sử ────────────────────────────────
    _group = "CACHE"
    print("\n── 3. CACHE lớp-2 (gộp theo đặc trưng, tách theo tiền sử) ──")
    c = ExactMatchResponseCache()
    log_a = {
        "Source IP": "203.0.113.211",
        "Destination Port": 443,
        "Protocol": 6,
        "service": "https",
        "tier1_action": "ESCALATE",
        "tier1_reasons": ["x"],
    }
    log_b = dict(log_a, **{"Source IP": "203.0.113.212"})  # KHÁC IP, CÙNG đặc trưng

    check(
        "hai IP cùng đặc trưng -> CÙNG dấu vân (gộp được)",
        c.feature_fingerprint(log_a) == c.feature_fingerprint(log_b),
    )

    verdict = {"action": "ALERT", "confidence": 0.5, "reasoning": "lô A"}
    c.set_by_features(log_a, verdict, has_history=False)
    hit_same = c.get_by_features(log_b, has_history=False)
    check("IP khác, cùng đặc trưng, cùng 'chưa tiền sử' -> HIT (gộp đúng)", hit_same is not None)

    hit_diff = c.get_by_features(log_b, has_history=True)
    check(
        "cùng đặc trưng nhưng CÓ tiền sử -> MISS (không tái dùng verdict IP sạch)",
        hit_diff is None,
    )

    # Bản sao sâu: hạ nguồn sửa verdict KHÔNG được làm bẩn mục trong cache.
    got = c.get_by_features(log_a, has_history=False)
    assert got is not None
    got["action"] = "BLOCK_IP"
    again = c.get_by_features(log_a, has_history=False)
    check(
        "verdict trả về là BẢN SAO (sửa hạ nguồn không làm bẩn cache)",
        (again or {}).get("action") == "ALERT",
        f"đọc lại được action={(again or {}).get('action')}",
    )

    # ── Dọn dẹp ──────────────────────────────────────────────────────
    _group = "DON_DEP"
    print("\n── Dọn dẹp ──")
    mem.reset_ip_reputation(BAD_IP)
    mem.reset_ip_reputation(WL_IP)
    r1 = mem.get_ip_reputation(BAD_IP) or {}
    check(
        "reputation IP thử nghiệm đã reset",
        float(r1.get("reputation_score", 0) or 0) < 70,
        f"điểm={r1.get('reputation_score')}",
    )

    n_fail = sum(1 for r in results if not r["dat"])
    print("\n" + "=" * 78)
    print(f"KẾT QUẢ: {len(results) - n_fail}/{len(results)} đạt · {n_fail} hỏng")
    print("=" * 78)
    for r in results:
        if not r["dat"]:
            print(f"  HỎNG: {r['phep_kiem']}  — {r['chi_tiet']}")

    theo_co_che: dict[str, dict[str, int]] = {}
    for r in results:
        o = theo_co_che.setdefault(r["co_che"], {"tong": 0, "dat": 0})
        o["tong"] += 1
        o["dat"] += int(r["dat"])
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "tong_phep_kiem": len(results),
                "dat": len(results) - n_fail,
                "hong": n_fail,
                # `metric_valid` chỉ đúng khi KHÔNG có phép kiểm nào hỏng: đây là audit
                # nhị phân, một phép hỏng nghĩa là cơ chế giảm tải tương ứng không đứng.
                "metric_valid": n_fail == 0,
                "theo_co_che": theo_co_che,
                "ghi_chu": (
                    "Kịch bản dựng sẵn trên IP TEST-NET (RFC 5737), KHÔNG phải lượt chạy sống. "
                    "Chứng minh TỪNG cơ chế giảm tải Tier-1 hoạt động; không thay cho tỉ lệ xả "
                    "tải tổng ở 1.e."
                ),
                "chi_tiet": results,
            },
            fh,
            ensure_ascii=False,
            indent=1,
        )
    print(f"[+] Đã ghi: {OUT_JSON}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
