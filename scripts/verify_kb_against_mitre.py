"""Đối chiếu `knowledge_base/mitre_attack.json` với ATT&CK CHÍNH THỨC của MITRE.

VÌ SAO BẮT BUỘC CÓ. `attack_mapper.canonical_technique_name()` dùng CHÍNH KB này làm "nguồn
sự thật" để đối chiếu nhãn LLM trả về (`attack_mapper.py:454-467`). Đó là một vòng tròn: nếu
KB chứa mã bịa hoặc mã đã bị MITRE khai tử, bộ đối chiếu sẽ xác nhận chúng là ĐÚNG và gắn
`name_verified=True`. Lá chắn chống "đúng ID sai tên" khi ấy chỉ là trang trí.

Nguồn sự thật THẬT: kho STIX chính thức
    https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

Kịch bản CHỈ ĐỌC — báo cáo, không sửa gì. Bốn nhóm phát hiện:
  1. MÃ KHÔNG TỒN TẠI   — không có trong ATT&CK, kể cả nhóm đã khai tử  -> nghi bịa
  2. MÃ ĐÃ KHAI TỬ      — MITRE đã thu hồi/thay thế                     -> phải cập nhật
  3. SAI TÊN            — mã đúng nhưng tên KB khác tên chính thức
  4. SAI TACTIC         — tactic KB không khớp kill-chain phase chính thức

Chạy:
    .venv/bin/python scripts/verify_kb_against_mitre.py
    .venv/bin/python scripts/verify_kb_against_mitre.py --stix /đường/dẫn/enterprise-attack.json
    .venv/bin/python scripts/verify_kb_against_mitre.py --json reports/kb_verification.json
"""

import argparse
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


# KHÔNG hard-code danh sách tactic. Bản đầu của kịch bản này ghi cứng mô hình 14 tactic
# (có "Defense Evasion") rồi kết luận nhầm rằng 83 mục trong KB mang nhãn bịa — trong khi
# MITRE đã tách "Defense Evasion" thành "Stealth" + "Defense Impairment", nâng lên 15 tactic.
# Bài học: danh mục của MITRE thay đổi theo phiên bản, nên phải ĐỌC từ chính bó STIX.
def phase_map(stix: dict) -> dict[str, str]:
    """shortname (kebab-case) -> tên tactic chính thức, lấy từ đối tượng x-mitre-tactic."""
    return {
        o["x_mitre_shortname"]: o["name"]
        for o in stix.get("objects", [])
        if o.get("type") == "x-mitre-tactic" and o.get("x_mitre_shortname")
    }


def _norm(s: str) -> str:
    """Chuẩn hoá tên để so khớp lỏng (bỏ dấu câu, gộp khoảng trắng, hạ chữ)."""
    return " ".join(re.sub(r"[^a-z0-9 ]+", " ", (s or "").lower()).split())


def load_stix(path: str | None) -> dict:
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    print(f"[*] Tải ATT&CK chính thức từ {STIX_URL} (~45 MB)...")
    with urllib.request.urlopen(STIX_URL, timeout=120) as r:  # noqa: S310 (URL hằng, https)
        return json.loads(r.read().decode("utf-8"))


def build_official(stix: dict) -> tuple[dict, dict]:
    """(còn_hiệu_lực, đã_khai_tử): id -> {name, tactics}."""
    p2t = phase_map(stix)
    live: dict = {}
    dead: dict = {}
    for o in stix.get("objects", []):
        if o.get("type") != "attack-pattern":
            continue
        tid = next(
            (
                r.get("external_id")
                for r in o.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not tid:
            continue
        rec = {
            "name": o.get("name", ""),
            "tactics": [
                p2t.get(p.get("phase_name", ""), p.get("phase_name", ""))
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ],
        }
        (dead if (o.get("revoked") or o.get("x_mitre_deprecated")) else live)[tid] = rec
    return live, dead


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", default=None, help="dùng bản STIX có sẵn thay vì tải")
    ap.add_argument("--json", default=None, help="ghi kết quả ra tệp JSON")
    args = ap.parse_args()

    live, dead = build_official(load_stix(args.stix))
    print(f"[+] ATT&CK chính thức: {len(live)} còn hiệu lực · {len(dead)} đã khai tử\n")

    with open(KB_PATH) as f:
        raw = json.load(f)
    items = raw if isinstance(raw, list) else list(raw.values())[0]

    missing, deprecated, badname, badtactic, ok = [], [], [], [], 0
    for x in items:
        tid = str(x.get("id", "")).strip().upper()
        name = str(x.get("name", "")).strip()
        tac = str(x.get("tactic", "")).strip()
        if tid in live:
            o = live[tid]
            name_ok = _norm(name) == _norm(o["name"])
            # KB giữ MỘT tactic/kỹ thuật; ATT&CK cho phép nhiều -> khớp nếu nằm trong tập.
            # So KHÔNG phân biệt hoa thường: KB viết "Command And Control", MITRE viết
            # "Command and Control" — khác đúng một chữ 'a', không phải sai dữ liệu.
            tac_ok = (not o["tactics"]) or (_norm(tac) in {_norm(t) for t in o["tactics"]})
            if not name_ok:
                badname.append((tid, name, o["name"]))
            if not tac_ok:
                badtactic.append((tid, tac, "/".join(o["tactics"])))
            if name_ok and tac_ok:
                ok += 1
        elif tid in dead:
            deprecated.append((tid, name, dead[tid]["name"]))
        else:
            missing.append((tid, name, tac))

    n = len(items)

    def head(title: str, rows: list, cols: tuple) -> None:
        print(f"\n{'=' * 92}\n{title}  —  {len(rows)}/{n}\n{'=' * 92}")
        if not rows:
            print("  (không có)")
            return
        print(f"  {cols[0]:<16s}{cols[1]:<40s}{cols[2]}")
        for a, b, c in rows[:40]:
            print(f"  {a:<16s}{str(b)[:38]:<40s}{c}")
        if len(rows) > 40:
            print(f"  ... còn {len(rows) - 40} mục nữa")

    head(
        "1. MÃ KHÔNG TỒN TẠI trong ATT&CK (nghi BỊA)", missing, ("id", "tên trong KB", "tactic KB")
    )
    head("2. MÃ ĐÃ BỊ MITRE KHAI TỬ", deprecated, ("id", "tên trong KB", "tên bản khai tử"))
    head("3. SAI TÊN", badname, ("id", "tên trong KB", "tên CHÍNH THỨC"))
    head("4. SAI TACTIC", badtactic, ("id", "tactic KB", "tactic CHÍNH THỨC"))

    print(f"\n{'=' * 92}\nTỔNG KẾT\n{'=' * 92}")
    print(f"  Mục trong KB              : {n}")
    print(f"  Khớp hoàn toàn            : {ok}  ({100 * ok / n:.1f}%)")
    print(f"  Mã không tồn tại (nghi bịa): {len(missing)}  ({100 * len(missing) / n:.1f}%)")
    print(f"  Mã đã khai tử             : {len(deprecated)}  ({100 * len(deprecated) / n:.1f}%)")
    print(f"  Sai tên                   : {len(badname)}")
    print(f"  Sai tactic                : {len(badtactic)}")
    print(
        "\n  LƯU Ý: `attack_mapper.canonical_technique_name()` lấy CHÍNH KB này làm nguồn đối\n"
        "  chiếu, nên mọi mã ở nhóm 1 và 2 vẫn được gắn `name_verified=True` khi chạy thật."
    )

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(
                {
                    "kb_items": n,
                    "fully_ok": ok,
                    "missing": missing,
                    "deprecated": deprecated,
                    "bad_name": badname,
                    "bad_tactic": badtactic,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        print(f"\n[+] JSON -> {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
