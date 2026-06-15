"""
Xây dựng / mở rộng TOÀN BỘ tri thức RAG trong MỘT lần chạy (single source of truth).

Gộp 2 batch tri thức trước đây chạy lẻ (`expand_knowledge_base` + `supplement_knowledge_base`)
thành MỘT luồng: append idempotent toàn bộ kỹ thuật MITRE ATT&CK (phủ đủ 14 tactic) +
playbook NIST SP 800-61r2 vào knowledge_base, RỒI rebuild FAISS/BM25 index + checksum —
"một lần xây dựng tri thức" duy nhất.

Chạy:
    .venv/bin/python scripts/build_knowledge_base.py            # mở rộng KB + rebuild index
    .venv/bin/python scripts/build_knowledge_base.py --no-index # chỉ mở rộng KB, KHÔNG rebuild
"""
import argparse
import json
import os

# Hai module dưới giờ là NGUỒN DỮ LIỆU thuần (không còn entry point riêng) — chỉ chứa
# định nghĩa technique/playbook. build_knowledge_base.py là entry point DUY NHẤT.
try:
    from scripts.expand_knowledge_base import EXPANDED_MITRE, EXPANDED_NIST
    from scripts.supplement_knowledge_base import NEW_MITRE, NEW_NIST
except ImportError:  # chạy trực tiếp trong scripts/
    from expand_knowledge_base import EXPANDED_MITRE, EXPANDED_NIST  # type: ignore
    from supplement_knowledge_base import NEW_MITRE, NEW_NIST  # type: ignore

KB_DIR = os.path.join(os.path.dirname(__file__), "..", "knowledge_base")
MITRE_PATH = os.path.join(KB_DIR, "mitre_attack.json")
NIST_PATH = os.path.join(KB_DIR, "nist_800_61r2.json")

# Gộp 2 nguồn (đã xác minh: 0 trùng id MITRE, 0 trùng control NIST -> append an toàn)
ALL_MITRE = EXPANDED_MITRE + NEW_MITRE
ALL_NIST = EXPANDED_NIST + NEW_NIST


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def extend_knowledge_base() -> tuple[int, int]:
    """Append idempotent toàn bộ MITRE + NIST còn thiếu. Trả (added_mitre, added_nist)."""
    # --- MITRE ---
    mitre = _load(MITRE_PATH)
    existing_ids = {e.get("id") for e in mitre}
    added_m = 0
    for t in ALL_MITRE:
        if t["id"] not in existing_ids:
            mitre.append(t)
            existing_ids.add(t["id"])
            added_m += 1
    _save(MITRE_PATH, mitre)

    # --- NIST ---
    nist = _load(NIST_PATH)
    controls = nist.get("controls", [])
    existing_ctrl = {c.get("control") for c in controls}
    added_n = 0
    for c in ALL_NIST:
        if c["control"] not in existing_ctrl:
            controls.append(c)
            existing_ctrl.add(c["control"])
            added_n += 1
    nist["controls"] = controls
    nist["_total_controls"] = len(controls)
    _save(NIST_PATH, nist)

    print(f"[MITRE] +{added_m} kỹ thuật (tổng {len(mitre)})")
    print(f"[NIST]  +{added_n} playbook (tổng {len(controls)})")
    return added_m, added_n


def main():
    ap = argparse.ArgumentParser(description="Xây dựng/mở rộng tri thức RAG trong 1 lần")
    ap.add_argument("--no-index", action="store_true",
                    help="Chỉ mở rộng KB JSON, KHÔNG rebuild FAISS/BM25 index")
    args = ap.parse_args()

    print("=== [1/2] Mở rộng tri thức (MITRE ATT&CK + NIST SP 800-61r2) ===")
    extend_knowledge_base()

    if args.no_index:
        print("\n[!] Bỏ qua rebuild index (--no-index). Nhớ chạy lại embedder khi cần.")
        return

    print("\n=== [2/2] Rebuild FAISS + BM25 index + checksum ===")
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from src.rag.embedder import update_checksums_file, build_all_indexes
    build_all_indexes()
    update_checksums_file()
    print("\n✅ Hoàn tất: tri thức đã mở rộng + index/checksum đã rebuild (1 lần xây dựng).")


if __name__ == "__main__":
    main()
