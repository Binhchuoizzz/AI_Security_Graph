#!/usr/bin/env python3
"""Chấm lại ablation THEO HÀNH ĐỘNG trên dân số đã loại mẫu tự soạn.

VÌ SAO CẦN SCRIPT NÀY (đọc trước khi sửa):

1. **Thước nhị phân bão hoà, không dùng được.** Trên `ground_truth.json` tỉ lệ tấn công là
   86,86%, nên F1/Accuracy nhị phân xấp xỉ base rate và MỌI cấu hình cho gần như cùng một
   con số — `ablation_results.json → metric_health` đã tự gắn cờ
   `binary_f1_trustworthy: false`. Thước dùng được là **chấm theo hành động**: phán quyết
   cuối (`BLOCK_IP` / `ALERT` / `LOG` / `AWAIT_HITL`) có trùng hành động kỳ vọng không.

2. **`run_ablation.py` chấm A/F trên CẢ 1.750 mẫu, tức GỒM 50 mẫu tác giả tự soạn.**
   `drop_authored()` trong tệp đó chỉ áp cho *tập chấm quy kết* (550 → 250), không áp cho
   vòng ablation. Mà 50 mẫu ấy đều kỳ vọng `ALERT` cả 50 — đưa vào là để thước đo tự chấm
   văn mình viết. Luận văn đã tuyên bố loại chúng khỏi **mọi** tỉ lệ, nên phải loại thật.

Script này KHÔNG chạy lại mô hình. Nó đọc mảng dự đoán ĐÃ LƯU trong
`ablation_{results,bcde_results}.json` — đã kiểm chứng thứ tự phần tử trùng khít
`ground_truth.json` — rồi bỏ đúng các chỉ số của mẫu tự soạn và tính lại. Tất định, không
tốn token, chạy được offline.

Chạy: `.venv/bin/python scripts/score_ablation_actions.py`
Ra:   `experiments/results/ablation_action_scores.json`
"""

from __future__ import annotations

import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# DÙNG LẠI bộ chấm CHÍNH THỨC, không viết lại. Tự định nghĩa "hành động kết thúc" ở đây là
# cách chắc chắn nhất để ra số lệch: bản nháp đầu của script này bỏ sót `DROP` (hệ sinh
# `DROP` cho lưu lượng lành, ground_truth ghi nhãn di sản `LOG`) nên Config F tụt từ 0,3434
# xuống 0,0706 — không phải phát hiện gì cả, chỉ là chấm sai. `action_scoring` đã có sẵn
# bí danh DROP≡LOG và có unit test trong CI; mọi thay đổi ngữ nghĩa phải sửa ở ĐÓ.
from experiments.action_scoring import score_actions  # noqa: E402

RESULTS = os.path.join(BASE_DIR, "experiments", "results")
GROUND_TRUTH = os.path.join(BASE_DIR, "experiments", "ground_truth.json")
OUT = os.path.join(RESULTS, "ablation_action_scores.json")


def load_authored_mask() -> tuple[list[bool], list[str]]:
    """Trả về (mặt nạ tự-soạn, hành động kỳ vọng) theo ĐÚNG thứ tự của ground_truth."""
    with open(GROUND_TRUTH, encoding="utf-8") as fh:
        gt = json.load(fh)
    items = gt if isinstance(gt, list) else gt.get("samples") or gt.get("data") or []
    mask = [str(s.get("input", {}).get("cicids_label", "")) == "Adversarial" for s in items]
    expected = [str(s.get("expected_action")) for s in items]
    return mask, expected


def score(actions: list[str], expected: list[str], keep: list[bool]) -> dict:
    """Lọc theo `keep` rồi giao cho bộ chấm chính thức."""
    kept = [(e, a) for e, a, k in zip(expected, actions, keep, strict=True) if k]
    return score_actions([e for e, _ in kept], [a for _, a in kept])


def main() -> int:
    mask, gt_expected = load_authored_mask()
    keep = [not m for m in mask]
    n_authored = sum(mask)

    out: dict = {
        "how_to_read": (
            "Chấm THEO HÀNH ĐỘNG, không phải nhị phân: thước nhị phân bão hoà vì tập lệch "
            "86,86% tấn công. Mẫu số đã loại mẫu tác giả tự soạn. A/F chấm trên toàn tập; "
            "B-E chấm trên lát 300 mẫu nên KHÔNG so trực tiếp với A/F được."
        ),
        "n_authored_dropped": n_authored,
        "configs": {},
    }

    # ── A và F: mảng dài 1.750, khớp thứ tự ground_truth ─────────────────────────
    path_af = os.path.join(RESULTS, "ablation_results.json")
    with open(path_af, encoding="utf-8") as fh:
        af = json.load(fh)

    if af.get("expected_actions") != gt_expected:
        print("[!] THỨ TỰ KHÔNG KHỚP ground_truth — dừng, không chấm bừa.", file=sys.stderr)
        return 1

    for cfg in ("Config_A", "Config_F"):
        actions = af[cfg]["actions"]
        if len(actions) != len(keep):
            print(f"[!] {cfg}: độ dài {len(actions)} != {len(keep)}", file=sys.stderr)
            return 1
        out["configs"][cfg.replace("Config_", "")] = score(actions, gt_expected, keep)

    # ── B-E: lát 300 mẫu riêng, expected_actions của CHÍNH tệp đó ────────────────
    # Không dùng mặt nạ 1.750 ở đây: lát này được chọn lại, chỉ số không tương ứng.
    path_bcde = os.path.join(RESULTS, "ablation_bcde_results.json")
    if os.path.exists(path_bcde):
        with open(path_bcde, encoding="utf-8") as fh:
            bcde = json.load(fh)
        exp_b = bcde.get("expected_actions", [])
        for cfg in ("B", "C", "D", "E"):
            if cfg not in bcde:
                continue
            actions = bcde[cfg]["actions"]
            out["configs"][cfg] = score(actions, exp_b, [True] * len(actions))
            out["configs"][cfg]["note_population"] = "lát 300 mẫu, không so trực tiếp với A/F"

    # ── Bão hoà: C, D, E có khác nhau không? Ghi thẳng vào tệp, đừng để người đọc tự đoán.
    cde = [out["configs"].get(c, {}).get("action_accuracy") for c in ("C", "D", "E")]
    out["cde_identical"] = len({v for v in cde if v is not None}) == 1
    out["cde_note"] = (
        "C, D, E cho kết quả TRÙNG KHÍT ngay cả với thước hành động. Nguyên nhân do cấu tạo: "
        "cả ba chỉ gọi LLM khi Tier-1 leo thang, phần còn lại rơi về cùng `tier1_verdict`. "
        "Đây là giới hạn của thiết kế ablation, KHÔNG phải bằng chứng ba bậc RAG vô dụng."
    )

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)

    print(f"[i] Đã loại {n_authored} mẫu tự soạn khỏi A/F.")
    print(
        f"{'cấu hình':<10}{'n':>6}{'đúng h.động':>13}{'tự quyết':>10}{'hoãn':>8}{'bỏ ngỏ':>9}{'c.xác tự quyết':>16}"
    )
    for cfg, sc in out["configs"].items():
        print(
            f"{cfg:<10}{sc['n']:>6}{sc['action_accuracy']:>13.4f}{sc['autonomy_rate']:>10.4f}"
            f"{sc['defer_rate']:>8.4f}{sc['unresolved_rate']:>9.4f}{sc['autonomous_precision']:>16.4f}"
        )
    print(f"\n[+] Đã ghi: {OUT}")
    if out["cde_identical"]:
        print("[!] C ≡ D ≡ E — phải nêu rõ trong luận văn, không được giấu.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
