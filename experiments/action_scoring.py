"""Chấm theo HÀNH ĐỘNG CUỐI CÙNG — thước đo chính của ablation.

TÁCH RIÊNG khỏi `run_ablation.py` có chủ đích: file đó import cả agent/LLM/retriever nên
không thể unit-test và không script eval nào khác dùng lại được. Module này thuần Python,
không phụ thuộc gì, nên vừa test được trong CI vừa dùng chung cho mọi phép đo.

BỐI CẢNH (vì sao cần thước đo này):
Thước đo nhị phân "có gắn cờ hay không" gộp `ESCALATE` (Tầng 1 chuyển tiếp) và
`AWAIT_HITL` (hoãn cho người) vào CÙNG Ô với `BLOCK_IP`. Đo thật ngày 2026-07-21 trên
`ablation_results.json` + `ablation_bcde_results.json`: Config A ≡ F từng bit, và
B ≡ C ≡ D ≡ E từng bit — mọi cấu hình đều "gắn cờ tất cả", nên F1 = 0.9655 chính là điểm
của một hàm `return True` trên tập 93.3% tấn công. Ablation mất sạch khả năng phân biệt và
McNemar cho p = 1.0.
"""

# NGUYÊN TẮC: `expected_action` trong ground_truth có ĐỦ 4 nhãn (ALERT 770 · BLOCK_IP 320 ·
# AWAIT_HITL 80 · LOG 80). AWAIT_HITL là ĐÁP ÁN ĐÚNG cho 80 mẫu — hoãn cho người đôi khi
# CHÍNH LÀ hành động đúng. Vậy phải chấm bằng KHỚP HÀNH ĐỘNG, không phải 'có gắn cờ hay
# không'. Và `ESCALATE` KHÔNG phải phán quyết: nó nghĩa là pipeline CHƯA quyết xong, nên
# tính riêng thành 'chưa phân giải' — tuyệt đối không tính là phát hiện.
TERMINAL_ACTIONS = ("BLOCK_IP", "ALERT", "LOG", "DROP")
DEFER_ACTIONS = ("AWAIT_HITL",)
UNRESOLVED_ACTIONS = ("ESCALATE", "ERROR", "UNKNOWN")

# Nhãn benign trong ground_truth là "LOG" (tên di sản); hệ sinh ra "DROP". Coi là một.
_ACTION_ALIAS = {"DROP": "LOG", "TIER1_DROP": "LOG"}


def _canon_action(raw: object) -> str:
    """Chuẩn hoá tên hành động (bỏ tiền tố TIER1_, gộp DROP≡LOG) trước khi so khớp.

    Nhận `object` chứ không phải `str`: giá trị tới từ `dict.get()` nên có thể là None —
    ép kiểu ở đây để một bản ghi thiếu trường không làm hỏng cả lượt chấm.
    """
    a = str(raw or "UNKNOWN").strip().upper()
    if a.startswith("TIER1_"):
        a = a[len("TIER1_") :]
    return _ACTION_ALIAS.get(a, a)


def score_actions(expected: list, actual: list) -> dict:
    """Chấm theo HÀNH ĐỘNG CUỐI CÙNG — thước đo phân biệt được các cấu hình.

    Trả về:
      action_accuracy   — tỉ lệ khớp CHÍNH XÁC hành động kỳ vọng (thước đo CHÍNH)
      autonomy_rate     — tỉ lệ hệ TỰ QUYẾT (ra hành động cuối, không hoãn/không treo)
      defer_rate        — tỉ lệ hoãn cho người (AWAIT_HITL)
      unresolved_rate   — tỉ lệ pipeline CHƯA quyết xong (ESCALATE/ERROR) — chỉ Config A
                          thiếu tầng sau mới có; KHÔNG được tính là phát hiện
      autonomous_precision — trong các ca TỰ QUYẾT, bao nhiêu phần trăm quyết ĐÚNG. Đây là
                          câu hỏi vận hành thật: "khi hệ dám tự hành động, nó có đáng tin?"
      confusion         — bảng chéo kỳ vọng × thực tế, để soi hệ sai kiểu gì
    """
    n = len(expected)
    if not n:
        return {"n": 0}
    exp = [_canon_action(e) for e in expected]
    act = [_canon_action(a) for a in actual]

    correct = sum(1 for e, a in zip(exp, act, strict=False) if e == a)
    n_terminal = sum(1 for a in act if a in TERMINAL_ACTIONS)
    n_defer = sum(1 for a in act if a in DEFER_ACTIONS)
    n_unres = sum(1 for a in act if a in UNRESOLVED_ACTIONS)
    n_term_correct = sum(
        1 for e, a in zip(exp, act, strict=False) if a in TERMINAL_ACTIONS and e == a
    )

    confusion: dict[str, dict[str, int]] = {}
    for e, a in zip(exp, act, strict=False):
        confusion.setdefault(e, {}).setdefault(a, 0)
        confusion[e][a] += 1

    return {
        "n": n,
        "action_accuracy": round(correct / n, 4),
        "autonomy_rate": round(n_terminal / n, 4),
        "defer_rate": round(n_defer / n, 4),
        "unresolved_rate": round(n_unres / n, 4),
        "autonomous_precision": round(n_term_correct / n_terminal, 4) if n_terminal else None,
        "n_correct": correct,
        "n_terminal": n_terminal,
        "n_defer": n_defer,
        "n_unresolved": n_unres,
        "confusion": confusion,
    }
