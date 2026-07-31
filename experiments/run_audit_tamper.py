"""Đo khả năng CHỐNG CHỐI BỎ của chuỗi niêm phong HMAC-SHA256 trên vết kiểm toán.

[Luận văn Ch.4 — vế thứ hai của RQ2]

VÌ SAO CÓ TỆP NÀY. RQ2 hỏi thẳng: *"chuỗi niêm phong mật mã HMAC bảo vệ tính chống chối bỏ
của vết pháp y ra sao trước nguy cơ bị thao túng nhật ký?"* — nhưng trước đây cơ chế này chỉ
được chạm tới trong `tests/unit/test_executor.py`. Test đơn vị trả lời "có hoạt động không",
KHÔNG trả lời "phát hiện được bao nhiêu phần trăm". Hội đồng hỏi con số thì không có gì đưa.

ĐO CÁI GÌ. Ba kiểu thao túng mà kẻ tấn công có quyền ghi DB sẽ thực sự làm:

  SỬA   — đổi nội dung một dòng (che dấu vết một lệnh chặn, đổi target sang IP khác)
  CHÈN  — thêm một dòng ngụy tạo vào giữa chuỗi (dựng bằng chứng giả)
  XOÁ   — gỡ hẳn một dòng (phi tang)

Mỗi kiểu lặp `--trials` lần ở vị trí NGẪU NHIÊN trong chuỗi, đếm tỉ lệ bị
`verify_audit_trail_integrity()` bắt.

ĐỐI CHỨNG ÂM LÀ BẮT BUỘC. Trước mỗi lượt, bản sao chưa đụng vào phải verify SẠCH. Thiếu bước
này thì "phát hiện 100%" là vô nghĩa — một chuỗi vốn đã gãy sẵn cũng cho đúng con số đó.

AN TOÀN. KHÔNG bao giờ đụng `config/audit_trail.db` thật: mỗi lượt sao ra thư mục tạm rồi
trỏ `executor.DB_PATH` sang bản sao. Vết kiểm toán thật là bằng chứng pháp y của chính luận
văn — làm hỏng nó thì không dựng lại được.

Chạy:  .venv/bin/python experiments/run_audit_tamper.py [--trials 30]
Ra:    experiments/results/audit_tamper_results.json
"""

import argparse
import json
import os
import random
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.response import executor  # noqa: E402

REAL_DB = os.path.join(os.path.dirname(__file__), "..", "config", "audit_trail.db")
OUT = "experiments/results/audit_tamper_results.json"


def _rows(db: str) -> list[tuple]:
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT id FROM audit_trail ORDER BY id ASC").fetchall()


def _verify(db: str) -> tuple[bool, str]:
    """Chạy verifier THẬT trên bản sao — không viết lại logic kiểm tra ở đây.

    Viết lại sẽ kiểm một thuật toán khác với thuật toán đang chạy, và phép đo mất ý nghĩa.
    """
    old = executor.DB_PATH
    try:
        executor.DB_PATH = db
        return executor.verify_audit_trail_integrity()
    finally:
        executor.DB_PATH = old


def _fresh_copy(tmpdir: str, n: int) -> str:
    dst = os.path.join(tmpdir, f"audit_{n}.db")
    shutil.copy2(REAL_DB, dst)
    return dst


def tamper_modify(db: str, rng: random.Random) -> str:
    ids = [r[0] for r in _rows(db)]
    rid = rng.choice(ids)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_trail SET reason = ? WHERE id = ?", ("(đã bị sửa)", rid))
    return f"SỬA dòng id={rid}"


def tamper_insert(db: str, rng: random.Random) -> str:
    """Chèn một dòng ngụy tạo KÈM integrity_hash trông hợp lệ về hình thức.

    Cố tình dùng hash sao chép từ dòng khác chứ không để rỗng: kẻ tấn công biết cột đó tồn
    tại sẽ điền một giá trị 64 ký tự hex, không bỏ trống. Phép thử phải khó đúng mức đó.
    """
    ids = [r[0] for r in _rows(db)]
    anchor = rng.choice(ids[:-1]) if len(ids) > 1 else ids[0]
    with sqlite3.connect(db) as conn:
        borrowed = conn.execute(
            "SELECT integrity_hash FROM audit_trail WHERE id = ?", (anchor,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO audit_trail (id, timestamp, action, target, reason, integrity_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                max(ids) + 1000,
                "2026-01-01T00:00:00",
                "BLOCK_IP",
                "203.0.113.99",
                "bằng chứng ngụy tạo",
                borrowed,
            ),
        )
    return f"CHÈN dòng giả (mượn hash của id={anchor})"


def tamper_delete(db: str, rng: random.Random) -> str:
    ids = [r[0] for r in _rows(db)]
    # Không xoá dòng CUỐI: xoá đuôi chuỗi thì không có mắt xích nào phía sau để lộ ra chỗ
    # gãy, và đó là một hạn chế THẬT của log-chaining, phải nói riêng chứ không trộn vào
    # tỉ lệ phát hiện chung.
    rid = rng.choice(ids[:-1]) if len(ids) > 1 else ids[0]
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM audit_trail WHERE id = ?", (rid,))
    return f"XOÁ dòng id={rid}"


def tamper_delete_tail(db: str, _rng: random.Random) -> str:
    ids = [r[0] for r in _rows(db)]
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM audit_trail WHERE id = ?", (ids[-1],))
    return f"XOÁ dòng CUỐI id={ids[-1]}"


MODES = {
    "sửa_nội_dung": tamper_modify,
    "chèn_dòng_giả": tamper_insert,
    "xoá_dòng_giữa": tamper_delete,
    "xoá_dòng_cuối": tamper_delete_tail,
}


def run(trials: int = 30, seed: int = 42) -> dict:
    if not os.path.exists(REAL_DB):
        print(f"[!] Không thấy {REAL_DB} — chạy demo trước để sinh vết kiểm toán.")
        return {}

    n_rows = len(_rows(REAL_DB))
    rng = random.Random(seed)
    results: dict = {
        "n_audit_rows": n_rows,
        "trials_per_mode": trials,
        "seed": seed,
        "key_is_default": executor.audit_key_is_default(),
        "by_mode": {},
    }

    with tempfile.TemporaryDirectory(prefix="audit_tamper_") as tmp:
        # ── ĐỐI CHỨNG ÂM ────────────────────────────────────────────────────────
        clean = _fresh_copy(tmp, 0)
        ok, msg = _verify(clean)
        results["negative_control"] = {"intact": bool(ok), "message": msg}
        print(f"[*] Đối chứng âm (bản sao chưa đụng): {'SẠCH' if ok else 'ĐÃ GÃY SẴN'} — {msg}")
        if not ok:
            results["metric_valid"] = False
            results["note"] = (
                "Chuỗi gốc ĐÃ gãy trước khi thử — mọi tỉ lệ phát hiện bên dưới vô nghĩa. "
                "Phải dựng lại vết kiểm toán sạch rồi đo lại."
            )
            print("[!] " + results["note"])
            return results
        results["metric_valid"] = True

        # ── BA KIỂU THAO TÚNG ───────────────────────────────────────────────────
        for name, fn in MODES.items():
            detected = 0
            examples: list[str] = []
            for i in range(trials):
                db = _fresh_copy(tmp, f"{name}_{i}")  # type: ignore[arg-type]
                what = fn(db, rng)
                ok, msg = _verify(db)
                if not ok:
                    detected += 1
                elif len(examples) < 3:
                    examples.append(f"KHÔNG BẮT ĐƯỢC: {what}")
            rate = detected / trials if trials else 0.0
            results["by_mode"][name] = {
                "trials": trials,
                "detected": detected,
                "detection_rate": round(rate, 4),
                "missed_examples": examples,
            }
            print(f"    {name:16s}: {detected}/{trials} = {rate:.1%}")

    core = ["sửa_nội_dung", "chèn_dòng_giả", "xoá_dòng_giữa"]
    tot_d = sum(results["by_mode"][m]["detected"] for m in core)
    tot_t = sum(results["by_mode"][m]["trials"] for m in core)
    results["overall_detection_rate_core"] = round(tot_d / tot_t, 4) if tot_t else 0.0
    results["core_modes"] = core
    results["note_tail_deletion"] = (
        "`xoá_dòng_cuối` tách riêng khỏi tỉ lệ chung: cắt ĐUÔI chuỗi không để lại mắt xích "
        "nào phía sau nên log-chaining về nguyên lý không phát hiện được. Đây là giới hạn "
        "cần nêu thẳng, không phải con số để làm đẹp."
    )
    if results["key_is_default"]:
        results["warning_default_key"] = (
            "Đang ký bằng khoá MẶC ĐỊNH công khai: con số trên chứng minh tính NHẤT QUÁN "
            "chứ chưa phải chống giả mạo có chủ đích. Đặt SENTINEL_LOG_SECRET trong .env."
        )

    Path("experiments/results").mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Phát hiện (3 kiểu chính): {results['overall_detection_rate_core']:.2%}")
    print(f"[+] Đã lưu: {OUT}")
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Đo chống chối bỏ của chuỗi HMAC vết kiểm toán.")
    ap.add_argument("--trials", type=int, default=30, help="Số lượt mỗi kiểu thao túng.")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    run(a.trials, a.seed)
