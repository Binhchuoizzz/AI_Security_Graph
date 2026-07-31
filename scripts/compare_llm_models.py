"""So sánh nhiều model local trên CÙNG một bộ prompt THẬT đã ghi trong tracer.

VÌ SAO PHÁT LẠI THAY VÌ CHẠY LẠI PIPELINE. Chạy trọn luồng 5.000 sự kiện cho mỗi model mất
hàng giờ, và mỗi lượt lại khác nhau ở luật động/trí nhớ/cache — hai model sẽ KHÔNG được hỏi
cùng câu hỏi, nên chênh lệch đo được không quy cho model. Ở đây ta lấy ĐÚNG các prompt đã
gửi trong một lượt chạy thật (`reports/runs/<nhãn>/tier2_trace.jsonl`) và gửi lại y hệt cho
từng model. Cùng đầu vào, cùng nhiệt độ, cùng seed -> chênh lệch là của model.

Đo bốn thứ, theo thứ tự quan trọng với đồ án này:
  1. JSON hỏng      — model không trả đúng schema thì mọi thứ phía sau vô dụng
  2. Đúng kỹ thuật  — chỉ trên lô có kỹ thuật kỳ vọng suy ra được (bỏ trắng VẪN nằm mẫu số)
  3. Neo bằng chứng — có chọn kỹ thuật NGOÀI tài liệu RAG của chính lô đó không (tự chém)
  4. Độ trễ         — p50/p95

Chạy (server phải đang phục vụ model cần đo — script tự đổi qua .env + docker compose):
    .venv/bin/python scripts/compare_llm_models.py --list
    .venv/bin/python scripts/compare_llm_models.py --model WhiteRabbitNeo-V3-7B-Q4_K_M.gguf --ctx 32768
    .venv/bin/python scripts/compare_llm_models.py --report
"""

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(ROOT, ".env"))

import logging  # noqa: E402

logging.disable(logging.WARNING)

TRACE = "reports/runs/p1_cold/tier2_trace.jsonl"
LABELS = "data/demo_small.labels.json"
OUTDIR = "reports/model_bench"
MITRE_KEYS = ("wa_mitre", "gz_mitre", "zd_mitre", "adv_mitre", "apt_mitre_ttp")
TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def expected_of(rec: dict, labels: dict) -> set[str]:
    out: set[str] = set()
    for g in (rec.get("batch") or {}).get("gt_ids") or []:
        lb = labels.get(g) or {}
        for k in MITRE_KEYS:
            out |= set(TID.findall(str(lb.get(k) or "")))
    return out


def _assert_trace_matches_labels(allow_stale: bool = False) -> None:
    """Chặn phép so sánh dựa trên KHOÁ NỐI ĐÃ LỆCH.

    `gt_id` được đúc theo CHỈ SỐ sự kiện (`mint_event_id(i)`), nên sau khi dựng lại
    `demo.json` thì CÙNG một `gt_id` trỏ sang một sự kiện KHÁC. Trace của lượt chạy cũ vẫn
    tra được khoá trong sidecar mới — không lỗi, chỉ là ĐÁP ÁN SAI. Hệ quả: cột "đúng kỹ
    thuật" trông vẫn bình thường nhưng vô nghĩa, và không có dấu hiệu nào báo.
    """
    if not (os.path.exists(TRACE) and os.path.exists(LABELS)):
        return
    if os.path.getmtime(LABELS) > os.path.getmtime(TRACE):
        if allow_stale:
            print(
                "[!] CẢNH BÁO: sidecar mới hơn trace -> CỘT 'đúng kỹ thuật' KHÔNG DÙNG ĐƯỢC.\n"
                "    Chỉ đọc các chỉ số ĐỘC LẬP NHÃN: JSON hỏng, tự chém, p50/p95."
            )
            return
        raise SystemExit(
            f"[!] {LABELS} MỚI HƠN {TRACE} — sidecar đã được đúc lại sau lượt chạy đó, nên\n"
            f"    `gt_id` trong trace trỏ sang sự kiện khác. Cột 'đúng kỹ thuật' sẽ SAI.\n"
            f"    Chạy một lượt SỐNG mới để sinh trace khớp sidecar, rồi đo lại."
        )


def load_cases(limit: int, allow_stale: bool = False) -> list[dict]:
    """Ưu tiên lô CÓ kỹ thuật kỳ vọng (chấm được), rồi bù thêm lô khác để đo JSON/độ trễ."""
    _assert_trace_matches_labels(allow_stale)
    labels = json.load(open(LABELS))
    scorable, filler = [], []
    for line in open(TRACE):
        r = json.loads(line)
        msgs = (r.get("llm") or {}).get("prompt")
        if not msgs:
            continue
        rag_ids = set(TID.findall(str((r.get("rag") or {}).get("technique_mitre") or "")))
        case = {
            "messages": msgs,
            "expected": sorted(expected_of(r, labels)),
            "rag_ids": sorted(rag_ids),
        }
        (scorable if case["expected"] else filler).append(case)
    return scorable + filler[: max(0, limit - len(scorable))]


def switch_model(model_file: str, ctx: int) -> None:
    """Đổi model trong .env rồi dựng lại container LLM. Chờ tới khi /models trả lời."""
    env = open(".env").read()
    env = re.sub(r"^LLM_MODEL_FILE=.*$", f"LLM_MODEL_FILE={model_file}", env, flags=re.M)
    env = re.sub(r"^LLAMA_ARG_CTX_SIZE=.*$", f"LLAMA_ARG_CTX_SIZE={ctx}", env, flags=re.M)
    open(".env", "w").write(env)
    # PHẢI cập nhật CẢ `os.environ`, không chỉ tệp `.env`.
    #
    # LỖI ĐÃ VÁ: `load_dotenv()` ở đầu module đã nạp `LLM_MODEL_FILE` cũ vào `os.environ`.
    # `subprocess` kế thừa môi trường đó, mà docker-compose ƯU TIÊN biến môi trường hơn tệp
    # `.env` — nên nó dựng lại container bằng ĐÚNG model cũ, rồi vòng xác minh thấy "sai
    # model" và chờ tới hết 10 phút. Quan sát được: các mô hình khác đều trượt ở
    # đây, chỉ model đang chạy sẵn là đo được.
    os.environ["LLM_MODEL_FILE"] = model_file
    os.environ["LLAMA_ARG_CTX_SIZE"] = str(ctx)
    print(f"[*] Đổi sang {model_file} (ctx={ctx}), dựng lại container...")
    # Máy này chỉ có `docker-compose` (snap, v5.1.1); plugin `docker compose` KHÔNG có ->
    # lệnh cũ trả "unknown shorthand flag: 'd'". Bản trước nuốt lỗi bằng capture_output rồi
    # chạy tiếp, nên nó lặng lẽ đo LẠI model đang chạy và gán kết quả cho model mới — một
    # phép so sánh sai hoàn toàn mà không có dấu hiệu gì.
    cmd = None
    for candidate in (["docker-compose"], ["docker", "compose"]):
        probe = subprocess.run([*candidate, "version"], capture_output=True)
        if probe.returncode == 0:
            cmd = candidate
            break
    if cmd is None:
        raise RuntimeError("không tìm thấy docker-compose")
    # `--no-deps` LÀ BẮT BUỘC, không phải tối ưu. Quan sát được: `up -d --force-recreate llm`
    # (không có cờ này) trả về mã 0 nhưng KHÔNG dựng lại container — `docker inspect` cho
    # thấy container vẫn là bản cũ, tạo từ nhiều giờ trước, đang chạy model CŨ. Vì hàm này
    # chỉ kiểm mã trả về nên nó đi tiếp và đo lại model cũ dưới tên model mới.
    r = subprocess.run(
        [*cmd, "up", "-d", "--force-recreate", "--no-deps", "llm"], capture_output=True, text=True
    )
    if r.returncode != 0:
        raise RuntimeError(f"dựng lại container thất bại: {r.stderr[-400:]}")
    import urllib.request

    want = model_file.replace(".gguf", "")
    for _ in range(120):
        try:
            with urllib.request.urlopen("http://127.0.0.1:5000/v1/models", timeout=3) as resp:  # noqa: S310
                body = resp.read().decode("utf-8", "replace")
            # XÁC MINH server đang phục vụ ĐÚNG model vừa đặt. Chỉ chờ HTTP 200 là không đủ:
            # container cũ vẫn trả 200 với model CŨ, và ta sẽ gán số của model cũ cho model mới.
            if want in body:
                time.sleep(5)
                print(f"[+] Server sẵn sàng, đang phục vụ {want}.")
                return
        except Exception:
            pass
        time.sleep(5)
    raise RuntimeError(f"server không phục vụ {want} sau 10 phút")


def run_model(name: str, cases: list[dict]) -> dict:
    from src.agent.llm_client import LLMClient

    client = LLMClient()
    lat, bad_json, exact, scorable, abstain, ungrounded = [], 0, 0, 0, 0, 0
    # SỐ LÔ MÔ HÌNH THỰC SỰ NÊU TÊN MỘT KỸ THUẬT, trên TOÀN BỘ lô (không chỉ lô chấm được).
    # Thiếu con số này thì 'tự chém thấp' không diễn giải được: một model luôn trả 'N/A' sẽ
    # đạt tự-chém = 0 mà chẳng có năng lực gì.
    answered = 0
    for i, c in enumerate(cases, 1):
        t0 = time.time()
        try:
            raw = client.invoke(c["messages"], seed=42)
        except Exception as e:
            print(f"  [{i}/{len(cases)}] LỖI GỌI: {type(e).__name__}")
            bad_json += 1
            continue
        lat.append(time.time() - t0)
        parsed = client.parse_llm_response(raw)
        if not parsed or parsed.get("error"):
            bad_json += 1
            continue
        ans = set(TID.findall(str(parsed.get("mitre_technique") or "")))
        if ans:
            answered += 1
        if c["rag_ids"] and ans and not (ans & set(c["rag_ids"])):
            ungrounded += 1
        if c["expected"]:
            scorable += 1
            if not ans:
                abstain += 1
            elif ans & set(c["expected"]):
                exact += 1
        if i % 10 == 0:
            print(f"  [{i}/{len(cases)}] ...")
    lat.sort()
    return {
        "model": name,
        "n": len(cases),
        "bad_json": bad_json,
        "scorable": scorable,
        "exact": exact,
        "abstain": abstain,
        "ungrounded": ungrounded,
        "answered": answered,
        "p50": round(statistics.median(lat), 2) if lat else None,
        "p95": round(lat[int(len(lat) * 0.95)], 2) if lat else None,
    }


def report() -> None:
    rows = []
    for f in sorted(os.listdir(OUTDIR)) if os.path.isdir(OUTDIR) else []:
        if f.endswith(".json"):
            rows.append(json.load(open(os.path.join(OUTDIR, f))))
    if not rows:
        print("[!] chưa có kết quả nào trong " + OUTDIR)
        return
    print("\n" + "=" * 104)
    print("SO SÁNH MODEL — cùng prompt thật, cùng seed=42, temperature mặc định")
    print("=" * 104)
    print(
        f"  {'model':<34s}{'JSON hỏng':>11s}{'đúng KT':>16s}{'bỏ trắng':>10s}"
        f"{'tự chém':>9s}{'có trả lời':>12s}{'p50':>8s}{'p95':>8s}"
    )
    print("  " + "-" * 100)
    for r in rows:
        acc = f"{r['exact']}/{r['scorable']}" + (
            f" ({100 * r['exact'] / r['scorable']:.0f}%)" if r["scorable"] else ""
        )
        answered = r.get("answered")
        ans_s = f"{answered}/{r['n']}" if answered is not None else "—"
        print(
            f"  {r['model'][:33]:<34s}{r['bad_json']:>11d}{acc:>16s}"
            f"{r['abstain']:>10d}{r['ungrounded']:>9d}{ans_s:>12s}"
            f"{str(r['p50']):>8s}{str(r['p95']):>8s}"
        )
    print(
        "\n  'tự chém' = chọn kỹ thuật KHÔNG có trong tài liệu RAG của chính lô đó — càng thấp\n"
        "  càng tốt. 'bỏ trắng' cao KHÔNG xấu: với NetFlow thuần, N/A mới là câu trả lời đúng."
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", help="tên tệp .gguf trong /models")
    ap.add_argument("--ctx", type=int, default=16384)
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument(
        "--no-switch", action="store_true", help="dùng server đang chạy, không đổi model"
    )
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument(
        "--allow-stale-labels",
        action="store_true",
        help="cho chạy dù sidecar mới hơn trace — CHỈ để đọc JSON hỏng/tự chém/độ trễ",
    )
    args = ap.parse_args()

    if args.list:
        subprocess.run(["docker", "exec", "sentinel_llm", "ls", "/models"])
        return 0
    if args.report:
        report()
        return 0
    if not args.model:
        ap.error("cần --model hoặc --report/--list")

    os.makedirs(OUTDIR, exist_ok=True)
    cases = load_cases(args.limit, args.allow_stale_labels)
    n_sc = sum(1 for c in cases if c["expected"])
    print(f"[*] {len(cases)} lô phát lại ({n_sc} lô chấm được kỹ thuật)")

    if not args.no_switch:
        switch_model(args.model, args.ctx)
    tag = args.model.replace(".gguf", "")
    res = run_model(tag, cases)
    res["ctx"] = args.ctx
    res["labels_stale"] = bool(args.allow_stale_labels)
    with open(os.path.join(OUTDIR, f"{tag}.json"), "w") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(f"\n[+] -> {OUTDIR}/{tag}.json")
    report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
