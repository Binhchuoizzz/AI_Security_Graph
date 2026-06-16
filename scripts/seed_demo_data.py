"""
Seed dữ liệu Dashboard từ DATA THẬT đã chuẩn hóa (KHÔNG bịa).

Nguồn dữ liệu thật:
  - experiments/ground_truth.json : mẫu CICSE-CIC-IDS2018 đã chuẩn hóa (flow thật + nhãn thật)
  - data/processed/dapt2020_chains.jsonl : chuỗi APT DAPT2020 thật (nhiều ngày)

Cách hoạt động (chính danh):
  1. Với MỖI loại tấn công CICIDS (14 lớp), lấy mẫu THẬT và chạy QUA PIPELINE THẬT:
     RuleEngine (Tier-1) -> LangGraph Agent (Guardrails -> RAG -> LLM Gemma 2).
     Agent tự sinh quyết định THẬT và GHI vào audit_trail / threat_memory / pending_rules
     (qua node_action_executor, audit_logger, threat_memory.record_incident).
  2. Nạp 9 chuỗi APT DAPT2020 THẬT vào threat_memory (ingest_dapt_chains).

=> Mọi con số trên Dashboard đều là quyết định LLM thật trên flow thật.
   (Lưu ý trung thực: IP nguồn trong CICIDS đã được dataset ẩn danh/chuẩn hóa;
    đặc trưng flow, nhãn tấn công, MITRE mapping và lập luận LLM đều là THẬT.)

Chạy SAU CÙNG, ngay trước khi demo:
    .venv/bin/python scripts/seed_demo_data.py
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

GT_PATH = os.path.join(os.path.dirname(__file__), "..", "experiments", "ground_truth.json")
DAPT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "processed", "dapt2020_chains.jsonl"
)

# Các lớp tấn công CICIDS cần phủ đầy đủ (bỏ Benign/Adversarial — không phải "cảnh báo")
ATTACK_CLASSES = [
    "SSH-Bruteforce",
    "FTP-BruteForce",
    "DoS attacks-Hulk",
    "DoS attacks-GoldenEye",
    "DoS attacks-Slowloris",
    "DoS attacks-SlowHTTPTest",
    "DDOS attack-HOIC",
    "DDOS attack-LOIC-UDP",
    "DDoS attacks-LOIC-HTTP",
    "Brute Force -Web",
    "Brute Force -XSS",
    "SQL Injection",
    "Infilteration",
    "Bot",
]
# Số flow gộp thành 1 incident. Một cuộc tấn công thật (brute force/DoS) là MỘT
# nguồn tạo NHIỀU flow; ground_truth đã tách rời thành các flow đơn lẻ với IP tổng
# hợp khác nhau (artifact của bước trích xuất). Ta gộp lại dưới một attacker IP để
# Tier-1 session baseline phát hiện đúng pattern (đặc trưng flow/port/nhãn giữ NGUYÊN).
FLOWS_PER_INCIDENT = 15
# Số incident demo tạo cho MỖI loại tấn công (tăng để dashboard có nhiều dữ liệu hơn).
# Mỗi incident dùng một nhóm flow THẬT khác nhau (đan xen) -> attacker IP khác nhau.
INCIDENTS_PER_CLASS = 3


def run_real_pipeline_on_cicids():
    """Chạy pipeline THẬT (Tier-1 + LangGraph Agent + LLM) trên mẫu CICIDS thật."""
    from src.agent.state import SentinelState
    from src.agent.workflow import agent_app
    from src.guardrails import loop_detector
    from src.tier1_filter.rule_engine import RuleEngine

    with open(GT_PATH) as f:
        gt = json.load(f)
    by_class = {}
    for s in gt:
        lbl = s.get("input", {}).get("cicids_label", "?")
        by_class.setdefault(lbl, []).append(s)

    done = 0
    for cls in ATTACK_CLASSES:
        samples = by_class.get(cls, [])
        if not samples:
            print(f"  [skip] no samples for {cls}")
            continue
        # Tạo nhiều incident demo cho mỗi loại tấn công, mỗi cái từ một nhóm flow
        # THẬT khác nhau (đan xen grp::INCIDENTS_PER_CLASS) -> attacker IP khác nhau.
        for grp in range(INCIDENTS_PER_CLASS):
            grp_samples = samples[grp::INCIDENTS_PER_CLASS]
            if not grp_samples:
                continue
            # Gom FLOWS_PER_INCIDENT flow THẬT của cùng loại tấn công
            flows = []
            for s in grp_samples:
                flows.extend(s.get("logs", []))
                if len(flows) >= FLOWS_PER_INCIDENT:
                    break
            flows = flows[:FLOWS_PER_INCIDENT]
            if not flows:
                continue
            # Gộp về MỘT attacker IP (đại diện nguồn tấn công thật)
            attacker_ip = flows[0].get("src_ip", "unknown")
            # RuleEngine mới cho mỗi incident để session baseline tích lũy đúng theo IP này
            engine = RuleEngine()
            evaluated = []
            for log in flows:
                e = dict(log)
                e["src_ip"] = attacker_ip  # consolidate nguồn (đặc trưng flow giữ nguyên)
                e["dataset_source"] = "CSE-CIC-IDS2018"
                e["log_source"] = "queue_waf"
                evaluated.append(engine.evaluate(e))  # Tier-1 thật, tích lũy baseline

            expected = grp_samples[0]
            state = SentinelState(
                current_batch_logs=evaluated,
                current_batch_size=len(evaluated),
                narrative_summary="",
            )
            loop_detector.reset()
            try:
                final = agent_app.invoke(state)
                dec = (final.get("decisions") or [{}])[-1] if isinstance(final, dict) else {}
                t1 = evaluated[-1]
                print(
                    f"  [{cls:24s} #{grp + 1}] T1={t1.get('tier1_action')}({t1.get('tier1_score')}) -> LLM {dec.get('action', '?')} {dec.get('target', '?')} | {str(dec.get('mitre_technique', ''))[:34]} (exp {expected.get('expected_action')}/{expected.get('expected_mitre_technique')})"
                )
                done += 1
            except Exception as e:
                print(f"  [{cls:24s} #{grp + 1}] pipeline error: {e}")
    print(f"[CICIDS] {done} real incidents analyzed by LLM across attack types")


def ingest_real_apt():
    """Nạp 9 chuỗi APT DAPT2020 THẬT vào threat_memory.

    LƯU Ý: đây là SEED cho DASHBOARD (để UI có sẵn lịch sử APT hiển thị) — KHÔNG
    phải benchmark phát hiện APT. Việc đánh giá năng lực phát hiện APT (emergent,
    bộ nhớ sạch, không nạp-sẵn) nằm ở `experiments/evaluate_unified_stream.py`.

    Muốn DEMO APT emergent SỐNG trên dashboard (bản án nổi lên dần thay vì lịch sử
    nạp sẵn): KHÔNG chạy hàm này; thay vào đó xóa `config/threat_memory.db` rồi chạy
    `experiments/stream_unified_online.py` + `main.py --mode server`
    (docs/guides/RUN_PROJECT.md — Bước 5).
    """
    from src.agent.threat_memory import ThreatMemoryStore

    s = ThreatMemoryStore()
    n = s.ingest_dapt_chains(DAPT_PATH)
    # Đánh dấu APT indicator cho các attacker IP đa-ngày thật
    with open(DAPT_PATH) as f:
        chains = [json.loads(line) for line in f]
    apt_ips = 0
    for c in chains:
        ip = c["attacker_ip"]
        if len(c.get("days_spanned", [])) >= 2:
            chain = s.check_apt_chain(ip)
            if chain.get("is_apt"):
                s.record_apt_indicator(
                    "dapt2020_apt",
                    ip,
                    0.9,
                    related_ips=ip,
                    mitre_chain="→".join([str(p) for p in c.get("phases", [])][:5]),
                )
                apt_ips += 1
    print(f"[DAPT2020] ingested {n} real threat events; {apt_ips} multi-day APT attackers flagged")
    print(f"[THREAT] stats: {s.get_stats()} | threat_events={len(s.get_all_threat_events())}")


def seed_known_entities():
    """Bối cảnh tổ chức (config hợp lệ do admin định nghĩa — KHÔNG phải 'kết quả')."""
    from src.agent.threat_memory import ThreatMemoryStore

    s = ThreatMemoryStore()
    entities = [
        ("scanner", "10.10.10.5", "Nessus Vulnerability Scanner (scheduled scan)", "admin"),
        ("pentest_ip", "192.168.50.10", "Red Team pentest VM - authorized engagement", "manager"),
        (
            "backup_server",
            "192.168.1.30",
            "Veeam backup server (large outbound is normal)",
            "admin",
        ),
    ]
    added = 0
    for t, v, d, by in entities:
        if not s.is_known_entity(v):
            s.add_known_entity(t, v, d, by)
            added += 1
    print(f"[ENTITIES] +{added} known internal entities (organizational context)")


if __name__ == "__main__":
    print("=== Seed Dashboard từ DATA THẬT (CICIDS2018 + DAPT2020) ===\n")
    print("[1/3] Chạy pipeline THẬT trên mẫu CICIDS (14 loại tấn công)...")
    run_real_pipeline_on_cicids()
    print("\n[2/3] Nạp chuỗi APT DAPT2020 thật...")
    ingest_real_apt()
    print("\n[3/3] Bối cảnh tổ chức (known entities)...")
    seed_known_entities()
    print(
        "\n✅ Done. Dashboard (http://localhost:8501) hiển thị quyết định LLM THẬT trên data THẬT."
    )
