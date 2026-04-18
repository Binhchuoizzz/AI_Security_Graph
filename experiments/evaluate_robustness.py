"""
Adversarial Evaluation Pipeline — FULL IMPLEMENTATION

Chạy toàn bộ adversarial test suite qua Guardrails pipeline.
Đo lường Defeat Rate theo từng attack category.

Usage:
    python experiments/evaluate_robustness.py
"""
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.guardrails.prompt_filter import (
    GuardrailsPipeline,
    PromptInjectionDetector,
    EncodingNeutralizer,
    DelimitedDataEncapsulator
)

# =============================================================================
# ADVERSARIAL SAMPLE LOADER
# =============================================================================
ADVERSARIAL_DIR = os.path.join(os.path.dirname(__file__), "adversarial")

def load_adversarial_samples():
    """Load tất cả adversarial samples từ 3 categories."""
    all_samples = []
    categories = ["encoding_bypass", "structural_attacks", "semantic_confusion"]
    
    for cat in categories:
        sample_path = os.path.join(ADVERSARIAL_DIR, cat, "samples.json")
        if os.path.exists(sample_path):
            with open(sample_path, 'r') as f:
                samples = json.load(f)
                all_samples.extend(samples)
                print(f"  [+] Loaded {len(samples)} samples from {cat}/")
        else:
            print(f"  [!] Missing: {sample_path}")
    
    return all_samples


# =============================================================================
# GUARDRAILS EVALUATION ENGINE
# =============================================================================
def evaluate_guardrails_defense(samples: list) -> dict:
    """
    Chạy mỗi adversarial sample qua Guardrails pipeline.
    Đo: (1) Pattern Detection, (2) Encoding Neutralization, (3) Delimiter Sanitization.
    """
    pipeline = GuardrailsPipeline()
    detector = PromptInjectionDetector()
    neutralizer = EncodingNeutralizer()
    
    results_by_category = defaultdict(lambda: {
        "total": 0,
        "detected_by_pattern": 0,
        "neutralized_encoding": 0,
        "delimiter_stripped": 0,
        "fully_blocked": 0,
        "bypassed": 0,
        "details": []
    })
    
    for sample in samples:
        category = sample["category"]
        payload_field = sample.get("payload_field", "payload")
        payload = sample["payload"]
        expected_blocked = sample.get("expected_blocked", True)
        
        # Tạo log entry giả với payload
        log_entry = {
            "Source IP": "10.0.0.1",
            "Destination Port": 80,
            "Total Fwd Packets": 100,
            payload_field: payload,
            "log_source": "queue_waf"
        }
        
        stats = results_by_category[category]
        stats["total"] += 1
        
        # === Test Layer 1: Pattern Detection ===
        flagged = detector.scan(log_entry)
        pattern_detected = flagged.get("_injection_detected", False)
        if pattern_detected:
            stats["detected_by_pattern"] += 1
        
        # === Test Layer 2: Encoding Neutralization ===
        neutralized = neutralizer.neutralize(log_entry)
        encoding_changed = str(neutralized.get(payload_field)) != str(log_entry.get(payload_field))
        if encoding_changed:
            stats["neutralized_encoding"] += 1
        
        # === Test Layer 3: Delimiter Sanitization ===
        encapsulator = DelimitedDataEncapsulator()
        encapsulated = encapsulator.encapsulate_fields(log_entry)
        delimiter_stripped = "[DELIMITER_STRIPPED]" in encapsulated
        if delimiter_stripped:
            stats["delimiter_stripped"] += 1
        
        # === Overall Assessment ===
        is_blocked = pattern_detected or encoding_changed or delimiter_stripped
        if is_blocked:
            stats["fully_blocked"] += 1
        else:
            stats["bypassed"] += 1
        
        detail = {
            "id": sample["id"],
            "attack_type": sample.get("attack_type", "unknown"),
            "pattern_detected": pattern_detected,
            "encoding_neutralized": encoding_changed,
            "delimiter_stripped": delimiter_stripped,
            "overall_blocked": is_blocked,
            "expected_blocked": expected_blocked,
            "correct_prediction": is_blocked == expected_blocked
        }
        stats["details"].append(detail)
    
    return dict(results_by_category)


# =============================================================================
# REPORT GENERATOR
# =============================================================================
def print_report(results: dict):
    """In báo cáo chi tiết theo từng category."""
    print("\n" + "=" * 70)
    print("  SENTINEL ADVERSARIAL ROBUSTNESS EVALUATION REPORT")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    total_all = 0
    blocked_all = 0
    correct_all = 0
    
    for category, stats in results.items():
        total = stats["total"]
        blocked = stats["fully_blocked"]
        bypassed = stats["bypassed"]
        correct = sum(1 for d in stats["details"] if d["correct_prediction"])
        defeat_rate = (blocked / total * 100) if total > 0 else 0
        accuracy = (correct / total * 100) if total > 0 else 0
        
        total_all += total
        blocked_all += blocked
        correct_all += correct
        
        print(f"\n{'─' * 70}")
        print(f"  Category: {category.upper().replace('_', ' ')}")
        print(f"{'─' * 70}")
        print(f"  Total Samples:          {total}")
        print(f"  Blocked by Guardrails:  {blocked} ({defeat_rate:.1f}%)")
        print(f"  Bypassed:               {bypassed} ({100 - defeat_rate:.1f}%)")
        print(f"  Prediction Accuracy:    {correct}/{total} ({accuracy:.1f}%)")
        print(f"  ├─ Pattern Detection:   {stats['detected_by_pattern']}")
        print(f"  ├─ Encoding Neutral.:   {stats['neutralized_encoding']}")
        print(f"  └─ Delimiter Strip:     {stats['delimiter_stripped']}")
        
        # Chi tiết bypassed samples
        bypassed_details = [d for d in stats["details"] if not d["overall_blocked"]]
        if bypassed_details:
            print(f"\n   Bypassed samples:")
            for d in bypassed_details:
                print(f"    - {d['id']} ({d['attack_type']})")
    
    # Summary
    overall_defeat = (blocked_all / total_all * 100) if total_all > 0 else 0
    overall_accuracy = (correct_all / total_all * 100) if total_all > 0 else 0
    
    print(f"\n{'=' * 70}")
    print(f"  OVERALL SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total Adversarial Samples:  {total_all}")
    print(f"  Overall Defeat Rate:        {blocked_all}/{total_all} ({overall_defeat:.1f}%)")
    print(f"  Overall Prediction Acc:     {correct_all}/{total_all} ({overall_accuracy:.1f}%)")
    print(f"{'=' * 70}\n")
    
    return {
        "total": total_all,
        "blocked": blocked_all,
        "defeat_rate": overall_defeat,
        "accuracy": overall_accuracy,
        "by_category": {
            cat: {
                "total": s["total"],
                "blocked": s["fully_blocked"],
                "defeat_rate": (s["fully_blocked"] / s["total"] * 100) if s["total"] > 0 else 0
            } for cat, s in results.items()
        }
    }


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    print("[*] SENTINEL Adversarial Robustness Evaluation")
    print("[*] Loading adversarial samples...\n")
    
    samples = load_adversarial_samples()
    if not samples:
        print("[!] No samples found. Please create adversarial datasets first.")
        sys.exit(1)
    
    print(f"\n[*] Running {len(samples)} samples through Guardrails pipeline...\n")
    results = evaluate_guardrails_defense(samples)
    
    summary = print_report(results)
    
    # Lưu kết quả vào JSON
    output_path = os.path.join(os.path.dirname(__file__), "robustness_results.json")
    with open(output_path, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "detailed_results": {
                cat: {
                    "stats": {k: v for k, v in stats.items() if k != "details"},
                    "details": stats["details"]
                } for cat, stats in results.items()
            }
        }, f, indent=2)
    print(f"[+] Results saved to: {output_path}")
