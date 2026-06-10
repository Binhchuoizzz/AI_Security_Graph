"""
Hệ thống Đánh giá Tấn công Adversarial — BẢN ĐẦY ĐỦ

Chạy toàn bộ tập kiểm thử adversarial qua pipeline Guardrails.
Đo lường Tỷ lệ Chặn (Defeat Rate) theo từng nhóm tấn công.

Cách dùng:
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
    DelimitedDataEncapsulator,
)

# =============================================================================
# BỘ TẢI MẪU TẤN CÔNG ADVERSARIAL
# =============================================================================
ADVERSARIAL_DIR = os.path.join(os.path.dirname(__file__), "adversarial")


def load_adversarial_samples():
    """Tải toàn bộ mẫu adversarial từ 5 nhóm tấn công."""
    all_samples = []
    categories = ["encoding_bypass", "structural_attacks", "semantic_confusion",
                  "jailbreak", "rag_poisoning"]

    for cat in categories:
        sample_path = os.path.join(ADVERSARIAL_DIR, cat, "samples.json")
        if os.path.exists(sample_path):
            with open(sample_path, "r") as f:
                samples = json.load(f)
                all_samples.extend(samples)
                print(f"  [+] Loaded {len(samples)} samples from {cat}/")
        else:
            print(f"  [!] Missing: {sample_path}")

    return all_samples


# =============================================================================
# BỘ ĐÁNH GIÁ PHÒNG THỦ GUARDRAILS
# =============================================================================
def evaluate_guardrails_defense(samples: list) -> dict:
    """
    Chạy từng mẫu adversarial qua pipeline Guardrails.
    Đo lường: (1) Phát hiện mẫu định sẵn, (2) Hóa giải mã hóa, (3) Lọc ký tự phân tách.
    """
    pipeline = GuardrailsPipeline()
    detector = PromptInjectionDetector()
    neutralizer = EncodingNeutralizer()

    from typing import TypedDict, Any

    class CategoryStats(TypedDict):
        total: int
        detected_by_pattern: int
        neutralized_encoding: int
        delimiter_stripped: int
        fully_blocked: int
        bypassed: int
        details: list[dict[str, Any]]

    results_by_category: dict[str, CategoryStats] = defaultdict(
        lambda: {
            "total": 0,
            "detected_by_pattern": 0,
            "neutralized_encoding": 0,
            "delimiter_stripped": 0,
            "fully_blocked": 0,
            "bypassed": 0,
            "details": [],
        }
    )

    for sample in samples:
        category = sample["category"]
        payload_field = sample.get("payload_field", "payload")
        payload = sample["payload"]
        expected_blocked = sample.get("expected_blocked", True)

        # Tạo log entry giả lập kèm payload
        log_entry = {
            "Source IP": "10.0.0.1",
            "Destination Port": 80,
            "Total Fwd Packets": 100,
            payload_field: payload,
            "log_source": "queue_waf",
        }

        stats = results_by_category[category]
        stats["total"] += 1

        # === Lớp 1: Phát hiện mẫu định sẵn ===
        flagged = detector.scan(log_entry)
        pattern_detected = flagged.get("_injection_detected", False)
        if pattern_detected:
            stats["detected_by_pattern"] += 1

        # === Lớp 2: Hóa giải mã hóa ===
        neutralized = neutralizer.neutralize(log_entry)
        encoding_changed = str(neutralized.get(payload_field)) != str(
            log_entry.get(payload_field)
        )
        if encoding_changed:
            stats["neutralized_encoding"] += 1

        # === Lớp 3: Lọc ký tự phân tách ===
        encapsulator = DelimitedDataEncapsulator()
        encapsulated = encapsulator.encapsulate_fields(log_entry)
        delimiter_stripped = "[DELIMITER_STRIPPED]" in encapsulated
        if delimiter_stripped:
            stats["delimiter_stripped"] += 1

        # === Đánh giá tổng thể ===
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
            "correct_prediction": is_blocked == expected_blocked,
        }
        stats["details"].append(detail)

    return dict(results_by_category)


# =============================================================================
# BỘ XUẤT BÁO CÁO
# =============================================================================
def print_report(results: dict):
    """In báo cáo chi tiết theo từng nhóm tấn công."""
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

        # Chi tiết các mẫu lọt bộ lọc (bypassed)
        bypassed_details = [d for d in stats["details"] if not d["overall_blocked"]]
        if bypassed_details:
            print(f"\n   Bypassed samples:")
            for d in bypassed_details:
                print(f"    - {d['id']} ({d['attack_type']})")

    # Tóm tắt
    overall_defeat = (blocked_all / total_all * 100) if total_all > 0 else 0
    overall_accuracy = (correct_all / total_all * 100) if total_all > 0 else 0

    print(f"\n{'=' * 70}")
    print(f"  OVERALL SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total Adversarial Samples:  {total_all}")
    print(
        f"  Overall Defeat Rate:        {blocked_all}/{total_all} ({overall_defeat:.1f}%)"
    )
    print(
        f"  Overall Prediction Acc:     {correct_all}/{total_all} ({overall_accuracy:.1f}%)"
    )
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
                "defeat_rate": (
                    (s["fully_blocked"] / s["total"] * 100) if s["total"] > 0 else 0
                ),
            }
            for cat, s in results.items()
        },
    }


# =============================================================================
# HÀM CHẠY CHÍNH
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

    # Lưu kết quả ra file JSON
    output_path = os.path.join(os.path.dirname(__file__), "robustness_results.json")
    with open(output_path, "w") as f:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(),
                "summary": summary,
                "detailed_results": {
                    cat: {
                        "stats": {k: v for k, v in stats.items() if k != "details"},
                        "details": stats["details"],
                    }
                    for cat, stats in results.items()
                },
            },
            f,
            indent=2,
        )
    print(f"[+] Results saved to: {output_path}")
