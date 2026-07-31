import csv
import json
import os
import random

RAW_DIR = "data/adversarial_llm/raw"
EXP_DIR = "experiments/adversarial"
DEMO_OUT = "data/demo_adversarial.json"


# Define standard templates for simulated network traffic (for UI demo)
# This mimics the format of data/demo_small.json
def generate_attack_log(payload, attack_category):
    fields = ["payload", "URI", "User-Agent"]
    selected_field = random.choice(fields)

    log = {
        "Source IP": f"10.0.0.{random.randint(100, 254)}",
        "Destination IP": "10.0.0.5",
        "Destination Port": 80 if selected_field != "payload" else 22,
        "Protocol": 6,
        "Total Fwd Packets": random.randint(3, 20),
        "Flow Duration": random.randint(100, 5000),
        "service": "HTTP" if selected_field != "payload" else "SSH",
        "message": f"Suspicious traffic flagged by Tier-1. Adversarial Type: {attack_category}",
        "Label": "Anomaly",
        selected_field: payload,
    }
    return log


def ingest_deepset():
    path = os.path.join(RAW_DIR, "deepset_prompt_injections.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    samples = []
    for i, text in enumerate(data):
        samples.append(
            {
                "id": f"PI-{i + 1:03d}",
                "category": "prompt_injection_hf",
                "attack_type": "direct_injection",
                "payload_field": "payload",
                "payload": text,
                "expected_blocked": True,
            }
        )
    return samples


def ingest_jackhhao():
    path = os.path.join(RAW_DIR, "jackhhao_jailbreaks.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    samples = []
    # Take a subset if too large, but 527 is fine. Let's take 200 to keep UI demo fast
    random.shuffle(data)
    for i, text in enumerate(data[:200]):
        samples.append(
            {
                "id": f"JB-{i + 1:03d}",
                "category": "jailbreak_hf",
                "attack_type": "roleplay_bypass",
                "payload_field": "payload",
                "payload": text,
                "expected_blocked": True,
            }
        )
    return samples


def ingest_advbench():
    path = os.path.join(RAW_DIR, "advbench_harmful_behaviors.csv")
    if not os.path.exists(path):
        return []

    samples = []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= 200:
                break  # Limit to 200 for benchmark balance
            goal = row.get("goal", "")
            samples.append(
                {
                    "id": f"GCG-{i + 1:03d}",
                    "category": "advbench_gcg",
                    "attack_type": "harmful_behavior",
                    "payload_field": "payload",
                    "payload": goal,
                    "expected_blocked": True,
                }
            )
    return samples


def main():
    # 1. Load and standardise datasets
    print("Ingesting Prompt Injections (Deepset)...")
    pi_samples = ingest_deepset()
    print("Ingesting Jailbreaks (Jackhhao)...")
    jb_samples = ingest_jackhhao()
    print("Ingesting AdvBench (GCG)...")
    adv_samples = ingest_advbench()

    all_samples = {
        "prompt_injection_hf": pi_samples,
        "jailbreak_hf": jb_samples,
        "advbench_gcg": adv_samples,
    }

    # 2. Write to experiments/adversarial/
    demo_logs = []
    total = 0
    for category, samples in all_samples.items():
        if not samples:
            continue
        cat_dir = os.path.join(EXP_DIR, category)
        os.makedirs(cat_dir, exist_ok=True)
        with open(os.path.join(cat_dir, "samples.json"), "w", encoding="utf-8") as f:
            json.dump(samples, f, indent=2, ensure_ascii=False)
        print(f"Saved {len(samples)} to {cat_dir}/samples.json")
        total += len(samples)

        # Add to demo UI dataset
        for s in samples:
            demo_logs.append(generate_attack_log(s["payload"], category))

    # 3. Write Demo Dataset for UI
    random.shuffle(demo_logs)
    with open(DEMO_OUT, "w", encoding="utf-8") as f:
        json.dump(demo_logs, f, indent=2, ensure_ascii=False)
    print(f"\nGenerated unified UI demo dataset: {DEMO_OUT} ({len(demo_logs)} events)")


if __name__ == "__main__":
    main()
