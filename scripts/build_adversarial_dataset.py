#!/usr/bin/env python3
import json
import os

import requests

OUTPUT_DIR = "data/adversarial_llm"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "mixed_llm_attacks.json")

import random


def fetch_deepset_prompt_injections(num_samples=200):
    print("Fetching deepset/prompt-injections...")
    samples = []
    offset = 0
    while len(samples) < num_samples:
        url = f"https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=train&offset={offset}&length=100"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for row in data["rows"]:
                if row["row"]["label"] == 1:
                    samples.append(row["row"]["text"].strip())
                    if len(samples) >= num_samples:
                        break
            offset += 100
        else:
            print(f"Error fetching deepset: {response.status_code} - {response.text}")
            break
    return samples


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Fetch malicious text payloads
    pi_samples = fetch_deepset_prompt_injections(100)
    print(f"Fetched {len(pi_samples)} prompt injections.")

    # Load raw realistic data (demo_small.json)
    raw_data_path = "data/demo_small.json"
    if not os.path.exists(raw_data_path):
        print(f"Error: {raw_data_path} not found. Run scripts/build_demo_small.py first.")
        return

    with open(raw_data_path, encoding="utf-8") as f:
        real_logs = json.load(f)

    print(f"Loaded {len(real_logs)} real network events.")

    # Inject into real logs
    mixed_dataset = []
    random.shuffle(real_logs)

    for i, payload in enumerate(pi_samples):
        # Take a real log
        real_log = dict(real_logs[i % len(real_logs)])

        # Inject payload into a text field (simulate injection)
        injection_field = random.choice(["payload", "URI", "User-Agent", "message"])
        real_log[injection_field] = payload

        mixed_dataset.append(
            {
                "source": "deepset/prompt-injections",
                "attack_type": "prompt_injection",
                "injected_field": injection_field,
                "raw_log": real_log,
            }
        )

    print(f"Successfully injected {len(mixed_dataset)} adversarial payloads into RAW real data.")

    # Save
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(mixed_dataset, f, indent=4, ensure_ascii=False)

    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
