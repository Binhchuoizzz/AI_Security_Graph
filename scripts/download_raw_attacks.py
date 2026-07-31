import json
import os
from urllib.parse import quote

import requests


def fetch_hf_dataset(dataset_name, output_file, max_rows=1000, text_field="text", condition=None):
    print(f"Fetching {dataset_name}...")
    samples = []
    offset = 0
    while len(samples) < max_rows:
        limit = min(100, max_rows - len(samples))
        url = f"https://datasets-server.huggingface.co/rows?dataset={quote(dataset_name, safe='')}&config=default&split=train&offset={offset}&length={limit}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            rows = data.get("rows", [])
            if not rows:
                break  # No more data
            for row in rows:
                r_data = row.get("row", {})
                # apply condition
                if condition and not condition(r_data):
                    continue

                # Extract text
                if isinstance(text_field, list):
                    text = ""
                    for f in text_field:
                        if f in r_data and r_data[f]:
                            text = r_data[f]
                            break
                else:
                    text = r_data.get(text_field)

                if text:
                    samples.append(str(text).strip())

                if len(samples) >= max_rows:
                    break
            offset += 100
        else:
            print(f"  -> Stopped or Error: {response.status_code}")
            break

    print(f"  -> Fetched {len(samples)} samples.")
    if samples:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(samples, f, indent=4, ensure_ascii=False)


def main():
    raw_dir = "data/adversarial_llm/raw"
    os.makedirs(raw_dir, exist_ok=True)

    # 1. Prompt Injection (deepset/prompt-injections) -> Label 1 means malicious
    fetch_hf_dataset(
        "deepset/prompt-injections",
        f"{raw_dir}/deepset_prompt_injections.json",
        max_rows=1000,
        text_field="text",
        condition=lambda r: r.get("label") == 1,
    )

    # 2. Jailbreak (ShawnMenz/DAN_jailbreak)
    fetch_hf_dataset(
        "ShawnMenz/DAN_jailbreak",
        f"{raw_dir}/shawnmenz_dan_jailbreak.json",
        max_rows=1000,
        text_field="prompt",
    )

    # 3. Prompt Leakage / System Prompt Extraction (E.g. from jailbreak datasets or toxic-chat)
    # Using 'markush1/LLM-Jailbreak-Prompts' as another source for jailbreaks/leaks
    fetch_hf_dataset(
        "markush1/LLM-Jailbreak-Prompts",
        f"{raw_dir}/llm_jailbreak_prompts.json",
        max_rows=1000,
        text_field="prompt",
    )

    print("Done downloading raw datasets.")


if __name__ == "__main__":
    main()
