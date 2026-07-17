import html
import re


def test(raw_reason):
    clean_reason = html.escape(raw_reason)
    clean_reason = re.sub(
        r"\[MITRE:(?:[^\[\]]|\[[^\[\]]*\])*\]", "", clean_reason, flags=re.IGNORECASE
    )
    clean_reason = re.sub(
        r"\[(?:Confidence|Độ\s+tin\s+cậy):\s*[^\]]*\]", "", clean_reason, flags=re.IGNORECASE
    ).strip()
    if clean_reason.startswith("]"):
        clean_reason = clean_reason[1:].strip()

    mitre_match = re.search(r"\[MITRE:\s*((?:[^\[\]]|\[[^\[\]]*\])*)\]", raw_reason, re.IGNORECASE)
    mitre_tech = mitre_match.group(1).strip() if mitre_match else "N/A"

    conf_match = re.search(
        r"(?:Confidence|Độ\s+tin\s+cậy):\s*([01]?\.\d+|1(?:\.0)?|\d+(?:\.\d+)?%)",
        raw_reason,
        re.IGNORECASE,
    )
    conf = conf_match.group(1) if conf_match else "Chưa rõ"

    print(f"Original: {raw_reason}")
    print(f"Mitre: {mitre_tech}")
    print(f"Conf: {conf}")
    print(f"Clean: {clean_reason}")
    print("-" * 20)


test(
    "[MITRE: T1568.001 - Fast Flux DNS] [Độ tin cậy: 0.99] IP này đã thực hiện hành vi đáng ngờ..."
)
test("Cảnh báo rủi cao bởi Cổng ML Tier-1.5 (LightGBM). Độ tin cậy: 76.52%")
test("[MITRE: [Tự suy luận] Command and Control] [Độ tin cậy: 0.85] Phát hiện bất thường")
