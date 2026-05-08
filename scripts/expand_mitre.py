import json
import urllib.request
import os

CTI_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "knowledge_base", "mitre_attack.json")

print("Downloading MITRE CTI Enterprise dataset...")
try:
    with urllib.request.urlopen(CTI_URL) as response:
        stix_data = json.loads(response.read().decode())
    
    print("Parsing ATT&CK Patterns...")
    new_kb = []
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            # Extract External ID
            ext_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    break
            
            if not ext_id: continue
            
            # Tactics
            tactics = []
            for kp in obj.get("kill_chain_phases", []):
                if kp.get("kill_chain_name") == "mitre-attack":
                    tactics.append(kp.get("phase_name", "").replace("-", " ").title())
            
            tactic_str = tactics[0] if tactics else "Unknown"
            
            # Create SENTINEL Schema
            entry = {
                "id": ext_id,
                "name": obj.get("name", "Unknown"),
                "tactic": tactic_str,
                "description": obj.get("description", "")[:500] + "...",  # Truncate for size
                "detection_indicators": [obj.get("name", ""), ext_id],
                "log_patterns": ["malicious activity detected matching " + ext_id],
                "response_actions": ["isolate host", "investigate process tree", "check network connections"]
            }
            new_kb.append(entry)
            
            if len(new_kb) >= 250:  # Limit to 250 to keep it concise but much larger than before
                break
                
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(new_kb, f, indent=2, ensure_ascii=False)
        
    print(f"Successfully expanded MITRE KB to {len(new_kb)} TTPs in {OUT_FILE}")
    
except Exception as e:
    print(f"Error: {e}")
