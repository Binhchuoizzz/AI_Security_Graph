"""
Bổ sung tri thức RAG: thêm các kỹ thuật MITRE ATT&CK còn thiếu (liên quan trực tiếp
tới các loại tấn công mạng hệ thống xử lý) và các playbook NIST SP 800-61r2 còn thiếu.

Idempotent: chạy lại nhiều lần không tạo trùng lặp.
Sau khi chạy script này, BẮT BUỘC rebuild index:
    .venv/bin/python src/rag/embedder.py
"""

# =========================================================================
# MITRE ATT&CK — các kỹ thuật còn thiếu (khớp schema hiện có)
# schema: id, name, tactic, description, detection_indicators, log_patterns, response_actions
# =========================================================================
NEW_MITRE = [
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system. Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Port scanning sweeps a range of TCP/UDP ports across one or many hosts to map the attack surface before lateral movement or exploitation.",
        "detection_indicators": ["Port scanning across many distinct destination ports", "High count of unique destination ports from a single source IP", "SYN scan / connect scan patterns", "T1046"],
        "log_patterns": ["single Source IP contacting > 10 non-HTTP ports in short window", "sequential or randomized destination port access", "low packet count per flow across many ports", "Tier-1 session baseline: Port scan detected"],
        "response_actions": ["rate-limit or block scanning Source IP at firewall", "correlate with subsequent exploitation attempts", "enable port-scan detection signatures on IDS", "monitor the scanned hosts for follow-on access"],
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services. Successful brute-force or credential-stuffing attacks often culminate in valid account abuse, which blends with legitimate activity and evades detection.",
        "detection_indicators": ["successful login after multiple failures", "login from anomalous geolocation or ASN", "concurrent sessions for the same account", "service account interactive logon", "T1078"],
        "log_patterns": ["failed brute-force burst followed by a single SUCCESS for same account", "authentication from new/unrecognized Source IP", "off-hours privileged login"],
        "response_actions": ["force password reset and revoke active sessions", "enforce MFA on the account", "review account privileges for least-privilege", "hunt for lateral movement from the account"],
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications. This blends exfiltration with routine C2 beaconing, making it hard to separate from benign management traffic. Large outbound transfers correlated with prior C2 activity are a strong indicator.",
        "detection_indicators": ["large outbound data volume to a known C2 endpoint", "asymmetric flow (small inbound, large outbound)", "data transfer correlated with beaconing host", "T1041"],
        "log_patterns": ["Total Length of Fwd Packets anomalously high to external IP", "sustained outbound flow to non-business destination", "exfil over already-flagged C2 session"],
        "response_actions": ["block the C2 destination and isolate the source host", "capture full PCAP for forensic scoping", "identify what data left the network (DLP review)", "rotate any credentials/secrets potentially exposed"],
    },
    {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system (e.g., ping, net view, arp) could also be used. This often precedes Lateral Movement in multi-stage APT campaigns.",
        "detection_indicators": ["host sweeping via ICMP/ARP across subnet", "enumeration of SMB/AD hosts", "many short-lived connections to internal hosts", "T1018"],
        "log_patterns": ["single internal IP contacting many other internal IPs", "ping sweep pattern within RFC1918 range", "discovery activity preceding lateral movement"],
        "response_actions": ["isolate the discovering host pending review", "tighten east-west segmentation", "alert on internal reconnaissance from non-admin hosts"],
    },
    {
        "id": "T1110.002",
        "name": "Brute Force: Password Cracking",
        "tactic": "Credential Access",
        "description": "Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. Cracking is done offline against captured hashes (e.g., NTLM, Kerberos AS-REP, /etc/shadow) and does not generate network login noise, so detection focuses on the precursor hash-theft and subsequent valid-account use.",
        "detection_indicators": ["preceding credential dumping activity", "sudden valid-account access after data theft", "T1110.002"],
        "log_patterns": ["access to SAM/LSASS or shadow files", "AS-REP roasting requests", "successful logon with cracked credentials"],
        "response_actions": ["rotate all potentially-exposed credentials", "increase password hash iteration/length policy", "monitor for offline-cracked account usage"],
    },
    {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g., 'Password1') or a small list of passwords that matches the complexity policy of the domain and may possibly combine that with knowledge of valid usernames. This low-and-slow approach evades per-account lockout thresholds.",
        "detection_indicators": ["one password tried against many distinct usernames", "low failure rate per account but high across the org", "distributed login attempts over time", "T1110.003"],
        "log_patterns": ["many accounts each with 1-2 failed logins from same Source IP", "authentication failures spread across user base", "spray pattern below per-account lockout threshold"],
        "response_actions": ["block source IP and enforce org-wide MFA", "implement smart lockout / risk-based auth", "alert on horizontal authentication anomalies"],
    },
    {
        "id": "T1110.004",
        "name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, two or more individuals share the same username and password, allowing the adversary to access the target's account. Credential stuffing is automated at high volume against web login endpoints.",
        "detection_indicators": ["high-volume automated login attempts to web auth endpoint", "rotating Source IPs with consistent user-agent", "known-breached credential pairs", "T1110.004"],
        "log_patterns": ["burst of POST /login from botnet IPs", "high request rate to authentication URI", "credential-stuffing tooling user-agent"],
        "response_actions": ["deploy CAPTCHA / bot mitigation at login", "block offending IP ranges and enforce MFA", "monitor for successful stuffed logins"],
    },
    {
        "id": "T1498.001",
        "name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "description": "Adversaries may attempt to cause a denial of service by directly sending a high-volume of network traffic to a target. Direct Network Floods are when one or more systems are used to send a high-volume of network packets towards the targeted service's network, exhausting bandwidth capabilities. SYN floods and UDP floods are common variants.",
        "detection_indicators": ["abnormal spike in inbound packets/sec", "SYN/UDP flood signatures", "bandwidth saturation toward one service", "T1498.001"],
        "log_patterns": ["Flow Pkts/s far above baseline toward single destination", "high Total Fwd Packets volumetric pattern", "many half-open connections"],
        "response_actions": ["engage upstream DDoS scrubbing / BGP blackhole", "rate-limit at edge, do NOT block (often spoofed)", "scale or failover the targeted service"],
    },
    {
        "id": "T1499.001",
        "name": "Endpoint Denial of Service: OS Exhaustion Flood",
        "tactic": "Impact",
        "description": "Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system. A system's OS is responsible for managing finite resources such as connection state tables; attackers exhaust these (e.g., via Slowloris-style slow connections or connection floods) to render the service unavailable without high bandwidth.",
        "detection_indicators": ["many slow/incomplete connections held open", "connection table exhaustion on host", "Slowloris HTTP partial requests", "T1499.001"],
        "log_patterns": ["high count of long-duration low-throughput flows", "Flow Duration anomalously high with tiny packet payloads", "concurrent half-open sessions to web server"],
        "response_actions": ["lower connection timeouts and cap per-IP connections", "deploy reverse proxy that buffers slow requests", "block offending Source IPs"],
    },
    {
        "id": "T1095",
        "name": "Non-Application Layer Protocol",
        "tactic": "Command And Control",
        "description": "Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. Examples include ICMP, transport layer protocols like UDP, or network layer protocols like raw sockets, which avoid application-layer inspection.",
        "detection_indicators": ["unusual ICMP/raw-socket traffic volume", "C2 over non-standard transport", "data encoded in ICMP echo payloads", "T1095"],
        "log_patterns": ["abnormal ICMP request size/frequency", "non-TCP/UDP protocol numbers in flow records", "periodic beacon over transport protocol"],
        "response_actions": ["block non-essential ICMP/raw protocols at egress", "inspect payloads of allowed non-app protocols", "isolate beaconing host"],
    },
    {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command And Control",
        "description": "Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or HTTP over port 8443 instead of the standard port 443 or 80. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.",
        "detection_indicators": ["known protocol running on unexpected port", "HTTP/TLS on non-standard ports", "C2 over uncommon high ports", "T1571"],
        "log_patterns": ["TLS handshake on non-443 port", "Destination Port unusual for the observed protocol", "outbound to high non-standard port sustained"],
        "response_actions": ["enforce egress allowlist by port", "deep-packet-inspect protocol/port mismatches", "block anomalous port usage to external IPs"],
    },
    {
        "id": "T1572",
        "name": "Protocol Tunneling",
        "tactic": "Command And Control",
        "description": "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another (e.g., DNS tunneling, SSH tunneling, HTTP CONNECT).",
        "detection_indicators": ["DNS queries with high-entropy/large TXT payloads", "SSH connections used as SOCKS proxy", "encapsulated protocol inside another", "T1572"],
        "log_patterns": ["abnormally high DNS query volume to one domain", "long-lived SSH session with port forwarding", "HTTP CONNECT to arbitrary hosts"],
        "response_actions": ["restrict and monitor DNS to approved resolvers", "block unauthorized tunneling/proxy use", "alert on DNS exfiltration heuristics"],
    },
    {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command And Control",
        "description": "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. This includes internal proxies, external proxies, multi-hop proxies, and domain fronting.",
        "detection_indicators": ["traffic relayed through intermediary hosts", "use of TOR / open proxies", "multi-hop or chained connections", "T1090"],
        "log_patterns": ["connections to known proxy/TOR exit nodes", "internal host acting as relay between others", "domain-fronted TLS SNI mismatch"],
        "response_actions": ["block known proxy/TOR infrastructure", "investigate internal relay hosts", "enforce direct, logged egress paths"],
    },
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main C2 server. Protocols such as FTP, SMTP, HTTP/S, DNS, SMB, or other network protocols not being used as the main C2 channel are leveraged.",
        "detection_indicators": ["large outbound transfer over FTP/SMTP/DNS not used for C2", "data sent to a different endpoint than C2", "unusual protocol carrying bulk data out", "T1048"],
        "log_patterns": ["bulk outbound over FTP/SMTP to external IP", "DNS exfiltration with encoded subdomains", "off-channel data transfer to new destination"],
        "response_actions": ["DLP inspection and block on alternative egress protocols", "isolate source host and scope data loss", "restrict outbound protocols by policy"],
    },
    {
        "id": "T1556",
        "name": "Modify Authentication Process",
        "tactic": "Credential Access",
        "description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authority (LSA) and pluggable authentication modules (PAM) on Linux, that adversaries tamper with to bypass or capture credentials.",
        "detection_indicators": ["unauthorized changes to PAM/LSA modules", "rogue authentication packages registered", "MFA bypass configuration changes", "T1556"],
        "log_patterns": ["modification of /etc/pam.d or security packages", "new auth provider registered", "authentication succeeding without expected factor"],
        "response_actions": ["restore authentication config from known-good baseline", "rotate credentials and re-enroll MFA", "audit authentication module integrity"],
    },
    {
        "id": "T1212",
        "name": "Exploitation for Credential Access",
        "tactic": "Credential Access",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code, for example targeting credential stores or domain controllers (e.g., Zerologon, NTLM relay).",
        "detection_indicators": ["exploitation attempts against auth services", "anomalous DC/Kerberos traffic", "known credential-access CVE exploitation", "T1212"],
        "log_patterns": ["malformed authentication protocol requests", "exploit signature against LDAP/Kerberos/SMB", "credential-access exploit matching known CVE"],
        "response_actions": ["patch the exploited authentication service immediately", "rotate domain/krbtgt credentials if DC affected", "block exploit source and hunt for follow-on access"],
    },
    {
        "id": "T1210",
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to enable remote code execution, enabling lateral movement (e.g., EternalBlue/SMB, RDP vulnerabilities).",
        "detection_indicators": ["exploitation of SMB/RDP/SSH on internal hosts", "lateral RCE attempts east-west", "known remote-service CVE traffic", "T1210"],
        "log_patterns": ["exploit signature against internal SMB/RDP", "internal host triggering RCE pattern on peer", "lateral movement following exploitation"],
        "response_actions": ["isolate exploited and source hosts", "patch vulnerable remote services network-wide", "enforce internal segmentation and disable legacy SMBv1"],
    },
    {
        "id": "T1570",
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
        "description": "Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., Ingress Tool Transfer) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation, often via SMB admin shares or remote copy.",
        "detection_indicators": ["binaries copied to admin shares (C$, ADMIN$)", "file transfer between internal hosts", "staging of tooling on multiple hosts", "T1570"],
        "log_patterns": ["SMB write of executable to remote admin share", "internal file copy preceding execution", "lateral transfer of known tool hashes"],
        "response_actions": ["block executable writes to admin shares", "quarantine transferred tooling and source host", "hunt for the tool across all endpoints"],
    },
    {
        "id": "T1133",
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, RDP gateways, and other access mechanisms allow users to connect to internal enterprise network resources from external locations and are frequently targeted with valid or brute-forced credentials.",
        "detection_indicators": ["external login to VPN/RDP gateway from new IP", "brute force against remote access portal", "valid-account access from untrusted network", "T1133"],
        "log_patterns": ["authentication to internet-facing VPN/RDP from anomalous geo", "remote service login outside business hours", "repeated failures then success on remote portal"],
        "response_actions": ["enforce MFA on all external remote services", "geo-fence and conditional-access policies", "block source and review remote-access logs"],
    },
]


# =========================================================================
# NIST SP 800-61r2 — các playbook còn thiếu (khớp schema controls hiện có)
# schema: control, name, domain, description, applicability, response_guidance
# =========================================================================
NEW_NIST = [
    {
        "control": "NIST.IR.RECON",
        "name": "Network Reconnaissance & Port Scanning Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for handling reconnaissance activity such as port scanning, host sweeping, and network/remote system discovery (MITRE T1046, T1018) that typically precedes exploitation.",
        "applicability": "Relevant when the agent detects a single Source IP touching many distinct ports, ping/host sweeps across an internal subnet, or service enumeration patterns from the Tier-1 session baseline.",
        "response_guidance": "DETECTION & ANALYSIS: Confirm scan source, scope (which hosts/ports), and whether it is internal (potential lateral recon) or external. CONTAINMENT: Rate-limit or block the scanning Source IP at the firewall; for internal sources, isolate the host pending review. ERADICATION & RECOVERY: Patch any exposed vulnerable services discovered, tighten firewall egress/ingress rules and network segmentation. POST-INCIDENT: Tune IDS port-scan thresholds; treat recon as an early-warning indicator and watch the scanned assets for follow-on access.",
    },
    {
        "control": "NIST.IR.LATERAL",
        "name": "Lateral Movement & Internal Pivoting Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for handling lateral movement across the internal network (MITRE T1021 Remote Services, T1210 Exploitation of Remote Services, T1570 Lateral Tool Transfer) during multi-stage / APT intrusions.",
        "applicability": "Relevant when the agent correlates a Source IP across multiple internal hosts/sensors, observes east-west exploitation, SMB admin-share writes, or APT chain events spanning multiple days (DAPT2020 chains).",
        "response_guidance": "DETECTION & ANALYSIS: Map the movement path (source host -> targets), identify the pivot account and technique. CONTAINMENT: Isolate all hosts on the lateral path, disable the compromised account, and block internal RDP/SMB between the affected segments. ERADICATION & RECOVERY: Patch exploited remote services, remove transferred tooling, rotate credentials used for movement, and rebuild confirmed-compromised hosts. POST-INCIDENT: Enforce micro-segmentation, disable legacy protocols (SMBv1), and add detection for admin-share executable writes.",
    },
    {
        "control": "NIST.IR.BOTNET",
        "name": "Botnet & Command-and-Control (C2) Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for handling botnet infections and C2 communications (MITRE T1071 Application Layer Protocol, T1095 Non-Application Layer Protocol, T1571 Non-Standard Port, T1572 Protocol Tunneling, T1090 Proxy).",
        "applicability": "Relevant when the agent detects periodic beaconing, traffic to known C2/TOR infrastructure, protocol/port mismatches, DNS tunneling, or hosts acting as relays.",
        "response_guidance": "DETECTION & ANALYSIS: Identify the C2 destination(s), beacon interval, and all hosts beaconing. CONTAINMENT: Sinkhole/block the C2 domains and IPs at the firewall and DNS, isolate beaconing hosts. ERADICATION & RECOVERY: Remove the malware/implant, rebuild hosts if persistence is confirmed, and rotate exposed credentials. POST-INCIDENT: Add egress allowlisting, monitor for beaconing heuristics and DNS exfiltration, and share C2 IOCs to threat intel.",
    },
    {
        "control": "NIST.IR.ZERODAY",
        "name": "Zero-Day / Statistical Anomaly Response Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for handling signature-less / zero-day threats detected via statistical anomaly (Tier-1 Welford Z-Score) where no known signature matches, requiring Tier-2 LLM reasoning to triage.",
        "applicability": "Relevant when Tier-1 escalates a flow with a high Z-Score (> 3.5) on core features (Flow Duration, packet/byte volumes) but no static rule or WAF signature fires — i.e., a novel or evasive attack.",
        "response_guidance": "DETECTION & ANALYSIS: Treat the anomaly as suspicious-by-default; capture full context (which feature deviated, by how many sigma) and full PCAP for the flow. CONTAINMENT: Apply a conservative containment (ALERT + monitor, or AWAIT_HITL for high-value assets) rather than auto-block, to limit false-positive impact; escalate to a human analyst. ERADICATION & RECOVERY: If confirmed malicious, derive a new signature/dynamic rule and push it to Tier-1 via the feedback loop; patch the targeted asset. POST-INCIDENT: Feed the confirmed sample back to retrain/recalibrate the baseline and update detection content; document the novel TTP.",
    },
]


# NOTE: file này giờ là MODULE DỮ LIỆU thuần (chỉ export NEW_MITRE / NEW_NIST).
# Entry point xây dựng tri thức DUY NHẤT là `scripts/build_knowledge_base.py`.
