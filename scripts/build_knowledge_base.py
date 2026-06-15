"""
Xây dựng / mở rộng TOÀN BỘ tri thức RAG trong MỘT lần chạy (single source of truth).

File TỰ-CHỨA: dữ liệu (67 kỹ thuật MITRE ATT&CK phủ đủ 14 tactic + 7 playbook NIST
SP 800-61r2) inline trực tiếp, append idempotent vào knowledge_base, RỒI rebuild
FAISS/BM25 index + checksum — "một lần xây dựng tri thức" duy nhất.
(Đã gộp từ expand_knowledge_base + supplement_knowledge_base, nay đã xóa.)

Chạy:
    .venv/bin/python scripts/build_knowledge_base.py            # mở rộng KB + rebuild index
    .venv/bin/python scripts/build_knowledge_base.py --no-index # chỉ mở rộng KB, KHÔNG rebuild
"""
import argparse
import json
import os

KB_DIR = os.path.join(os.path.dirname(__file__), "..", "knowledge_base")
MITRE_PATH = os.path.join(KB_DIR, "mitre_attack.json")
NIST_PATH = os.path.join(KB_DIR, "nist_800_61r2.json")

ALL_MITRE = [
    {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting, scanning victim infrastructure via IP blocks, vulnerability scanning, or wordlist scanning of web content.",
        "detection_indicators": [
            "vulnerability scanner signatures",
            "web content/path wordlist scanning",
            "IP block sweeps",
            "T1595"
        ],
        "log_patterns": [
            "scanner user-agents (nmap, nikto, nuclei)",
            "bursts of 404s from path fuzzing",
            "broad IP-range probing"
        ],
        "response_actions": [
            "block scanning source at edge",
            "fingerprint scanner tooling",
            "watch targeted assets for exploitation"
        ]
    },
    {
        "id": "T1595.002",
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may scan victims for vulnerabilities that can be used during targeting, checking for specific software versions and configurations against known CVE databases.",
        "detection_indicators": [
            "version-probing requests",
            "CVE-targeted scan patterns",
            "T1595.002"
        ],
        "log_patterns": [
            "requests probing known-vulnerable paths/versions",
            "scanner fingerprint in user-agent"
        ],
        "response_actions": [
            "patch exposed vulnerable services",
            "block scanner IPs",
            "harden version disclosure"
        ]
    },
    {
        "id": "T1592",
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may gather information about the victim's hosts (hardware, software, firmware, configuration) used during targeting.",
        "detection_indicators": [
            "banner grabbing",
            "OS/service fingerprinting",
            "T1592"
        ],
        "log_patterns": [
            "service banner enumeration",
            "fingerprint probes to many services"
        ],
        "response_actions": [
            "minimize banner/version disclosure",
            "alert on enumeration patterns"
        ]
    },
    {
        "id": "T1590",
        "name": "Gather Victim Network Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may gather information about the victim's networks (IP ranges, domains, topology, DNS) used during targeting.",
        "detection_indicators": [
            "DNS enumeration",
            "WHOIS/range lookups",
            "subdomain brute forcing",
            "T1590"
        ],
        "log_patterns": [
            "high-volume DNS queries enumerating zone",
            "AXFR zone-transfer attempts"
        ],
        "response_actions": [
            "restrict zone transfers",
            "rate-limit DNS",
            "monitor subdomain enumeration"
        ]
    },
    {
        "id": "T1584",
        "name": "Compromise Infrastructure",
        "tactic": "Resource Development",
        "description": "Adversaries may compromise third-party infrastructure (servers, domains, botnets) that can be used during targeting, blending C2 with legitimate-looking sources.",
        "detection_indicators": [
            "traffic to compromised legitimate hosts",
            "newly-malicious known-good domains",
            "T1584"
        ],
        "log_patterns": [
            "beaconing to previously-benign domains",
            "C2 on compromised CDN/host"
        ],
        "response_actions": [
            "block confirmed-compromised infra",
            "share IOCs to threat intel"
        ]
    },
    {
        "id": "T1588",
        "name": "Obtain Capabilities",
        "tactic": "Resource Development",
        "description": "Adversaries may buy and/or steal capabilities (malware, exploits, certificates, tools) that can be used during targeting.",
        "detection_indicators": [
            "use of commodity malware/exploit kits",
            "stolen code-signing certs",
            "T1588"
        ],
        "log_patterns": [
            "known malware family signatures",
            "exploit-kit landing patterns"
        ],
        "response_actions": [
            "block known tooling hashes/certs",
            "update detection content"
        ]
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems, via malicious attachments or links (spearphishing).",
        "detection_indicators": [
            "malicious email links/attachments",
            "credential-harvesting landing pages",
            "T1566"
        ],
        "log_patterns": [
            "clicks to known-malicious URLs from corp net",
            "macro-enabled attachment execution"
        ],
        "response_actions": [
            "purge malicious email org-wide",
            "block sender/URL",
            "reset credentials of clickers"
        ]
    },
    {
        "id": "T1199",
        "name": "Trusted Relationship",
        "tactic": "Initial Access",
        "description": "Adversaries may breach or otherwise leverage organizations who have access to intended victims, abusing trusted third-party/VPN/MSP connections.",
        "detection_indicators": [
            "access via trusted partner/VPN connection",
            "anomalous third-party account activity",
            "T1199"
        ],
        "log_patterns": [
            "partner-network access outside normal pattern",
            "MSP account anomalies"
        ],
        "response_actions": [
            "scope and revoke trusted access",
            "enforce least-privilege for partners"
        ]
    },
    {
        "id": "T1189",
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries may gain access through a user visiting a compromised website, exploiting the browser for code execution.",
        "detection_indicators": [
            "browser exploitation traffic",
            "redirect to exploit kit",
            "T1189"
        ],
        "log_patterns": [
            "malicious iframe/redirect chains",
            "exploit-kit traffic to client"
        ],
        "response_actions": [
            "block malicious domains",
            "patch browsers",
            "isolate affected client"
        ]
    },
    {
        "id": "T1203",
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications (browsers, office apps, readers) to execute code.",
        "detection_indicators": [
            "malformed documents/exploits",
            "client app crash + spawn",
            "T1203"
        ],
        "log_patterns": [
            "office app spawning shell/script host",
            "exploit payload in document"
        ],
        "response_actions": [
            "patch client software",
            "isolate host",
            "block delivery vector"
        ]
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Execution",
        "description": "Adversaries may abuse task scheduling (cron, at, Windows Task Scheduler) to execute malicious code, often for persistence as well.",
        "detection_indicators": [
            "new/unusual scheduled tasks",
            "cron entries spawning network connections",
            "T1053"
        ],
        "log_patterns": [
            "creation of scheduled task running script/binary",
            "cron job with C2 callout"
        ],
        "response_actions": [
            "remove malicious tasks",
            "audit scheduled-task creation",
            "baseline legitimate jobs"
        ]
    },
    {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell for execution, including download-and-execute, encoded commands, and in-memory operation to evade detection.",
        "detection_indicators": [
            "encoded/obfuscated PowerShell",
            "PowerShell downloading from internet",
            "T1059.001"
        ],
        "log_patterns": [
            "powershell -enc / -nop / IEX (New-Object Net.WebClient)",
            "EncodedCommand usage"
        ],
        "response_actions": [
            "enable PowerShell script-block logging",
            "constrained language mode",
            "isolate host"
        ]
    },
    {
        "id": "T1505.003",
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may backdoor web servers with web shells to establish persistent access, executing commands via crafted HTTP requests.",
        "detection_indicators": [
            "web shell files in web root",
            "command execution via HTTP params",
            "T1505.003"
        ],
        "log_patterns": [
            "POST to suspicious .php/.jsp/.aspx with cmd params",
            "web server spawning shell"
        ],
        "response_actions": [
            "quarantine the web shell file",
            "block source IP at WAF",
            "audit web root integrity"
        ]
    },
    {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts (add credentials, modify permissions, add to groups) to maintain access.",
        "detection_indicators": [
            "unexpected privilege/group changes",
            "new credentials added to account",
            "T1098"
        ],
        "log_patterns": [
            "account added to admin group",
            "new SSH key / app password added"
        ],
        "response_actions": [
            "revert unauthorized changes",
            "rotate credentials",
            "audit privileged group membership"
        ]
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Adversaries may create accounts to maintain access to victim systems (local, domain, or cloud).",
        "detection_indicators": [
            "unexpected new account creation",
            "rogue admin accounts",
            "T1136"
        ],
        "log_patterns": [
            "new user/admin account outside change process",
            "service account creation anomaly"
        ],
        "response_actions": [
            "disable rogue accounts",
            "alert on account creation",
            "review IAM change logs"
        ]
    },
    {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to automatically execute a program during boot or logon (registry run keys, startup folder, services).",
        "detection_indicators": [
            "new autostart registry/services entries",
            "startup-folder implants",
            "T1547"
        ],
        "log_patterns": [
            "modification of Run keys / startup items",
            "new auto-start service"
        ],
        "response_actions": [
            "remove malicious autostart entries",
            "baseline autostart locations"
        ]
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges, taking advantage of kernel or service bugs to gain SYSTEM/root.",
        "detection_indicators": [
            "local privilege-escalation exploit",
            "kernel exploit indicators",
            "T1068"
        ],
        "log_patterns": [
            "process unexpectedly running as SYSTEM/root",
            "known privesc CVE exploitation"
        ],
        "response_actions": [
            "patch vulnerable component",
            "isolate host",
            "hunt for follow-on actions"
        ]
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges (sudo, UAC, setuid) to gain higher-level permissions.",
        "detection_indicators": [
            "sudo/UAC bypass patterns",
            "setuid abuse",
            "T1548"
        ],
        "log_patterns": [
            "unexpected sudo usage",
            "UAC-bypass technique execution"
        ],
        "response_actions": [
            "audit sudoers/UAC config",
            "restrict elevation paths"
        ]
    },
    {
        "id": "T1134",
        "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may modify access tokens to operate under a different user or system security context to escalate privileges or bypass access controls.",
        "detection_indicators": [
            "token theft/impersonation",
            "process running with stolen token",
            "T1134"
        ],
        "log_patterns": [
            "token duplication/impersonation API usage",
            "privilege context change"
        ],
        "response_actions": [
            "isolate host",
            "rotate impacted credentials",
            "audit token-manipulation events"
        ]
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Stealth",
        "description": "Adversaries may delete or modify artifacts (logs, files, command history) to remove evidence of their presence and hinder detection.",
        "detection_indicators": [
            "log clearing",
            "shell history deletion",
            "timestomping",
            "T1070"
        ],
        "log_patterns": [
            "Windows event log cleared (1102)",
            "auth.log/secure truncated",
            "history file emptied"
        ],
        "response_actions": [
            "forward logs off-host (immutable)",
            "alert on log-clearing",
            "restore from backups"
        ]
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Stealth",
        "description": "Adversaries may obfuscate/encode files or commands (base64, packing, encryption) to evade detection and analysis.",
        "detection_indicators": [
            "base64/packed payloads",
            "high-entropy content",
            "T1027"
        ],
        "log_patterns": [
            "encoded command-lines",
            "packed binaries with high entropy"
        ],
        "response_actions": [
            "deobfuscate and analyze",
            "entropy-based detection",
            "isolate host"
        ]
    },
    {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Impairment",
        "description": "Adversaries may modify/disable security tools (AV, EDR, firewall, logging) to avoid detection and enable their operations.",
        "detection_indicators": [
            "security service stopped/disabled",
            "firewall/AV tampering",
            "T1562"
        ],
        "log_patterns": [
            "EDR/AV service stop",
            "firewall rule deletion",
            "logging disabled"
        ],
        "response_actions": [
            "re-enable and alert on defense tampering",
            "tamper-protect security tools",
            "isolate host"
        ]
    },
    {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Stealth",
        "description": "Adversaries may manipulate features of their artifacts to appear legitimate (renaming malware to system process names, fake extensions).",
        "detection_indicators": [
            "process name/path mismatch",
            "system-process impersonation",
            "T1036"
        ],
        "log_patterns": [
            "svchost/lsass running from wrong path",
            "double-extension files"
        ],
        "response_actions": [
            "compare process path/hash to baseline",
            "alert on masquerading",
            "quarantine artifact"
        ]
    },
    {
        "id": "T1497",
        "name": "Virtualization/Sandbox Evasion",
        "tactic": "Stealth",
        "description": "Adversaries may employ checks to detect and avoid virtualization and analysis environments, delaying or altering behavior in sandboxes.",
        "detection_indicators": [
            "sandbox/VM detection checks",
            "execution stalling/delays",
            "T1497"
        ],
        "log_patterns": [
            "VM-artifact checks",
            "long sleeps before payload"
        ],
        "response_actions": [
            "use hardened analysis env",
            "extend detonation time",
            "behavioral detection"
        ]
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may dump credentials from the OS and software (LSASS memory, SAM, /etc/shadow, NTDS.dit) to obtain account logins for movement.",
        "detection_indicators": [
            "LSASS memory access",
            "SAM/NTDS access",
            "credential dumping tools",
            "T1003"
        ],
        "log_patterns": [
            "procdump/mimikatz on lsass",
            "shadow/SAM file read",
            "NTDS.dit extraction"
        ],
        "response_actions": [
            "rotate exposed credentials",
            "enable Credential Guard",
            "isolate and investigate"
        ]
    },
    {
        "id": "T1555",
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "description": "Adversaries may search for and obtain credentials from password stores (browsers, keychains, password managers).",
        "detection_indicators": [
            "access to browser/keychain credential stores",
            "password-manager DB access",
            "T1555"
        ],
        "log_patterns": [
            "read of browser login data DB",
            "keychain/credential vault access"
        ],
        "response_actions": [
            "rotate stored credentials",
            "alert on credential-store access",
            "isolate host"
        ]
    },
    {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems for insecurely stored credentials (config files, scripts, history, cloud metadata).",
        "detection_indicators": [
            "credentials in plaintext files/scripts",
            "cloud metadata credential access",
            "T1552"
        ],
        "log_patterns": [
            "grep for password/secret in files",
            "access to 169.254.169.254 metadata"
        ],
        "response_actions": [
            "remove hardcoded secrets, use vaults",
            "restrict metadata access",
            "rotate exposed keys"
        ]
    },
    {
        "id": "T1557",
        "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access",
        "description": "Adversaries may position between networked devices (ARP spoofing, LLMNR/NBT-NS poisoning, rogue DHCP) to intercept credentials/traffic.",
        "detection_indicators": [
            "ARP spoofing",
            "LLMNR/NBT-NS poisoning",
            "rogue gateway",
            "T1557"
        ],
        "log_patterns": [
            "gratuitous ARP anomalies",
            "LLMNR/NBT-NS response from non-DNS host",
            "MAC-IP binding changes"
        ],
        "response_actions": [
            "enable dynamic ARP inspection",
            "disable LLMNR/NBT-NS",
            "isolate rogue host"
        ]
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate files and directories to find information of interest before collection/exfiltration.",
        "detection_indicators": [
            "recursive directory listing",
            "search for sensitive file types",
            "T1083"
        ],
        "log_patterns": [
            "mass dir/file enumeration",
            "search for *.kdbx/*.pem/*.config"
        ],
        "response_actions": [
            "alert on mass enumeration",
            "monitor sensitive-file access"
        ]
    },
    {
        "id": "T1087",
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate accounts (local, domain, cloud, email) to understand the environment and plan further actions.",
        "detection_indicators": [
            "enumeration of users/groups",
            "LDAP/AD account queries",
            "T1087"
        ],
        "log_patterns": [
            "net user/net group enumeration",
            "bulk LDAP account queries"
        ],
        "response_actions": [
            "alert on bulk account enumeration",
            "limit directory read access"
        ]
    },
    {
        "id": "T1135",
        "name": "Network Share Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for shared folders and drives on remote systems to identify data and lateral-movement targets.",
        "detection_indicators": [
            "SMB share enumeration",
            "net view / share scans",
            "T1135"
        ],
        "log_patterns": [
            "enumeration of network shares",
            "SMB tree-connect sweep"
        ],
        "response_actions": [
            "audit share permissions",
            "alert on share enumeration"
        ]
    },
    {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate active network connections to/from a system to understand the environment and identify pivots.",
        "detection_indicators": [
            "netstat / connection enumeration",
            "active session listing",
            "T1049"
        ],
        "log_patterns": [
            "netstat/ss execution",
            "enumeration of established sessions"
        ],
        "response_actions": [
            "baseline normal discovery",
            "alert on recon from non-admin hosts"
        ]
    },
    {
        "id": "T1550",
        "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use stolen authentication material (hashes, tickets, tokens) to move laterally without the plaintext password (pass-the-hash/ticket).",
        "detection_indicators": [
            "pass-the-hash/ticket patterns",
            "NTLM relay",
            "Kerberos ticket reuse",
            "T1550"
        ],
        "log_patterns": [
            "overpass-the-hash logon",
            "PtH NTLM auth from unusual host",
            "golden/silver ticket usage"
        ],
        "response_actions": [
            "rotate krbtgt and impacted creds",
            "enable Credential Guard",
            "monitor anomalous Kerberos"
        ]
    },
    {
        "id": "T1563",
        "name": "Remote Service Session Hijacking",
        "tactic": "Lateral Movement",
        "description": "Adversaries may take control of preexisting remote sessions (RDP, SSH) to move laterally using already-authenticated access.",
        "detection_indicators": [
            "hijacked RDP/SSH session",
            "session takeover patterns",
            "T1563"
        ],
        "log_patterns": [
            "RDP session reconnect anomaly",
            "SSH session multiplexing abuse"
        ],
        "response_actions": [
            "terminate suspicious sessions",
            "alert on session hijack",
            "isolate hosts"
        ]
    },
    {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search local system sources (file systems, databases) to collect data of interest prior to exfiltration.",
        "detection_indicators": [
            "bulk local data access",
            "staging of collected files",
            "T1005"
        ],
        "log_patterns": [
            "mass read of documents/DB files",
            "archive creation before exfil"
        ],
        "response_actions": [
            "DLP on sensitive data",
            "alert on bulk collection",
            "investigate staging"
        ]
    },
    {
        "id": "T1119",
        "name": "Automated Collection",
        "tactic": "Collection",
        "description": "Adversaries may use automated techniques (scripts) to gather internal data, often with other discovery techniques.",
        "detection_indicators": [
            "scripted mass collection",
            "scheduled data gathering",
            "T1119"
        ],
        "log_patterns": [
            "automated archive of many files",
            "loop-based file collection"
        ],
        "response_actions": [
            "alert on automated collection patterns",
            "DLP and access monitoring"
        ]
    },
    {
        "id": "T1039",
        "name": "Data from Network Shared Drive",
        "tactic": "Collection",
        "description": "Adversaries may search network shares on remote systems to collect data prior to exfiltration.",
        "detection_indicators": [
            "bulk access to network shares",
            "copying from file servers",
            "T1039"
        ],
        "log_patterns": [
            "mass file reads from SMB shares",
            "staging from network drives"
        ],
        "response_actions": [
            "audit share access",
            "DLP on file servers",
            "alert on bulk share reads"
        ]
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command And Control",
        "description": "Adversaries may transfer tools or files from an external system into a compromised environment (download via C2, certutil, curl/wget).",
        "detection_indicators": [
            "download of tooling from internet",
            "LOLBin file download",
            "T1105"
        ],
        "log_patterns": [
            "certutil/bitsadmin/curl downloading executable",
            "tool transfer over C2"
        ],
        "response_actions": [
            "block download sources",
            "alert on LOLBin downloads",
            "quarantine transferred tools"
        ]
    },
    {
        "id": "T1573",
        "name": "Encrypted Channel",
        "tactic": "Command And Control",
        "description": "Adversaries may employ encryption to conceal C2 traffic (TLS, custom crypto), blending with normal encrypted traffic.",
        "detection_indicators": [
            "TLS C2 to suspicious endpoints",
            "custom-encrypted beacon",
            "T1573"
        ],
        "log_patterns": [
            "self-signed/JA3-anomalous TLS to C2",
            "periodic encrypted beacon"
        ],
        "response_actions": [
            "TLS inspection/JA3 fingerprinting",
            "block C2 destinations",
            "isolate host"
        ]
    },
    {
        "id": "T1568",
        "name": "Dynamic Resolution",
        "tactic": "Command And Control",
        "description": "Adversaries may dynamically establish C2 by changing infrastructure (DGA, fast flux, DNS calculation) to evade blocking.",
        "detection_indicators": [
            "DGA domains",
            "fast-flux DNS",
            "high NXDOMAIN rate",
            "T1568"
        ],
        "log_patterns": [
            "many algorithmically-generated domain lookups",
            "rapidly-changing A records"
        ],
        "response_actions": [
            "DGA detection and DNS sinkholing",
            "block resolved C2 IPs"
        ]
    },
    {
        "id": "T1090.003",
        "name": "Proxy: Multi-hop Proxy (TOR)",
        "tactic": "Command And Control",
        "description": "Adversaries may chain multiple proxies (e.g., TOR) to disguise the source of malicious traffic and evade attribution.",
        "detection_indicators": [
            "traffic to TOR entry/exit nodes",
            "multi-hop relay chains",
            "T1090.003"
        ],
        "log_patterns": [
            "connections to known TOR nodes",
            "chained proxy hops"
        ],
        "response_actions": [
            "block TOR infrastructure",
            "alert on anonymization-network use"
        ]
    },
    {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Adversaries may use legitimate external web services (cloud storage, paste sites, code repos) to exfiltrate data, blending with normal traffic.",
        "detection_indicators": [
            "upload to cloud storage/paste sites",
            "data to code repositories",
            "T1567"
        ],
        "log_patterns": [
            "large uploads to pastebin/dropbox/github",
            "exfil to web service API"
        ],
        "response_actions": [
            "DLP on web-service uploads",
            "restrict/monitor cloud egress",
            "block confirmed exfil services"
        ]
    },
    {
        "id": "T1030",
        "name": "Data Transfer Size Limits",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data in fixed-size chunks (instead of whole files) to avoid triggering volume-based alerts.",
        "detection_indicators": [
            "uniform-sized periodic transfers",
            "chunked exfiltration",
            "T1030"
        ],
        "log_patterns": [
            "repeated equal-sized outbound transfers",
            "low-and-slow exfil pattern"
        ],
        "response_actions": [
            "correlate chunked transfers over time",
            "DLP on cumulative volume"
        ]
    },
    {
        "id": "T1020",
        "name": "Automated Exfiltration",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data using automated processing after it has been collected.",
        "detection_indicators": [
            "scripted/scheduled exfiltration",
            "automated upload routines",
            "T1020"
        ],
        "log_patterns": [
            "scheduled outbound transfer jobs",
            "automated exfil after collection"
        ],
        "response_actions": [
            "alert on automated exfil patterns",
            "DLP and egress monitoring"
        ]
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems (ransomware) to interrupt availability and extort the victim.",
        "detection_indicators": [
            "mass file encryption",
            "ransom notes",
            "shadow-copy deletion",
            "T1486"
        ],
        "log_patterns": [
            "rapid file modification/rename to encrypted extensions",
            "vssadmin delete shadows",
            "ransom note creation"
        ],
        "response_actions": [
            "isolate affected hosts immediately",
            "restore from offline backups",
            "block ransomware C2/spread"
        ]
    },
    {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or disable recovery features (shadow copies, backups, recovery console) to maximize impact of destructive attacks.",
        "detection_indicators": [
            "shadow copy/backup deletion",
            "recovery disabled",
            "T1490"
        ],
        "log_patterns": [
            "vssadmin/wbadmin delete",
            "bcdedit recovery disable"
        ],
        "response_actions": [
            "maintain offline immutable backups",
            "alert on recovery tampering"
        ]
    },
    {
        "id": "T1489",
        "name": "Service Stop",
        "tactic": "Impact",
        "description": "Adversaries may stop or disable services to render systems unusable or to aid further attacks (e.g., stopping DBs before ransomware).",
        "detection_indicators": [
            "critical services stopped",
            "DB/backup services killed",
            "T1489"
        ],
        "log_patterns": [
            "mass service stop",
            "termination of database/security services"
        ],
        "response_actions": [
            "alert on critical-service stop",
            "restore services",
            "investigate intent"
        ]
    },
    {
        "id": "T1496",
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": "Adversaries may leverage victim resources (CPU/GPU) for cryptomining or other compute-intensive tasks, degrading availability.",
        "detection_indicators": [
            "cryptomining traffic/processes",
            "sustained high CPU/GPU",
            "T1496"
        ],
        "log_patterns": [
            "connections to mining pools",
            "miner process/user-agent"
        ],
        "response_actions": [
            "block mining pools",
            "kill miner and isolate host",
            "investigate initial access"
        ]
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system. Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Port scanning sweeps a range of TCP/UDP ports across one or many hosts to map the attack surface before lateral movement or exploitation.",
        "detection_indicators": [
            "Port scanning across many distinct destination ports",
            "High count of unique destination ports from a single source IP",
            "SYN scan / connect scan patterns",
            "T1046"
        ],
        "log_patterns": [
            "single Source IP contacting > 10 non-HTTP ports in short window",
            "sequential or randomized destination port access",
            "low packet count per flow across many ports",
            "Tier-1 session baseline: Port scan detected"
        ],
        "response_actions": [
            "rate-limit or block scanning Source IP at firewall",
            "correlate with subsequent exploitation attempts",
            "enable port-scan detection signatures on IDS",
            "monitor the scanned hosts for follow-on access"
        ]
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services. Successful brute-force or credential-stuffing attacks often culminate in valid account abuse, which blends with legitimate activity and evades detection.",
        "detection_indicators": [
            "successful login after multiple failures",
            "login from anomalous geolocation or ASN",
            "concurrent sessions for the same account",
            "service account interactive logon",
            "T1078"
        ],
        "log_patterns": [
            "failed brute-force burst followed by a single SUCCESS for same account",
            "authentication from new/unrecognized Source IP",
            "off-hours privileged login"
        ],
        "response_actions": [
            "force password reset and revoke active sessions",
            "enforce MFA on the account",
            "review account privileges for least-privilege",
            "hunt for lateral movement from the account"
        ]
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications. This blends exfiltration with routine C2 beaconing, making it hard to separate from benign management traffic. Large outbound transfers correlated with prior C2 activity are a strong indicator.",
        "detection_indicators": [
            "large outbound data volume to a known C2 endpoint",
            "asymmetric flow (small inbound, large outbound)",
            "data transfer correlated with beaconing host",
            "T1041"
        ],
        "log_patterns": [
            "Total Length of Fwd Packets anomalously high to external IP",
            "sustained outbound flow to non-business destination",
            "exfil over already-flagged C2 session"
        ],
        "response_actions": [
            "block the C2 destination and isolate the source host",
            "capture full PCAP for forensic scoping",
            "identify what data left the network (DLP review)",
            "rotate any credentials/secrets potentially exposed"
        ]
    },
    {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system (e.g., ping, net view, arp) could also be used. This often precedes Lateral Movement in multi-stage APT campaigns.",
        "detection_indicators": [
            "host sweeping via ICMP/ARP across subnet",
            "enumeration of SMB/AD hosts",
            "many short-lived connections to internal hosts",
            "T1018"
        ],
        "log_patterns": [
            "single internal IP contacting many other internal IPs",
            "ping sweep pattern within RFC1918 range",
            "discovery activity preceding lateral movement"
        ],
        "response_actions": [
            "isolate the discovering host pending review",
            "tighten east-west segmentation",
            "alert on internal reconnaissance from non-admin hosts"
        ]
    },
    {
        "id": "T1110.002",
        "name": "Brute Force: Password Cracking",
        "tactic": "Credential Access",
        "description": "Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. Cracking is done offline against captured hashes (e.g., NTLM, Kerberos AS-REP, /etc/shadow) and does not generate network login noise, so detection focuses on the precursor hash-theft and subsequent valid-account use.",
        "detection_indicators": [
            "preceding credential dumping activity",
            "sudden valid-account access after data theft",
            "T1110.002"
        ],
        "log_patterns": [
            "access to SAM/LSASS or shadow files",
            "AS-REP roasting requests",
            "successful logon with cracked credentials"
        ],
        "response_actions": [
            "rotate all potentially-exposed credentials",
            "increase password hash iteration/length policy",
            "monitor for offline-cracked account usage"
        ]
    },
    {
        "id": "T1110.003",
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g., 'Password1') or a small list of passwords that matches the complexity policy of the domain and may possibly combine that with knowledge of valid usernames. This low-and-slow approach evades per-account lockout thresholds.",
        "detection_indicators": [
            "one password tried against many distinct usernames",
            "low failure rate per account but high across the org",
            "distributed login attempts over time",
            "T1110.003"
        ],
        "log_patterns": [
            "many accounts each with 1-2 failed logins from same Source IP",
            "authentication failures spread across user base",
            "spray pattern below per-account lockout threshold"
        ],
        "response_actions": [
            "block source IP and enforce org-wide MFA",
            "implement smart lockout / risk-based auth",
            "alert on horizontal authentication anomalies"
        ]
    },
    {
        "id": "T1110.004",
        "name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, two or more individuals share the same username and password, allowing the adversary to access the target's account. Credential stuffing is automated at high volume against web login endpoints.",
        "detection_indicators": [
            "high-volume automated login attempts to web auth endpoint",
            "rotating Source IPs with consistent user-agent",
            "known-breached credential pairs",
            "T1110.004"
        ],
        "log_patterns": [
            "burst of POST /login from botnet IPs",
            "high request rate to authentication URI",
            "credential-stuffing tooling user-agent"
        ],
        "response_actions": [
            "deploy CAPTCHA / bot mitigation at login",
            "block offending IP ranges and enforce MFA",
            "monitor for successful stuffed logins"
        ]
    },
    {
        "id": "T1498.001",
        "name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "description": "Adversaries may attempt to cause a denial of service by directly sending a high-volume of network traffic to a target. Direct Network Floods are when one or more systems are used to send a high-volume of network packets towards the targeted service's network, exhausting bandwidth capabilities. SYN floods and UDP floods are common variants.",
        "detection_indicators": [
            "abnormal spike in inbound packets/sec",
            "SYN/UDP flood signatures",
            "bandwidth saturation toward one service",
            "T1498.001"
        ],
        "log_patterns": [
            "Flow Pkts/s far above baseline toward single destination",
            "high Total Fwd Packets volumetric pattern",
            "many half-open connections"
        ],
        "response_actions": [
            "engage upstream DDoS scrubbing / BGP blackhole",
            "rate-limit at edge, do NOT block (often spoofed)",
            "scale or failover the targeted service"
        ]
    },
    {
        "id": "T1499.001",
        "name": "Endpoint Denial of Service: OS Exhaustion Flood",
        "tactic": "Impact",
        "description": "Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system. A system's OS is responsible for managing finite resources such as connection state tables; attackers exhaust these (e.g., via Slowloris-style slow connections or connection floods) to render the service unavailable without high bandwidth.",
        "detection_indicators": [
            "many slow/incomplete connections held open",
            "connection table exhaustion on host",
            "Slowloris HTTP partial requests",
            "T1499.001"
        ],
        "log_patterns": [
            "high count of long-duration low-throughput flows",
            "Flow Duration anomalously high with tiny packet payloads",
            "concurrent half-open sessions to web server"
        ],
        "response_actions": [
            "lower connection timeouts and cap per-IP connections",
            "deploy reverse proxy that buffers slow requests",
            "block offending Source IPs"
        ]
    },
    {
        "id": "T1095",
        "name": "Non-Application Layer Protocol",
        "tactic": "Command And Control",
        "description": "Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. Examples include ICMP, transport layer protocols like UDP, or network layer protocols like raw sockets, which avoid application-layer inspection.",
        "detection_indicators": [
            "unusual ICMP/raw-socket traffic volume",
            "C2 over non-standard transport",
            "data encoded in ICMP echo payloads",
            "T1095"
        ],
        "log_patterns": [
            "abnormal ICMP request size/frequency",
            "non-TCP/UDP protocol numbers in flow records",
            "periodic beacon over transport protocol"
        ],
        "response_actions": [
            "block non-essential ICMP/raw protocols at egress",
            "inspect payloads of allowed non-app protocols",
            "isolate beaconing host"
        ]
    },
    {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command And Control",
        "description": "Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or HTTP over port 8443 instead of the standard port 443 or 80. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.",
        "detection_indicators": [
            "known protocol running on unexpected port",
            "HTTP/TLS on non-standard ports",
            "C2 over uncommon high ports",
            "T1571"
        ],
        "log_patterns": [
            "TLS handshake on non-443 port",
            "Destination Port unusual for the observed protocol",
            "outbound to high non-standard port sustained"
        ],
        "response_actions": [
            "enforce egress allowlist by port",
            "deep-packet-inspect protocol/port mismatches",
            "block anomalous port usage to external IPs"
        ]
    },
    {
        "id": "T1572",
        "name": "Protocol Tunneling",
        "tactic": "Command And Control",
        "description": "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another (e.g., DNS tunneling, SSH tunneling, HTTP CONNECT).",
        "detection_indicators": [
            "DNS queries with high-entropy/large TXT payloads",
            "SSH connections used as SOCKS proxy",
            "encapsulated protocol inside another",
            "T1572"
        ],
        "log_patterns": [
            "abnormally high DNS query volume to one domain",
            "long-lived SSH session with port forwarding",
            "HTTP CONNECT to arbitrary hosts"
        ],
        "response_actions": [
            "restrict and monitor DNS to approved resolvers",
            "block unauthorized tunneling/proxy use",
            "alert on DNS exfiltration heuristics"
        ]
    },
    {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command And Control",
        "description": "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. This includes internal proxies, external proxies, multi-hop proxies, and domain fronting.",
        "detection_indicators": [
            "traffic relayed through intermediary hosts",
            "use of TOR / open proxies",
            "multi-hop or chained connections",
            "T1090"
        ],
        "log_patterns": [
            "connections to known proxy/TOR exit nodes",
            "internal host acting as relay between others",
            "domain-fronted TLS SNI mismatch"
        ],
        "response_actions": [
            "block known proxy/TOR infrastructure",
            "investigate internal relay hosts",
            "enforce direct, logged egress paths"
        ]
    },
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main C2 server. Protocols such as FTP, SMTP, HTTP/S, DNS, SMB, or other network protocols not being used as the main C2 channel are leveraged.",
        "detection_indicators": [
            "large outbound transfer over FTP/SMTP/DNS not used for C2",
            "data sent to a different endpoint than C2",
            "unusual protocol carrying bulk data out",
            "T1048"
        ],
        "log_patterns": [
            "bulk outbound over FTP/SMTP to external IP",
            "DNS exfiltration with encoded subdomains",
            "off-channel data transfer to new destination"
        ],
        "response_actions": [
            "DLP inspection and block on alternative egress protocols",
            "isolate source host and scope data loss",
            "restrict outbound protocols by policy"
        ]
    },
    {
        "id": "T1556",
        "name": "Modify Authentication Process",
        "tactic": "Credential Access",
        "description": "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authority (LSA) and pluggable authentication modules (PAM) on Linux, that adversaries tamper with to bypass or capture credentials.",
        "detection_indicators": [
            "unauthorized changes to PAM/LSA modules",
            "rogue authentication packages registered",
            "MFA bypass configuration changes",
            "T1556"
        ],
        "log_patterns": [
            "modification of /etc/pam.d or security packages",
            "new auth provider registered",
            "authentication succeeding without expected factor"
        ],
        "response_actions": [
            "restore authentication config from known-good baseline",
            "rotate credentials and re-enroll MFA",
            "audit authentication module integrity"
        ]
    },
    {
        "id": "T1212",
        "name": "Exploitation for Credential Access",
        "tactic": "Credential Access",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code, for example targeting credential stores or domain controllers (e.g., Zerologon, NTLM relay).",
        "detection_indicators": [
            "exploitation attempts against auth services",
            "anomalous DC/Kerberos traffic",
            "known credential-access CVE exploitation",
            "T1212"
        ],
        "log_patterns": [
            "malformed authentication protocol requests",
            "exploit signature against LDAP/Kerberos/SMB",
            "credential-access exploit matching known CVE"
        ],
        "response_actions": [
            "patch the exploited authentication service immediately",
            "rotate domain/krbtgt credentials if DC affected",
            "block exploit source and hunt for follow-on access"
        ]
    },
    {
        "id": "T1210",
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to enable remote code execution, enabling lateral movement (e.g., EternalBlue/SMB, RDP vulnerabilities).",
        "detection_indicators": [
            "exploitation of SMB/RDP/SSH on internal hosts",
            "lateral RCE attempts east-west",
            "known remote-service CVE traffic",
            "T1210"
        ],
        "log_patterns": [
            "exploit signature against internal SMB/RDP",
            "internal host triggering RCE pattern on peer",
            "lateral movement following exploitation"
        ],
        "response_actions": [
            "isolate exploited and source hosts",
            "patch vulnerable remote services network-wide",
            "enforce internal segmentation and disable legacy SMBv1"
        ]
    },
    {
        "id": "T1570",
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
        "description": "Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., Ingress Tool Transfer) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation, often via SMB admin shares or remote copy.",
        "detection_indicators": [
            "binaries copied to admin shares (C$, ADMIN$)",
            "file transfer between internal hosts",
            "staging of tooling on multiple hosts",
            "T1570"
        ],
        "log_patterns": [
            "SMB write of executable to remote admin share",
            "internal file copy preceding execution",
            "lateral transfer of known tool hashes"
        ],
        "response_actions": [
            "block executable writes to admin shares",
            "quarantine transferred tooling and source host",
            "hunt for the tool across all endpoints"
        ]
    },
    {
        "id": "T1133",
        "name": "External Remote Services",
        "tactic": "Initial Access",
        "description": "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, RDP gateways, and other access mechanisms allow users to connect to internal enterprise network resources from external locations and are frequently targeted with valid or brute-forced credentials.",
        "detection_indicators": [
            "external login to VPN/RDP gateway from new IP",
            "brute force against remote access portal",
            "valid-account access from untrusted network",
            "T1133"
        ],
        "log_patterns": [
            "authentication to internet-facing VPN/RDP from anomalous geo",
            "remote service login outside business hours",
            "repeated failures then success on remote portal"
        ],
        "response_actions": [
            "enforce MFA on all external remote services",
            "geo-fence and conditional-access policies",
            "block source and review remote-access logs"
        ]
    }
]

ALL_NIST = [
    {
        "control": "NIST.IR.RANSOMWARE",
        "name": "Ransomware Incident Response Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for ransomware (MITRE T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery, T1489 Service Stop) where data is encrypted for extortion.",
        "applicability": "Relevant when detecting rapid mass file encryption, ransom notes, shadow-copy/backup deletion, or service-stop activity preceding encryption.",
        "response_guidance": "DETECTION & ANALYSIS: Identify patient-zero, encryption scope, and ransomware family. CONTAINMENT: Immediately isolate affected hosts from the network (keep powered on for forensics), block spread via SMB/admin shares, and disable affected accounts. ERADICATION & RECOVERY: Remove the ransomware, rebuild encrypted hosts, and restore from OFFLINE/immutable backups (do NOT pay). POST-INCIDENT: Close the initial-access vector, enforce offline backups + EDR, and segment to limit blast radius."
    },
    {
        "control": "NIST.IR.CREDACCESS",
        "name": "Credential Theft & Dumping Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for credential access (MITRE T1003 OS Credential Dumping, T1555 Password Stores, T1552 Unsecured Credentials, T1557 AiTM) where account secrets are stolen.",
        "applicability": "Relevant when detecting LSASS/SAM/shadow access, credential-store reads, ARP/LLMNR poisoning, or use of cracked/dumped credentials.",
        "response_guidance": "DETECTION & ANALYSIS: Determine which credentials were exposed and how. CONTAINMENT: Force-reset and revoke sessions for all exposed accounts, enforce MFA, and isolate the dumping host. ERADICATION & RECOVERY: Rotate service/domain credentials (krbtgt twice if DC affected), enable Credential Guard, and remove the dumping tooling. POST-INCIDENT: Deploy LSASS protection, disable LLMNR/NBT-NS, and monitor for pass-the-hash/ticket."
    },
    {
        "control": "NIST.IR.WEBSHELL",
        "name": "Web Shell & Server Backdoor Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for web shells / server software component backdoors (MITRE T1505.003) providing persistent command execution on web servers.",
        "applicability": "Relevant when detecting suspicious files in web roots, command execution via HTTP parameters, or web servers spawning shells.",
        "response_guidance": "DETECTION & ANALYSIS: Locate the web shell file(s) and review web/access logs for the upload vector and commands executed. CONTAINMENT: Quarantine the web shell, block the attacker IP at the WAF, and take the affected app offline if active compromise. ERADICATION & RECOVERY: Patch the exploited web vulnerability, audit web-root integrity, and rebuild if backdoors are widespread. POST-INCIDENT: Add file-integrity monitoring on web roots and WAF rules for the exploit."
    },
    {
        "control": "NIST.IR.RECON",
        "name": "Network Reconnaissance & Port Scanning Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for handling reconnaissance activity such as port scanning, host sweeping, and network/remote system discovery (MITRE T1046, T1018) that typically precedes exploitation.",
        "applicability": "Relevant when the agent detects a single Source IP touching many distinct ports, ping/host sweeps across an internal subnet, or service enumeration patterns from the Tier-1 session baseline.",
        "response_guidance": "DETECTION & ANALYSIS: Confirm scan source, scope (which hosts/ports), and whether it is internal (potential lateral recon) or external. CONTAINMENT: Rate-limit or block the scanning Source IP at the firewall; for internal sources, isolate the host pending review. ERADICATION & RECOVERY: Patch any exposed vulnerable services discovered, tighten firewall egress/ingress rules and network segmentation. POST-INCIDENT: Tune IDS port-scan thresholds; treat recon as an early-warning indicator and watch the scanned assets for follow-on access."
    },
    {
        "control": "NIST.IR.LATERAL",
        "name": "Lateral Movement & Internal Pivoting Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for handling lateral movement across the internal network (MITRE T1021 Remote Services, T1210 Exploitation of Remote Services, T1570 Lateral Tool Transfer) during multi-stage / APT intrusions.",
        "applicability": "Relevant when the agent correlates a Source IP across multiple internal hosts/sensors, observes east-west exploitation, SMB admin-share writes, or APT chain events spanning multiple days (DAPT2020 chains).",
        "response_guidance": "DETECTION & ANALYSIS: Map the movement path (source host -> targets), identify the pivot account and technique. CONTAINMENT: Isolate all hosts on the lateral path, disable the compromised account, and block internal RDP/SMB between the affected segments. ERADICATION & RECOVERY: Patch exploited remote services, remove transferred tooling, rotate credentials used for movement, and rebuild confirmed-compromised hosts. POST-INCIDENT: Enforce micro-segmentation, disable legacy protocols (SMBv1), and add detection for admin-share executable writes."
    },
    {
        "control": "NIST.IR.BOTNET",
        "name": "Botnet & Command-and-Control (C2) Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for handling botnet infections and C2 communications (MITRE T1071 Application Layer Protocol, T1095 Non-Application Layer Protocol, T1571 Non-Standard Port, T1572 Protocol Tunneling, T1090 Proxy).",
        "applicability": "Relevant when the agent detects periodic beaconing, traffic to known C2/TOR infrastructure, protocol/port mismatches, DNS tunneling, or hosts acting as relays.",
        "response_guidance": "DETECTION & ANALYSIS: Identify the C2 destination(s), beacon interval, and all hosts beaconing. CONTAINMENT: Sinkhole/block the C2 domains and IPs at the firewall and DNS, isolate beaconing hosts. ERADICATION & RECOVERY: Remove the malware/implant, rebuild hosts if persistence is confirmed, and rotate exposed credentials. POST-INCIDENT: Add egress allowlisting, monitor for beaconing heuristics and DNS exfiltration, and share C2 IOCs to threat intel."
    },
    {
        "control": "NIST.IR.ZERODAY",
        "name": "Zero-Day / Statistical Anomaly Response Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for handling signature-less / zero-day threats detected via statistical anomaly (Tier-1 Welford Z-Score) where no known signature matches, requiring Tier-2 LLM reasoning to triage.",
        "applicability": "Relevant when Tier-1 escalates a flow with a high Z-Score (> 3.5) on core features (Flow Duration, packet/byte volumes) but no static rule or WAF signature fires — i.e., a novel or evasive attack.",
        "response_guidance": "DETECTION & ANALYSIS: Treat the anomaly as suspicious-by-default; capture full context (which feature deviated, by how many sigma) and full PCAP for the flow. CONTAINMENT: Apply a conservative containment (ALERT + monitor, or AWAIT_HITL for high-value assets) rather than auto-block, to limit false-positive impact; escalate to a human analyst. ERADICATION & RECOVERY: If confirmed malicious, derive a new signature/dynamic rule and push it to Tier-1 via the feedback loop; patch the targeted asset. POST-INCIDENT: Feed the confirmed sample back to retrain/recalibrate the baseline and update detection content; document the novel TTP."
    }
]


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def extend_knowledge_base():
    """Append idempotent toàn bộ MITRE + NIST còn thiếu. Trả (added_mitre, added_nist)."""
    mitre = _load(MITRE_PATH)
    existing_ids = {e.get("id") for e in mitre}
    added_m = 0
    for t in ALL_MITRE:
        if t["id"] not in existing_ids:
            mitre.append(t)
            existing_ids.add(t["id"])
            added_m += 1
    _save(MITRE_PATH, mitre)

    nist = _load(NIST_PATH)
    controls = nist.get("controls", [])
    existing_ctrl = {c.get("control") for c in controls}
    added_n = 0
    for c in ALL_NIST:
        if c["control"] not in existing_ctrl:
            controls.append(c)
            existing_ctrl.add(c["control"])
            added_n += 1
    nist["controls"] = controls
    nist["_total_controls"] = len(controls)
    _save(NIST_PATH, nist)

    print(f"[MITRE] +{added_m} ky thuat (tong {len(mitre)})".replace("ky thuat", "k\u1ef9 thu\u1eadt").replace("tong", "t\u1ed5ng"))
    print(f"[NIST]  +{added_n} playbook (tong {len(controls)})".replace("tong", "t\u1ed5ng"))
    return added_m, added_n


def main():
    ap = argparse.ArgumentParser(description="Xay dung/mo rong tri thuc RAG trong 1 lan")
    ap.add_argument("--no-index", action="store_true",
                    help="Chi mo rong KB JSON, KHONG rebuild FAISS/BM25 index")
    args = ap.parse_args()

    print("=== [1/2] Mo rong tri thuc (MITRE ATT&CK + NIST SP 800-61r2) ===")
    extend_knowledge_base()

    if args.no_index:
        print("\n[!] Bo qua rebuild index (--no-index).")
        return

    print("\n=== [2/2] Rebuild FAISS + BM25 index + checksum ===")
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from src.rag.embedder import update_checksums_file, build_all_indexes
    build_all_indexes()
    update_checksums_file()
    print("\nDone: tri thuc da mo rong + index/checksum da rebuild (1 lan xay dung).")


if __name__ == "__main__":
    main()
