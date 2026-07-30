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
            "T1595",
        ],
        "log_patterns": [
            "scanner user-agents (nmap, nikto, nuclei)",
            "bursts of 404s from path fuzzing",
            "broad IP-range probing",
        ],
        "response_actions": [
            "block scanning source at edge",
            "fingerprint scanner tooling",
            "watch targeted assets for exploitation",
        ],
    },
    {
        "id": "T1595.002",
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may scan victims for vulnerabilities that can be used during targeting, checking for specific software versions and configurations against known CVE databases.",
        "detection_indicators": [
            "version-probing requests",
            "CVE-targeted scan patterns",
            "T1595.002",
        ],
        "log_patterns": [
            "requests probing known-vulnerable paths/versions",
            "scanner fingerprint in user-agent",
        ],
        "response_actions": [
            "patch exposed vulnerable services",
            "block scanner IPs",
            "harden version disclosure",
        ],
    },
    {
        "id": "T1592",
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may gather information about the victim's hosts (hardware, software, firmware, configuration) used during targeting.",
        "detection_indicators": ["banner grabbing", "OS/service fingerprinting", "T1592"],
        "log_patterns": ["service banner enumeration", "fingerprint probes to many services"],
        "response_actions": ["minimize banner/version disclosure", "alert on enumeration patterns"],
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
            "T1590",
        ],
        "log_patterns": ["high-volume DNS queries enumerating zone", "AXFR zone-transfer attempts"],
        "response_actions": [
            "restrict zone transfers",
            "rate-limit DNS",
            "monitor subdomain enumeration",
        ],
    },
    {
        "id": "T1584",
        "name": "Compromise Infrastructure",
        "tactic": "Resource Development",
        "description": "Adversaries may compromise third-party infrastructure (servers, domains, botnets) that can be used during targeting, blending C2 with legitimate-looking sources.",
        "detection_indicators": [
            "traffic to compromised legitimate hosts",
            "newly-malicious known-good domains",
            "T1584",
        ],
        "log_patterns": ["beaconing to previously-benign domains", "C2 on compromised CDN/host"],
        "response_actions": ["block confirmed-compromised infra", "share IOCs to threat intel"],
    },
    {
        "id": "T1588",
        "name": "Obtain Capabilities",
        "tactic": "Resource Development",
        "description": "Adversaries may buy and/or steal capabilities (malware, exploits, certificates, tools) that can be used during targeting.",
        "detection_indicators": [
            "use of commodity malware/exploit kits",
            "stolen code-signing certs",
            "T1588",
        ],
        "log_patterns": ["known malware family signatures", "exploit-kit landing patterns"],
        "response_actions": ["block known tooling hashes/certs", "update detection content"],
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems, via malicious attachments or links (spearphishing).",
        "detection_indicators": [
            "malicious email links/attachments",
            "credential-harvesting landing pages",
            "T1566",
        ],
        "log_patterns": [
            "clicks to known-malicious URLs from corp net",
            "macro-enabled attachment execution",
        ],
        "response_actions": [
            "purge malicious email org-wide",
            "block sender/URL",
            "reset credentials of clickers",
        ],
    },
    {
        "id": "T1199",
        "name": "Trusted Relationship",
        "tactic": "Initial Access",
        "description": "Adversaries may breach or otherwise leverage organizations who have access to intended victims, abusing trusted third-party/VPN/MSP connections.",
        "detection_indicators": [
            "access via trusted partner/VPN connection",
            "anomalous third-party account activity",
            "T1199",
        ],
        "log_patterns": ["partner-network access outside normal pattern", "MSP account anomalies"],
        "response_actions": [
            "scope and revoke trusted access",
            "enforce least-privilege for partners",
        ],
    },
    {
        "id": "T1189",
        "name": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries may gain access through a user visiting a compromised website, exploiting the browser for code execution.",
        "detection_indicators": [
            "browser exploitation traffic",
            "redirect to exploit kit",
            "T1189",
        ],
        "log_patterns": ["malicious iframe/redirect chains", "exploit-kit traffic to client"],
        "response_actions": [
            "block malicious domains",
            "patch browsers",
            "isolate affected client",
        ],
    },
    {
        "id": "T1203",
        "name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications (browsers, office apps, readers) to execute code.",
        "detection_indicators": [
            "malformed documents/exploits",
            "client app crash + spawn",
            "T1203",
        ],
        "log_patterns": ["office app spawning shell/script host", "exploit payload in document"],
        "response_actions": ["patch client software", "isolate host", "block delivery vector"],
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Execution",
        "description": "Adversaries may abuse task scheduling (cron, at, Windows Task Scheduler) to execute malicious code, often for persistence as well.",
        "detection_indicators": [
            "new/unusual scheduled tasks",
            "cron entries spawning network connections",
            "T1053",
        ],
        "log_patterns": [
            "creation of scheduled task running script/binary",
            "cron job with C2 callout",
        ],
        "response_actions": [
            "remove malicious tasks",
            "audit scheduled-task creation",
            "baseline legitimate jobs",
        ],
    },
    {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell for execution, including download-and-execute, encoded commands, and in-memory operation to evade detection.",
        "detection_indicators": [
            "encoded/obfuscated PowerShell",
            "PowerShell downloading from internet",
            "T1059.001",
        ],
        "log_patterns": [
            "powershell -enc / -nop / IEX (New-Object Net.WebClient)",
            "EncodedCommand usage",
        ],
        "response_actions": [
            "enable PowerShell script-block logging",
            "constrained language mode",
            "isolate host",
        ],
    },
    {
        "id": "T1505.003",
        "name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may backdoor web servers with web shells to establish persistent access, executing commands via crafted HTTP requests.",
        "detection_indicators": [
            "web shell files in web root",
            "command execution via HTTP params",
            "T1505.003",
        ],
        "log_patterns": [
            "POST to suspicious .php/.jsp/.aspx with cmd params",
            "web server spawning shell",
        ],
        "response_actions": [
            "quarantine the web shell file",
            "block source IP at WAF",
            "audit web root integrity",
        ],
    },
    {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversaries may manipulate accounts (add credentials, modify permissions, add to groups) to maintain access.",
        "detection_indicators": [
            "unexpected privilege/group changes",
            "new credentials added to account",
            "T1098",
        ],
        "log_patterns": ["account added to admin group", "new SSH key / app password added"],
        "response_actions": [
            "revert unauthorized changes",
            "rotate credentials",
            "audit privileged group membership",
        ],
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "description": "Adversaries may create accounts to maintain access to victim systems (local, domain, or cloud).",
        "detection_indicators": [
            "unexpected new account creation",
            "rogue admin accounts",
            "T1136",
        ],
        "log_patterns": [
            "new user/admin account outside change process",
            "service account creation anomaly",
        ],
        "response_actions": [
            "disable rogue accounts",
            "alert on account creation",
            "review IAM change logs",
        ],
    },
    {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to automatically execute a program during boot or logon (registry run keys, startup folder, services).",
        "detection_indicators": [
            "new autostart registry/services entries",
            "startup-folder implants",
            "T1547",
        ],
        "log_patterns": ["modification of Run keys / startup items", "new auto-start service"],
        "response_actions": ["remove malicious autostart entries", "baseline autostart locations"],
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges, taking advantage of kernel or service bugs to gain SYSTEM/root.",
        "detection_indicators": [
            "local privilege-escalation exploit",
            "kernel exploit indicators",
            "T1068",
        ],
        "log_patterns": [
            "process unexpectedly running as SYSTEM/root",
            "known privesc CVE exploitation",
        ],
        "response_actions": [
            "patch vulnerable component",
            "isolate host",
            "hunt for follow-on actions",
        ],
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevated privileges (sudo, UAC, setuid) to gain higher-level permissions.",
        "detection_indicators": ["sudo/UAC bypass patterns", "setuid abuse", "T1548"],
        "log_patterns": ["unexpected sudo usage", "UAC-bypass technique execution"],
        "response_actions": ["audit sudoers/UAC config", "restrict elevation paths"],
    },
    {
        "id": "T1134",
        "name": "Access Token Manipulation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may modify access tokens to operate under a different user or system security context to escalate privileges or bypass access controls.",
        "detection_indicators": [
            "token theft/impersonation",
            "process running with stolen token",
            "T1134",
        ],
        "log_patterns": ["token duplication/impersonation API usage", "privilege context change"],
        "response_actions": [
            "isolate host",
            "rotate impacted credentials",
            "audit token-manipulation events",
        ],
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Stealth",
        "description": "Adversaries may delete or modify artifacts (logs, files, command history) to remove evidence of their presence and hinder detection.",
        "detection_indicators": ["log clearing", "shell history deletion", "timestomping", "T1070"],
        "log_patterns": [
            "Windows event log cleared (1102)",
            "auth.log/secure truncated",
            "history file emptied",
        ],
        "response_actions": [
            "forward logs off-host (immutable)",
            "alert on log-clearing",
            "restore from backups",
        ],
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Stealth",
        "description": "Adversaries may obfuscate/encode files or commands (base64, packing, encryption) to evade detection and analysis.",
        "detection_indicators": ["base64/packed payloads", "high-entropy content", "T1027"],
        "log_patterns": ["encoded command-lines", "packed binaries with high entropy"],
        "response_actions": ["deobfuscate and analyze", "entropy-based detection", "isolate host"],
    },
    {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Impairment",
        "description": "Adversaries may modify/disable security tools (AV, EDR, firewall, logging) to avoid detection and enable their operations.",
        "detection_indicators": [
            "security service stopped/disabled",
            "firewall/AV tampering",
            "T1562",
        ],
        "log_patterns": ["EDR/AV service stop", "firewall rule deletion", "logging disabled"],
        "response_actions": [
            "re-enable and alert on defense tampering",
            "tamper-protect security tools",
            "isolate host",
        ],
    },
    {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Stealth",
        "description": "Adversaries may manipulate features of their artifacts to appear legitimate (renaming malware to system process names, fake extensions).",
        "detection_indicators": [
            "process name/path mismatch",
            "system-process impersonation",
            "T1036",
        ],
        "log_patterns": ["svchost/lsass running from wrong path", "double-extension files"],
        "response_actions": [
            "compare process path/hash to baseline",
            "alert on masquerading",
            "quarantine artifact",
        ],
    },
    {
        "id": "T1497",
        "name": "Virtualization/Sandbox Evasion",
        "tactic": "Stealth",
        "description": "Adversaries may employ checks to detect and avoid virtualization and analysis environments, delaying or altering behavior in sandboxes.",
        "detection_indicators": [
            "sandbox/VM detection checks",
            "execution stalling/delays",
            "T1497",
        ],
        "log_patterns": ["VM-artifact checks", "long sleeps before payload"],
        "response_actions": [
            "use hardened analysis env",
            "extend detonation time",
            "behavioral detection",
        ],
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
            "T1003",
        ],
        "log_patterns": [
            "procdump/mimikatz on lsass",
            "shadow/SAM file read",
            "NTDS.dit extraction",
        ],
        "response_actions": [
            "rotate exposed credentials",
            "enable Credential Guard",
            "isolate and investigate",
        ],
    },
    {
        "id": "T1555",
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "description": "Adversaries may search for and obtain credentials from password stores (browsers, keychains, password managers).",
        "detection_indicators": [
            "access to browser/keychain credential stores",
            "password-manager DB access",
            "T1555",
        ],
        "log_patterns": ["read of browser login data DB", "keychain/credential vault access"],
        "response_actions": [
            "rotate stored credentials",
            "alert on credential-store access",
            "isolate host",
        ],
    },
    {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems for insecurely stored credentials (config files, scripts, history, cloud metadata).",
        "detection_indicators": [
            "credentials in plaintext files/scripts",
            "cloud metadata credential access",
            "T1552",
        ],
        "log_patterns": ["grep for password/secret in files", "access to 169.254.169.254 metadata"],
        "response_actions": [
            "remove hardcoded secrets, use vaults",
            "restrict metadata access",
            "rotate exposed keys",
        ],
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
            "T1557",
        ],
        "log_patterns": [
            "gratuitous ARP anomalies",
            "LLMNR/NBT-NS response from non-DNS host",
            "MAC-IP binding changes",
        ],
        "response_actions": [
            "enable dynamic ARP inspection",
            "disable LLMNR/NBT-NS",
            "isolate rogue host",
        ],
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate files and directories to find information of interest before collection/exfiltration.",
        "detection_indicators": [
            "recursive directory listing",
            "search for sensitive file types",
            "T1083",
        ],
        "log_patterns": ["mass dir/file enumeration", "search for *.kdbx/*.pem/*.config"],
        "response_actions": ["alert on mass enumeration", "monitor sensitive-file access"],
    },
    {
        "id": "T1087",
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate accounts (local, domain, cloud, email) to understand the environment and plan further actions.",
        "detection_indicators": ["enumeration of users/groups", "LDAP/AD account queries", "T1087"],
        "log_patterns": ["net user/net group enumeration", "bulk LDAP account queries"],
        "response_actions": ["alert on bulk account enumeration", "limit directory read access"],
    },
    {
        "id": "T1135",
        "name": "Network Share Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for shared folders and drives on remote systems to identify data and lateral-movement targets.",
        "detection_indicators": ["SMB share enumeration", "net view / share scans", "T1135"],
        "log_patterns": ["enumeration of network shares", "SMB tree-connect sweep"],
        "response_actions": ["audit share permissions", "alert on share enumeration"],
    },
    {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate active network connections to/from a system to understand the environment and identify pivots.",
        "detection_indicators": [
            "netstat / connection enumeration",
            "active session listing",
            "T1049",
        ],
        "log_patterns": ["netstat/ss execution", "enumeration of established sessions"],
        "response_actions": ["baseline normal discovery", "alert on recon from non-admin hosts"],
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
            "T1550",
        ],
        "log_patterns": [
            "overpass-the-hash logon",
            "PtH NTLM auth from unusual host",
            "golden/silver ticket usage",
        ],
        "response_actions": [
            "rotate krbtgt and impacted creds",
            "enable Credential Guard",
            "monitor anomalous Kerberos",
        ],
    },
    {
        "id": "T1563",
        "name": "Remote Service Session Hijacking",
        "tactic": "Lateral Movement",
        "description": "Adversaries may take control of preexisting remote sessions (RDP, SSH) to move laterally using already-authenticated access.",
        "detection_indicators": ["hijacked RDP/SSH session", "session takeover patterns", "T1563"],
        "log_patterns": ["RDP session reconnect anomaly", "SSH session multiplexing abuse"],
        "response_actions": [
            "terminate suspicious sessions",
            "alert on session hijack",
            "isolate hosts",
        ],
    },
    {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search local system sources (file systems, databases) to collect data of interest prior to exfiltration.",
        "detection_indicators": ["bulk local data access", "staging of collected files", "T1005"],
        "log_patterns": ["mass read of documents/DB files", "archive creation before exfil"],
        "response_actions": [
            "DLP on sensitive data",
            "alert on bulk collection",
            "investigate staging",
        ],
    },
    {
        "id": "T1119",
        "name": "Automated Collection",
        "tactic": "Collection",
        "description": "Adversaries may use automated techniques (scripts) to gather internal data, often with other discovery techniques.",
        "detection_indicators": ["scripted mass collection", "scheduled data gathering", "T1119"],
        "log_patterns": ["automated archive of many files", "loop-based file collection"],
        "response_actions": ["alert on automated collection patterns", "DLP and access monitoring"],
    },
    {
        "id": "T1039",
        "name": "Data from Network Shared Drive",
        "tactic": "Collection",
        "description": "Adversaries may search network shares on remote systems to collect data prior to exfiltration.",
        "detection_indicators": [
            "bulk access to network shares",
            "copying from file servers",
            "T1039",
        ],
        "log_patterns": ["mass file reads from SMB shares", "staging from network drives"],
        "response_actions": [
            "audit share access",
            "DLP on file servers",
            "alert on bulk share reads",
        ],
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command And Control",
        "description": "Adversaries may transfer tools or files from an external system into a compromised environment (download via C2, certutil, curl/wget).",
        "detection_indicators": [
            "download of tooling from internet",
            "LOLBin file download",
            "T1105",
        ],
        "log_patterns": ["certutil/bitsadmin/curl downloading executable", "tool transfer over C2"],
        "response_actions": [
            "block download sources",
            "alert on LOLBin downloads",
            "quarantine transferred tools",
        ],
    },
    {
        "id": "T1573",
        "name": "Encrypted Channel",
        "tactic": "Command And Control",
        "description": "Adversaries may employ encryption to conceal C2 traffic (TLS, custom crypto), blending with normal encrypted traffic.",
        "detection_indicators": [
            "TLS C2 to suspicious endpoints",
            "custom-encrypted beacon",
            "T1573",
        ],
        "log_patterns": ["self-signed/JA3-anomalous TLS to C2", "periodic encrypted beacon"],
        "response_actions": [
            "TLS inspection/JA3 fingerprinting",
            "block C2 destinations",
            "isolate host",
        ],
    },
    {
        "id": "T1568",
        "name": "Dynamic Resolution",
        "tactic": "Command And Control",
        "description": "Adversaries may dynamically establish C2 by changing infrastructure (DGA, fast flux, DNS calculation) to evade blocking.",
        "detection_indicators": ["DGA domains", "fast-flux DNS", "high NXDOMAIN rate", "T1568"],
        "log_patterns": [
            "many algorithmically-generated domain lookups",
            "rapidly-changing A records",
        ],
        "response_actions": ["DGA detection and DNS sinkholing", "block resolved C2 IPs"],
    },
    {
        "id": "T1090.003",
        "name": "Proxy: Multi-hop Proxy (TOR)",
        "tactic": "Command And Control",
        "description": "Adversaries may chain multiple proxies (e.g., TOR) to disguise the source of malicious traffic and evade attribution.",
        "detection_indicators": [
            "traffic to TOR entry/exit nodes",
            "multi-hop relay chains",
            "T1090.003",
        ],
        "log_patterns": ["connections to known TOR nodes", "chained proxy hops"],
        "response_actions": ["block TOR infrastructure", "alert on anonymization-network use"],
    },
    {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Adversaries may use legitimate external web services (cloud storage, paste sites, code repos) to exfiltrate data, blending with normal traffic.",
        "detection_indicators": [
            "upload to cloud storage/paste sites",
            "data to code repositories",
            "T1567",
        ],
        "log_patterns": ["large uploads to pastebin/dropbox/github", "exfil to web service API"],
        "response_actions": [
            "DLP on web-service uploads",
            "restrict/monitor cloud egress",
            "block confirmed exfil services",
        ],
    },
    {
        "id": "T1030",
        "name": "Data Transfer Size Limits",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data in fixed-size chunks (instead of whole files) to avoid triggering volume-based alerts.",
        "detection_indicators": [
            "uniform-sized periodic transfers",
            "chunked exfiltration",
            "T1030",
        ],
        "log_patterns": ["repeated equal-sized outbound transfers", "low-and-slow exfil pattern"],
        "response_actions": ["correlate chunked transfers over time", "DLP on cumulative volume"],
    },
    {
        "id": "T1020",
        "name": "Automated Exfiltration",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data using automated processing after it has been collected.",
        "detection_indicators": [
            "scripted/scheduled exfiltration",
            "automated upload routines",
            "T1020",
        ],
        "log_patterns": ["scheduled outbound transfer jobs", "automated exfil after collection"],
        "response_actions": ["alert on automated exfil patterns", "DLP and egress monitoring"],
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
            "T1486",
        ],
        "log_patterns": [
            "rapid file modification/rename to encrypted extensions",
            "vssadmin delete shadows",
            "ransom note creation",
        ],
        "response_actions": [
            "isolate affected hosts immediately",
            "restore from offline backups",
            "block ransomware C2/spread",
        ],
    },
    {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversaries may delete or disable recovery features (shadow copies, backups, recovery console) to maximize impact of destructive attacks.",
        "detection_indicators": ["shadow copy/backup deletion", "recovery disabled", "T1490"],
        "log_patterns": ["vssadmin/wbadmin delete", "bcdedit recovery disable"],
        "response_actions": ["maintain offline immutable backups", "alert on recovery tampering"],
    },
    {
        "id": "T1489",
        "name": "Service Stop",
        "tactic": "Impact",
        "description": "Adversaries may stop or disable services to render systems unusable or to aid further attacks (e.g., stopping DBs before ransomware).",
        "detection_indicators": ["critical services stopped", "DB/backup services killed", "T1489"],
        "log_patterns": ["mass service stop", "termination of database/security services"],
        "response_actions": [
            "alert on critical-service stop",
            "restore services",
            "investigate intent",
        ],
    },
    {
        "id": "T1496",
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": "Adversaries may leverage victim resources (CPU/GPU) for cryptomining or other compute-intensive tasks, degrading availability.",
        "detection_indicators": [
            "cryptomining traffic/processes",
            "sustained high CPU/GPU",
            "T1496",
        ],
        "log_patterns": ["connections to mining pools", "miner process/user-agent"],
        "response_actions": [
            "block mining pools",
            "kill miner and isolate host",
            "investigate initial access",
        ],
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
            "T1046",
        ],
        "log_patterns": [
            "single Source IP contacting > 10 non-HTTP ports in short window",
            "sequential or randomized destination port access",
            "low packet count per flow across many ports",
            "Tier-1 session baseline: Port scan detected",
        ],
        "response_actions": [
            "rate-limit or block scanning Source IP at firewall",
            "correlate with subsequent exploitation attempts",
            "enable port-scan detection signatures on IDS",
            "monitor the scanned hosts for follow-on access",
        ],
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
            "T1078",
        ],
        "log_patterns": [
            "failed brute-force burst followed by a single SUCCESS for same account",
            "authentication from new/unrecognized Source IP",
            "off-hours privileged login",
        ],
        "response_actions": [
            "force password reset and revoke active sessions",
            "enforce MFA on the account",
            "review account privileges for least-privilege",
            "hunt for lateral movement from the account",
        ],
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
            "T1041",
        ],
        "log_patterns": [
            "Total Length of Fwd Packets anomalously high to external IP",
            "sustained outbound flow to non-business destination",
            "exfil over already-flagged C2 session",
        ],
        "response_actions": [
            "block the C2 destination and isolate the source host",
            "capture full PCAP for forensic scoping",
            "identify what data left the network (DLP review)",
            "rotate any credentials/secrets potentially exposed",
        ],
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
            "T1018",
        ],
        "log_patterns": [
            "single internal IP contacting many other internal IPs",
            "ping sweep pattern within RFC1918 range",
            "discovery activity preceding lateral movement",
        ],
        "response_actions": [
            "isolate the discovering host pending review",
            "tighten east-west segmentation",
            "alert on internal reconnaissance from non-admin hosts",
        ],
    },
    {
        "id": "T1110.002",
        "name": "Brute Force: Password Cracking",
        "tactic": "Credential Access",
        "description": "Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. Cracking is done offline against captured hashes (e.g., NTLM, Kerberos AS-REP, /etc/shadow) and does not generate network login noise, so detection focuses on the precursor hash-theft and subsequent valid-account use.",
        "detection_indicators": [
            "preceding credential dumping activity",
            "sudden valid-account access after data theft",
            "T1110.002",
        ],
        "log_patterns": [
            "access to SAM/LSASS or shadow files",
            "AS-REP roasting requests",
            "successful logon with cracked credentials",
        ],
        "response_actions": [
            "rotate all potentially-exposed credentials",
            "increase password hash iteration/length policy",
            "monitor for offline-cracked account usage",
        ],
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
            "T1110.003",
        ],
        "log_patterns": [
            "many accounts each with 1-2 failed logins from same Source IP",
            "authentication failures spread across user base",
            "spray pattern below per-account lockout threshold",
        ],
        "response_actions": [
            "block source IP and enforce org-wide MFA",
            "implement smart lockout / risk-based auth",
            "alert on horizontal authentication anomalies",
        ],
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
            "T1110.004",
        ],
        "log_patterns": [
            "burst of POST /login from botnet IPs",
            "high request rate to authentication URI",
            "credential-stuffing tooling user-agent",
        ],
        "response_actions": [
            "deploy CAPTCHA / bot mitigation at login",
            "block offending IP ranges and enforce MFA",
            "monitor for successful stuffed logins",
        ],
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
            "T1498.001",
        ],
        "log_patterns": [
            "Flow Pkts/s far above baseline toward single destination",
            "high Total Fwd Packets volumetric pattern",
            "many half-open connections",
        ],
        "response_actions": [
            "engage upstream DDoS scrubbing / BGP blackhole",
            "rate-limit at edge, do NOT block (often spoofed)",
            "scale or failover the targeted service",
        ],
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
            "T1499.001",
        ],
        "log_patterns": [
            "high count of long-duration low-throughput flows",
            "Flow Duration anomalously high with tiny packet payloads",
            "concurrent half-open sessions to web server",
        ],
        "response_actions": [
            "lower connection timeouts and cap per-IP connections",
            "deploy reverse proxy that buffers slow requests",
            "block offending Source IPs",
        ],
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
            "T1095",
        ],
        "log_patterns": [
            "abnormal ICMP request size/frequency",
            "non-TCP/UDP protocol numbers in flow records",
            "periodic beacon over transport protocol",
        ],
        "response_actions": [
            "block non-essential ICMP/raw protocols at egress",
            "inspect payloads of allowed non-app protocols",
            "isolate beaconing host",
        ],
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
            "T1571",
        ],
        "log_patterns": [
            "TLS handshake on non-443 port",
            "Destination Port unusual for the observed protocol",
            "outbound to high non-standard port sustained",
        ],
        "response_actions": [
            "enforce egress allowlist by port",
            "deep-packet-inspect protocol/port mismatches",
            "block anomalous port usage to external IPs",
        ],
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
            "T1572",
        ],
        "log_patterns": [
            "abnormally high DNS query volume to one domain",
            "long-lived SSH session with port forwarding",
            "HTTP CONNECT to arbitrary hosts",
        ],
        "response_actions": [
            "restrict and monitor DNS to approved resolvers",
            "block unauthorized tunneling/proxy use",
            "alert on DNS exfiltration heuristics",
        ],
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
            "T1090",
        ],
        "log_patterns": [
            "connections to known proxy/TOR exit nodes",
            "internal host acting as relay between others",
            "domain-fronted TLS SNI mismatch",
        ],
        "response_actions": [
            "block known proxy/TOR infrastructure",
            "investigate internal relay hosts",
            "enforce direct, logged egress paths",
        ],
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
            "T1048",
        ],
        "log_patterns": [
            "bulk outbound over FTP/SMTP to external IP",
            "DNS exfiltration with encoded subdomains",
            "off-channel data transfer to new destination",
        ],
        "response_actions": [
            "DLP inspection and block on alternative egress protocols",
            "isolate source host and scope data loss",
            "restrict outbound protocols by policy",
        ],
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
            "T1556",
        ],
        "log_patterns": [
            "modification of /etc/pam.d or security packages",
            "new auth provider registered",
            "authentication succeeding without expected factor",
        ],
        "response_actions": [
            "restore authentication config from known-good baseline",
            "rotate credentials and re-enroll MFA",
            "audit authentication module integrity",
        ],
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
            "T1212",
        ],
        "log_patterns": [
            "malformed authentication protocol requests",
            "exploit signature against LDAP/Kerberos/SMB",
            "credential-access exploit matching known CVE",
        ],
        "response_actions": [
            "patch the exploited authentication service immediately",
            "rotate domain/krbtgt credentials if DC affected",
            "block exploit source and hunt for follow-on access",
        ],
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
            "T1210",
        ],
        "log_patterns": [
            "exploit signature against internal SMB/RDP",
            "internal host triggering RCE pattern on peer",
            "lateral movement following exploitation",
        ],
        "response_actions": [
            "isolate exploited and source hosts",
            "patch vulnerable remote services network-wide",
            "enforce internal segmentation and disable legacy SMBv1",
        ],
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
            "T1570",
        ],
        "log_patterns": [
            "SMB write of executable to remote admin share",
            "internal file copy preceding execution",
            "lateral transfer of known tool hashes",
        ],
        "response_actions": [
            "block executable writes to admin shares",
            "quarantine transferred tooling and source host",
            "hunt for the tool across all endpoints",
        ],
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
            "T1133",
        ],
        "log_patterns": [
            "authentication to internet-facing VPN/RDP from anomalous geo",
            "remote service login outside business hours",
            "repeated failures then success on remote portal",
        ],
        "response_actions": [
            "enforce MFA on all external remote services",
            "geo-fence and conditional-access policies",
            "block source and review remote-access logs",
        ],
    },
    # =========================================================================
    # KỸ THUẬT CHA (parent techniques) — bổ sung 2026-07-27
    # =========================================================================
    # VÌ SAO CẦN: kho có sẵn 155 sub-technique nhưng THIẾU 37 kỹ thuật CHA của chúng.
    # Hệ quả đo được:
    #   - Lớp `Brute Force -Web` trong ground_truth kỳ vọng `T1110` — mã KHÔNG tồn tại
    #     trong kho, nên 80 mẫu không bao giờ khớp đúng được.
    #   - 12/37 mẫu thăm dò của chính dự án (zero-day / gray-zone / adversarial) trỏ tới
    #     mã cha không có trong kho (T1498, T1059, T1071.001, T1021.00x, T1074, ...).
    # Vì prompt triage dặn LLM trả `N/A` + `AWAIT_HITL` khi không khớp kỹ thuật nào trong
    # ngữ cảnh RAG, những ca này VỀ CẤU TRÚC không thể trả lời đúng — chúng đội tỉ lệ
    # AWAIT_HITL và dìm Context Precision, mà nhìn từ ngoài lại giống "LLM kém".
    #
    # Trường `tactic` dùng ĐÚNG từ vựng đang có trong kho (vd "Stealth", "Defense
    # Impairment") thay vì tên chiến thuật chuẩn của MITRE, để không tạo ra hai hệ nhãn
    # song song trong cùng một kho.
    {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems, including IP and MAC addresses, routing tables, DNS and proxy settings, to shape follow-on behaviours.",
        "detection_indicators": [
            "ipconfig/ifconfig/route/arp enumeration",
            "reading resolv.conf or proxy settings",
            "network adapter enumeration via API",
            "T1016",
        ],
        "log_patterns": [
            "process execution of ipconfig, ifconfig, route, arp, netstat",
            "burst of network-configuration commands from one host",
            "registry reads of network interface keys",
        ],
        "response_actions": [
            "correlate with subsequent lateral movement attempts",
            "baseline which hosts legitimately run network tooling",
            "alert on discovery bursts from user workstations",
        ],
    },
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into a service that accepts remote connections, such as SSH, RDP, SMB/Windows Admin Shares, VNC, or WinRM, and then act as the logged-on user to move laterally through an environment.",
        "detection_indicators": [
            "authenticated session to internal host over RDP/SSH/SMB/WinRM",
            "same account authenticating to many hosts in sequence",
            "remote service access on a relocated/non-standard port",
            "T1021",
        ],
        "log_patterns": [
            "logon type 3/10 to multiple internal hosts from one source",
            "SMB/WinRM/RDP connections fanning out across a subnet",
            "remote service traffic outside business hours",
        ],
        "response_actions": [
            "isolate source host and disable the account",
            "restrict lateral protocols with host firewall and segmentation",
            "hunt for the initial access that preceded the movement",
        ],
    },
    {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Stealth",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Running code in the context of another process may allow access to that process's memory, system resources, and elevated privileges.",
        "detection_indicators": [
            "cross-process memory write followed by remote thread creation",
            "unsigned module loaded into a signed process",
            "unexpected parent/child process relationship",
            "T1055",
        ],
        "log_patterns": [
            "OpenProcess/WriteProcessMemory/CreateRemoteThread sequence",
            "process with anomalous memory-region protections",
            "legitimate binary making unexpected network connections",
        ],
        "response_actions": [
            "capture process memory before termination",
            "isolate host and hunt for injected payload persistence",
            "enable exploit protections and driver-level telemetry",
        ],
    },
    {
        "id": "T1056",
        "name": "Input Capture",
        "tactic": "Collection",
        "description": "Adversaries may use methods of capturing user input to obtain credentials or collect information, including keylogging, GUI input capture, web portal capture, and credential API hooking.",
        "detection_indicators": [
            "keyboard hook installation",
            "credential prompt spawned by an untrusted process",
            "API hooking on authentication functions",
            "T1056",
        ],
        "log_patterns": [
            "SetWindowsHookEx or raw input device registration",
            "unexpected process reading keystroke buffers",
            "spoofed credential dialog outside logon flow",
        ],
        "response_actions": [
            "force password reset for affected users",
            "isolate host and remove hooking component",
            "enable credential guard and MFA",
        ],
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters such as PowerShell, Windows Command Shell, Unix shells, Python, JavaScript, and Visual Basic to execute arbitrary commands, scripts, or binaries, often as an interactive foothold or as part of a payload delivered by another technique.",
        "detection_indicators": [
            "interpreter spawned by a non-interactive parent (web server, office app)",
            "encoded or obfuscated command line",
            "reverse shell established from an interpreter process",
            "T1059",
        ],
        "log_patterns": [
            "powershell -enc / -nop -w hidden command lines",
            "bash -i redirected to /dev/tcp",
            "sh or cmd.exe spawned by httpd/nginx/w3wp",
        ],
        "response_actions": [
            "kill the interpreter process and isolate the host",
            "enable script block and command line logging",
            "hunt for the delivery vector that spawned the shell",
        ],
    },
    {
        "id": "T1074",
        "name": "Data Staged",
        "tactic": "Collection",
        "description": "Adversaries may stage collected data in a central location or directory prior to exfiltration, sometimes compressing or encrypting it. Staging may occur on the local system or on a remote internal host.",
        "detection_indicators": [
            "large volume of files copied into one directory",
            "archive created in a temporary or public directory",
            "internal host receiving bulk data before outbound transfer",
            "T1074",
        ],
        "log_patterns": [
            "many file reads across shares followed by a single large write",
            "archive utility invoked on a directory of collected documents",
            "unusual growth of a staging folder before outbound traffic",
        ],
        "response_actions": [
            "preserve the staging directory as evidence",
            "block outbound transfer paths before exfiltration completes",
            "identify the full scope of data collected",
        ],
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained, including password guessing, password spraying, credential stuffing, and offline password cracking.",
        "detection_indicators": [
            "high volume of failed authentications from one source",
            "single password tried across many accounts (spraying)",
            "failure burst followed by a success",
            "T1110",
        ],
        "log_patterns": [
            "repeated 4625/authentication-failure events from one IP",
            "SSH/FTP/RDP login failures at machine speed",
            "one-to-one forward/backward packet ratio on an auth port",
        ],
        "response_actions": [
            "block source IP and enforce account lockout policy",
            "require MFA and reset any account that succeeded",
            "review whether the source reached other services",
        ],
    },
    {
        "id": "T1132",
        "name": "Data Encoding",
        "tactic": "Command And Control",
        "description": "Adversaries may encode data with a standard or non-standard data encoding system to make command and control traffic more difficult to detect, such as Base64, hexadecimal, or custom character substitution.",
        "detection_indicators": [
            "long encoded strings inside HTTP parameters or headers",
            "high-entropy payload on an otherwise plaintext protocol",
            "non-standard encoding scheme in beacon traffic",
            "T1132",
        ],
        "log_patterns": [
            "base64/hex blobs in URI query strings or cookies",
            "uniform-length encoded payloads at regular intervals",
            "encoded content on a protocol that normally carries text",
        ],
        "response_actions": [
            "decode captured payloads to recover C2 commands",
            "block the C2 destination and hunt for the implant",
            "add decoding to inspection pipeline before signature matching",
        ],
    },
    {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "description": "An adversary may rely upon specific actions by a user in order to gain execution, such as opening a malicious file or link delivered via phishing. User execution often directly follows initial access and precedes further compromise.",
        "detection_indicators": [
            "office application spawning a script interpreter",
            "executable launched from a mail or browser download path",
            "user opening an archive containing an executable payload",
            "T1204",
        ],
        "log_patterns": [
            "winword.exe/excel.exe spawning powershell or cmd",
            "process started from Downloads or Temp directory",
            "double-extension or masqueraded filename executed",
        ],
        "response_actions": [
            "isolate host and preserve the delivered file",
            "block the delivery sender/domain and sweep other mailboxes",
            "disable macros and enforce attachment filtering",
        ],
    },
    {
        "id": "T1205",
        "name": "Traffic Signaling",
        "tactic": "Stealth",
        "description": "Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signalling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port.",
        "detection_indicators": [
            "port knocking sequence preceding a new listening service",
            "socket filter attached to a network interface",
            "dormant implant activating after a specific packet",
            "T1205",
        ],
        "log_patterns": [
            "ordered connection attempts to a series of closed ports",
            "raw socket or BPF filter installation on a host",
            "service appearing on a port with no prior binding event",
        ],
        "response_actions": [
            "capture full packet data around the activation",
            "isolate host and enumerate listening sockets",
            "block inbound access to the signalled port range",
        ],
    },
    {
        "id": "T1213",
        "name": "Data from Information Repositories",
        "tactic": "Collection",
        "description": "Adversaries may leverage information repositories such as wikis, ticketing systems, code repositories, and shared drives to mine valuable information, including credentials, network diagrams, and business-sensitive documents.",
        "detection_indicators": [
            "bulk read or export from a wiki, ticketing, or code repository",
            "account accessing repositories outside its normal scope",
            "search queries for credential-like keywords",
            "T1213",
        ],
        "log_patterns": [
            "mass page/attachment downloads from a knowledge base",
            "repository clone of many projects by one account",
            "API export calls at volumes far above the user baseline",
        ],
        "response_actions": [
            "revoke the account's repository tokens and sessions",
            "audit exactly which documents were accessed",
            "rotate any credentials that were stored in the repository",
        ],
    },
    {
        "id": "T1216",
        "name": "System Script Proxy Execution",
        "tactic": "Stealth",
        "description": "Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that are default on Windows installations can be used to proxy execution of other files and bypass application control.",
        "detection_indicators": [
            "signed system script invoking a remote or unusual payload",
            "cscript/wscript running a built-in script with attacker arguments",
            "application-control bypass via trusted script",
            "T1216",
        ],
        "log_patterns": [
            "PubPrn.vbs or similar system script with a remote script argument",
            "signed .vbs/.js executed with network paths",
            "script host process making outbound connections",
        ],
        "response_actions": [
            "block the abused script path via application control rules",
            "hunt for the payload the script proxied",
            "enable script block logging and constrained language mode",
        ],
    },
    {
        "id": "T1218",
        "name": "System Binary Proxy Execution",
        "tactic": "Stealth",
        "description": "Adversaries may bypass process and signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries that ship with the operating system (commonly called LOLBins).",
        "detection_indicators": [
            "signed system binary loading an unexpected remote payload",
            "rundll32/regsvr32/mshta invoking network resources",
            "certutil or bitsadmin used for file transfer",
            "T1218",
        ],
        "log_patterns": [
            "regsvr32 /i:http..., mshta http..., rundll32 javascript:",
            "certutil -urlcache -f downloading a payload",
            "trusted binary spawning a child process from a temp path",
        ],
        "response_actions": [
            "block the abused LOLBin via application control",
            "isolate host and recover the proxied payload",
            "alert on the specific command-line patterns going forward",
        ],
    },
    {
        "id": "T1222",
        "name": "File and Directory Permissions Modification",
        "tactic": "Defense Impairment",
        "description": "Adversaries may modify file or directory permissions to evade access control lists and access protected files, or to make their own artefacts harder for defenders and other users to inspect or remove.",
        "detection_indicators": [
            "chmod/chown or icacls applied to sensitive paths",
            "permissions loosened on system or log directories",
            "ownership change on defender-relevant artefacts",
            "T1222",
        ],
        "log_patterns": [
            "icacls/takeown against system directories",
            "chmod 777 or recursive chown on protected paths",
            "ACL modification events on audit or backup locations",
        ],
        "response_actions": [
            "restore intended permissions from a known-good baseline",
            "audit what was accessed while permissions were relaxed",
            "alert on permission changes to sensitive paths",
        ],
    },
    {
        "id": "T1484",
        "name": "Domain or Tenant Policy Modification",
        "tactic": "Defense Impairment",
        "description": "Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges, for example by altering Group Policy Objects or adding a rogue federated identity provider.",
        "detection_indicators": [
            "unexpected Group Policy Object creation or modification",
            "new federation trust or identity provider added to the tenant",
            "domain-wide policy change outside a change window",
            "T1484",
        ],
        "log_patterns": [
            "GPO modification events from a non-administrative workstation",
            "federation trust configuration change in tenant audit log",
            "policy change immediately followed by broad access",
        ],
        "response_actions": [
            "revert the policy change and preserve the prior version",
            "treat the whole domain/tenant as suspect and rotate keys",
            "alert on all policy and trust modifications",
        ],
    },
    {
        "id": "T1485",
        "name": "Data Destruction",
        "tactic": "Impact",
        "description": "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability. Data destruction is often irrecoverable by forensic means through overwriting files or data on local and remote drives.",
        "detection_indicators": [
            "mass file deletion or overwrite across shares",
            "secure-wipe utility execution",
            "backup or shadow copy removal preceding deletion",
            "T1485",
        ],
        "log_patterns": [
            "cipher /w, sdelete, or dd overwriting volumes",
            "high-rate delete operations on file servers",
            "destruction following successful exfiltration",
        ],
        "response_actions": [
            "isolate affected hosts immediately to halt spread",
            "restore from offline backups and verify integrity",
            "preserve forensic images before remediation",
        ],
    },
    {
        "id": "T1491",
        "name": "Defacement",
        "tactic": "Impact",
        "description": "Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Defacement may be used to deliver messaging, intimidate, or claim credit for an intrusion.",
        "detection_indicators": [
            "unauthorised modification of web root content",
            "replacement of index pages or internal portals",
            "content change with no corresponding deployment record",
            "T1491",
        ],
        "log_patterns": [
            "web root file writes outside a deployment window",
            "CMS content modification by an unexpected account",
            "integrity monitoring alerts on public-facing pages",
        ],
        "response_actions": [
            "restore content from version control and preserve the defaced copy",
            "find and close the web application entry point used",
            "review whether defacement masked a deeper compromise",
        ],
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform network denial of service attacks to degrade or block the availability of targeted resources to users, by exhausting the network bandwidth services rely on. This may be a direct flood or a reflection/amplification attack.",
        "detection_indicators": [
            "inbound bandwidth saturation from many sources",
            "extremely high packet rate with no return traffic",
            "reflection/amplification traffic from open services",
            "T1498",
        ],
        "log_patterns": [
            "very high flow packets-per-second with zero backward packets",
            "traffic volume orders of magnitude above baseline",
            "distributed sources targeting a single destination",
        ],
        "response_actions": [
            "engage upstream/ISP scrubbing rather than blocking single IPs",
            "rate-limit at the network edge and enable anti-DDoS services",
            "treat as possible cover for a concurrent intrusion",
        ],
    },
    {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform endpoint denial of service attacks to degrade or block the availability of services to users, by exhausting the system resources those services rely on such as connection tables, CPU, or memory.",
        "detection_indicators": [
            "connection table exhaustion on a service",
            "many long-lived half-open or slow connections",
            "application-layer request flood with low bandwidth",
            "T1499",
        ],
        "log_patterns": [
            "very long flow duration with very few packets (slow-rate attack)",
            "concurrent connection count far above baseline",
            "repeated expensive application requests from one source",
        ],
        "response_actions": [
            "apply per-source connection limits and timeouts",
            "alert rather than auto-block when the source may be spoofed",
            "scale or shield the targeted service",
        ],
    },
    {
        "id": "T1505",
        "name": "Server Software Component",
        "tactic": "Persistence",
        "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access, such as installing web shells, malicious server modules, transport agents, or IIS components.",
        "detection_indicators": [
            "new script file written into a web-accessible directory",
            "server module or transport agent registered unexpectedly",
            "web server process spawning a command interpreter",
            "T1505",
        ],
        "log_patterns": [
            "PHP/JSP/ASPX file created under the web root",
            "requests to an unfamiliar single-file endpoint with command parameters",
            "w3wp/httpd spawning cmd.exe or /bin/sh",
        ],
        "response_actions": [
            "remove the component and preserve it for analysis",
            "audit the full web root for additional implants",
            "patch the vulnerability that allowed the write",
        ],
    },
    {
        "id": "T1542",
        "name": "Pre-OS Boot",
        "tactic": "Stealth",
        "description": "Adversaries may abuse pre-OS boot mechanisms such as the master boot record, bootkits, firmware, or TFTP boot as a way to establish persistence and evade defenses that operate at the operating system level.",
        "detection_indicators": [
            "raw write to boot sectors or firmware regions",
            "unexpected bootloader or firmware version change",
            "persistence surviving a full OS reinstall",
            "T1542",
        ],
        "log_patterns": [
            "direct disk access to sector zero by a user-mode process",
            "firmware update event with no change record",
            "secure boot violation or integrity measurement mismatch",
        ],
        "response_actions": [
            "treat the hardware as untrusted; reflash firmware",
            "verify boot integrity measurements against known-good",
            "consider hardware replacement for confirmed bootkits",
        ],
    },
    {
        "id": "T1546",
        "name": "Event Triggered Execution",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may establish persistence and possibly elevate privileges using system mechanisms that trigger execution based on specific events, such as WMI subscriptions, shell profile modification, accessibility features, or application shims.",
        "detection_indicators": [
            "WMI permanent event subscription created",
            "shell profile or logon script modified",
            "accessibility binary replaced or debugger key set",
            "T1546",
        ],
        "log_patterns": [
            "__EventFilter/__EventConsumer creation in WMI",
            "modification of .bashrc, .profile, or logon scripts",
            "Image File Execution Options debugger registry writes",
        ],
        "response_actions": [
            "remove the trigger and identify what it launched",
            "audit all event-based execution mechanisms on the host",
            "monitor WMI subscription creation continuously",
        ],
    },
    {
        "id": "T1553",
        "name": "Subvert Trust Controls",
        "tactic": "Defense Impairment",
        "description": "Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs, for example by installing rogue root certificates, abusing code signing, or stripping mark-of-the-web.",
        "detection_indicators": [
            "new root certificate installed in the trust store",
            "invalid or suspicious code-signing certificate accepted",
            "mark-of-the-web removed from downloaded files",
            "T1553",
        ],
        "log_patterns": [
            "certificate store modification by a non-administrative process",
            "execution of a binary with a recently issued signing certificate",
            "SmartScreen or Gatekeeper bypass events",
        ],
        "response_actions": [
            "remove the rogue certificate and rebuild the trust store",
            "hunt for anything signed by the untrusted certificate",
            "alert on all trust store modifications",
        ],
    },
    {
        "id": "T1559",
        "name": "Inter-Process Communication",
        "tactic": "Execution",
        "description": "Adversaries may abuse inter-process communication mechanisms such as COM, DDE, or XPC for local code execution, allowing one process to drive execution in another and thereby blend into legitimate application behaviour.",
        "detection_indicators": [
            "office application invoking COM/DDE to spawn a process",
            "unexpected IPC endpoint created by a user process",
            "execution chain crossing process boundaries without a normal parent",
            "T1559",
        ],
        "log_patterns": [
            "DDE formula execution from a document",
            "COM object instantiation followed by process creation",
            "IPC channel usage between unrelated applications",
        ],
        "response_actions": [
            "disable DDE and restrict COM object instantiation",
            "trace the full execution chain across processes",
            "isolate host and inspect the originating document",
        ],
    },
    {
        "id": "T1560",
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration, minimising the volume sent over the network and obfuscating the content from inspection.",
        "detection_indicators": [
            "archive utility run against a staging directory",
            "password-protected or encrypted archive created",
            "compression immediately preceding outbound transfer",
            "T1560",
        ],
        "log_patterns": [
            "7z/rar/zip/tar invoked with encryption flags",
            "large archive appearing shortly before an outbound spike",
            "archive created in a temp or public directory",
        ],
        "response_actions": [
            "preserve the archive to determine what was taken",
            "block the outbound path before transfer completes",
            "alert on archiving of sensitive directories",
        ],
    },
    {
        "id": "T1565",
        "name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Adversaries may insert, delete, or manipulate data at rest, in transit, or in stored form in order to influence external outcomes or hide activity, thereby threatening the integrity rather than the availability of data.",
        "detection_indicators": [
            "unauthorised record modification in a business database",
            "log or audit entries altered or removed",
            "integrity check failure on stored data",
            "T1565",
        ],
        "log_patterns": [
            "direct database writes bypassing the application layer",
            "checksum or hash mismatch on monitored files",
            "modification of financial or transactional records off-hours",
        ],
        "response_actions": [
            "restore affected data from verified backups",
            "determine the full window of manipulation for restatement",
            "enable integrity monitoring and immutable audit logging",
        ],
    },
    {
        "id": "T1574",
        "name": "Hijack Execution Flow",
        "tactic": "Stealth",
        "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs, for example via DLL search order hijacking, path interception, or service binary replacement, gaining both persistence and privilege escalation.",
        "detection_indicators": [
            "DLL loaded from an unexpected directory adjacent to a binary",
            "service binary path modified",
            "writable directory appearing early in a search path",
            "T1574",
        ],
        "log_patterns": [
            "module loaded from a user-writable path by a system service",
            "service configuration change altering the executable path",
            "unquoted service path with a writable parent directory",
        ],
        "response_actions": [
            "restore the original binary and remove the planted module",
            "audit service paths and directory permissions",
            "enable DLL load telemetry and safe search order",
        ],
    },
    {
        "id": "T1586",
        "name": "Compromise Accounts",
        "tactic": "Resource Development",
        "description": "Adversaries may compromise accounts with services that can be used during targeting, such as social media, email, or cloud accounts, using them to build trust with a victim ahead of an operation.",
        "detection_indicators": [
            "trusted third-party account exhibiting anomalous behaviour",
            "supplier or partner mailbox sending unusual requests",
            "known-good sender suddenly delivering malicious content",
            "T1586",
        ],
        "log_patterns": [
            "inbound mail from a trusted partner with anomalous attachments",
            "compromised vendor account initiating access requests",
            "credential reuse from a third-party breach corpus",
        ],
        "response_actions": [
            "verify requests out of band before acting",
            "notify the partner organisation of the suspected compromise",
            "apply additional scrutiny to that sender for a period",
        ],
    },
    {
        "id": "T1587",
        "name": "Develop Capabilities",
        "tactic": "Resource Development",
        "description": "Adversaries may build capabilities that can be used during targeting, such as malware, exploits, code signing certificates, or digital certificates, rather than purchasing or stealing them.",
        "detection_indicators": [
            "previously unseen malware family with no public signature",
            "certificate issued to a fictitious organisation",
            "custom tooling tailored to the victim environment",
            "T1587",
        ],
        "log_patterns": [
            "binary with zero reputation and no vendor detections",
            "self-signed or newly issued certificate on delivered code",
            "exploit targeting an environment-specific configuration",
        ],
        "response_actions": [
            "preserve samples and share indicators with the community",
            "prioritise behaviour-based rather than signature-based detection",
            "assume targeted intent and widen the investigation scope",
        ],
    },
    {
        "id": "T1591",
        "name": "Gather Victim Org Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may gather information about the victim's organisation that can be used during targeting, including physical locations, business relationships, operating tempo, and the roles and identities of key staff.",
        "detection_indicators": [
            "systematic scraping of organisational pages",
            "enumeration of staff directories or org charts",
            "queries for supplier and partner relationships",
            "T1591",
        ],
        "log_patterns": [
            "sequential access to staff or contact pages from one source",
            "automated retrieval of corporate documents",
            "external searches correlating employees to roles",
        ],
        "response_actions": [
            "minimise sensitive organisational detail exposed publicly",
            "brief high-profile staff on targeted social engineering",
            "monitor for follow-on phishing using the gathered detail",
        ],
    },
    {
        "id": "T1596",
        "name": "Search Open Technical Databases",
        "tactic": "Reconnaissance",
        "description": "Adversaries may search freely available technical databases such as DNS/passive DNS, WHOIS, digital certificates, CDN records, and scan databases for information about victims that can be used during targeting.",
        "detection_indicators": [
            "certificate transparency monitoring of the organisation's domains",
            "passive DNS and WHOIS lookups preceding an attack",
            "appearance of assets in public scan databases",
            "T1596",
        ],
        "log_patterns": [
            "newly issued certificates for lookalike domains",
            "external enumeration of subdomains",
            "internet-wide scanners indexing exposed services",
        ],
        "response_actions": [
            "monitor certificate transparency for lookalike domains",
            "reduce information disclosed in WHOIS and DNS records",
            "inventory and shield internet-exposed assets",
        ],
    },
    {
        "id": "T1597",
        "name": "Search Closed Sources",
        "tactic": "Reconnaissance",
        "description": "Adversaries may search and gather information about victims from closed or paid sources, such as threat intelligence vendors, private data brokers, and criminal marketplaces selling stolen credentials or access.",
        "detection_indicators": [
            "organisational credentials appearing in breach corpora",
            "access to the environment advertised for sale",
            "targeted intelligence not available from public sources",
            "T1597",
        ],
        "log_patterns": [
            "credential stuffing using credentials never publicly leaked",
            "attacker knowledge of internal naming conventions",
            "initial access consistent with purchased access",
        ],
        "response_actions": [
            "subscribe to breach and dark-web monitoring for the domain",
            "force rotation of any credentials found for sale",
            "assume valid-account access and audit accordingly",
        ],
    },
    {
        "id": "T1598",
        "name": "Phishing for Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Unlike phishing for initial access, this variant seeks information rather than execution.",
        "detection_indicators": [
            "message soliciting credentials or organisational detail",
            "spoofed internal sender requesting verification of information",
            "link to a credential-harvesting page with no payload",
            "T1598",
        ],
        "log_patterns": [
            "inbound mail with a spoofed internal display name",
            "user submitting credentials to an external lookalike domain",
            "reply-to address inconsistent with the sender domain",
        ],
        "response_actions": [
            "reset credentials for any user who responded",
            "block the harvesting domain and sweep other recipients",
            "reinforce out-of-band verification procedures",
        ],
    },
    {
        "id": "T1606",
        "name": "Forge Web Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may forge credential materials such as web cookies or SAML tokens that can be used to access web applications and internet services, bypassing the normal authentication process entirely.",
        "detection_indicators": [
            "session token accepted without a corresponding authentication event",
            "SAML assertion signed by an unexpected key",
            "JWT with a weakened or absent signature algorithm",
            "T1606",
        ],
        "log_patterns": [
            "alg=none or unsigned token presented to an application",
            "application access with no preceding identity provider logon",
            "cookie reuse from a geographically impossible location",
        ],
        "response_actions": [
            "revoke all sessions and rotate token signing keys",
            "audit application access that bypassed the identity provider",
            "enforce short token lifetimes and signature validation",
        ],
    },
    {
        "id": "T1608",
        "name": "Stage Capabilities",
        "tactic": "Resource Development",
        "description": "Adversaries may upload, install, or otherwise set up capabilities on infrastructure under their control that can be used during targeting, such as staging malware, exploits, or credential-harvesting pages.",
        "detection_indicators": [
            "payload hosted on newly registered infrastructure",
            "credential-harvesting page impersonating the organisation",
            "staging server referenced by delivered content",
            "T1608",
        ],
        "log_patterns": [
            "outbound requests to a recently registered domain",
            "download of a payload from attacker-controlled hosting",
            "lookalike domain serving a cloned login page",
        ],
        "response_actions": [
            "block and sinkhole the staging infrastructure",
            "request takedown of impersonating content",
            "hunt for hosts that already retrieved the staged payload",
        ],
    },
    # T1685/T1686: kỹ thuật CHA của nhóm sub-technique vô hiệu hoá phòng thủ đã có sẵn
    # trong kho (Disable or Modify Windows Event Log / Cloud Log / Linux Audit / Windows
    # Host Firewall). Tên đặt theo đúng tập sub-technique của chúng.
    {
        "id": "T1685",
        "name": "Disable or Modify Logging",
        "tactic": "Defense Impairment",
        "description": "Adversaries may disable or modify logging capabilities to limit the data available for detection and audit, covering host event logs, cloud logging integrations, and platform audit subsystems.",
        "detection_indicators": [
            "audit or event logging service stopped or reconfigured",
            "cloud logging integration disabled or diverted",
            "log retention or forwarding silently reduced",
            "T1685",
        ],
        "log_patterns": [
            "wevtutil cl, auditpol /clear, or auditd configuration changes",
            "cloud trail/diagnostic setting deleted or paused",
            "sudden gap in expected telemetry from a host",
        ],
        "response_actions": [
            "treat telemetry gaps as active-intrusion indicators",
            "restore logging configuration and forward to immutable storage",
            "alert on any logging-service modification in real time",
        ],
    },
    # ── Bổ sung đợt 2: các mã mà chính bộ thăm dò của dự án trỏ tới nhưng kho chưa có.
    # Khác đợt trên (kỹ thuật CHA bị thiếu), đây chủ yếu là SUB-TECHNIQUE cụ thể mà
    # ZD/GZ/ADV specs dùng làm nhãn kỳ vọng — thiếu chúng thì những ca đó không thể chấm
    # đúng dù bộ ánh xạ hoạt động hoàn hảo.
    {
        "id": "T1102",
        "name": "Web Service",
        "tactic": "Command And Control",
        "description": "Adversaries may use an existing, legitimate external web service as a means for relaying data to or from a compromised system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to being commonly visited before or during a compromise.",
        "detection_indicators": [
            "beaconing to a legitimate cloud or social platform",
            "C2 traffic blended into normally allowed web destinations",
            "regular polling of a public paste or repository service",
            "T1102",
        ],
        "log_patterns": [
            "periodic requests to a public web service with uniform sizing",
            "long-lived connection to a legitimate domain from a server host",
            "traffic to a web service inconsistent with the host's role",
        ],
        "response_actions": [
            "block the specific service endpoint rather than the whole domain",
            "hunt for the implant polling the service",
            "baseline which hosts legitimately reach external web services",
        ],
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command And Control",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic (HTTP/HTTPS) to avoid detection by blending in with existing traffic. Commands are embedded in the protocol traffic between client and server.",
        "detection_indicators": [
            "HTTP/HTTPS beaconing at a fixed cadence",
            "web requests with anomalous user-agent or URI structure",
            "long-lived web session carrying command traffic",
            "T1071.001",
        ],
        "log_patterns": [
            "uniform-interval outbound HTTP requests with small responses",
            "POST bodies with encoded content to a single endpoint",
            "web traffic to a destination with no browsing context",
        ],
        "response_actions": [
            "block the C2 destination and capture full request bodies",
            "hunt for the implant on the beaconing host",
            "apply jitter-tolerant beacon detection on egress",
        ],
    },
    {
        "id": "T1021.001",
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into a computer using the Remote Desktop Protocol, then act as the logged-on user to move laterally, often after harvesting credentials from an initial foothold.",
        "detection_indicators": [
            "RDP session to an internal host from a workstation",
            "RDP exposed or relocated to a non-standard port",
            "interactive logon outside business hours",
            "T1021.001",
        ],
        "log_patterns": [
            "logon type 10 events across multiple internal hosts",
            "RDP traffic on a port other than 3389",
            "one account opening RDP sessions to many machines",
        ],
        "response_actions": [
            "disable the account and terminate active sessions",
            "restrict RDP to jump hosts and enforce MFA",
            "hunt for credential theft that preceded the movement",
        ],
    },
    {
        "id": "T1021.002",
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to interact with a remote network share using Server Message Block, then perform actions as the logged-on user, commonly abusing hidden administrative shares such as C$ and ADMIN$.",
        "detection_indicators": [
            "access to hidden administrative shares from a workstation",
            "file written to a remote host's ADMIN$ before service creation",
            "SMB authentication relay attempts between servers",
            "T1021.002",
        ],
        "log_patterns": [
            "share access events for C$/ADMIN$/IPC$ across many hosts",
            "remote file write followed by remote service start",
            "NTLM relay indicators on file server logs",
        ],
        "response_actions": [
            "block SMB between workstations via host firewall",
            "require SMB signing to defeat relay attacks",
            "audit which hosts the account reached",
        ],
    },
    {
        "id": "T1021.006",
        "name": "Windows Remote Management",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to interact with remote systems using Windows Remote Management (WinRM), a service that allows a user to interact with a remote system and execute commands, often blending with legitimate administration.",
        "detection_indicators": [
            "WinRM command execution fanning out to several hosts",
            "wsmprovhost.exe spawning unexpected child processes",
            "remote PowerShell session from a non-administrative host",
            "T1021.006",
        ],
        "log_patterns": [
            "WinRM connections on ports 5985/5986 across a subnet",
            "wsmprovhost.exe as parent of cmd.exe or script interpreters",
            "remote PowerShell sessions outside a change window",
        ],
        "response_actions": [
            "restrict WinRM to designated management hosts",
            "disable the account and review commands executed remotely",
            "enable PowerShell script block and transcription logging",
        ],
    },
    {
        "id": "T1567.002",
        "name": "Exfiltration to Cloud Storage",
        "tactic": "Exfiltration",
        "description": "Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel, blending the transfer with normal cloud usage and avoiding volume limits on the C2 channel.",
        "detection_indicators": [
            "bulk upload to a cloud storage provider not used by the organisation",
            "archive transferred outbound to a personal storage account",
            "large egress to a storage API from a server host",
            "T1567.002",
        ],
        "log_patterns": [
            "sustained outbound transfer to a cloud storage endpoint",
            "compressed database dump uploaded to third-party storage",
            "storage API traffic from a host with no business need",
        ],
        "response_actions": [
            "block unsanctioned cloud storage destinations at egress",
            "determine exactly what was uploaded and notify data owners",
            "enforce DLP on outbound archives",
        ],
    },
    {
        "id": "T1686",
        "name": "Disable or Modify Firewall",
        "tactic": "Defense Impairment",
        "description": "Adversaries may disable or modify host or cloud firewall rules to bypass controls limiting network usage, enabling command and control channels or lateral movement that policy would otherwise block.",
        "detection_indicators": [
            "host firewall disabled or profile turned off",
            "permissive inbound rule added for an unusual port",
            "cloud security group opened to the internet",
            "T1686",
        ],
        "log_patterns": [
            "netsh advfirewall set ... state off, or iptables -F",
            "new allow rule created immediately before outbound C2",
            "security group ingress opened to 0.0.0.0/0",
        ],
        "response_actions": [
            "restore firewall policy from configuration management",
            "investigate traffic permitted during the exposure window",
            "alert on all firewall state and rule modifications",
        ],
    },
]

ALL_NIST = [
    {
        "control": "NIST.IR.RANSOMWARE",
        "name": "Ransomware Incident Response Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for ransomware (MITRE T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery, T1489 Service Stop) where data is encrypted for extortion.",
        "applicability": "Relevant when detecting rapid mass file encryption, ransom notes, shadow-copy/backup deletion, or service-stop activity preceding encryption.",
        "response_guidance": "DETECTION & ANALYSIS: Identify patient-zero, encryption scope, and ransomware family. CONTAINMENT: Immediately isolate affected hosts from the network (keep powered on for forensics), block spread via SMB/admin shares, and disable affected accounts. ERADICATION & RECOVERY: Remove the ransomware, rebuild encrypted hosts, and restore from OFFLINE/immutable backups (do NOT pay). POST-INCIDENT: Close the initial-access vector, enforce offline backups + EDR, and segment to limit blast radius.",
    },
    {
        "control": "NIST.IR.CREDACCESS",
        "name": "Credential Theft & Dumping Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for credential access (MITRE T1003 OS Credential Dumping, T1555 Password Stores, T1552 Unsecured Credentials, T1557 AiTM) where account secrets are stolen.",
        "applicability": "Relevant when detecting LSASS/SAM/shadow access, credential-store reads, ARP/LLMNR poisoning, or use of cracked/dumped credentials.",
        "response_guidance": "DETECTION & ANALYSIS: Determine which credentials were exposed and how. CONTAINMENT: Force-reset and revoke sessions for all exposed accounts, enforce MFA, and isolate the dumping host. ERADICATION & RECOVERY: Rotate service/domain credentials (krbtgt twice if DC affected), enable Credential Guard, and remove the dumping tooling. POST-INCIDENT: Deploy LSASS protection, disable LLMNR/NBT-NS, and monitor for pass-the-hash/ticket.",
    },
    {
        "control": "NIST.IR.WEBSHELL",
        "name": "Web Shell & Server Backdoor Playbook",
        "domain": "Incident Response Life Cycle",
        "description": "Playbook for web shells / server software component backdoors (MITRE T1505.003) providing persistent command execution on web servers.",
        "applicability": "Relevant when detecting suspicious files in web roots, command execution via HTTP parameters, or web servers spawning shells.",
        "response_guidance": "DETECTION & ANALYSIS: Locate the web shell file(s) and review web/access logs for the upload vector and commands executed. CONTAINMENT: Quarantine the web shell, block the attacker IP at the WAF, and take the affected app offline if active compromise. ERADICATION & RECOVERY: Patch the exploited web vulnerability, audit web-root integrity, and rebuild if backdoors are widespread. POST-INCIDENT: Add file-integrity monitoring on web roots and WAF rules for the exploit.",
    },
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


def _load(path):
    with open(path, encoding="utf-8") as f:
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

    print(
        f"[MITRE] +{added_m} ky thuat (tong {len(mitre)})".replace(
            "ky thuat", "k\u1ef9 thu\u1eadt"
        ).replace("tong", "t\u1ed5ng")
    )
    print(f"[NIST]  +{added_n} playbook (tong {len(controls)})".replace("tong", "t\u1ed5ng"))
    return added_m, added_n


def main():
    ap = argparse.ArgumentParser(description="Xay dung/mo rong tri thuc RAG trong 1 lan")
    ap.add_argument(
        "--no-index",
        action="store_true",
        help="Chi mo rong KB JSON, KHONG rebuild FAISS/BM25 index",
    )
    args = ap.parse_args()

    print("=== [1/2] Mo rong tri thuc (MITRE ATT&CK + NIST SP 800-61r2) ===")
    added_m, added_n = extend_knowledge_base()

    if args.no_index:
        print("\n[!] Bo qua rebuild index (--no-index).")
        if added_m or added_n:
            print(
                "[!] CANH BAO: KB da doi nhung checksum CHUA duoc niem phong lai -> "
                "DualRetriever se TU CHOI khoi dong. Chay lai KHONG co --no-index."
            )
        return

    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from src.rag.embedder import build_all_indexes, update_checksums_file

    # NIEM PHONG LAI checksum nguon TRUOC khi build index.
    #
    # VI SAO CAN: `build_all_indexes()` tu kiem tra toan ven KB va NEM LOI neu checksum
    # lech (chot chong dau doc RAG). Nhung `extend_knowledge_base()` vua sua KB mot cach
    # HOP LE -> checksum chac chan lech -> script tu chan chinh no. Truoc day day la be
    # tac: khong the mo rong KB roi rebuild index trong cung mot lan chay.
    #
    # AN TOAN: chot toan ven bao ve DUONG CHAY (DualRetriever doc KB da niem phong). Cong
    # cu nay CHINH LA duong sua doi hop phap duy nhat, nen viec no tu niem phong lai sau
    # khi sua la dung vai tro. Ke tan cong sua tay file KB van bi chan o runtime.
    # Dieu kien la "checksum CO LECH khong", KHONG phai "lan chay NAY co them gi khong":
    # mot lan chay truoc bi dut giua chung (da ghi KB, chua kip build index) se de lai KB
    # moi voi checksum cu, va khi do added_m = 0 nen kiem tra theo added_* se bo sot.
    from src.rag.security import verify_document_integrity

    if not verify_document_integrity(exclude_generated=True)["verified"]:
        print(
            f"\n=== [2/3] Niem phong lai checksum nguon (KB da doi; lan nay +{added_m}/+{added_n}) ==="
        )
        update_checksums_file()

    print("\n=== [3/3] Rebuild FAISS + BM25 index + checksum ===")
    build_all_indexes()
    update_checksums_file()  # niem phong ca file nguon LAN index vua sinh
    print("\nDone: tri thuc da mo rong + index/checksum da rebuild (1 lan xay dung).")


if __name__ == "__main__":
    main()
