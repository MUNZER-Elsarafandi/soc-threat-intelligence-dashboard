"""
MITRE ATT&CK Framework mapping service.
====================================================
This module provides metadata for the tactics and techniques used by
each alert in the dashboard.

Why local data instead of an API?
- The MITRE ATT&CK framework is published as static JSON; it changes
  only when MITRE issues a new version (a few times a year).
- Bundling the small subset we use avoids an extra network dependency
  and keeps the dashboard fast and offline-friendly.

Reference: https://attack.mitre.org/
"""

# ----- Tactics dictionary -----
# Tactics are the "why" of an attack: the adversary's tactical goal at
# a given point in the attack chain (e.g. Initial Access, Execution,
# Exfiltration). Each alert is mapped to one tactic.
MITRE_TACTICS = {
    "Initial Access": {"id": "TA0001", "description": "The adversary is trying to get into your network.", "url": "https://attack.mitre.org/tactics/TA0001/"},
    "Execution": {"id": "TA0002", "description": "The adversary is trying to run malicious code.", "url": "https://attack.mitre.org/tactics/TA0002/"},
    "Credential Access": {"id": "TA0006", "description": "The adversary is trying to steal account credentials.", "url": "https://attack.mitre.org/tactics/TA0006/"},
    "Lateral Movement": {"id": "TA0008", "description": "The adversary is trying to move through your environment.", "url": "https://attack.mitre.org/tactics/TA0008/"},
    "Exfiltration": {"id": "TA0010", "description": "The adversary is trying to steal data.", "url": "https://attack.mitre.org/tactics/TA0010/"},
    "Command and Control": {"id": "TA0011", "description": "The adversary is trying to communicate with compromised systems.", "url": "https://attack.mitre.org/tactics/TA0011/"},
}

# ----- Techniques dictionary -----
# Techniques are the "how": the specific method the adversary uses.
# Each technique has a Tnnnn identifier, a description, and a list
# of suggested mitigations drawn from MITRE's published guidance.
MITRE_TECHNIQUES = {
    "T1110": {"name": "Brute Force", "description": "Adversaries may use brute force techniques to gain access to accounts.", "url": "https://attack.mitre.org/techniques/T1110/", "mitigations": ["Account Lockout Policies", "Multi-Factor Authentication", "Password Policies"]},
    "T1204": {"name": "User Execution", "description": "An adversary may rely upon specific actions by a user to gain execution.", "url": "https://attack.mitre.org/techniques/T1204/", "mitigations": ["User Training", "Execution Prevention", "Restrict Web-Based Content"]},
    "T1566": {"name": "Phishing", "description": "Adversaries may send phishing messages to gain access to victim systems.", "url": "https://attack.mitre.org/techniques/T1566/", "mitigations": ["User Training", "Anti-Spoofing", "Email Filtering"]},
    "T1071": {"name": "Application Layer Protocol", "description": "Adversaries may communicate using application layer protocols to avoid detection.", "url": "https://attack.mitre.org/techniques/T1071/", "mitigations": ["Network Intrusion Prevention", "Network Segmentation", "SSL/TLS Inspection"]},
    "T1059": {"name": "Command and Scripting Interpreter", "description": "Adversaries may abuse command and script interpreters to execute malicious commands.", "url": "https://attack.mitre.org/techniques/T1059/", "mitigations": ["Code Signing", "Disable or Remove Feature", "Execution Prevention"]},
    "T1021": {"name": "Remote Services", "description": "Adversaries may use valid accounts to log into remote services.", "url": "https://attack.mitre.org/techniques/T1021/", "mitigations": ["MFA", "Network Segmentation", "Limit Remote Access"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.", "url": "https://attack.mitre.org/techniques/T1041/", "mitigations": ["Data Loss Prevention", "Network Segmentation", "Traffic Monitoring"]},
    "T1190": {"name": "Exploit Public-Facing Application", "description": "Adversaries may exploit a weakness in an Internet-facing application.", "url": "https://attack.mitre.org/techniques/T1190/", "mitigations": ["Vulnerability Scanning", "Patch Management", "WAF"]},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "description": "Adversaries may steal data using a protocol other than the existing C2 channel.", "url": "https://attack.mitre.org/techniques/T1048/", "mitigations": ["DNS Monitoring", "Network Segmentation", "Filter Network Traffic"]},
}


def get_tactic_info(tactic_name):
    """Return metadata for a tactic by name, or None if not found."""
    return MITRE_TACTICS.get(tactic_name, None)


def get_technique_info(technique_id):
    """Return metadata for a technique by its Tnnnn identifier."""
    return MITRE_TECHNIQUES.get(technique_id, None)
