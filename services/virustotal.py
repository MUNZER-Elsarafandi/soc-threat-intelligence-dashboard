"""
VirusTotal API integration for threat intelligence enrichment.
Free API: 4 requests/minute, 500 requests/day

Mock data is always used for known training scenario IPs/hashes,
even when an API key is configured, to ensure consistent demo behaviour.
"""

import requests
from config import Config

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def get_headers():
    return {"x-apikey": Config.VIRUSTOTAL_API_KEY, "Accept": "application/json"}


def lookup_ip(ip_address):
    # Always use mock data for known training scenario IPs
    if ip_address in _MOCK_IP_DB:
        return _MOCK_IP_DB[ip_address]

    # Fall back to mock for any IP if no API key
    if not Config.VIRUSTOTAL_API_KEY:
        return _mock_ip_data(ip_address)

    # Real API for everything else
    try:
        url = f"{VT_BASE_URL}/ip_addresses/{ip_address}"
        response = requests.get(url, headers=get_headers(), timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "ip": ip_address, "country": data.get("country", "Unknown"),
                "as_owner": data.get("as_owner", "Unknown"),
                "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0), "source": "VirusTotal API"
            }
        return {"error": f"API returned status {response.status_code}", "ip": ip_address}
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "ip": ip_address}


def lookup_hash(file_hash):
    # Always use mock for the known training hash
    if file_hash in _MOCK_HASH_DB:
        return _MOCK_HASH_DB[file_hash]

    if not Config.VIRUSTOTAL_API_KEY:
        return _mock_hash_data(file_hash)

    try:
        url = f"{VT_BASE_URL}/files/{file_hash}"
        response = requests.get(url, headers=get_headers(), timeout=10)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "hash": file_hash, "file_name": data.get("meaningful_name", "Unknown"),
                "file_type": data.get("type_description", "Unknown"),
                "file_size": data.get("size", 0),
                "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0), "undetected": stats.get("undetected", 0),
                "popular_threat_name": data.get("popular_threat_classification", {}).get("suggested_threat_label", "Unknown"),
                "source": "VirusTotal API"
            }
        return {"error": f"API returned status {response.status_code}", "hash": file_hash}
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "hash": file_hash}


# ============ MOCK DATA FOR TRAINING SCENARIOS ============
# These IPs/hashes are referenced in the seeded alerts. Mock data is always
# returned for them so the training scenarios are consistent and educational.

_MOCK_IP_DB = {
    "185.220.101.34": {"ip": "185.220.101.34", "country": "DE", "as_owner": "Tor Exit Node - Zwiebelfreunde e.V.", "malicious": 42, "suspicious": 5, "harmless": 18, "undetected": 12, "reputation": -87, "source": "Training Mock Data"},
    "203.0.113.50": {"ip": "203.0.113.50", "country": "RU", "as_owner": "Bulletproof Hosting Ltd.", "malicious": 56, "suspicious": 8, "harmless": 5, "undetected": 8, "reputation": -95, "source": "Training Mock Data"},
    "198.51.100.78": {"ip": "198.51.100.78", "country": "NG", "as_owner": "Unknown ISP", "malicious": 28, "suspicious": 12, "harmless": 22, "undetected": 15, "reputation": -62, "source": "Training Mock Data"},
    "192.0.2.100": {"ip": "192.0.2.100", "country": "CN", "as_owner": "AS4134 ChinaNet", "malicious": 38, "suspicious": 7, "harmless": 15, "undetected": 17, "reputation": -78, "source": "Training Mock Data"},
    "198.51.100.200": {"ip": "198.51.100.200", "country": "KP", "as_owner": "Star Joint Venture Co.", "malicious": 61, "suspicious": 3, "harmless": 2, "undetected": 11, "reputation": -99, "source": "Training Mock Data"},
    "104.21.45.12": {"ip": "104.21.45.12", "country": "US", "as_owner": "Cloudflare Inc.", "malicious": 3, "suspicious": 2, "harmless": 55, "undetected": 17, "reputation": -12, "source": "Training Mock Data"},
    "203.0.113.88": {"ip": "203.0.113.88", "country": "CN", "as_owner": "AS4837 China Unicom", "malicious": 31, "suspicious": 9, "harmless": 12, "undetected": 18, "reputation": -71, "source": "Training Mock Data"},
    "185.234.72.11": {"ip": "185.234.72.11", "country": "RU", "as_owner": "Hosting Solutions LLC", "malicious": 49, "suspicious": 6, "harmless": 8, "undetected": 14, "reputation": -88, "source": "Training Mock Data"},
    "45.33.32.156": {"ip": "45.33.32.156", "country": "US", "as_owner": "Linode LLC (Compromised VPS)", "malicious": 35, "suspicious": 11, "harmless": 14, "undetected": 16, "reputation": -68, "source": "Training Mock Data"},
    "198.51.100.23": {"ip": "198.51.100.23", "country": "Unknown", "as_owner": "Spoofed origin (phishing)", "malicious": 24, "suspicious": 8, "harmless": 18, "undetected": 26, "reputation": -45, "source": "Training Mock Data"},
    "198.51.100.53": {"ip": "198.51.100.53", "country": "PA", "as_owner": "Privacy-Protected Hosting", "malicious": 38, "suspicious": 14, "harmless": 6, "undetected": 18, "reputation": -82, "source": "Training Mock Data"},
}

_MOCK_HASH_DB = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_name": "invoice_update.exe", "file_type": "Win32 EXE", "file_size": 245760,
        "malicious": 48, "suspicious": 4, "harmless": 8, "undetected": 17,
        "popular_threat_name": "trojan.emotet/heodo", "source": "Training Mock Data"
    },
    "7a2b1f4c8e9d3a5b6c0f1e2d4a8b7c9e": {
        "hash": "7a2b1f4c8e9d3a5b6c0f1e2d4a8b7c9e",
        "file_name": "payload.exe", "file_type": "Win32 EXE", "file_size": 348160,
        "malicious": 52, "suspicious": 3, "harmless": 6, "undetected": 16,
        "popular_threat_name": "trojan.cobaltstrike", "source": "Training Mock Data"
    },
}


def _mock_ip_data(ip_address):
    return _MOCK_IP_DB.get(ip_address, {
        "ip": ip_address, "country": "Unknown", "as_owner": "Unknown",
        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        "reputation": 0, "source": "Mock Data (No API Key)"
    })


def _mock_hash_data(file_hash):
    return _MOCK_HASH_DB.get(file_hash, {
        "hash": file_hash, "file_name": "unknown_sample.exe", "file_type": "Win32 EXE",
        "file_size": 245760, "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        "popular_threat_name": "Unknown", "source": "Mock Data (No API Key)"
    })
