# SOC Threat Intelligence & Alert Analysis Dashboard

**Third-year university project — educational use only.**

This repository is a Year 3 capstone for the BSc in Cybercrime & IT Security at South East Technological University (SETU), Carlow. It is a self-hosted training application that lets students practise Security Operations Center (SOC) alert triage in a safe, simulated environment.

It is an educational project. The alerts, evidence, and threat-intelligence results are training scenarios (with optional live VirusTotal lookups). This software is not a production SOC platform, and it is not intended for monitoring or responding to real incidents.

مشروع تعليمي للسنة الثالثة في الجامعة. الهدف منه تدريب الطلاب على فرز التنبيهات الأمنية داخل بيئة محاكاة، وليس استخدامه كنظام أمني حقيقي.

Interactive SOC analyst training platform built with Flask. Simulates real-world alert triage with VirusTotal integration and MITRE ATT&CK mapping.

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure environment
Copy `.env.example` to `.env` and add your VirusTotal API key (optional):
```bash
copy .env.example .env
```

Edit `.env`:
```
VIRUSTOTAL_API_KEY=your_key_here
```

Get a free API key at: https://www.virustotal.com/gui/join-us

**Note:** If no API key is provided, the app uses realistic mock data automatically.

### 3. Run the app
```bash
python app.py
```

Open http://localhost:5000 in your browser.

## Features

- User authentication with hashed passwords
- 15 realistic SOC alert scenarios (Easy/Medium/Hard)
- VirusTotal API integration with mock fallback
- MITRE ATT&CK mapping
- Interactive triage workflow with decision evaluation
- Quiz system with sound and visual feedback
- Scoreboard with leaderboard
- Printable performance reports

## Troubleshooting

**Reset database:**
```bash
del soc_dashboard.db
python app.py
```

## Author

Munzer Elsarafandi (C00281934)  
SETU Carlow — 3rd Year Cybercrime & IT Security Project
