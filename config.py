"""
Application configuration.
============================
Reads sensitive values (API keys, secret key) from a local .env file
that is excluded from version control via .gitignore. Falls back to
safe defaults for development if a value is not set.
"""

import os
from dotenv import load_dotenv

# Load variables from .env into os.environ so os.environ.get() can read them
load_dotenv()


class Config:
    # Flask uses this to sign session cookies — must be changed in production
    SECRET_KEY = os.environ.get('SECRET_KEY', 'soc-dashboard-secret-key-change-in-production')

    # SQLAlchemy URL (kept for compatibility — the project uses raw sqlite3)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///soc_dashboard.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # VirusTotal API key — leave blank to use mock data only
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
