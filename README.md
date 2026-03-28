# Phishara — Phishing Detection & Analysis Platform

A full-stack cybersecurity platform for detecting phishing in URLs, emails, and phone numbers.

## Quick Start

### 1. Backend (FastAPI)

```bash
cd phishara/backend
python -m venv venv
# Windows: venv\Scripts\activate  |  Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys (optional — works without them)
python run.py
# API running at http://localhost:8000
```

> Uses SQLite by default. For MySQL, set `DATABASE_URL` in `.env`.

### 2. Frontend (React)

```bash
cd phishara/frontend
npm install
npm start
# App running at http://localhost:3000
```

### 3. Chrome Extension

1. Open Chrome → `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" → select `phishara/extension/`
4. Extension is now active

## API Keys (Optional but recommended)

| Key | Where to get |
|-----|-------------|
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| `GOOGLE_SAFE_BROWSING_API_KEY` | https://console.cloud.google.com |

## Architecture

```
Browser Extension (MV3)
        ↓
React Frontend (port 3000)
        ↓
FastAPI Backend (port 8000)
        ↓
SQLite / MySQL + Threat Intel APIs
```

## Detection Layers

- URL: WHOIS, DNS, SSL, redirect chain, HTML/form analysis, keyword matching
- Email: MX/SPF/DMARC records, disposable domain check, body analysis
- Phone: phonenumbers validation, VoIP detection, urgency keyword analysis
- Threat Intel: VirusTotal, Google Safe Browsing (when API keys provided)

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Scan a URL, email, or phone |
| GET | `/api/history` | Scan history |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/scan/{id}` | Get scan by ID |
| GET | `/api/report/{id}?fmt=json\|pdf` | Download report |
