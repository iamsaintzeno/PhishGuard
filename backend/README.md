# PhishGuard Backend API 🛡️

Backend REST API for **PhishGuard: Phishing URL Detector**.

This service accepts suspicious URLs, runs multi-point heuristic phishing detection algorithms, checks against a Supabase-backed malicious domain blocklist, stores scan records, and serves scan history.

---

## 📋 Features

- **7-Point Phishing Detection Engine**:
  - `No HTTPS` (+20 points)
  - `IP address instead of domain` (+30 points)
  - `URL longer than 100 characters` (+10 points)
  - `Suspicious keyword present` (+10 points)
  - `More than 2 subdomains` (+15 points)
  - `'@' symbol` (+20 points)
  - `Domain in blocklist` (+50 points)
- **Supabase Integration**:
  - `blocklist` table: lookup malicious domains
  - `scans` table: persistence of scans with `reasons` stored as `jsonb` array
  - Built-in graceful local fallback when Supabase keys are pending
- **CORS Enabled**: Compatible with all frontend dev servers (`localhost:3000`, `localhost:5173`, etc.)

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Open `.env` and fill in your Supabase project keys (provided by the Database team):
```env
PORT=5000
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=your-supabase-anon-or-service-role-key
```
*(Note: If left empty, the server automatically boots in in-memory fallback mode for local testing).*

### 3. Start Server
```bash
# Start production server
npm start

# Or start with live reload
npm run dev
```

The server will be available at: **`http://localhost:5000`**

---

## 📡 API Endpoints

### 1. Scan a URL
- **Method**: `POST`
- **Path**: `/api/scan`
- **Request Body**:
```json
{
  "url": "http://fake-bank.com/login"
}
```

- **Response Body (`200 OK`)**:
```json
{
  "id": 1,
  "url": "http://fake-bank.com/login",
  "score": 80,
  "verdict": "Dangerous",
  "reasons": [
    "No HTTPS",
    "Suspicious keyword: bank",
    "Suspicious keyword: login",
    "Domain found in blocklist"
  ],
  "created_at": "2026-10-08T10:30:00.000Z"
}
```

### 2. Get Scan History
- **Method**: `GET`
- **Path**: `/api/scans` (or `/api/history`)
- **Query Params**: `?limit=50` (optional)
- **Response (`200 OK`)**:
```json
[
  {
    "id": 1,
    "url": "http://fake-bank.com/login",
    "score": 80,
    "verdict": "Dangerous",
    "reasons": [
      "No HTTPS",
      "Suspicious keyword: bank",
      "Domain found in blocklist"
    ],
    "created_at": "2026-10-08T10:30:00.000Z"
  }
]
```

### 3. Health Check
- **Method**: `GET`
- **Path**: `/api/health`
- **Response (`200 OK`)**:
```json
{
  "status": "online",
  "service": "PhishGuard API",
  "database": {
    "provider": "supabase_live",
    "isConfigured": true
  }
}
```

---

## 🧪 Testing

Run automated tests:
```bash
npm test
```
