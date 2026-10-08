# PhishGuard - Phishing URL Detector

PhishGuard is a web app that helps users check whether a suspicious URL is likely to be safe, suspicious, or dangerous. The user pastes a URL, the app runs basic phishing checks, calculates a risk score, and returns a short explanation of the verdict.

## Problem Statement

Build a web app where a user pastes a suspicious URL and gets back a verdict:

- Safe
- Suspicious
- Dangerous

The result should include a short explanation showing why the URL received that verdict.

## Core Features

- URL input box for submitting suspicious links
- Risk analysis using basic phishing indicators
- Color-coded result card showing the verdict
- Risk score with triggered reasons
- Scan history page
- Database storage for scan history
- Blocklist support for known bad domains

## Phishing Checks

The detector evaluates URLs using the following checks:

- URL does not use HTTPS
- URL uses an IP address instead of a domain name
- URL is very long
- URL contains suspicious keywords such as `login`, `verify`, or `bank`
- URL has too many subdomains
- URL contains `@` symbols
- Domain exists in the known bad domain blocklist

## Risk Score

Each triggered check increases the risk score. Based on the final score, the app returns one of three verdicts:

- **Safe**: Low or no risk indicators found
- **Suspicious**: Some warning signs found
- **Dangerous**: Multiple high-risk indicators or blocklisted domain found

## Team Split

### Samrudhi - Frontend

Responsible for:

- URL input form
- Result card
- Color-coded verdict display
- Scan history table
- User-facing layout and styling

### Anushka - Backend

Responsible for:

- API endpoint for URL scanning
- Running phishing checks
- Calculating the risk score
- Returning verdict, score, and reasons to the frontend

### Sanskar - Database

Responsible for:

- Scan history schema
- Blocklist schema for known bad domains
- Queries to save scans
- Queries to fetch scan history
- Queries to check blocklisted domains

### Rushi - Integration

Responsible for:

- Connecting frontend with backend API
- Connecting backend with database
- Handling the complete demo flow
- Ensuring scan results are saved and displayed in history

## Suggested API Endpoints

### Scan a URL

```http
POST /api/scan
```

Request body:

```json
{
  "url": "http://example-login.com/verify"
}
```

Example response:

```json
{
  "url": "http://example-login.com/verify",
  "verdict": "Dangerous",
  "score": 85,
  "reasons": [
    "URL does not use HTTPS",
    "URL contains suspicious keyword: login",
    "URL contains suspicious keyword: verify"
  ]
}
```

### Fetch Scan History

```http
GET /api/history
```

Example response:

```json
[
  {
    "id": 1,
    "url": "http://example-login.com/verify",
    "verdict": "Dangerous",
    "score": 85,
    "createdAt": "2026-10-08T10:30:00Z"
  }
]
```

## Suggested Database Tables

### scan_history

| Column | Type | Description |
| --- | --- | --- |
| id | Integer | Unique scan ID |
| url | Text | Submitted URL |
| verdict | Text | Safe, Suspicious, or Dangerous |
| score | Integer | Risk score |
| reasons | Text/JSON | Reasons that triggered the score |
| created_at | Timestamp | Scan date and time |

### blocklist

| Column | Type | Description |
| --- | --- | --- |
| id | Integer | Unique blocklist ID |
| domain | Text | Known bad domain |
| created_at | Timestamp | Date added |

## Demo Flow

1. User opens the PhishGuard web app.
2. User pastes a suspicious URL into the input box.
3. Frontend sends the URL to the backend scan API.
4. Backend runs phishing checks and checks the blocklist.
5. Backend returns verdict, score, and reasons.
6. Result card displays the verdict with color coding.
7. Scan result is saved in the database.
8. User can view previous scans on the history page.

## Verdict Colors

- Safe: Green
- Suspicious: Yellow or Orange
- Dangerous: Red

## Project Goal

The goal of PhishGuard is to provide a simple and understandable phishing URL detection demo. It is not a replacement for professional security tools, but it helps users recognize common warning signs in suspicious links.
