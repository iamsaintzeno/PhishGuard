# Phishing URL Detector - Test Cases

## Test Case 1 — Normal HTTPS URL

URL:
https://example.com

Expected triggers:
- None

Expected verdict:
Safe


## Test Case 2 — No HTTPS

URL:
http://example.com

Expected triggers:
- No HTTPS

Expected verdict:
Suspicious


## Test Case 3 — IP Address

URL:
http://192.168.1.1/login

Expected triggers:
- No HTTPS
- IP address
- Suspicious keyword: login

Expected verdict:
Dangerous


## Test Case 4 — Multiple Subdomains + Suspicious Keyword

URL:
https://secure.login.verify.example.com/verify

Expected triggers:
- Too many subdomains
- Suspicious keyword: login
- Suspicious keyword: verify

Expected verdict:
Suspicious


## Test Case 5 — Blocklisted Domain

URL:
http://fake-bank.com/login

Expected triggers:
- No HTTPS
- Suspicious keyword: bank
- Suspicious keyword: login
- Domain found in blocklist

Expected verdict:
Dangerous


## Test Case 6 — @ Symbol

URL:
https://example.com/@user/login

Expected triggers:
- @ symbol
- Suspicious keyword: login

Expected verdict:
Suspicious


## Test Case 7 — Very Long URL

URL:
https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Expected triggers:
- URL longer than 100 characters

Expected verdict:
Suspicious
