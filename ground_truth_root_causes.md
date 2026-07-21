# Ground Truth: Root Cause Analysis for 12 Attack Scenarios

This document defines the expected root cause analysis for each attack scenario.
Use this to evaluate the LLM-generated postmortems.

---

## Attack 1: SQL Injection (Aggressive)
**Source IP:** 172.19.0.10 (attacker-1)  
**Time Window:** 0-5 minutes  
**MITRE:** T1190 | **OWASP:** A03:2021 - Injection

### Ground Truth Checklist
- [ ] **Target:** `/rest/products/search` endpoint, `q` parameter
- [ ] **Trigger Payload:** `' UNION SELECT 1,2,3,email,password,6,7,8,9 FROM Users--`
- [ ] **Attack Technique:** Union-based blind SQL injection
- [ ] **Attacker Goal:** Extract user credentials (email + password hashes)
- [ ] **System Weakness:** Product search concatenates user input directly into SQL query
- [ ] **Root Cause:** Missing parameterized statements in `/rest/products/search` handler
- [ ] **Code Location:** `routes/products.ts` → `searchProducts()` → raw SQL string interpolation
- [ ] **Impact:** Critical — all user emails and password hashes exposed
- [ ] **Exploitability:** No authentication required, single request
- [ ] **Expected Evidence:** WAF rule 942100 triggered, 403 responses, UNION SELECT in logs

---

## Attack 2: SQL Injection (Stealthy)
**Source IP:** 172.19.0.10 (attacker-1)  
**Time Window:** 15-20 minutes  
**MITRE:** T1190 | **OWASP:** A03:2021 - Injection

### Ground Truth Checklist
- [ ] **Target:** `/rest/user/login` endpoint, `email` parameter
- [ ] **Trigger Payload:** `' OR 1=1--`
- [ ] **Attack Technique:** Boolean-based authentication bypass
- [ ] **Attacker Goal:** Bypass login without valid credentials
- [ ] **System Weakness:** Login endpoint uses string concatenation for SQL WHERE clause
- [ ] **Root Cause:** Missing input validation in `/rest/user/login` email field
- [ ] **Code Location:** `routes/login.ts` → `authenticate()` → raw SQL WHERE clause
- [ ] **Impact:** Critical — full admin session hijack
- [ ] **Exploitability:** Single POST request, no auth required
- [ ] **Expected Evidence:** WAF rule 942110 triggered, 401/403 responses, slow request rate

---

## Attack 3: Cross-Site Scripting - Reflected (Aggressive)
**Source IP:** 172.19.0.11 (attacker-2)  
**Time Window:** 0-5 minutes  
**MITRE:** T1059.007 | **OWASP:** A03:2021 - Injection

### Ground Truth Checklist
- [ ] **Target:** `/rest/products/search` endpoint, `q` parameter
- [ ] **Trigger Payload:** `<script>alert(document.cookie)</script>`
- [ ] **Attack Technique:** Reflected XSS via search parameter
- [ ] **Attacker Goal:** Steal session cookies from victim browsers
- [ ] **System Weakness:** Search results page renders user input directly into DOM without encoding
- [ ] **Root Cause:** Angular template uses `[innerHTML]` binding without `DomSanitizer`
- [ ] **Code Location:** `frontend/src/app/search.ts` → `renderSearchResult()` → innerHTML assignment
- [ ] **Impact:** High — session cookies, CSRF tokens, user PII exposed
- [ ] **Exploitability:** Requires victim to click crafted link
- [ ] **Expected Evidence:** WAF rule 941100 triggered, `<script>` in logs, 403 responses

---

## Attack 4: Cross-Site Scripting - Stored (Stealthy)
**Source IP:** 172.19.0.11 (attacker-2)  
**Time Window:** 15-20 minutes  
**MITRE:** T1059.007 | **OWASP:** A03:2021 - Injection

### Ground Truth Checklist
- [ ] **Target:** `/api/Feedbacks` endpoint, `comment` parameter
- [ ] **Trigger Payload:** `<img src=x onerror=alert(document.cookie)>`
- [ ] **Attack Technique:** Stored XSS via product feedback
- [ ] **Attacker Goal:** Persistent payload that executes for every user viewing feedback
- [ ] **System Weakness:** Feedback comments stored without sanitization, rendered unsandboxed
- [ ] **Root Cause:** Missing output encoding in feedback rendering component
- [ ] **Code Location:** `routes/feedback.ts` → `createFeedback()` → DB insert without sanitize
- [ ] **Impact:** Critical — all users' session cookies who visit feedback page
- [ ] **Exploitability:** Single POST, persists until feedback deleted
- [ ] **Expected Evidence:** WAF rule 941110 triggered, `<img onerror=` in logs, 200 OK (stored)

---

## Attack 5: Web Vulnerability Scanning (Aggressive)
**Source IP:** 172.19.0.12 (attacker-3)  
**Time Window:** 5-10 minutes  
**MITRE:** T1595.001 | **OWASP:** A05:2021 - Security Misconfiguration

### Ground Truth Checklist
- [ ] **Target:** Multiple sensitive paths: `/.env, /.git, /admin, /robots.txt, /swagger-ui.html`
- [ ] **Trigger Payload:** Rapid sequential GET requests to sensitive paths
- [ ] **Attack Technique:** Directory and file enumeration
- [ ] **Attacker Goal:** Map attack surface, discover exposed config files and admin panels
- [ ] **System Weakness:** Sensitive files (.env, .git/config) accessible via web root
- [ ] **Root Cause:** Nginx configuration does not block access to dotfiles and backup files
- [ ] **Code Location:** `nginx.conf` → missing `location ~ /\.` rules
- [ ] **Impact:** High — environment variables, database credentials, API keys exposed
- [ ] **Exploitability:** No authentication required, standard HTTP GET
- [ ] **Expected Evidence:** WAF rule 913100 triggered, rapid 403/404 responses, scanner detection

---

## Attack 6: Web Vulnerability Scanning (Stealthy)
**Source IP:** 172.19.0.12 (attacker-3)  
**Time Window:** 20-25 minutes  
**MITRE:** T1595.001 | **OWASP:** A05:2021 - Security Misconfiguration

### Ground Truth Checklist
- [ ] **Target:** API documentation: `/api-docs, /rest/admin/application-version, /rest/admin/application-configuration`
- [ ] **Trigger Payload:** Slow, targeted requests to API endpoints with legitimate User-Agent
- [ ] **Attack Technique:** API endpoint discovery with noise blending
- [ ] **Attacker Goal:** Discover undocumented admin APIs and version information
- [ ] **System Weakness:** Admin API endpoints exposed without authentication; Swagger docs publicly accessible
- [ ] **Root Cause:** Missing authentication middleware on `/rest/admin/*` routes; API docs not disabled in production
- [ ] **Code Location:** `routes/admin.ts` → no auth middleware; `server.ts` → swagger-ui enabled in prod
- [ ] **Impact:** Medium — application version, internal configuration exposed
- [ ] **Exploitability:** No authentication, looks like normal API usage
- [ ] **Expected Evidence:** WAF rule 913110 triggered, 200 responses on admin endpoints, slow request rate

---

## Attack 7: Brute Force (Aggressive)
**Source IP:** 172.19.0.13 (attacker-4)  
**Time Window:** 5-10 minutes  
**MITRE:** T1110.001 | **OWASP:** A07:2021 - Identification and Authentication Failures

### Ground Truth Checklist
- [ ] **Target:** `/rest/user/login` endpoint, `email` + `password` (POST body)
- [ ] **Trigger Payload:** 10+ rapid login attempts with common passwords: admin, password, 123456, letmein, qwerty
- [ ] **Attack Technique:** Dictionary-based brute force against admin account
- [ ] **Attacker Goal:** Guess admin password through credential stuffing
- [ ] **System Weakness:** No rate limiting on login endpoint; no account lockout after failed attempts
- [ ] **Root Cause:** Missing rate limiter middleware on `/rest/user/login`; no account lockout mechanism
- [ ] **Code Location:** `routes/login.ts` → no `rateLimit()` middleware; no `maxAttempts` check
- [ ] **Impact:** High — full admin account compromise if password is weak
- [ ] **Exploitability:** Unlimited attempts, no lockout, ~1 attempt/second
- [ ] **Expected Evidence:** Multiple 401 responses, same source_ip, rapid frequency, Wazuh rule 31103

---

## Attack 8: Brute Force - Credential Stuffing (Stealthy)
**Source IP:** 172.19.0.13 (attacker-4)  
**Time Window:** 20-25 minutes  
**MITRE:** T1110.003 | **OWASP:** A07:2021 - Identification and Authentication Failures

### Ground Truth Checklist
- [ ] **Target:** `/rest/user/login` endpoint across multiple user accounts
- [ ] **Trigger Payload:** 1 attempt per account across 5 users with leaked password lists
- [ ] **Attack Technique:** Low-and-slow credential stuffing (1 attempt per account, spread over time)
- [ ] **Attacker Goal:** Find reused passwords across multiple accounts without triggering rate limits
- [ ] **System Weakness:** No per-account rate limiting; no breach password checking; no MFA enforcement
- [ ] **Root Cause:** Missing credential stuffing detection; no HaveIBeenPwned integration; no MFA
- [ ] **Code Location:** `routes/login.ts` → no password breach check; no MFA middleware
- [ ] **Impact:** High — multiple user accounts compromised via password reuse
- [ ] **Exploitability:** Distributed across accounts, evades per-IP rate limits
- [ ] **Expected Evidence:** 401 responses across different emails, slow rate, Wazuh brute force correlation

---

## Attack 9: Broken Authentication Access (Aggressive)
**Source IP:** 172.19.0.14 (attacker-5)  
**Time Window:** 10-15 minutes  
**MITRE:** T1550.001 | **OWASP:** A07:2021 - Identification and Authentication Failures

### Ground Truth Checklist
- [ ] **Target:** `/rest/admin/application-configuration, /rest/admin/application-version`
- [ ] **Trigger Payload:** Direct GET requests to `/rest/admin/*` endpoints without any JWT or session cookie
- [ ] **Attack Technique:** Unauthenticated admin API access
- [ ] **Attacker Goal:** Access admin functionality and configuration without credentials
- [ ] **System Weakness:** Admin API routes lack authentication middleware
- [ ] **Root Cause:** Missing `isAdmin()` middleware on `/rest/admin/*` route definitions
- [ ] **Code Location:** `routes/admin.ts` → `router.get('/application-configuration')` → no auth check
- [ ] **Impact:** Critical — full application configuration, database credentials, internal system details exposed
- [ ] **Exploitability:** Single GET request, no auth required, returns 200 with full config
- [ ] **Expected Evidence:** 200 on `/rest/admin/*`, no Authorization header, Wazuh rule 31105

---

## Attack 10: Broken Authentication - JWT Manipulation (Stealthy)
**Source IP:** 172.19.0.14 (attacker-5)  
**Time Window:** 25-30 minutes  
**MITRE:** T1550.001 | **OWASP:** A07:2021 - Identification and Authentication Failures

### Ground Truth Checklist
- [ ] **Target:** All authenticated endpoints via manipulated JWT
- [ ] **Trigger Payload:** JWT with `alg:none` or forged signature using leaked secret `pa4qacea4VK9t9xG47p7R23Y58d0cK2j`
- [ ] **Attack Technique:** JWT algorithm confusion / signature forgery
- [ ] **Attacker Goal:** Forge admin-level JWT token to access any user's data
- [ ] **System Weakness:** JWT signing secret hardcoded in source code and exposed via `/ftp/coupons_2013.md.bak`
- [ ] **Root Cause:** Hardcoded JWT secret in `lib/insecurity.ts`; secret also present in publicly accessible FTP file
- [ ] **Code Location:** `lib/insecurity.ts` → `jwtSecret = 'pa4qacea4VK9t9xG47p7R23Y58d0cK2j'`; `/ftp/` serves `.bak` files
- [ ] **Impact:** Critical — full account takeover of any user including admin
- [ ] **Exploitability:** Requires JWT secret (leaked in FTP file), single forged token
- [ ] **Expected Evidence:** Forged JWT in Authorization header, 200 on protected endpoints, JWT anomaly detection

---

## Attack 11: Sensitive Data Exposure (Aggressive)
**Source IP:** 172.19.0.15 (attacker-6)  
**Time Window:** 10-15 minutes  
**MITRE:** T1530 | **OWASP:** A02:2021 - Cryptographic Failures

### Ground Truth Checklist
- [ ] **Target:** `/ftp/coupons_2013.md.bak, /ftp/eastere.gg, /ftp/legal.md`
- [ ] **Trigger Payload:** `GET /ftp/` to list directory, then `GET /ftp/coupons_2013.md.bak`
- [ ] **Attack Technique:** Directory traversal via exposed FTP-style file server
- [ ] **Attacker Goal:** Download backup files containing JWT secret, internal documents, credentials
- [ ] **System Weakness:** `/ftp/` directory serves all files including `.bak, .md, .gg` without access control
- [ ] **Root Cause:** Nginx `location /ftp/` has `autoindex on` and no file extension filtering
- [ ] **Code Location:** `server.ts` → `serveStatic('/ftp')` → no extension whitelist; `nginx.conf` → `autoindex on`
- [ ] **Impact:** Critical — JWT signing secret, internal coupon data, Easter eggs with system info exposed
- [ ] **Exploitability:** Single GET request, no auth, directory listing reveals all files
- [ ] **Expected Evidence:** `GET /ftp/`, 200 response, `.bak` file access, Wazuh rule 31107

---

## Attack 12: Sensitive Data Exposure - User Data Dump (Stealthy)
**Source IP:** 172.19.0.15 (attacker-6)  
**Time Window:** 25-30 minutes  
**MITRE:** T1530 | **OWASP:** A01:2021 - Broken Access Control

### Ground Truth Checklist
- [ ] **Target:** `/rest/user/data-delight, /rest/user/accounting, /rest/user/whoami`
- [ ] **Trigger Payload:** `GET /rest/user/data-delight` with valid user JWT
- [ ] **Attack Technique:** Excessive data exposure via verbose API endpoints
- [ ] **Attacker Goal:** Extract all user PII, order history, and payment details
- [ ] **System Weakness:** API endpoints return full user records including password hashes, security questions
- [ ] **Root Cause:** No data minimization in API responses; endpoints return entire DB model instead of DTO
- [ ] **Code Location:** `routes/user.ts` → `data-delight` handler → returns full User model with `passwordHash`, `securityAnswer`
- [ ] **Impact:** Critical — all user PII, password hashes, security question answers, order history exposed
- [ ] **Exploitability:** Requires valid user session (obtainable via brute force)
- [ ] **Expected Evidence:** `GET /rest/user/data-delight`, 200 with large response, Wazuh rule 31108

---

## Evaluation Criteria

For each postmortem, check if the LLM correctly identified:

1. **Target** — Did it name the correct endpoint/parameter?
2. **Trigger** — Did it describe the payload/technique accurately?
3. **System Weakness** — Did it explain the technical vulnerability?
4. **Root Cause** — Did it pinpoint the code-level flaw?
5. **Impact** — Did it assess severity and data at risk?
6. **Exploitability** — Did it describe how easy it is to exploit?
7. **Evidence** — Did it reference the correct log markers?

Score each checklist item as: ✅ Correct | ⚠️ Partial | ❌ Missing
