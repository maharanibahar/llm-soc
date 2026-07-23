# Ground Truth: Root Cause Analysis for 12 Attack Scenarios

This document defines the expected root cause analysis for each attack scenario.
These are defined BEFORE running attacks based on attack intent and threat modeling.
Use this to evaluate the LLM-generated postmortems.

> **Note:** "Suspected" and "Expected" fields reflect our pre-attack hypotheses.
> Actual system weaknesses and impact may differ and will be validated post-attack.

---

## Attack 1: SQL Injection (Aggressive)
**Source IP:** 172.19.0.10 (attacker-1)  
**Time Window:** 0-5 minutes  
**MITRE:** T1190 | **OWASP:** A03:2021 - Injection

### Ground Truth
- [ ] **Target:** `/rest/products/search` endpoint
- [ ] **Attack Technique:** Union-based SQL injection
- [ ] **Attacker Goal:** Extract user credentials (email + password hashes)
- [ ] **Expected Weakness:** Product search concatenates user input directly into SQL query
- [ ] **Expected Root Cause:** Missing parameterized statements in search handler
- [ ] **Expected Impact:** Critical — all user emails and password hashes exposed

---

## Attack 2: SQL Injection (Stealthy)
**Source IP:** 172.19.0.10 (attacker-1)  
**Time Window:** 15-20 minutes  
**MITRE:** T1190 | **OWASP:** A03:2021 - Injection

### Ground Truth
- [ ] **Target:** `/rest/user/login` endpoint
- [ ] **Attack Technique:** Boolean-based authentication bypass
- [ ] **Attacker Goal:** Bypass login without valid credentials
- [ ] **Expected Weakness:** Login endpoint uses string concatenation for SQL WHERE clause
- [ ] **Expected Root Cause:** Missing input validation in login email field
- [ ] **Expected Impact:** Critical — full admin session hijack

---

## Attack 3: Cross-Site Scripting - Reflected (Aggressive)
**Source IP:** 172.19.0.11 (attacker-2)  
**Time Window:** 0-5 minutes  
**MITRE:** T1059.007 | **OWASP:** A03:2021 - Injection

### Ground Truth
- [ ] **Target:** `/rest/products/search` endpoint
- [ ] **Attack Technique:** Reflected XSS via search parameter
- [ ] **Attacker Goal:** Steal session cookies from victim browsers
- [ ] **Expected Weakness:** Search results page renders user input directly into DOM without encoding
- [ ] **Expected Root Cause:** Missing output sanitization in search result rendering
- [ ] **Expected Impact:** High — session cookies, CSRF tokens, user PII exposed

---

## Attack 4: Cross-Site Scripting - Stored (Stealthy)
**Source IP:** 172.19.0.11 (attacker-2)  
**Time Window:** 15-20 minutes  
**MITRE:** T1059.007 | **OWASP:** A03:2021 - Injection

### Ground Truth
- [ ] **Target:** `/api/Feedbacks` endpoint
- [ ] **Attack Technique:** Stored XSS via product feedback
- [ ] **Attacker Goal:** Persistent payload that executes for every user viewing feedback
- [ ] **Expected Weakness:** Feedback comments stored without sanitization, rendered unsandboxed
- [ ] **Expected Root Cause:** Missing output encoding in feedback rendering component
- [ ] **Expected Impact:** Critical — all users' session cookies who visit feedback page

---

## Attack 5: Web Vulnerability Scanning (Aggressive)
**Source IP:** 172.19.0.12 (attacker-3)  
**Time Window:** 5-10 minutes  
**MITRE:** T1595.001 | **OWASP:** A05:2021 - Security Misconfiguration

### Ground Truth
- [ ] **Target:** Multiple sensitive paths: `/.env, /.git, /admin, /robots.txt, /swagger-ui.html`
- [ ] **Attack Technique:** Directory and file enumeration
- [ ] **Attacker Goal:** Map attack surface, discover exposed config files and admin panels
- [ ] **Expected Weakness:** Sensitive files (.env, .git/config) accessible via web root
- [ ] **Expected Root Cause:** Nginx configuration does not block access to dotfiles and backup files
- [ ] **Expected Impact:** High — environment variables, database credentials, API keys exposed

---

## Attack 6: Web Vulnerability Scanning (Stealthy)
**Source IP:** 172.19.0.12 (attacker-3)  
**Time Window:** 20-25 minutes  
**MITRE:** T1595.001 | **OWASP:** A05:2021 - Security Misconfiguration

### Ground Truth
- [ ] **Target:** API documentation: `/api-docs, /rest/admin/*` endpoints
- [ ] **Attack Technique:** API endpoint discovery with noise blending
- [ ] **Attacker Goal:** Discover undocumented admin APIs and version information
- [ ] **Expected Weakness:** Admin API endpoints exposed without authentication; Swagger docs publicly accessible
- [ ] **Expected Root Cause:** Missing authentication middleware on admin routes; API docs not disabled in production
- [ ] **Expected Impact:** Medium — application version, internal configuration exposed

---

## Attack 7: Brute Force (Aggressive)
**Source IP:** 172.19.0.13 (attacker-4)  
**Time Window:** 5-10 minutes  
**MITRE:** T1110.001 | **OWASP:** A07:2021 - Identification and Authentication Failures

### Ground Truth
- [ ] **Target:** `/rest/user/login` endpoint
- [ ] **Attack Technique:** Dictionary-based brute force against admin account
- [ ] **Attacker Goal:** Guess admin password through credential stuffing
- [ ] **Expected Weakness:** No rate limiting on login endpoint; no account lockout after failed attempts
- [ ] **Expected Root Cause:** Missing rate limiter middleware on login endpoint; no account lockout mechanism
- [ ] **Expected Impact:** High — full admin account compromise if password is weak

---

## Attack 8: Brute Force - Credential Stuffing (Stealthy)
**Source IP:** 172.19.0.13 (attacker-4)  
**Time Window:** 20-25 minutes  
**MITRE:** T1110.003 | **OWASP:** A07:2021 - Identification and Authentication Failures

### Ground Truth
- [ ] **Target:** `/rest/user/login` endpoint across multiple user accounts
- [ ] **Attack Technique:** Low-and-slow credential stuffing (1 attempt per account, spread over time)
- [ ] **Attacker Goal:** Find reused passwords across multiple accounts without triggering rate limits
- [ ] **Expected Weakness:** No per-account rate limiting; no breach password checking; no MFA enforcement
- [ ] **Expected Root Cause:** Missing credential stuffing detection; no MFA
- [ ] **Expected Impact:** High — multiple user accounts compromised via password reuse

---

## Attack 9: Broken Authentication Access (Aggressive)
**Source IP:** 172.19.0.14 (attacker-5)  
**Time Window:** 10-15 minutes  
**MITRE:** T1550.001 | **OWASP:** A07:2021 - Identification and Authentication Failures

### Ground Truth
- [ ] **Target:** `/rest/admin/application-configuration, /rest/admin/application-version`
- [ ] **Attack Technique:** Unauthenticated admin API access
- [ ] **Attacker Goal:** Access admin functionality and configuration without credentials
- [ ] **Expected Weakness:** Admin API routes lack authentication middleware
- [ ] **Expected Root Cause:** Missing authentication middleware on admin route definitions
- [ ] **Expected Impact:** Critical — full application configuration, database credentials, internal system details exposed

---

## Attack 10: Broken Authentication - JWT Manipulation (Stealthy)
**Source IP:** 172.19.0.14 (attacker-5)  
**Time Window:** 25-30 minutes  
**MITRE:** T1550.001 | **OWASP:** A07:2021 - Identification and Authentication Failures

### Ground Truth
- [ ] **Target:** All authenticated endpoints via manipulated JWT
- [ ] **Attack Technique:** JWT algorithm confusion / signature forgery
- [ ] **Attacker Goal:** Forge admin-level JWT token to access any user's data
- [ ] **Expected Weakness:** JWT signing secret exposed via publicly accessible files
- [ ] **Expected Root Cause:** Hardcoded JWT secret; secret present in publicly accessible file
- [ ] **Expected Impact:** Critical — full account takeover of any user including admin

---

## Attack 11: Sensitive Data Exposure (Aggressive)
**Source IP:** 172.19.0.15 (attacker-6)  
**Time Window:** 10-15 minutes  
**MITRE:** T1530 | **OWASP:** A02:2021 - Cryptographic Failures

### Ground Truth
- [ ] **Target:** `/ftp/` directory (`.bak, .md, .gg` files)
- [ ] **Attack Technique:** Directory listing via exposed file server
- [ ] **Attacker Goal:** Download backup files containing JWT secret, internal documents, credentials
- [ ] **Expected Weakness:** `/ftp/` directory serves all files without access control
- [ ] **Expected Root Cause:** No file extension filtering; directory listing enabled
- [ ] **Expected Impact:** Critical — JWT signing secret, internal coupon data, system info exposed

---

## Attack 12: Sensitive Data Exposure - User Data Dump (Stealthy)
**Source IP:** 172.19.0.15 (attacker-6)  
**Time Window:** 25-30 minutes  
**MITRE:** T1530 | **OWASP:** A01:2021 - Broken Access Control

### Ground Truth
- [ ] **Target:** `/rest/user/data-delight, /rest/user/accounting, /rest/user/whoami`
- [ ] **Attack Technique:** Excessive data exposure via verbose API endpoints
- [ ] **Attacker Goal:** Extract all user PII, order history, and payment details
- [ ] **Expected Weakness:** API endpoints return full user records including password hashes, security questions
- [ ] **Expected Root Cause:** No data minimization in API responses; endpoints return entire DB model instead of DTO
- [ ] **Expected Impact:** Critical — all user PII, password hashes, security question answers, order history exposed


