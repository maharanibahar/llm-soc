import json
import re
import os
from datetime import datetime

OUTPUT_LOG = os.path.join(os.path.dirname(__file__), "output")

def unified_scheme():
    return {
        "event_id": None,
        "timestamp": None,
        "log_source": None,
        "source_ip": None,
        "session_id": None,
        
        "attack_class": None,
        "http_method": None,
        "http_uri": None,
        "http_status": None,
        
        "rule_id": None,
        "rule_desc": None,
        "rule_level": None,
        "mitre_id": None,
        
        "firedtimes": None,
        "waf_action": None,
        "waf_score": None,
        
        "ml_label": None,
        "ml_conf": None,
    }

def map_to_mitre(attack_class):
    mapping = {
        "SQLi": "T1190",
        "XSS": "T1059.007",
        "BruteForce": "T1110.001",
        "PathTraversal": "T1083",
        "WebScan": "T1595.001"
    }
    return mapping.get(attack_class, None)

def parse_modsec_waf(filepath):
    events = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if 'ModSecurity:' not in line:
                    continue
                
                ts_match = re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})', line)
                timestamp = ts_match.group(1).replace('/', '-') + 'T' + ts_match.group(1).split(' ')[1] + '.000Z' if ts_match else datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
                
                ip_match = re.search(r'\[client (\d+\.\d+\.\d+\.\d+)\]', line)
                source_ip = ip_match.group(1) if ip_match else 'unknown'
                
                rule_match = re.search(r'\[id "(\d+)"\]', line)
                rule_id = rule_match.group(1) if rule_match else None
                
                msg_match = re.search(r'\[msg "([^"]+)"\]', line)
                rule_desc = msg_match.group(1) if msg_match else None
                
                uri_match = re.search(r'\[uri "([^"]+)"\]', line)
                uri = uri_match.group(1) if uri_match else '/'
                
                req_match = re.search(r'request: "(\S+) (\S+)', line)
                http_method = req_match.group(1) if req_match else 'GET'
                if req_match:
                    uri = req_match.group(2).split('?')[0]
                
                tags = re.findall(r'\[tag "([^"]+)"\]', line)
                
                attack_class = "WebScan"
                tags_lower = [t.lower() for t in tags]
                if any('sqli' in t for t in tags_lower):
                    attack_class = "SQLi"
                elif any('xss' in t for t in tags_lower):
                    attack_class = "XSS"
                elif any('lfi' in t or 'rfi' in t or 'traversal' in t for t in tags_lower):
                    attack_class = "PathTraversal"
                elif any('anomaly' in t for t in tags_lower):
                    if rule_desc:
                        desc_lower = rule_desc.lower()
                        if 'sql' in desc_lower or 'injection' in desc_lower:
                            attack_class = "SQLi"
                        elif 'xss' in desc_lower or 'script' in desc_lower:
                            attack_class = "XSS"
                
                score_match = re.search(r'Total Score: (\d+)', line)
                waf_score = int(score_match.group(1)) if score_match else 0
                
                event = unified_scheme()
                event.update({
                    "event_id": f"waf_{len(events)+1:04d}",
                    "timestamp": timestamp,
                    "log_source": "waf",
                    "source_ip": source_ip,
                    "session_id": "S1_s0",
                    "attack_class": attack_class,
                    "http_method": http_method,
                    "http_uri": uri,
                    "http_status": 403 if "Access denied" in line else 200,
                    "rule_id": rule_id,
                    "rule_desc": rule_desc,
                    "mitre_id": map_to_mitre(attack_class),
                    "waf_action": "block" if waf_score >= 5 else "detect",
                    "waf_score": waf_score if waf_score > 0 else None,
                })
                events.append(event)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found.")
    return events

def parse_nginx_logs(filepath):
    events = []
    pattern = r'^(\S+) - - \[(.*?)\] "(\S+) (\S+) \S+" (\d+) \S+ "(.*?)" "(.*?)"'
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                match = re.match(pattern, line)
                if match:
                    ip, ts_str, method, uri, status, referer, user_agent = match.groups()
                    
                    attack_class = "None"
                    if "script" in uri.lower() or "alert(" in uri.lower():
                        attack_class = "XSS"
                    elif "union" in uri.lower() or "or+1=1" in uri.lower() or "--" in uri:
                        attack_class = "SQLi"
                    elif "login" in uri and status == "401":
                        attack_class = "BruteForce"
                    
                    if attack_class != "None":
                        event = unified_scheme()
                        event.update({
                            "event_id": f"nginx_{len(events)+1:04d}",
                            "timestamp": parse_nginx_timestamp(ts_str),
                            "log_source": "nginx",
                            "source_ip": ip,
                            "session_id": "S1_s0",
                            "attack_class": attack_class,
                            "http_method": method,
                            "http_uri": uri,
                            "http_status": int(status),
                            "rule_id": "31101",
                            "rule_desc": f"{attack_class} detected in access log",
                            "rule_level": 6,
                            "mitre_id": map_to_mitre(attack_class),
                            "firedtimes": len(events) + 1,
                        })
                        events.append(event)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found.")
    return events

def parse_juice_shop_logs(filepath):
    events = []
    pattern = r'\[(.*?)\]\s+(\w+):\s+(.*)'
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    ts_str, level, message = match.groups()
                    
                    attack_class = "None"
                    if "login" in message.lower() and "failed" in message.lower():
                        attack_class = "BruteForce"
                    elif "error" in level.lower() and "sql" in message.lower():
                        attack_class = "SQLi"
                    
                    if attack_class != "None":
                        event = unified_scheme()
                        event.update({
                            "event_id": f"app_{len(events)+1:04d}",
                            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                            "log_source": "app",
                            "source_ip": "127.0.0.1",
                            "session_id": "S1_s0",
                            "attack_class": attack_class,
                            "http_method": "POST" if "login" in message else "GET",
                            "http_uri": "/rest/user/login" if "login" in message else "/unknown",
                            "http_status": 401 if "failed" in message else 500,
                            "rule_id": "31103" if attack_class == "BruteForce" else "31102",
                            "rule_desc": f"App log: {message[:50]}",
                            "rule_level": 5,
                            "mitre_id": map_to_mitre(attack_class),
                            "firedtimes": len(events) + 1,
                        })
                        events.append(event)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found.")
    return events

def parse_nginx_timestamp(ts_str):
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except:
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

def parse_nginx_access_log(filepath):
    events = []
    pattern = r'^(\S+) - - \[(.*?)\] "(\S+) (\S+) \S+" (\d+) \S+ "(.*?)" "(.*?)"'
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                match = re.match(pattern, line)
                if match:
                    ip, ts_str, method, uri, status, referer, user_agent = match.groups()
                    
                    attack_class = "None"
                    uri_lower = uri.lower()
                    if "script" in uri_lower or "alert(" in uri_lower or "onerror" in uri_lower or "onload" in uri_lower:
                        attack_class = "XSS"
                    elif "union" in uri_lower or "or+1=1" in uri_lower or "1=1" in uri_lower or "drop+table" in uri_lower:
                        attack_class = "SQLi"
                    elif "../" in uri or "..\\" in uri or "%2e%2e" in uri_lower or "%252e" in uri_lower:
                        attack_class = "PathTraversal"
                    elif "login" in uri_lower and status in ["401", "403"]:
                        attack_class = "BruteForce"
                    elif any(path in uri_lower for path in ["/.env", "/admin", "/.git", "/wp-admin", "/phpmyadmin"]):
                        attack_class = "WebScan"
                    
                    if attack_class != "None":
                        event = unified_scheme()
                        event.update({
                            "event_id": f"nginx_access_{len(events)+1:04d}",
                            "timestamp": parse_nginx_timestamp(ts_str),
                            "log_source": "nginx_access",
                            "source_ip": ip,
                            "session_id": "S1_s0",
                            "attack_class": attack_class,
                            "http_method": method,
                            "http_uri": uri.split('?')[0],
                            "http_status": int(status),
                            "rule_id": "31101",
                            "rule_desc": f"{attack_class} detected in access log",
                            "rule_level": 6,
                            "mitre_id": map_to_mitre(attack_class),
                            "firedtimes": len(events) + 1,
                        })
                        events.append(event)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found.")
    return events

def parse_modsec_audit_log(filepath):
    events = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    audit_data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                transaction = audit_data.get("transaction", {})
                request = transaction.get("request", {})
                response = transaction.get("response", {})
                producer = transaction.get("producer", {})
                
                timestamp = transaction.get("timestamp", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"))
                source_ip = request.get("remote_addr", "unknown")
                http_method = request.get("method", "GET")
                http_uri = request.get("uri", "/")
                http_status = response.get("status", 200)
                
                messages = audit_data.get("messages", [])
                attack_class = "WebScan"
                rule_id = None
                rule_desc = None
                waf_score = 0
                
                for msg in messages:
                    msg_str = str(msg).lower()
                    if "sql" in msg_str or "injection" in msg_str:
                        attack_class = "SQLi"
                    elif "xss" in msg_str or "script" in msg_str:
                        attack_class = "XSS"
                    elif "traversal" in msg_str or "lfi" in msg_str:
                        attack_class = "PathTraversal"
                    elif "brute" in msg_str or "login" in msg_str:
                        attack_class = "BruteForce"
                    
                    if rule_id is None:
                        id_match = re.search(r'id "(\d+)"', str(msg))
                        if id_match:
                            rule_id = id_match.group(1)
                    
                    if rule_desc is None:
                        msg_match = re.search(r'msg "([^"]+)"', str(msg))
                        if msg_match:
                            rule_desc = msg_match.group(1)
                
                event = unified_scheme()
                event.update({
                    "event_id": f"modsec_audit_{len(events)+1:04d}",
                    "timestamp": timestamp,
                    "log_source": "modsec_audit",
                    "source_ip": source_ip,
                    "session_id": "S1_s0",
                    "attack_class": attack_class,
                    "http_method": http_method,
                    "http_uri": http_uri.split('?')[0],
                    "http_status": http_status,
                    "rule_id": rule_id,
                    "rule_desc": rule_desc,
                    "mitre_id": map_to_mitre(attack_class),
                    "waf_action": "block" if http_status == 403 else "detect",
                    "waf_score": waf_score if waf_score > 0 else None,
                })
                events.append(event)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found.")
    return events

def find_latest_log_dir():
    log_base = "./testbed/logs"
    if not os.path.exists(log_base):
        return None
    
    run_dirs = [d for d in os.listdir(log_base) if d.startswith("run_")]
    if not run_dirs:
        return None
    
    latest = max(run_dirs)
    return os.path.join(log_base, latest)

def normalize_logs():
    print("Starting log normalization...")
    os.makedirs(OUTPUT_LOG, exist_ok=True)
    
    log_dir = find_latest_log_dir()
    if not log_dir:
        print("Error: No log directories found in ./testbed/logs/")
        return
    
    print(f"Using log directory: {log_dir}\n")
    
    waf_events = parse_modsec_waf(os.path.join(log_dir, "nginx_raw.log"))
    nginx_events = parse_nginx_logs(os.path.join(log_dir, "nginx_access.log"))
    nginx_access_events = parse_nginx_access_log(os.path.join(log_dir, "nginx_access.log"))
    modsec_audit_events = parse_modsec_audit_log(os.path.join(log_dir, "modsec_audit.log"))
    app_events = parse_juice_shop_logs(os.path.join(log_dir, "juice_app.log"))
    
    all_events = waf_events + nginx_events + nginx_access_events + modsec_audit_events + app_events
    all_events.sort(key=lambda x: x.get("timestamp", ""))
    
    out_path = os.path.join(OUTPUT_LOG, "normalized_logs.json")
    with open(out_path, "w", encoding='utf-8') as f:
        json.dump(all_events, f, indent=2)
    
    print(f"Success! Generated {len(all_events)} events:")
    print(f"  - WAF (ModSecurity error): {len(waf_events)}")
    print(f"  - Nginx (error logs): {len(nginx_events)}")
    print(f"  - Nginx (access logs): {len(nginx_access_events)}")
    print(f"  - ModSecurity (audit logs): {len(modsec_audit_events)}")
    print(f"  - Application (Juice Shop): {len(app_events)}")
    print(f"Saved to: {out_path}")

if __name__ == "__main__":
    normalize_logs()
