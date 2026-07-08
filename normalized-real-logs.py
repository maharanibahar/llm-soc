import json
import re
from datetime import datetime

def parse_modsec_waf(filepath):
    events = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('{'):
                    continue
                try:
                    log = json.loads(line)
                    transaction = log.get('transaction', {})
                    request = transaction.get('request', {})
                    messages = log.get('messages', [])
                    
                    attack_class = "WebScan"
                    rule_id = None
                    rule_desc = None
                    waf_score = 0
                    
                    for msg in messages:
                        rule_id = msg.get('ruleId', rule_id)
                        rule_desc = msg.get('message', rule_desc)
                        tags = msg.get('data', {}).get('tags', [])
                        if any('sqli' in t.lower() for t in tags): attack_class = "SQLi"
                        elif any('xss' in t.lower() for t in tags): attack_class = "XSS"
                        elif any('lfi' in t.lower() or 'rfi' in t.lower() for t in tags): attack_class = "PathTraversal"
                        

                        score_match = re.search(r'Inbound Anomaly Score Exceeded \(Score (\d+)\)', msg.get('message', ''))
                        if score_match: waf_score = int(score_match.group(1))

                    event = {
                        "event_id": f"waf_{len(events)+1:04d}",
                        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "log_source": "waf",
                        "source_ip": request.get('headers', {}).get('Host', 'unknown').split(':')[0], 
                        "session_id": "S1_s0",
                        "attack_class": attack_class,
                        "http_method": request.get('method', 'GET'),
                        "http_uri": request.get('uri', '/'),
                        "http_status": transaction.get('response', {}).get('http_code'),
                        "rule_id": str(rule_id) if rule_id else None,
                        "rule_desc": rule_desc,
                        "rule_level": None,
                        "mitre_id": map_to_mitre(attack_class),
                        "firedtimes": None,
                        "waf_action": "block" if waf_score > 5 else "detect",
                        "waf_score": waf_score if waf_score > 0 else None,
                        "ml_label": None,
                        "ml_conf": None
                    }
                    events.append(event)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"Warning: {filepath} not found.")
    return events

def parse_nginx_logs(filepath):
    """Parse Nginx access logs (Source 2)"""
    events = []

    pattern = r'^(\S+) - - \[(.*?)\] "(\S+) (\S+) \S+" (\d+) \S+ "(.*?)" "(.*?)"'
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                match = re.match(pattern, line)
                if match:
                    ip, ts_str, method, uri, status, referer, user_agent = match.groups()
                    
                
                    attack_class = "None"
                    if "script" in uri.lower() or "alert(" in uri.lower(): attack_class = "XSS"
                    elif "union" in uri.lower() or "or+1=1" in uri.lower() or "--" in uri: attack_class = "SQLi"
                    elif "login" in uri and status == "401": attack_class = "BruteForce"
                    
                    if attack_class != "None":
                        event = {
                            "event_id": f"nginx_{len(events)+1:04d}",
                            "timestamp": parse_nginx_timestamp(ts_str),
                            "log_source": "wazuh", 
                            "source_ip": ip,
                            "session_id": "S1_s0",
                            "attack_class": attack_class,
                            "http_method": method,
                            "http_uri": uri,
                            "http_status": int(status),
                            "rule_id": "31101" if attack_class != "None" else None,
                            "rule_desc": f"{attack_class} detected in access log",
                            "rule_level": 6,
                            "mitre_id": map_to_mitre(attack_class),
                            "firedtimes": len(events) + 1,
                            "waf_action": None,
                            "waf_score": None,
                            "ml_label": None,
                            "ml_conf": None
                        }
                        events.append(event)
    except FileNotFoundError:
        print(f"Warning: {filepath} not found.")
    return events

def parse_juice_shop_logs(filepath):
    """Parse Juice Shop application logs (Source 3)"""
    events = []
   
    pattern = r'\[(.*?)\]\s+(\w+):\s+(.*)'
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    ts_str, level, message = match.groups()
                    
                    attack_class = "None"
                    if "login" in message.lower() and "failed" in message.lower(): attack_class = "BruteForce"
                    elif "error" in level.lower() and "sql" in message.lower(): attack_class = "SQLi"
                    
                    if attack_class != "None":
                        event = {
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
                            "waf_action": None,
                            "waf_score": None,
                            "ml_label": None,
                            "ml_conf": None
                        }
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

def map_to_mitre(attack_class):
    mapping = {
        "SQLi": "T1190",
        "XSS": "T1059.007",
        "BruteForce": "T1110.001",
        "PathTraversal": "T1083",
        "WebScan": "T1595.001"
    }
    return mapping.get(attack_class, None)

if __name__ == "__main__":
    print("Starting log normalization...")
    

    waf_events = parse_modsec_waf("./testbed/modsec_waf.log")
    nginx_events = parse_nginx_logs("./testbed/nginx_raw.log")
    app_events = parse_juice_shop_logs("./testbed/juice_app.log")
    
   
    all_events = waf_events + nginx_events + app_events
    
    # Sort by timestamp
    # all_events.sort(key=lambda x: x["timestamp"])
    

    output_file = "test_clusters/real_attack_logs.json"
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(all_events, f, indent=2)
        
    print(f"Success! Generated {len(all_events)} events:")
    print(f"  - WAF (ModSecurity): {len(waf_events)}")
    print(f"  - Network (Nginx): {len(nginx_events)}")
    print(f"  - Application (Juice Shop): {len(app_events)}")
    print(f"Saved to: {output_file}")
