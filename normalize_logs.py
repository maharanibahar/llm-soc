import json
import re
import os
from datetime import datetime

OUTPUT_LOG = os.path.join(os.path.dirname(__file__), "output")
WAZUH_ARCHIVES = os.path.join(os.path.dirname(__file__), "testbed", "logs", "wazuh", "archives", "archives.json")

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
        "WebScan": "T1595.001",
        "BrokenAuth": "T1550.001",
        "SensitiveData": "T1530",
    }
    return mapping.get(attack_class, None)

def classify_attack_from_wazuh(archive):
    """Determine attack class from Wazuh rule groups, data fields, or raw log"""
    rule = archive.get("rule", {})
    data = archive.get("data", {})
    decoder = archive.get("decoder", {})
    full_log = archive.get("full_log", "")
    
    groups = rule.get("groups", [])
    groups_lower = [g.lower() for g in groups]
    
    if "sqli" in groups_lower or "sql" in groups_lower:
        return "SQLi"
    if "xss" in groups_lower:
        return "XSS"
    if "webscan" in groups_lower or "recon" in groups_lower or "scanner" in groups_lower:
        return "WebScan"
    if "pathtraversal" in groups_lower:
        return "PathTraversal"
    if "bruteforce" in groups_lower or "authentication" in groups_lower:
        return "BruteForce"
    
    modsec_rule_id = data.get("modsec_rule_id", "")
    if modsec_rule_id:
        rid = int(modsec_rule_id)
        if 942000 <= rid < 943000:
            return "SQLi"
        if 941000 <= rid < 942000:
            return "XSS"
        if 913000 <= rid < 914000:
            return "WebScan"
        if 930000 <= rid < 931000:
            return "PathTraversal"
    
    modsec_msg = data.get("modsec_msg", "").lower()
    if "sql" in modsec_msg or "injection" in modsec_msg:
        return "SQLi"
    if "xss" in modsec_msg or "script" in modsec_msg:
        return "XSS"
    if "scanner" in modsec_msg or "scanning" in modsec_msg:
        return "WebScan"
    if "traversal" in modsec_msg or "lfi" in modsec_msg:
        return "PathTraversal"
    
    url = data.get("url", "").lower()
    if "union" in url or "or+1=1" in url or "1=1" in url:
        return "SQLi"
    if "<script" in url or "alert(" in url or "onerror" in url:
        return "XSS"
    if "../" in url or "%2e%2e" in url:
        return "PathTraversal"
    if "/rest/user/login" in url and data.get("status") in ["401", "403"]:
        return "BruteForce"
    if any(p in url for p in ["/.env", "/.git", "/admin", "/phpmyadmin", "/wp-admin", "/swagger"]):
        return "WebScan"
    
    return "Benign"

def parse_wazuh_archives(filepath):
    """Parse Wazuh archives.json - contains EVERY log event (no aggregation)"""
    events = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    archive = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                data = archive.get("data", {})
                rule = archive.get("rule", {})
                decoder = archive.get("decoder", {})
                
                source_ip = data.get("srcip", "unknown")
                url = data.get("url", "/")
                protocol = data.get("protocol", "GET")
                status = data.get("status", None)
                
                if status:
                    try:
                        status = int(status)
                    except (ValueError, TypeError):
                        status = None
                
                attack_class = classify_attack_from_wazuh(archive)
                
                modsec_rule_id = data.get("modsec_rule_id", None)
                modsec_msg = data.get("modsec_msg", None)
                modsec_score = data.get("modsec_score", None)
                
                if modsec_score:
                    try:
                        modsec_score = int(modsec_score)
                    except (ValueError, TypeError):
                        modsec_score = None
                
                wazuh_rule_id = rule.get("id", None)
                wazuh_rule_desc = rule.get("description", None)
                wazuh_rule_level = rule.get("level", None)
                
                mitre_ids = rule.get("mitre", {}).get("id", [])
                mitre_id = mitre_ids[0] if mitre_ids else map_to_mitre(attack_class)
                
                log_source = "wazuh"
                location = archive.get("location", "")
                if "modsec" in location.lower():
                    log_source = "wazuh_modsec"
                elif "nginx" in location.lower():
                    log_source = "wazuh_nginx"
                
                waf_action = None
                if status == 403:
                    waf_action = "block"
                elif modsec_score and modsec_score >= 5:
                    waf_action = "block"
                elif attack_class != "Benign":
                    waf_action = "detect"
                
                event = unified_scheme()
                event.update({
                    "event_id": f"wazuh_{line_num:05d}",
                    "timestamp": archive.get("timestamp", ""),
                    "log_source": log_source,
                    "source_ip": source_ip,
                    "session_id": "S1_s0",
                    "attack_class": attack_class,
                    "http_method": protocol,
                    "http_uri": url.split("?")[0] if url else "/",
                    "http_status": status,
                    "rule_id": modsec_rule_id or wazuh_rule_id,
                    "rule_desc": modsec_msg or wazuh_rule_desc,
                    "rule_level": wazuh_rule_level,
                    "mitre_id": mitre_id,
                    "firedtimes": rule.get("firedtimes", None),
                    "waf_action": waf_action,
                    "waf_score": modsec_score,
                })
                
                events.append(event)
                
    except FileNotFoundError:
        print(f"Warning: {filepath} not found.")
    
    return events

def normalize_logs():
    print("Starting log normalization from Wazuh archives...")
    os.makedirs(OUTPUT_LOG, exist_ok=True)
    
    print(f"Reading from: {WAZUH_ARCHIVES}\n")
    
    events = parse_wazuh_archives(WAZUH_ARCHIVES)
    
    events.sort(key=lambda x: x.get("timestamp", ""))
    
    out_path = os.path.join(OUTPUT_LOG, "normalized_logs.json")
    with open(out_path, "w", encoding='utf-8') as f:
        json.dump(events, f, indent=2)
    
    attack_counts = {}
    for e in events:
        cls = e.get("attack_class", "Unknown")
        attack_counts[cls] = attack_counts.get(cls, 0) + 1
    
    source_counts = {}
    for e in events:
        src = e.get("log_source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
    
    print(f"Success! Generated {len(events)} events from Wazuh archives:")
    print(f"\n  By attack class:")
    for cls, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
        print(f"    {cls:20s}: {count}")
    print(f"\n  By log source:")
    for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"    {src:20s}: {count}")
    print(f"\nSaved to: {out_path}")

if __name__ == "__main__":
    normalize_logs()
