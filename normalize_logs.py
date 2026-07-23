import json
import re
import os
from datetime import datetime
from pathlib import Path

OUTPUT_LOG = os.path.join(os.path.dirname(__file__), "output")
BASE_DIR = Path(__file__).resolve().parent

WAZUH_ARCHIVES = BASE_DIR / "testbed" / "logs" / "wazuh" / "archives" / "archives.json"


def unified_scheme():
    return {
        "event_id": None,
        "timestamp": None,
        "log_source": None,
        "source_ip": None,
        
        "http_method": None,
        "http_uri": None,
        "http_status": None,
        "user_agent": None,
        
        "response_size": None,
        
        "modsec_rule_id": None,
        "modsec_msg": None,
        
        "waf_action": None,
    }

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
                
                location = archive.get("location", "")
                transaction = archive.get("data", {}).get("transaction", {})
                
                source_ip = transaction.get("client_ip", "unknown")
                timestamp = transaction.get("time_stamp", "")
                
                request = transaction.get("request", {})
                http_method = request.get("method", None)
                http_uri = request.get("uri", "/")
                
                request_headers = request.get("headers", {})
                user_agent = request_headers.get("user-agent", None)
                
                response = transaction.get("response", {})
                http_status = response.get("http_code", None)
                
                if http_status:
                    try:
                        http_status = int(http_status)
                    except (ValueError, TypeError):
                        http_status = None
                
                response_body = response.get("body", "")
                response_size = len(response_body) if response_body else 0
                
                messages = transaction.get("messages", [])
                modsec_rule_id = None
                modsec_msg = None
                
                if messages and len(messages) > 0:
                    msg_obj = messages[0]
                    modsec_msg = msg_obj.get("message", None)
                    details = msg_obj.get("details", {})
                    modsec_rule_id = details.get("ruleId", None)
                
                log_source = "wazuh"
                if "modsec" in location.lower():
                    log_source = "wazuh_modsec"
                elif "nginx" in location.lower():
                    log_source = "wazuh_nginx"
                
                waf_action = None
                if http_status == 403:
                    waf_action = "block"
                
                event = unified_scheme()
                event.update({
                    "event_id": f"wazuh_{line_num:05d}",
                    "timestamp": timestamp,
                    "log_source": log_source,
                    "source_ip": source_ip,
                    "http_method": http_method,
                    "http_uri": http_uri if http_uri else "/",
                    "http_status": http_status,
                    "user_agent": user_agent,
                    "response_size": response_size,
                    "modsec_rule_id": modsec_rule_id,
                    "modsec_msg": modsec_msg,
                    "waf_action": waf_action,
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
    
    source_counts = {}
    for e in events:
        src = e.get("log_source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
    
    print(f"Success! Generated {len(events)} events from Wazuh archives:")
    print(f"\n  By log source:")
    for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"    {src:20s}: {count}")
    print(f"\nSaved to: {out_path}")

if __name__ == "__main__":
    normalize_logs()
