import datetime
import json
import os


#NORMALIZED TIME_STAMP
time_stamp="2026-01-15T10:01:42.000Z"

normalized_time = datetime.datetime.fromisoformat(
   time_stamp.replace('Z','+00:00'),
)
#normalized_time=normalized_time.strftime('%Y-%m-%d %I:%M %p')
#print(normalized_time)


#HASH IP
#message = "Hello"
#hash_object = hashlib.sha256(message.encode())
#hex_digest = hash_object.hexdigest()

#print(f"Original:{message}")
#print(f"SHA-256:{hex_digest}")


#UNIFIED SCHEME
#from dummy structure
def unified_scheme():
    return{
        "event_id"   : None,
        "timestamp"  : None,
        "log_source" : None,
        "source_ip"  : None,
        "session_id" : None,

        "attack_class": None,
        "http_method": None,
        "http_uri"   : None,
        "http_status": None,
        
        "rule_id"    : None,
        "rule_desc"  : None,
        "rule_level" : None,
        "mitre_id"   : None,

        "firedtimes" : None,
        "waf_action" : None,
        "waf_score"  : None,

        "ml_label"   : None,
        "ml_conf"    : None,
    }

#NORMALIZED WAZUH LOGS

def norm_wazuh(e):
    return {
        "event_id"   : e.get("event_id"),
        "timestamp"  : e.get("timestamp"),
        "log_source" : "wazuh",
        "source_ip"  : e.get("source_ip"),
        "session_id" : e.get("session_id"),

        "attack_class": e.get("attack_class"),
        "http_method": e.get("http_method"),
        "http_uri"   : e.get("http_uri"),
        "http_status": e.get("http_status"),

        "rule_id"    : e.get("rule_id"),
        "rule_desc"  : e.get("rule_desc"),
        "rule_level" : e.get("rule_level", 0),
        "mitre_id"   : e.get("mitre_id"),

        "firedtimes" : e.get("firedtimes", 1),

        "waf_action" : None,
        "waf_score"  : None,

        "ml_label"   : e.get("ml_label"),
        "ml_conf"    : e.get("ml_conf"),
    }

def norm_waf(e):
    return {
        "event_id"   : e.get("event_id"),
        "timestamp"  : e.get("timestamp"),
        "source_ip"  : e.get("source_ip"),
        "log_source" : "waf",
        "session_id" : e.get("session_id"),

        "attack_class": e.get("attack_class"),
        "http_method": e.get("http_method"),
        "http_uri"   : e.get("http_uri"),
        "http_status": None,

        "rule_id"    : "|".join(e.get("matched_rules", [])),
        "rule_desc"  : e.get("rule_desc"),
        "rule_level" : None,
        "mitre_id"   : None,

        "firedtimes" : None,

        "waf_action" : e.get("waf_action"),
        "waf_score"  : e.get("anomaly_score"),

        "ml_label"   : None,
        "ml_conf"    : None,
    }


LOGS_DIR   = os.path.join(".\dummy-dataset")
OUTPUT_LOG = os.path.join(os.path.dirname(__file__), "output")

def load(fname):
    with open(os.path.join(LOGS_DIR, fname)) as f:
        return json.load(f)

def normalized_logs():
    os.makedirs(OUTPUT_LOG, exist_ok = True)
    all_logs = []
    for fname, norm_fname in [
        ("wazuh_events.json", norm_wazuh),
        ("waf_events.json", norm_waf)
    ]:
        raw_logs = load(fname)
        for e in raw_logs: 
            all_logs.append(norm_fname(e))

    #sort by time
    all_logs.sort(key=lambda e: (e.get("timestamp","")))

    out_path = os.path.join(OUTPUT_LOG, "normalized_logs.json")
    with open(out_path, "w") as f:
        json.dump(all_logs, f, indent=2)

    sources = {}
    for e in all_logs:
        s = e["log_source"]
        sources[s] = sources.get(s, 0) + 1

    print(f"Normalize {len(all_logs)} events")
    for s,n in sources.items():
        print(f" {s:15s} : {n}")
    print(f" → {out_path}")

if __name__ == "__main__":
    normalized_logs()
