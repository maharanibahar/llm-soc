import json
import os

OUTPUT_LOG = os.path.join(os.path.dirname(__file__),"output")

def load(fname):
    with open(os.path.join(OUTPUT_LOG, fname)) as f:
        return json.load(f)

#Treshold
def is_malicious(e):
    reasons = []

    if e.get("http_status") and e["http_status"] >= 400: 
        reasons.append("http_status")
    
    if e.get("rule_level") and e["rule_level"] >= 5: 
        reasons.append("wazuh_level")

    if e.get("mitre_id"): 
        reasons.append("mitre_id")
    
    if e.get("waf_score") and e["waf_score"] >= 10:  
        reasons.append("waf_score")
    
    if e.get("waf_action") in ("block", "challenge", "detect"):  
        reasons.append("waf_action")
    
    e["filtered_reasons"] = reasons
    return len(reasons)


def main():
    events = load("normalized_logs.json")
    malicious = []

    for e in events:
        if is_malicious(e) : malicious.append(e)

    for fname, data in [
        ("malicious_logs.json", malicious)
    ]:
        with open (os.path.join(OUTPUT_LOG, fname), "w") as f:
            json.dump(data,f,indent=2)

    out_path = os.path.join(OUTPUT_LOG, "malicious_logs.json")
    print(f" → Saved in {out_path}")

       
    rate = (len(malicious)/ len(events)) *100
    print(f" \n Pre-filtered logs: {len(events)} → {len(malicious)},") 
    print(f" which is {rate:.1f}% of all logs")
    
if __name__ == "__main__":
    main()
   

    

    