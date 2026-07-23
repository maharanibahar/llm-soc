import json
import os

OUTPUT_LOG = os.path.join(os.path.dirname(__file__),"output")

def load(fname):
    with open(os.path.join(OUTPUT_LOG, fname)) as f:
        return json.load(f)

#Treshold
def is_malicious(e):
    reasons = []
    
    # Must have at least one attack-specific indicator
    has_attack_indicator = False
    
    if e.get("modsec_rule_id"):
        reasons.append("modsec_rule_id")
        has_attack_indicator = True
    
    if e.get("waf_action") in ("block", "challenge", "detect"):  
        reasons.append("waf_action")
        has_attack_indicator = True
    
    if e.get("response_size") and e["response_size"] > 50000:
        reasons.append("response_size")
        has_attack_indicator = True
    
    # HTTP status >= 400 is supporting evidence, not standalone criterion
    if e.get("http_status") and e["http_status"] >= 400: 
        reasons.append("http_status")
    
    e["filtered_reasons"] = reasons
    
    # Only return True if we have at least one attack indicator
    return has_attack_indicator


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
    print(f" -> Saved in {out_path}")

        
    rate = (len(malicious)/ len(events)) *100
    print(f" \n Pre-filtered logs: {len(events)} -> {len(malicious)},") 
    print(f" which is {rate:.1f}% of all logs")
    
if __name__ == "__main__":
    main()
   

    

    