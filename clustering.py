import json
import os
from datetime import datetime
from pathlib import Path
from collections import defaultdict

OUTPUT_LOG = os.path.join(os.path.dirname(__file__), "output")
CLUSTER_DIR = os.path.join(os.path.dirname(__file__), "output", "clusters")

def load_malicious_logs():
    filepath = os.path.join(OUTPUT_LOG, "malicious_logs.json")
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_time_bucket(timestamp_str, window_seconds=300):
    try:
        dt = datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S %Y")
        epoch = dt.timestamp()
        bucket = int(epoch // window_seconds)
        return bucket
    except:
        return 0

def cluster_events(events):
    clusters = defaultdict(list)
    
    for event in events:
        source_ip = event.get("source_ip", "unknown")
        modsec_rule_id = event.get("modsec_rule_id", "no_rule")
        timestamp = event.get("timestamp", "")
        
        time_bucket = get_time_bucket(timestamp, window_seconds=300)
        cluster_key = (source_ip, modsec_rule_id, time_bucket)
        
        clusters[cluster_key].append(event)
    
    return clusters

def filter_clusters(clusters, min_events=3):
    filtered = {k: v for k, v in clusters.items() if len(v) >= min_events}
    return filtered

def save_clusters(clusters):
    os.makedirs(CLUSTER_DIR, exist_ok=True)
    
    for idx, (cluster_key, events) in enumerate(clusters.items(), 1):
        source_ip, modsec_rule_id, time_bucket = cluster_key
        
        ip_safe = source_ip.replace(".", "_")
        rule_safe = str(modsec_rule_id).replace("/", "_")
        filename = os.path.join(CLUSTER_DIR, f"cluster_{idx:03d}_{ip_safe}_rule{rule_safe}_t{time_bucket}.json")
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2)
        
        print(f"[Done] Saved {os.path.basename(filename)} ({len(events)} events)")
    
    return len(clusters)

def print_statistics(clusters_after, events_total):
    print(f"Total events processed: {events_total}")
    print(f"Clusters: {len(clusters_after)}")

def main():
    print("Starting event clustering...")   
    events = load_malicious_logs()
    print(f"Loaded {len(events)} malicious events from {OUTPUT_LOG}/malicious_logs.json\n")
    
    all_clusters = cluster_events(events)
    filtered_clusters = filter_clusters(all_clusters, min_events=3)
    
    print_statistics(filtered_clusters, len(events))
    
    print("\nSaving clusters...")
    saved_count = save_clusters(filtered_clusters)
    
    print(f"\n[Done] Clustering complete! Saved {saved_count} clusters to {CLUSTER_DIR}/")

if __name__ == "__main__":
    main()