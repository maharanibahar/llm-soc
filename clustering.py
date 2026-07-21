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
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        epoch = dt.timestamp()
        bucket = int(epoch // window_seconds)
        return bucket
    except:
        return 0

def cluster_events(events):
    clusters = defaultdict(list)
    
    for event in events:
        source_ip = event.get("source_ip", "unknown")
        attack_class = event.get("attack_class", "Unknown")
        timestamp = event.get("timestamp", "")
        
        time_bucket = get_time_bucket(timestamp, window_seconds=300)
        cluster_key = (source_ip, attack_class, time_bucket)
        
        clusters[cluster_key].append(event)
    
    return clusters

def filter_clusters(clusters, min_events=3):
    filtered = {k: v for k, v in clusters.items() if len(v) >= min_events}
    return filtered

def save_clusters(clusters):
    os.makedirs(CLUSTER_DIR, exist_ok=True)
    
    for idx, (cluster_key, events) in enumerate(clusters.items(), 1):
        source_ip, attack_class, time_bucket = cluster_key
        
        ip_safe = source_ip.replace(".", "_")
        filename = os.path.join(CLUSTER_DIR, f"cluster_{idx:03d}_{ip_safe}_{attack_class}_t{time_bucket}.json")
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2)
        
        print(f"[OK] Saved {os.path.basename(filename)} ({len(events)} events)")
    
    return len(clusters)

def print_statistics(clusters_before, clusters_after, events_total):
    print("\n" + "="*60)
    print("CLUSTERING STATISTICS")
    print("="*60)
    print(f"Total events processed: {events_total}")
    print(f"Clusters before filtering: {len(clusters_before)}")
    print(f"Clusters after filtering: {len(clusters_after)}")
    
    if clusters_after:
        sizes = [len(v) for v in clusters_after.values()]
        print(f"Min cluster size: {min(sizes)}")
        print(f"Max cluster size: {max(sizes)}")
        print(f"Avg cluster size: {sum(sizes)/len(sizes):.1f}")
    
    print("\nCluster breakdown:")
    for cluster_key, events in clusters_after.items():
        source_ip, attack_class, time_bucket = cluster_key
        print(f"  {source_ip:15s} | {attack_class:15s} | {len(events):3d} events")
    
    print("="*60)

def main():
    print("Starting event clustering...")
    print("Method: IP + Attack Class + 5-minute temporal windows\n")
    
    events = load_malicious_logs()
    print(f"Loaded {len(events)} malicious events from {OUTPUT_LOG}/malicious_logs.json\n")
    
    all_clusters = cluster_events(events)
    
    filtered_clusters = filter_clusters(all_clusters, min_events=3)
    
    print_statistics(all_clusters, filtered_clusters, len(events))
    
    print("\nSaving clusters...")
    saved_count = save_clusters(filtered_clusters)
    
    print(f"\n[OK] Clustering complete! Saved {saved_count} clusters to {CLUSTER_DIR}/")

if __name__ == "__main__":
    main()
