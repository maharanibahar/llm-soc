import json
from datetime import datetime
from pathlib import Path

# 1. LOAD EVENTS
with open('events.json', 'r') as f:
    events = json.load(f)

# 2. SORT BY TIMESTAMP
events = sorted(events, key=lambda x: datetime.fromisoformat(x['timestamp']))

# 3. GROUP BY source_ip ONLY (NOT session_id)
clusters = {}
for event in events:
    key = event['source_ip']  # Just IP, ignore session_id
    if key not in clusters:
        clusters[key] = []
    clusters[key].append(event)

# 4. RE-SORT EACH CLUSTER
for cluster_id in clusters:
    clusters[cluster_id] = sorted(
        clusters[cluster_id],
        key=lambda x: datetime.fromisoformat(x['timestamp'])
    )

# 5. FILTER: Keep only clusters with ≥10 events
min_events = 10
clusters_filtered = {
    k: v for k, v in clusters.items() 
    if len(v) >= min_events
}

print(f"Total clusters: {len(clusters)}")
print(f"Clusters ≥{min_events} events: {len(clusters_filtered)}")

# 6. HANDLE NULL VALUES
for cluster_id in clusters_filtered:
    for event in clusters_filtered[cluster_id]:
        if event.get('http_status') is None:
            event['http_status'] = 0

# 7. SAVE 5 SAMPLE CLUSTERS
output_dir = Path('test_clusters')
output_dir.mkdir(exist_ok=True)

sample_clusters = list(clusters_filtered.items())[:5]

for cluster_id, events_in_cluster in sample_clusters:
    filename = output_dir / f"{cluster_id}.json"
    with open(filename, 'w') as f:
        json.dump(events_in_cluster, f, indent=2)
    print(f"✓ Saved {filename} ({len(events_in_cluster)} events)")

# 8. VERIFY
print("\n" + "="*80)
print("CLUSTER VERIFICATION")
print("="*80 + "\n")

for cluster_id, events_in_cluster in sample_clusters:
    first = events_in_cluster[0]
    last = events_in_cluster[-1]
    
    print(f"Cluster IP: {cluster_id}")
    print(f"  Events: {len(events_in_cluster)}")
    print(f"  Duration: {first['timestamp']} → {last['timestamp']}")
    print(f"  First: {first['event_id']} | Status {first['http_status']}")
    print(f"  Last:  {last['event_id']} | Status {last['http_status']}")
    print()