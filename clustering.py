import json
from datetime import datetime
from pathlib import Path

# Load events
with open('./output/normalized_logs.json', 'r') as f:
    events = json.load(f)

# Sort and group by IP only
events = sorted(events, key=lambda x: datetime.fromisoformat(x['timestamp']))

clusters = {}
for event in events:
    key = event['source_ip']
    if key not in clusters:
        clusters[key] = []
    clusters[key].append(event)

# CHECK BEFORE FILTERING
print("BEFORE FILTERING:")
cluster_sizes = [len(v) for v in clusters.values()]
print(f"  Total clusters: {len(clusters)}")
print(f"  Min size: {min(cluster_sizes)}")
print(f"  Max size: {max(cluster_sizes)}")
print(f"  Clusters ≥10: {len([s for s in cluster_sizes if s >= 10])}")

# FILTER with LOWER threshold
min_events = 5  # Lower from 10 to 5
clusters_filtered = {k: v for k, v in clusters.items() if len(v) >= min_events}

print(f"\nAFTER FILTERING (min={min_events} events):")
print(f"  Clusters kept: {len(clusters_filtered)}")

# SAVE
output_dir = Path('test_clusters')
output_dir.mkdir(exist_ok=True)

sample_clusters = list(clusters_filtered.items())[:5]

for cluster_id, events_in_cluster in sample_clusters:
    filename = output_dir / f"{cluster_id}.json"
    with open(filename, 'w') as f:
        json.dump(events_in_cluster, f, indent=2)
    print(f"✓ Saved {filename}")

print(f"\nCheck folder: test_clusters/")
