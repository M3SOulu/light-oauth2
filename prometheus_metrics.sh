#!/bin/bash

metrics_file="prometheus_metrics.txt"
prometheus_url="http://localhost:9090"

python -c "import requests; resp = requests.get('$prometheus_url/api/v1/label/__name__/values'); open('$metrics_file', 'w').write('\n'.join(resp.json()['data']))"
