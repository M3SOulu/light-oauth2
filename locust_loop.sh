#!/bin/bash

# Configuration
prometheus_url="http://localhost:9090"
output_directory="csv_output"
python_script="prom_jaeger.py"
metrics_file="prometheus_metrics.txt"
locust_command="locust -f ./locust/locust_main.py --headless -t 15s"

# List of tags for different test scenarios
declare -a tags=("correct" "update_client_404_ownerId")

# Ensure the main output directory exists
mkdir -p "$output_directory"

# Fetch metric names once and save them globally
python -c "import requests; resp = requests.get('$prometheus_url/api/v1/label/__name__/values'); open('$metrics_file', 'w').write('\n'.join(resp.json()['data']))"

# Read metric names into an array
readarray -t metric_names < "$metrics_file"

# Loop through each tag and perform tests
for tag in "${tags[@]}"; do
    # Set up directories and files for this tag
    tag_output_directory="${output_directory}/${tag}"
    mkdir -p "$tag_output_directory"
    cp "$metrics_file" "$tag_output_directory/$metrics_file"  # Copy metrics file to tag directory

    # Record the start time
    start_time=$(date +%s)

    # Start the Locust test for this tag
    $locust_command --tags $tag &

    # Wait for Locust to finish
    wait

    # Fetch Prometheus metrics and Jaeger traces from start time to current time
    python $python_script $prometheus_url "$tag_output_directory" "${metric_names[@]}" "$start_time"
done
