#!/bin/bash

# Configuration
prometheus_url="http://localhost:9090"
output_directory="csv_output"
python_script="prom_jaeger.py"
metrics_file="prometheus_metrics.txt"
locust_command="locust --config locust/locust.conf"

# List of error_tags for different test scenarios
error_tags=($(grep -oP "@tag\('error'.*'\K[^']*(?='\))" -r locust/locustfiles/ -h))

# Ensure the main output directory exists
mkdir -p "$output_directory"

# Read metric names into an array
readarray -t metric_names < "$metrics_file"

deploy()
{
  docker compose -f docker-compose-oauth2-mysql.yml up --force-recreate -d
  while ! mysqladmin ping -h"127.0.0.1" --silent; do
      echo "Waiting for MySQL..."
      sleep 5
  done
  echo "Started containers"
  #sleep 30
  echo "Initializing database"
  docker exec light-oauth2-mysqldb-1 sh -c 'mysql -uroot -prootpassword < /docker-entrypoint-initdb.d/create_mysql.sql'
}

deploy
# Loop through each tag and perform tests
for tag in "${error_tags[@]}"; do
    # Set up directories and files for this tag
    tag_output_directory="${output_directory}/${tag}"
    mkdir -p "$tag_output_directory"
    cp "$metrics_file" "$tag_output_directory/$metrics_file"  # Copy metrics file to tag directory

    # Start the system and initialize MySQL database

    # Record the start time
    start_time=$(date +%s)

    # Start the Locust test for this tag
    $locust_command --tags correct $tag &

    # Wait for Locust to finish
    wait

    # Fetch Prometheus metrics and Jaeger traces from start time to current time
    python $python_script $prometheus_url "$tag_output_directory" "${metric_names[@]}" "$start_time"

    #Move locust log
    mv locust/locust.log $tag_output_directory
done
  # Stop the system
  docker compose -f docker-compose-oauth2-mysql.yml down -v
