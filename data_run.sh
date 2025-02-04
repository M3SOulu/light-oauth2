#!/bin/bash

# Configuration
prometheus_url="http://localhost:9090"
jaeger_url="http://localhost:16686"
output_directory="LO2_run_$(date +%s)"
python_script="fetch_data.py"
metrics_file="prometheus_metrics.txt"
run_log="run_log.log"
MIN_DUR=20
MAX_DUR=180
MIN_WAIT=1
MAX_WAIT=5

# List of error_tags for different test scenarios
error_tags=("correct")
error_tags+=($(grep -oP "@tag\('error'.*'\K[^']*(?='\))" -r locust/locustfiles/ -h))
shuffled_tags=($(shuf -e "${error_tags[@]}"))

# Ensure the main output directory exists
mkdir -p "$output_directory"

# Read metric names into an array
readarray -t metric_names < "$metrics_file"

deploy()
{
  docker compose -f docker-compose-oauth2-mysql.yml up --force-recreate -d
  while ! mysqladmin ping -h"127.0.0.1" --silent; do
      echo "$(date +%s) Waiting for MySQL..." | tee -a ${output_directory}/${run_log}
      sleep 5
  done
  echo "$(date +%s) Started containers" | tee -a ${output_directory}/${run_log}
  #sleep 30
  echo "$(date +%s) Initializing database" | tee -a ${output_directory}/${run_log}
  docker exec light-oauth2-mysqldb-1 sh -c 'mysql -uroot -prootpassword < /docker-entrypoint-initdb.d/create_mysql.sql'
}

echo "$(date +%s) LO2 Run started" | tee -a ${output_directory}/${run_log}

deploy
# Loop through each tag and perform tests
for tag in "${shuffled_tags[@]}"; do
    # Set up directories and files for this tag
    tag_output_directory="${output_directory}/${tag}"
    metric_output_directory="${tag_output_directory}/metrics"
    mkdir -p "$tag_output_directory"
    mkdir -p "$metric_output_directory"
    duration=$(( RANDOM % (MAX_DUR - MIN_DUR + 1) + MIN_DUR ))

    echo "$(date +%s) Starting locust test for tag '$tag' with duration ${duration}s" | tee -a ${output_directory}/${run_log}

    # Record the start time
    start_time=$(date +%s)

    # Start the Locust test for this tag
    if [ "$tag" == "correct" ]; then
      locust --config locust/locust.conf --tags correct --run-time "${duration}s" > /dev/null 2>&1 &
    else
      locust --config locust/locust.conf --tags correct $tag --run-time "${duration}s" > /dev/null 2>&1 &
    fi

    # Wait for Locust to finish
    wait

    end_time=$(date +%s)

    echo "$(date +%s) Finished locust test for tag '$tag'" | tee -a ${output_directory}/${run_log}

    #Move locust log
    mv locust/locust.log $tag_output_directory
    echo "$(date +%s) Moved locust logs for tag '$tag'" | tee -a ${output_directory}/${run_log}

    # Iterate over each container and move the logs
    for container_id in $(docker ps --format '{{.Names}}'); do
        docker logs $container_id --since "$start_time" --until "$end_time" > "$tag_output_directory/${container_id}.log" 2>&1
    done
    echo "$(date +%s) Fetched docker logs from ${start_time} to ${end_time}" | tee -a ${output_directory}/${run_log}

    # Fetch Prometheus metrics and Jaeger traces from start time to current time
    python $python_script $prometheus_url $jaeger_url "$metric_output_directory" "$start_time" "$end_time" "${metric_names[@]}"

    echo "$(date +%s) Fetched Prometheus metrics from ${start_time} to ${end_time}" | tee -a ${output_directory}/${run_log}

    wait_time=$(( RANDOM % (MAX_WAIT - MIN_WAIT + 1) + MIN_WAIT ))

    echo "$(date +%s) Waiting for ${wait_time}s" | tee -a ${output_directory}/${run_log}

    sleep ${wait_time}
done
  # Stop the system
  docker compose -f docker-compose-oauth2-mysql.yml down -v
echo "$(date +%s) LO2 Run ended" | tee -a ${output_directory}/${run_log}
