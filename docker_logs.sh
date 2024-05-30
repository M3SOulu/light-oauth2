#!/bin/bash

# Directory to store output files
output_directory="docker_logs"

# Create the directory if it doesn't exist
mkdir -p "$output_directory"

# Get the list of running container IDs
containers=$(docker ps -q)

for container in $containers; do
  # Get the container name for easier identification
  container_name=$(docker inspect --format '{{ .Name }}' $container | sed 's/^\/\(.*\)/\1/')
  
  # Define the output file for each container's logs
  output_file="${output_directory}/${container_name}.log"
  
  # Fetch the complete logs for the container
  docker logs $container > "$output_file"
done

echo "Logs have been saved to $output_directory."
