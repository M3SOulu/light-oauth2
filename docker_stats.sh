#!/bin/bash

# Output file
output_file="docker_stats.csv"

# Write CSV header if file doesn't exist
if [ ! -f "$output_file" ]; then
  echo "Timestamp,Container ID,Name,CPU %,Mem Usage / Limit,Mem %,Net I/O,Block I/O,PIDs" > "$output_file"
fi

while true; do
  # Get the current Unix timestamp
  timestamp=$(date +%s)
  
  # Append the timestamp to each docker stats entry
  docker stats --no-stream --format "$timestamp,{{.Container}},{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}" >> "$output_file"
  
  # Wait for a specific interval (e.g., 5 seconds)
  sleep 5
done
