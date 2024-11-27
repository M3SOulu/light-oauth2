import requests
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
import os

# Hardcoded Jaeger services
JAEGER_SERVICES = ['oauth2-code-service', 'oauth2-service-service', 'oauth2-token-service', 'jaeger-all-in-one',
                   'oauth2-user-service', 'oauth2-client-service', 'oauth2-refresh-token-service', 'oauth2-key-service']


def save_last_fetch_time(output_directory: str, end_time: datetime):
    """Saves the last fetch end time to a file."""
    # Define the path for storing the last fetch time
    file_path = os.path.join(output_directory, "last_fetch_time.txt")
    with open(file_path, 'w') as f:
        f.write(end_time.isoformat())


def fetch_metrics_data(url: str, metric_name: str, start_time: datetime, end_time: datetime):
    params = {
        'query': metric_name,
        'start': start_time.isoformat(),
        'end': end_time.isoformat(),
        'step': '5s'  # Defines the interval between two points in seconds
    }
    response = requests.get(f'{url}/api/v1/query_range', params=params)
    
    if response.status_code == 200:
        json_data = response.json()
        if 'data' in json_data and 'result' in json_data['data']:
            return json_data['data']['result']
        else:
            print(f"No data found for metric {metric_name}")
            return []
    else:
        print(f"Failed to fetch data for {metric_name}: HTTP {response.status_code}")
        return []


def save_metrics_data(output_directory, metric_name, metrics_data):
    file_name = f"metric_{metric_name.replace('/', '_')}.json"
    file_path = f"{output_directory}/{file_name}"
    # Write the dictionary to a JSON file
    with open(file_path, 'w') as json_file:
        json.dump(metrics_data, json_file, indent=4)  # `indent=4` makes the file human-readable


def fetch_and_save_jaeger_traces(jaeger_url, output_directory, services):
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(seconds=5)
    for service_name in services:
        traces = fetch_jaeger_traces(jaeger_url, service_name, start_time, end_time)
        if traces and 'data' in traces:
            file_name = f"traces_{service_name}.csv"
            file_path = f"{output_directory}/{file_name}"
            with open(file_path, 'a', newline='') as file:
                writer = csv.writer(file)
                # Define headers for your CSV file as per the data you want to extract
                if file.tell() == 0:
                    writer.writerow(['Trace ID', 'Span ID', 'Operation Name', 'Start Time', 'End Time', 'Tags'])

                for trace in traces['data']:
                    for span in trace.get('spans', []):
                        span_id = span.get('spanID')
                        operation_name = span.get('operationName')
                        start_time = datetime.fromtimestamp(span.get('startTime') / 1e6, timezone.utc).isoformat()
                        # Duration in Jaeger is in microseconds, calculate end time
                        duration_micros = span.get('duration', 0)
                        end_time = datetime.fromtimestamp((span.get('startTime') + duration_micros) / 1e6, timezone.utc).isoformat()
                        tags = {tag['key']: tag['value'] for tag in span.get('tags', [])}
                        tags_str = str(tags)

                        writer.writerow([trace['traceID'], span_id, operation_name, start_time, end_time, tags_str])
        else:
            print(f"Failed to save traces for {service_name}")


def fetch_jaeger_traces(jaeger_url: str, service_name: str, start_time: datetime, end_time: datetime):
    start_time_micro = int(start_time.timestamp() * 1e6)
    end_time_micro = int(end_time.timestamp() * 1e6)
    params = {
        'service': service_name,
        'start': start_time_micro,
        'end': end_time_micro,
        'limit': 20,
    }
    response = requests.get(f"{jaeger_url}/api/traces", params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch Jaeger traces for service '{service_name}': HTTP {response.status_code}")
        return {}


if __name__ == "__main__":
    prometheus_url = sys.argv[1]
    jaeger_url = sys.argv[2]
    output_directory = sys.argv[3]
    start_time = datetime.fromtimestamp(int(sys.argv[4]), tz=timezone.utc)
    end_time = datetime.fromtimestamp(int(sys.argv[5]), tz=timezone.utc)
    metric_names = sys.argv[6:]  # Remaining arguments are metrics
    metric_names = [name.rstrip('\r') for name in metric_names]  # Strip carriage returns

    # Fetch and save Prometheus metrics
    for metric_name in metric_names:
        metrics_data = fetch_metrics_data(prometheus_url, metric_name, start_time, end_time)
        if metrics_data:
            save_metrics_data(output_directory, metric_name, metrics_data)

    # Fetch and save Jaeger traces
    fetch_and_save_jaeger_traces(jaeger_url, output_directory, JAEGER_SERVICES)

    # Save the end time of this fetch
    save_last_fetch_time(output_directory, end_time)

    print("Fetched metrics and traces from ", str(start_time.isoformat()), " to ", str(end_time.isoformat()))
