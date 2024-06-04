import requests
import csv
import sys
from datetime import datetime, timedelta, timezone
from dateutil import parser
import os

def save_last_fetch_time(file_path, end_time):
    """Saves the last fetch end time to a file."""
    with open(file_path, 'w') as f:
        f.write(end_time.isoformat())

def load_last_fetch_time(file_path):
    """Loads the last fetch end time from a file. Returns a datetime object or None."""
    try:
        with open(file_path, 'r') as f:
            return datetime.fromisoformat(f.read())
    except FileNotFoundError:
        return None
    except ValueError as e:
        print(f"Error parsing datetime from file '{file_path}': {e}")
        return None

def ensure_datetime(time_value):
    """Ensure the time_value is a datetime object."""
    if isinstance(time_value, datetime):
        return time_value
    elif isinstance(time_value, str):
        # Attempt to parse the string to datetime
        try:
            return parser.parse(time_value)
        except ValueError as e:
            print(f"Error parsing datetime from string '{time_value}': {e}")
            return None  # or handle as appropriate for your use case
    else:
        print(f"Unexpected type for time_value: {type(time_value)}")
        return None  # or handle as appropriate for your use case


def fetch_metrics_data(url, metric_name, start_time, end_time):
    params = {
        'query': metric_name,
        'start': start_time,
        'end': end_time,
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


def write_metrics_to_csv(output_directory, metric_name, metrics_data):
    file_name = f"metric_{metric_name.replace('/', '_')}.csv"
    file_path = f"{output_directory}/{file_name}"
    with open(file_path, 'a', newline='') as file:
        writer = csv.writer(file)
        for result in metrics_data:
            for value in result['values']:
                writer.writerow([metric_name, value[0], value[1]])


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


def fetch_jaeger_traces(jaeger_url, service_name, start_time, end_time):
    start_time = ensure_datetime(start_time)
    end_time = ensure_datetime(end_time)
    
    # Proceed only if both start_time and end_time are successfully ensured as datetime objects
    if start_time and end_time:
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
    else:
        # Handle the case where start_time or end_time couldn't be ensured as datetime objects
        return {}


if __name__ == "__main__":
    prometheus_url = sys.argv[1]
    output_directory = sys.argv[2]
    start_time = datetime.fromtimestamp(int(sys.argv[3]), tz=timezone.utc)
    metric_names = sys.argv[4:]  # Remaining arguments are metrics

    # Hardcoded Jaeger services
    jaeger_services = ['oauth2-code-service','oauth2-service-service', 'oauth2-token-service', 'jaeger-all-in-one', 'oauth2-user-service', 'oauth2-client-service', 'oauth2-refresh-token-service', 'oauth2-key-service']
    jaeger_url = "http://localhost:16686"  # Jaeger Query Service URL

    # Define the path for storing the last fetch time
    last_fetch_time_file = os.path.join(output_directory, "last_fetch_time.txt")
    
    prometheus_url = sys.argv[1]
    output_directory = sys.argv[2]
    metric_names = [name.rstrip('\r') for name in sys.argv[3:]]  # Strip carriage returns

    # Current run's end time is now
    end_time = datetime.now(timezone.utc)

    # Your existing data fetching and processing logic...
    for metric_name in metric_names:
        metrics_data = fetch_metrics_data(prometheus_url, metric_name, start_time.isoformat(), end_time.isoformat())
        if metrics_data:
            write_metrics_to_csv(output_directory, metric_name, metrics_data)
    
    fetch_and_save_jaeger_traces(jaeger_url, output_directory, jaeger_services)

    # Save the end time of this fetch for the next run
    save_last_fetch_time(last_fetch_time_file, end_time)

    print("Fetched metrics and traces from ", str(start_time.isoformat()), " to ", str(end_time.isoformat()))
