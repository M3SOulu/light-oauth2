# A Dataset of logs, metrics, and traces for a Microservice system

This a fork of `light-oauth2` system by `networknt` adapted for the needs of creating the dataset.
Original README is here [OLD_README.md](OLD_README.md).
For other dockerfiles and more documentation, see original [repo](https://github.com/networknt/light-docker)

# Contents

This repository contains the following files:

- Original source code
 
  Most directories in this repository contain original source code of `light-oauth2` components;
- [Locust tests](locust)

  Locust tests created for `light-oauth2` APIs;
- [Docker compose file](docker-compose-oauth2-mysql.yml)

  The Docker compose file adapted to deploy `light-oauth2` system as well as additional components needed to gather the data.
  We use the MySQL database for deployment while `light-oauth2` supports other options. See original repo for other deployment files;
- [prometheus.yml](prometheus.yml) Configuration of Prometheus used in deployment
- [prometheus_metrics.txt](prometheus_metrics.txt) List of available and queried Prometheus metrics
- [opentelemetry-javaagent.jar](opentelemetry-javaagent.jar) Java agent for Jaeger that we attempt to inject into each container for tracing collection
- Scripts
  - [prometheus_metrics.sh](prometheus_metrics.sh) Script used to query all available Prometheus metrics
  - [fetch_data.py](fetch_data.py) Script to fetch data of Prometheus and Jaeger agents
  - [data_run.sh](data_run.sh) Main script that deploys the system, runs Locust tests and collects all data

# Setup 
To replicate the data collection process, set up the following things:

## Required packages
- Clone this repository
- Install MySQL (`mysqladmin` command should be available)
- Install Locust (`locust` command should be available)
- Install the `requests` python library
- Install Docker (`docker` and `docker compose` commands should be available)

## Prometheus metrics

The file [prometheus_metrics.txt](prometheus_metrics.txt) contains the list of all metrics that should be queried from Prometheus during data gathering.
Currently, it contains metrics that were available on our research server.

It is possible to use the [prometheus_metrics.sh](prometheus_metrics.sh) script to query all metrics available on your host system:

- Start your Prometheus instance (container)
- If it is deployed somewhere else that `localhost:9000`, change the URL in the script
- Run the script
- The list of metrics will be saved into [prometheus_metrics.txt](prometheus_metrics.txt) to be used by the main script
- If you need only a subset of metrics, edit the file accordingly

# Making a data run

To perform a single data run, i.e. deploy the system and execute all the locust test, run the [data_run.sh](data_run.sh) script.

The script performs the following:
- Get the list of all tagged error tasks from [locust](locust) files
- Get the list of all Prometheus metrics from [prometheus_metrics.txt](prometheus_metrics.txt)
- Deploy all the containers using `docker compose -f docker-compose-oauth2-mysql.yml up --force-recreate -d`
- Wait for the MySQL database to be ready and read the configuration for `light-oauth2`
- Run only the `correct` tests for 1 min and fetch all logs, metrics, traces
- For each error case, run `correct` + error tests for 10s and fetch all logs, metrics, traces
- The data is saved as follows:
  - `light-oauth2-data`: root folder of data
    - `correct`/`ERROR`: data for the correct or correct+ERROR test execution
      - `*.log` files: log files for each container and Locust
      - `metrics`: folder containing all data from Prometheus and Jaeger
        - `metric_*.json`: a JSON file for each Promethus metric from [prometheus_metrics.txt](prometheus_metrics.txt) with metric values
        - `traces_*.csv`: a CSV file for each container with Jaeger traces
        - `last_fetch_time.txt`: timestamp of the end of the interval the data was fetched for