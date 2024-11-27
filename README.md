# A Dataset of logs, metrics, and traces for a Microservice systems

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
- Scripts
  - [prometheus_metrics.sh](prometheus_metrics.sh) Script used to query all available Prometheus metrics
  - [prom_jaeger.py](prom_jaeger.py) Script to fetch data of Prometheus and Jaeger agents
  - [locust_loop.sh](locust_loop.sh) Main script that deploys the system, runs Locust tests and collects all data

# Making a data run
```
docker compose -f docker-compose-oauth2-mysql.yml up
```
