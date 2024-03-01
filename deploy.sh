#!/bin/bash
docker compose -f docker-compose-oauth2-mysql.yml up -d
docker exec -it light-oauth2-mysqldb-1 mysql -u mysqluser --password=mysqlpw < /docker-entrypoint-initdb.d/create_mysql.sql