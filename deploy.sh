#! /bin/bash
docker compose -f docker-compose-oauth2-mysql.yml up --force-recreate -d
while ! mysqladmin ping -h"127.0.0.1" --silent; do
    echo "Waiting for MySQL..."
    sleep 5
done
echo "Started containers"
#sleep 30
echo "Initializing database"
docker exec light-oauth2-mysqldb-1 sh -c 'mysql -uroot -prootpassword < /docker-entrypoint-initdb.d/create_mysql.sql'