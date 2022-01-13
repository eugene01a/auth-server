#!/usr/bin/env bash
docker run -d --name token_auth_server \
-e POSTGRES_DB=flask_jwt_auth_dev \
-e POSTGRES_PASSWORD=ONLIN3-ex4m \
-p 5432:5432 postgres

echo "Initializing database"
python /Users/eichinose/PycharmProjects/MyHomeServer/auth-server/manage.py init_db

echo "Starting auth server"
export FLASK_APP=/Users/eichinose/PycharmProjects/MyHomeServer/auth-server/manage.py
export FLASK_ENV=development
export FLASK_DEBUG=1