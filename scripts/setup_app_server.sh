#!/usr/bin/env bash
echo "Initializing database"
python /Users/eichinose/PycharmProjects/auth-server/auth/server/commands/manage.py init_db

echo "Starting auth server"
export FLASK_APP=/Users/eichinose/PycharmProjects/auth-server/manage.py
export FLASK_ENV=development
export FLASK_DEBUG=1
/Users/eichinose/.pyenv/versions/online-exam-3.6.1/bin/python -m flask run

python /Users/eichinose/PycharmProjects/MyHomeServer/web-server/auth-server/manage.py init_db

docker run --name auth-dev-db \
    -p 5432:5432 \
    -d postgres