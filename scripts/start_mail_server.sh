#!/usr/bin/env bash
pid=$(lsof -i:8025 -t)
if [ ! -z "$pid" ]
then
echo "Stopping mail server"
kill -9 $pid
fi

echo "Starting mail server"
set -x
python -m smtpd -n -c DebuggingServer localhost:8025
set +x
