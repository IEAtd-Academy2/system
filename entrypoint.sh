#!/bin/sh
set -eu
umask 077
mkdir -p "${LAI_DATA_DIR:-/var/lib/lai}"
# Never let provider defaults enable preloading or several workers.
unset GUNICORN_CMD_ARGS
exec gunicorn --config gunicorn.conf.py --workers 1 wsgi:application
