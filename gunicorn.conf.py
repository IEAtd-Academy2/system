"""One process is mandatory for this SQLite/in-memory-session architecture."""
import os
bind = '0.0.0.0:' + os.environ.get('PORT', '10000')
workers = 1
worker_class = 'gthread'
threads = 4
preload_app = False
accesslog = '-'
errorlog = '-'
# Exclude queries, bodies, cookies, referrers and credentials from access logs.
access_log_format = '%(t)s %(m)s %(U)s %(s)s %(L)s'
loglevel = 'info'
timeout = 120
graceful_timeout = 30
keepalive = 5
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190
# Safe ONLY because the included deployment accepts traffic through the HTTPS
# proxy. compose.yaml does not publish the application port to the host.
forwarded_allow_ips = os.environ.get('FORWARDED_ALLOW_IPS', '*')
secure_scheme_headers = {'X-FORWARDED-PROTO': 'https'}
umask = 0o077

def on_starting(server):
    if server.cfg.workers != 1 or server.cfg.preload_app:
        raise RuntimeError('LAI requires exactly one worker and preload_app=False.')
