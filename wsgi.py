"""Online WSGI gateway for LAI. Run behind HTTPS using the included deployment files.

Business rules remain in app.py. Its local http.server is NOT started here.
This build deliberately uses one process / one instance with serialized SQLite
operations. Never enable multiple workers, replicas, or shared network storage.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from email.message import Message
import fcntl
from http import HTTPStatus
import http.cookies
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import urlsplit

import app as core

LOG = logging.getLogger('lai.online')
ONLINE_VERSION = '1.1.0-online'
core.APP_VERSION = ONLINE_VERSION
MAX_RESTORE_BYTES = 32 * 1024 * 1024
MAX_ATTACHMENT_REQUEST = 12 * 1024 * 1024
MAX_NORMAL_REQUEST = 1024 * 1024
MAX_RESTORE_REQUEST = ((MAX_RESTORE_BYTES + 2) // 3) * 4 + 16384
PUBLIC_AUTH = {'/api/login', '/api/setup', '/api/signup'}
START_LOCK = threading.RLock()
_STARTED = False
_PROCESS_LOCK = None


def flag(name: str, default: str = '0') -> bool:
    return os.environ.get(name, default).strip().lower() in {'1', 'true', 'yes'}


class Settings:
    def __init__(self):
        external = os.environ.get('RENDER_EXTERNAL_URL', '').strip().rstrip('/')
        primary = os.environ.get('LAI_PUBLIC_URL', '').strip().rstrip('/') or external
        if not primary:
            raise RuntimeError('Set LAI_PUBLIC_URL to the exact HTTPS origin, or deploy on Render.')
        urls = {primary}
        if external:
            urls.add(external)
        self.allow_http = flag('LAI_ALLOW_LOCAL_HTTP')
        self.origins = set()
        self.hosts = set()
        for url in urls:
            p = urlsplit(url)
            if (not p.hostname or p.username or p.password or p.path not in ('', '/')
                    or p.query or p.fragment or p.scheme not in ('http', 'https')):
                raise RuntimeError('Public URL must be an origin without credentials, path or query.')
            _ = p.port  # Validate a malformed port before accepting the setting.
            if p.scheme == 'http' and not (self.allow_http and p.hostname in {'localhost', '127.0.0.1', '::1'}):
                raise RuntimeError('HTTP is permitted only for an explicitly enabled loopback test.')
            self.origins.add(p.scheme + '://' + p.netloc.lower())
            self.hosts.add(p.netloc.lower())
        self.public_url = primary
        self.setup_token = os.environ.get('LAI_SETUP_TOKEN', '')
        self.signup = flag('LAI_TRAINER_SIGNUP')
        # With Caddy, this header is stripped and set by our proxy. For Render,
        # leave it empty: use REMOTE_ADDR, not untrusted client-supplied XFF.
        self.client_ip_header = os.environ.get('LAI_CLIENT_IP_HEADER', '').strip().upper().replace('-', '_')
        if self.client_ip_header not in ('', 'X_LAI_CLIENT_IP'):
            raise RuntimeError('Only the explicitly configured Caddy client-IP header is supported.')


CONFIG = Settings()


class RateLimiter:
    """Bounded, process-local rolling windows. No passwords or tokens are stored."""
    def __init__(self):
        self.items = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, key, limit, seconds):
        moment = time.monotonic()
        with self.lock:
            q = self.items.pop(key, deque())
            while q and q[0] <= moment - seconds:
                q.popleft()
            self.items[key] = q
            while len(self.items) > 10000:
                self.items.popitem(last=False)
            if len(q) >= limit:
                return False
            q.append(moment)
            return True


LIMITER = RateLimiter()
_ORIGINAL_PASSWORD_HASH = core.password_hash


def online_password_hash(password):
    if not isinstance(password, str) or len(password) < 12:
        raise core.APIError('\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u064a\u062c\u0628 \u0623\u0646 \u062a\u062d\u062a\u0648\u064a \u0639\u0644\u0649 12 \u062d\u0631\u0641\u064b\u0627 \u0639\u0644\u0649 \u0627\u0644\u0623\u0642\u0644.')
    return _ORIGINAL_PASSWORD_HASH(password)


core.password_hash = online_password_hash


def initialize_runtime():
    global _STARTED, _PROCESS_LOCK
    with START_LOCK:
        if _STARTED:
            return
        core.DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_file = (core.DATA_DIR / '.online-process.lock').open('a+')
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock_file.close()
            raise RuntimeError('Only ONE online process may use this data directory. Stop the other instance.')
        _PROCESS_LOCK = lock_file
        core.initialize()
        with core.LOCK, core.connect() as db:
            if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise RuntimeError('Database integrity check failed. Restore a verified backup.')
            if not db.execute('SELECT COUNT(*) FROM users').fetchone()[0] and len(CONFIG.setup_token) < 32:
                raise RuntimeError('Before first setup, set LAI_SETUP_TOKEN to a random secret of at least 32 characters.')
        _STARTED = True
        threading.Thread(target=_backup_loop, name='lai-database-backup', daemon=True).start()


def _backup_loop():
    while True:
        try:
            with core.LOCK:
                with core.connect() as db:
                    has_users = db.execute('SELECT COUNT(*) FROM users').fetchone()[0] > 0
                if has_users:
                    core.automatic_backup()
        except Exception:
            LOG.exception('Automatic database backup failed. Check storage and permissions.')
        time.sleep(3600)


def security_headers(secure=True):
    csp = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
           "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    headers = {
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Content-Security-Policy': csp,
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'X-Robots-Tag': 'noindex, nofollow, noarchive',
    }
    if secure:
        headers['Strict-Transport-Security'] = 'max-age=31536000'
    return headers


class OnlineHandler(core.Handler):
    """Adapt the existing route methods to WSGI, without using HTTPServer."""
    def __init__(self, environ):
        self.environ = environ
        self.command = environ.get('REQUEST_METHOD', 'GET')
        self.path = environ.get('PATH_INFO', '/')
        query = environ.get('QUERY_STRING', '')
        if query:
            self.path += '?' + query
        self.route_path = environ.get('PATH_INFO', '/')
        self.headers = Message()
        for key, value in environ.items():
            if key.startswith('HTTP_'):
                self.headers[key[5:].replace('_', '-')] = str(value)
        for key in ('CONTENT_LENGTH', 'CONTENT_TYPE'):
            if key in environ:
                self.headers[key.replace('_', '-')] = str(environ[key])
        self.secure = environ.get('wsgi.url_scheme') == 'https'
        self.rfile = environ['wsgi.input']
        client = environ.get('REMOTE_ADDR') or 'proxy'
        if CONFIG.client_ip_header:
            candidate = environ.get('HTTP_' + CONFIG.client_ip_header, '')
            try:
                client = str(ipaddress.ip_address(candidate))
            except ValueError:
                raise core.APIError(core.M['forbidden'], 403)
        self.client_address = (client, 0)
        # On HTTPS only a __Host- cookie is accepted. Legacy cookies cannot shadow it.
        incoming = http.cookies.SimpleCookie()
        try:
            incoming.load(self.headers.get('Cookie', ''))
        except http.cookies.CookieError:
            incoming = http.cookies.SimpleCookie()
        name = '__Host-lai_session' if self.secure else 'lai_session'
        token = incoming[name].value if name in incoming else ''
        if 'Cookie' in self.headers:
            del self.headers['Cookie']
        if token:
            self.headers['Cookie'] = 'lai_session=' + token
        self.response = (500, [('Content-Type', 'application/json')], b'{"error":"Internal error"}')

    def send_bytes(self, data, content_type='application/json; charset=utf-8', status=200, extra=None):
        headers = security_headers(self.secure)
        headers.update({'Content-Type': content_type, 'Content-Length': str(len(data))})
        headers.update(extra or {})
        if 'Set-Cookie' in headers and self.secure:
            headers['Set-Cookie'] = headers['Set-Cookie'].replace('lai_session=', '__Host-lai_session=', 1) + '; Secure'
        if status == 429:
            headers['Retry-After'] = '900'
        self.response = (status, list(headers.items()), data)

    def guard(self, write=False):
        raw_host = (self.headers.get('X-Forwarded-Host') or self.headers.get('Host', '')).lower()
        host = raw_host.split(':')[0]
        allowed_hosts = {h.split(':')[0] for h in CONFIG.hosts} | CONFIG.hosts
        if host not in allowed_hosts and raw_host not in allowed_hosts:
            raise core.APIError(core.M['forbidden'], 403)
        if not self.secure and not (CONFIG.allow_http and ('http://' + host) in CONFIG.origins):
            raise core.APIError('HTTPS is required.', 426)
        origin = self.headers.get('Origin')
        if origin and origin not in CONFIG.origins:
            raise core.APIError(core.M['forbidden'], 403)
        sec_fetch_site = self.headers.get('Sec-Fetch-Site')
        sec_fetch_mode = self.headers.get('Sec-Fetch-Mode')
        if sec_fetch_site == 'cross-site' and (write or sec_fetch_mode != 'navigate'):
            raise core.APIError(core.M['forbidden'], 403)
        if write:
            if (self.headers.get('X-LAI-Client') != 'online'
                    or self.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json'):
                raise core.APIError(core.M['forbidden'], 403)
            if self.route_path in PUBLIC_AUTH:
                # Covers both rotating-account attempts and expensive password hashing.
                limit = 40 if self.route_path == '/api/login' else 10
                if (not LIMITER.allow(('auth-all',), 120, 60)
                        or not LIMITER.allow((self.route_path, self.client_address[0]), limit, 900)):
                    raise core.APIError(core.M['rate'], 429)
        if len(core.LOGIN_FAILURES) > 10000:
            with core.LOCK:
                moment = time.time()
                for key in list(core.LOGIN_FAILURES):
                    if not any(t > moment - 900 for t in core.LOGIN_FAILURES[key]):
                        core.LOGIN_FAILURES.pop(key, None)
                if len(core.LOGIN_FAILURES) > 10000:
                    raise core.APIError(core.M['rate'], 429)

    def body(self):
        path = self.route_path
        if path not in PUBLIC_AUTH:
            # Authenticate and check CSRF BEFORE consuming an upload body.
            with core.LOCK, core.connect() as db:
                user, _, _ = self.session(db, True)
                if path == '/api/restore' and not core.is_admin(user):
                    raise core.APIError(core.M['forbidden'], 403)
        limit = MAX_RESTORE_REQUEST if path == '/api/restore' else (
            MAX_ATTACHMENT_REQUEST if path.endswith('/attachment') else MAX_NORMAL_REQUEST)
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            raise core.APIError(core.M['invalid'], 400)
        if not 0 < size <= limit:
            raise core.APIError(core.M['invalid'], 413)
        payload = self.rfile.read(size)
        if len(payload) != size:
            raise core.APIError(core.M['invalid'], 400)
        body = json.loads(payload)
        if not isinstance(body, dict):
            raise core.APIError(core.M['invalid'], 400)
        if path in PUBLIC_AUTH:
            username = str(body.get('username', '')).strip().lower()
            if len(username) > 40:
                raise core.APIError(core.M['invalid'], 400)
            if path == '/api/login' and not LIMITER.allow(('login-account', username), 20, 900):
                raise core.APIError(core.M['rate'], 429)
        if path == '/api/restore':
            raw_length = len(str(body.get('content', '')))
            if raw_length > ((MAX_RESTORE_BYTES + 2) // 3) * 4:
                raise core.APIError('Online restore is limited to 32 MiB. Use the documented stopped-server migration for larger files.', 413)
        return body

    def route(self, db, path, query, body, write):
        if path == '/api/status' and not write:
            return {'setup_required': db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0,
                    'setup_token_required': True, 'trainer_signup': CONFIG.signup,
                    'version': ONLINE_VERSION, 'mode': 'online'}, None
        if path == '/api/setup' and write:
            supplied = body.get('setup_token', '')
            if (not isinstance(supplied, str) or not CONFIG.setup_token
                    or not secrets.compare_digest(supplied, CONFIG.setup_token)):
                raise core.APIError('\u0631\u0645\u0632 \u062a\u0647\u064a\u0626\u0629 \u0627\u0644\u0625\u062f\u0627\u0631\u0629 \u063a\u064a\u0631 \u0635\u062d\u064a\u062d.', 403)
        if path == '/api/signup' and not CONFIG.signup:
            raise core.APIError(core.M['forbidden'], 403)
        result, extra = super().route(db, path, query, body, write)
        if path == '/api/login' and write:
            uid = result['user']['id']
            same = [(k, s) for k, s in core.SESSIONS.items() if s['uid'] == uid]
            for key, _ in sorted(same, key=lambda item: item[1]['expires'])[:-10]:
                core.SESSIONS.pop(key, None)
        if path == '/api/bootstrap' and not write:
            result.update(mode='online', restore_limit_mb=32, refresh_seconds=15)
        return result, extra


def application(environ, start_response):
    try:
        initialize_runtime()
        method = environ.get('REQUEST_METHOD', 'GET')
        path = environ.get('PATH_INFO', '/')
        secure = environ.get('wsgi.url_scheme') == 'https'
        # Public, non-sensitive health endpoint for platform probes. No user data.
        if path == '/healthz' and method in {'GET', 'HEAD'}:
            with core.LOCK, core.connect() as db:
                db.execute('SELECT 1 FROM settings LIMIT 1').fetchone()
            data = b'{"status":"ok"}'
            headers = security_headers(secure)
            headers.update({'Content-Type': 'application/json', 'Content-Length': str(len(data))})
            start_response('200 OK', list(headers.items()))
            return [b'' if method == 'HEAD' else data]
        handler = OnlineHandler(environ)
        if method not in {'GET', 'HEAD', 'POST', 'PUT'}:
            handler.send_json({'error': core.M['archive']}, 405, {'Allow': 'GET, HEAD, POST, PUT'})
        elif path == '/robots.txt' and method in {'GET', 'HEAD'}:
            handler.guard(False)
            handler.send_bytes(b'User-agent: *\nDisallow: /\n', 'text/plain; charset=utf-8')
        else:
            handler.dispatch(method in {'POST', 'PUT'})
        code, headers, data = handler.response
        start_response(str(code) + ' ' + HTTPStatus(code).phrase, headers)
        return [b'' if method == 'HEAD' else data]
    except core.APIError as error:
        data = core.jsonstr({'error': str(error)}).encode()
        headers = security_headers(environ.get('wsgi.url_scheme') == 'https')
        headers.update({'Content-Type': 'application/json; charset=utf-8', 'Content-Length': str(len(data))})
        start_response(str(error.code) + ' ' + HTTPStatus(error.code).phrase, list(headers.items()))
        return [data]
    except Exception:
        LOG.exception('Online gateway failed. No request body is logged.')
        data = b'{"error":"Service unavailable. Check server configuration or logs."}'
        headers = security_headers(environ.get('wsgi.url_scheme') == 'https')
        headers.update({'Content-Type': 'application/json', 'Content-Length': str(len(data))})
        start_response('503 Service Unavailable', list(headers.items()))
        return [data]
