#!/usr/bin/env python3
"""Create a private .env for VPS deployment, without changing DNS or buying services."""
import os
from pathlib import Path
import re
import secrets

path = Path(__file__).resolve().parent / '.env'
if path.exists():
    raise SystemExit('.env already exists; keep its setup secret. Edit the existing file when necessary.')
domain = input('System subdomain (example: admin.lai.edu.sa): ').strip().lower()
if not re.fullmatch(r'(?=.{4,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', domain) or '.' not in domain:
    raise SystemExit('Enter only a valid domain name; no URL, path, whitespace or port.')
email = input('Email for HTTPS certificate notices: ').strip()
if not re.fullmatch(r'[A-Za-z0-9.!+_-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', email):
    raise SystemExit('Enter a valid email address without whitespace.')
token = secrets.token_urlsafe(40)
content = f'LAI_DOMAIN={domain}\nACME_EMAIL={email}\nLAI_SETUP_TOKEN={token}\nLAI_TRAINER_SIGNUP=0\n'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as out:
    out.write(content)
print('Created .env with restrictive permissions. Do not upload or share this file.')
print('Open https://' + domain + ' after deployment. Paste LAI_SETUP_TOKEN from .env into the first-run form.')
print('Start the stack with: docker compose up -d --build')
