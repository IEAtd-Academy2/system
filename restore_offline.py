#!/usr/bin/env python3
"""Restore a trusted v1-compatible snapshot while the online app is stopped.
Never merges records; the entire current database is replaced after validation.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import app


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--confirm-replace', action='store_true', required=True)
    args=parser.parse_args()
    source=args.source.resolve(strict=True)
    if source==app.DB_PATH:
        raise SystemExit('The source must not be the live database.')
    app.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with (app.DATA_DIR/'.online-process.lock').open('a+') as lock:
        try:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('The online application is running. Stop it before restoring.')
        existed=app.DB_PATH.exists()
        app.initialize()
        fd,name=tempfile.mkstemp(prefix='offline-restore-',suffix='.sqlite',dir=app.DATA_DIR)
        os.close(fd);candidate=Path(name)
        try:
            src=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)
            out=sqlite3.connect(candidate)
            try:src.backup(out)
            finally:out.close();src.close()
            db=sqlite3.connect(candidate)
            try:
                db.execute('PRAGMA trusted_schema=OFF')
                if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('Integrity check failed.')
                if db.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0]!=app.SCHEMA_VERSION:
                    raise ValueError('Schema version mismatch.')
                if not db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]:
                    raise ValueError('No active administrator.')
                if db.execute("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]:
                    raise ValueError('Unexpected views or triggers.')
                with app.connect() as current:
                    for table in ('settings','users','records','comments','attachments','audit'):
                        expected=[tuple(x) for x in current.execute(f'PRAGMA table_info({table})')]
                        actual=[tuple(x) for x in db.execute(f'PRAGMA table_info({table})')]
                        if expected!=actual:raise ValueError('Incompatible table: '+table)
                if db.execute('PRAGMA foreign_key_check').fetchall():raise ValueError('Invalid references.')
                for row in db.execute('SELECT data FROM records'):json.loads(row[0])
            finally:db.close()
            if existed:app.backup_db()
            os.replace(candidate,app.DB_PATH)
            with app.connect() as current:
                app.audit(current,None,'offline_restore',detail='Operator restored a validated snapshot while the server was stopped.')
            print('Restore completed. Restart the application and use an account from the restored snapshot.')
        finally:
            candidate.unlink(missing_ok=True)

if __name__=='__main__':main()
