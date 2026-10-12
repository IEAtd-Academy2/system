#!/usr/bin/env python3
"""LAI Executive Local - dependency-free, loopback-only executive workspace.
Copyright 2026. Application source supplied for the institute's internal use.
"""
from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import hmac
import http.cookies
import io
import json
import math
import mimetypes
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote
import webbrowser

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('LAI_DATA_DIR', str(ROOT / 'data'))).resolve()
DB_PATH = DATA_DIR / 'lai.sqlite'
APP_VERSION = '1.0.0'
SCHEMA_VERSION = '1'
TZ = timezone(timedelta(hours=3))
LOCK = threading.RLock()
SESSIONS: dict[str, dict] = {}
LOGIN_FAILURES: dict[str, list] = {}
PORT = 8765
DEPTS = {'sales': '\u0627\u0644\u0633\u064a\u0644\u0632', 'service': '\u062e\u062f\u0645\u0629 \u0627\u0644\u0639\u0645\u0644\u0627\u0621', 'media': '\u0627\u0644\u0633\u0648\u0634\u064a\u0627\u0644 \u0645\u064a\u062f\u064a\u0627 \u0648\u0627\u0644\u062a\u0635\u0645\u064a\u0645\u0627\u062a', 'admin': '\u0627\u0644\u0625\u062f\u0627\u0631\u0629 \u0648\u0627\u0644\u0645\u0648\u0627\u0631\u062f \u0627\u0644\u0628\u0634\u0631\u064a\u0629'}
# Human-facing Arabic messages are localized through the JSON catalog below.
M = json.loads('''{
"forbidden":"ليست لديك صلاحية لهذا الإجراء.","missing":"السجل غير موجود أو غير متاح لك.",
"login":"يرجى تسجيل الدخول.","bad_login":"اسم المستخدم أو كلمة المرور غير صحيحة، أو الحساب غير مفعّل.",
"invalid":"بيانات غير صحيحة.","conflict":"تغير السجل بواسطة مستخدم آخر. حدّث الصفحة ثم أعد المحاولة.",
"required":"يرجى استكمال الحقول المطلوبة.","password":"كلمة المرور يجب أن تحتوي على 10 أحرف على الأقل.",
"done":"تم الحفظ.","evidence":"أضف وصف النتيجة وإثباتًا نصيًا أو ملفًا قبل طلب الاعتماد.",
"backup":"ملف النسخة الاحتياطية غير صالح أو لا يطابق إصدار النظام.",
"last_admin":"لا يمكن تعطيل آخر مدير عام فعّال.","disabled":"الحساب غير مفعل.",
"rate":"محاولات كثيرة. انتظر 15 دقيقة قبل إعادة المحاولة.","archive":"لا يمكن حذف السجلات؛ استخدم الإلغاء أو الإغلاق للحفاظ على الأثر.",
"amount":"المبلغ يجب أن يكون موجبًا وبحد أقصى منزلتين عشريتين.",
"immutable":"الحركات المالية نهائية. أنشئ حركة عكسية مرتبطة بالأصل لتصحيح الخطأ.",
"self_approve":"لا يمكن اعتماد طلب الإجازة الخاص بك.","reconcile":"المبلغ يتجاوز رصيد التسجيل أو الحركة الأصلية.",
"capacity":"اكتملت سعة المجموعة. عدّل السعة المعتمدة أولًا.","file":"الحد الأقصى للملف 8 ميجابايت.",
"readonly":"هذا السجل معتمد. أعد فتحه من الإدارة قبل تعديله.",
"server":"حدث خطأ داخلي. لم يكتمل الإجراء؛ راجع ملف السجل المحلي."
}''')

class APIError(Exception):
    def __init__(self, message, code=400):
        super().__init__(message)
        self.code = code


def now():
    return datetime.now(TZ).isoformat(timespec='seconds')


def today():
    return datetime.now(TZ).date().isoformat()


def jsonstr(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def password_hash(password):
    if not isinstance(password, str) or len(password) < 10 or len(password) > 256:
        raise APIError(M['password'])
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600000).hex()
    return f'pbkdf2-sha256$600000${salt}${hashed}'


def check_password(password, stored):
    try:
        algorithm, rounds, salt, expected = stored.split('$')
        if algorithm != 'pbkdf2-sha256' or not 100000 <= int(rounds) <= 2000000:
            return False
        if not isinstance(password, str) or len(password) > 256:
            return False
        result = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(result, expected)
    except (ValueError, TypeError):
        return False


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            return super().__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.close()


def connect():
    db = sqlite3.connect(DB_PATH, timeout=20, factory=ClosingConnection)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=20000')
    return db


def initialize():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / 'backups').mkdir(exist_ok=True)
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL, dept TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          title TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', force_password INTEGER NOT NULL DEFAULT 0,
          demo INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS records(
          id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, dept TEXT NOT NULL,
          owner_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, status TEXT NOT NULL,
          due TEXT NOT NULL DEFAULT '', data TEXT NOT NULL DEFAULT '{}', version INTEGER NOT NULL DEFAULT 1,
          demo INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS records_kind ON records(kind, dept, owner_id);
        CREATE INDEX IF NOT EXISTS records_due ON records(due, status);
        CREATE TABLE IF NOT EXISTS comments(
          id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attachments(
          id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL, mime TEXT NOT NULL,
          size INTEGER NOT NULL, content BLOB NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT NOT NULL,
          action TEXT NOT NULL, record_id INTEGER, kind TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', created TEXT NOT NULL);
        ''')
        db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', ('schema_version', SCHEMA_VERSION))
        db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', ('institute', jsonstr({'name': '\u0645\u0639\u0647\u062f \u0634\u0631\u064a\u0627\u0646 \u0627\u0644\u0642\u064a\u0627\u062f\u0629', 'phone': '0547177595', 'email': 'info@lai.edu.sa', 'website': 'lai.edu.sa'})))
        db.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', ('trainer_signup', 'true'))


def audit(db, user, action, record=None, detail=''):
    db.execute('INSERT INTO audit(user_id,user_name,action,record_id,kind,detail,created) VALUES(?,?,?,?,?,?,?)',
               (user.get('id') if user else None, user.get('name', '') if user else '', action,
                record.get('id') if record else None, record.get('kind', '') if record else '', str(detail)[:20000], now()))


def unpack(row):
    if row is None:
        return None
    result = dict(row)
    result['data'] = json.loads(result['data'])
    return result


def get_record(db, rid):
    return unpack(db.execute('SELECT * FROM records WHERE id=?', (rid,)).fetchone())


def is_admin(u):
    return u['role'] == 'admin'


def is_manager(u, dept=None):
    return is_admin(u) or (u['role'] == 'manager' and (dept is None or u['dept'] == dept))


def course_for(db, r):
    cid = r['data'].get('course_id')
    return get_record(db, cid) if cid else None


def can_view(db, u, r):
    if is_admin(u):
        return True
    kind = r['kind']
    if kind == 'payments':
        return False  # Financial book is restricted to the executive administrator.
    if kind == 'courses':
        if u['role'] == 'trainer':
            return r['data'].get('trainer_id') == u['id']
        return True  # Staff need approved scheduling/seat availability, never margins.
    if kind == 'enrollments' and u['role'] == 'trainer':
        c = course_for(db, r)
        return bool(c and c['data'].get('trainer_id') == u['id'])
    if kind == 'goals' and r['dept'] == u['dept']:
        return is_manager(u, r['dept']) or r['owner_id'] == u['id']
    if r['owner_id'] == u['id']:
        return True
    return u['role'] == 'manager' and u['dept'] == r['dept']


def can_create(u, kind, dept):
    if is_admin(u):
        return True
    if u['role'] == 'trainer':
        return kind in ('leaves', 'attendance') and dept == u['dept']
    allowed = {'tasks', 'leaves', 'attendance'}
    if u['dept'] == 'sales':
        allowed.add('leads')
    if u['dept'] == 'service':
        allowed.update(('tickets', 'enrollments'))
    if u['dept'] == 'media':
        allowed.add('content')
    if u['dept'] == 'admin':
        allowed.add('courses')
    if u['role'] == 'manager':
        allowed.add('goals')
    return kind in allowed and dept == u['dept']


def can_edit(db, u, r):
    if is_admin(u):
        return True
    if r['kind'] == 'payments':
        return False
    if r['kind'] == 'courses':
        return u['role'] != 'trainer' and u['dept'] == 'admin' and (r['owner_id'] == u['id'] or is_manager(u, 'admin'))
    if r['kind'] == 'goals':
        return is_manager(u, r['dept'])
    if r['kind'] == 'enrollments' and u['role'] == 'trainer':
        return can_view(db, u, r)
    return can_view(db, u, r)


def public_record(u, r, db):
    r = json.loads(jsonstr(r))
    if r['kind'] == 'courses':
        enrollments = [e for e in all_kind(db,'enrollments') if e['data'].get('course_id') == r['id'] and e['status'] != 'cancelled']
        r['enrolled_count'] = len(enrollments)
        r['present_count'] = sum(e['data'].get('attendance') == 'present' for e in enrollments)
    if not is_admin(u):
        if r['kind'] == 'courses':
            for key in ('trainer_rate', 'marketing_pct', 'notes_finance'):
                r['data'].pop(key, None)
        if r['kind'] == 'enrollments' and u['role'] == 'trainer':
            r['data'] = {k:v for k,v in r['data'].items() if k in ('course_id','attendance','result','trainer_note','certificate')}
    r['editable'] = can_edit(db, u, r)
    r['can_approve'] = is_manager(u, r['dept'])
    return r


SCHEMAS = json.loads('''{
"tasks":{"status":["new","doing","waiting","review","done","cancelled"],"fields":["description","priority","acceptance","evidence","result","progress","checklist","repeat_days","completed_at","approved_by","review_note","parent_id"]},
"leads":{"status":["new","contacted","qualified","offered","won","lost"],"dept":"sales","fields":["phone","email","city","source","course_id","interest","value","notes","loss_reason","next_action","handoff_id"]},
"tickets":{"status":["open","working","waiting","resolved","cancelled"],"dept":"service","fields":["client_name","phone","category","priority","description","resolution","lead_id","course_id"]},
"content":{"status":["idea","writing","design","review","approved","published","cancelled"],"dept":"media","fields":["platform","format","description","brief","caption","course_id","asset_url","post_url","campaign","leads_count","bookings_count","approved_by","review_note"]},
"courses":{"status":["planned","ready","running","completed","cancelled"],"dept":"admin","fields":["code","city","location","batch","trainer_id","capacity","end_date","price","trainer_rate","marketing_pct","notes","venue_ready","tools_ready","trainer_confirmed"]},
"enrollments":{"status":["reserved","confirmed","completed","cancelled"],"dept":"service","fields":["phone","email","course_id","lead_id","fee","attendance","result","certificate","notes","trainer_note"]},
"payments":{"status":["verified"],"dept":"admin","fields":["course_id","enrollment_id","type","amount","category","method","reference","notes","reversal_of"]},
"goals":{"status":["active","closed"],"fields":["metric","target","actual","unit","direction","period","evidence","notes"]},
"leaves":{"status":["pending","approved","rejected","cancelled"],"fields":["start_date","end_date","leave_type","reason","decision_note","approved_by"]},
"attendance":{"status":["present","finished"],"fields":["day","check_in","check_out","note"]}
}''')
TEXT_FIELDS = {'description','acceptance','evidence','result','review_note','phone','email','city','source','interest','notes','loss_reason','next_action','client_name','category','resolution','platform','format','brief','caption','asset_url','post_url','campaign','code','location','batch','notes_finance','attendance','certificate','trainer_note','type','method','reference','metric','unit','direction','period','leave_type','reason','decision_note','note'}
MONEY_FIELDS = {'value','price','trainer_rate','fee','amount'}
ID_FIELDS = {'course_id','lead_id','enrollment_id','trainer_id','reversal_of','parent_id','handoff_id','approved_by'}
SERVER_FIELDS = {'completed_at','approved_by','review_note','parent_id','handoff_id','check_in','check_out','day','decision_note'}


def to_int(value, minimum=0, maximum=10**9):
    try:
        num = int(value)
        if isinstance(value, bool) or float(value) != num or not minimum <= num <= maximum:
            raise ValueError()
        return num
    except (TypeError, ValueError, OverflowError):
        raise APIError(M['invalid'])


def clean_money(value):
    # API money values are integer halalas; the UI converts decimal SAR.
    return to_int(value, 0, 10**12)


def valid_date(v, required=False):
    if not v and not required:
        return ''
    try:
        v = str(v)
        parsed = datetime.fromisoformat(v)
        if not 2000 <= parsed.year <= 2100 or len(v) > 25:
            raise ValueError()
        return v
    except (TypeError, ValueError):
        raise APIError(M['invalid'] + ' (\u0627\u0644\u062a\u0627\u0631\u064a\u062e)')


def validate_record(db, u, body, old=None):
    kind = old['kind'] if old else body.get('kind')
    if kind not in SCHEMAS:
        raise APIError(M['invalid'])
    schema = SCHEMAS[kind]
    title = str(body.get('title', old['title'] if old else '')).strip()
    if not title or len(title) > 220:
        raise APIError(M['required'])
    dept = body.get('dept', old['dept'] if old else schema.get('dept', u['dept']))
    if dept not in DEPTS or (schema.get('dept') and dept != schema['dept']):
        raise APIError(M['invalid'])
    if old and not is_admin(u) and dept != old['dept']:
        raise APIError(M['forbidden'], 403)
    owner_id = to_int(body.get('owner_id', old['owner_id'] if old else u['id']), 1)
    owner = db.execute('SELECT * FROM users WHERE id=? AND active=1', (owner_id,)).fetchone()
    if not owner:
        raise APIError(M['invalid'] + ' (\u0627\u0644\u0645\u0633\u0624\u0648\u0644)')
    if not is_admin(u):
        if not is_manager(u, dept) and owner_id != u['id'] and (not old or owner_id != old['owner_id']):
            raise APIError(M['forbidden'], 403)
        if is_manager(u, dept) and owner['dept'] != dept:
            raise APIError(M['forbidden'], 403)
    if not old and not can_create(u, kind, dept):
        raise APIError(M['forbidden'], 403)
    status = body.get('status', old['status'] if old else schema['status'][0])
    if status not in schema['status']:
        raise APIError(M['invalid'])
    due = valid_date(body.get('due', old['due'] if old else ''))
    incoming = body.get('data', {})
    if not isinstance(incoming, dict):
        raise APIError(M['invalid'])
    data = dict(old['data']) if old else {}
    for key, val in incoming.items():
        if key not in schema['fields']:
            raise APIError(M['invalid'] + f' ({key})')
        if key in SERVER_FIELDS:
            if not old or val != old['data'].get(key):
                raise APIError(M['forbidden'], 403)
            continue
        if key in MONEY_FIELDS:
            data[key] = clean_money(val)
        elif key in ID_FIELDS:
            data[key] = to_int(val) if val not in ('', None) else 0
        elif key in {'target','actual','marketing_pct'}:
            try:
                number = float(val)
                if not math.isfinite(number) or not 0 <= number <= (100 if key == 'marketing_pct' else 10**12):
                    raise ValueError()
                data[key] = number
            except (ValueError, TypeError, OverflowError):
                raise APIError(M['invalid'])
        elif key in {'capacity','progress','repeat_days','leads_count','bookings_count'}:
            data[key] = to_int(val, 0, 100 if key == 'progress' else 100000)
        elif key in {'venue_ready','tools_ready','trainer_confirmed'}:
            if not isinstance(val, bool):
                raise APIError(M['invalid'])
            data[key] = val
        elif key == 'checklist':
            if not isinstance(val, list) or len(val) > 60:
                raise APIError(M['invalid'])
            data[key] = [{'text': str(x.get('text',''))[:500], 'done': bool(x.get('done'))} for x in val if isinstance(x, dict) and str(x.get('text','')).strip()]
        elif key in {'start_date','end_date'}:
            data[key] = valid_date(val)
        elif key in TEXT_FIELDS:
            if not isinstance(val, (str, int, float)) or len(str(val)) > 12000:
                raise APIError(M['invalid'])
            data[key] = str(val).strip()
        else:
            data[key] = str(val)[:2000]
    if kind == 'tasks':
        if status == 'cancelled' and not is_manager(u,dept):
            raise APIError(M['forbidden'],403)
        if old and not is_manager(u,old['dept']):
            if title != old['title'] or due != old['due'] or owner_id != old['owner_id'] or dept != old['dept']:
                raise APIError(M['forbidden'],403)
            for protected in ('acceptance','priority','repeat_days','description'):
                if data.get(protected) != old['data'].get(protected):
                    raise APIError(M['forbidden'],403)
            if [x['text'] for x in data.get('checklist',[])] != [x['text'] for x in old['data'].get('checklist',[])]:
                raise APIError(M['forbidden'],403)
        if not due or not data.get('acceptance'):
            raise APIError(M['required'])
        if status == 'done' and (not old or old['status'] != 'done'):
            raise APIError(M['forbidden'], 403)
        if old and old['status'] == 'done':
            raise APIError(M['readonly'], 409)
        if status == 'review':
            attachments = db.execute('SELECT COUNT(*) FROM attachments WHERE record_id=?', (old['id'] if old else -1,)).fetchone()[0]
            if not data.get('result') or (not data.get('evidence') and not attachments):
                raise APIError(M['evidence'])
            if any(not c['done'] for c in data.get('checklist', [])):
                raise APIError('\u0623\u0643\u0645\u0644 \u0642\u0627\u0626\u0645\u0629 \u0627\u0644\u062a\u062d\u0642\u0642 \u0623\u0648\u0644\u064b\u0627.')
            data['progress'] = 100
        if data.get('priority','normal') not in ('low','normal','high','urgent'):
            raise APIError(M['invalid'])
    if kind == 'content':
        if status in ('approved','published') and (not old or old['status'] not in ('approved','published')):
            raise APIError(M['forbidden'], 403)
        if status == 'published' and not data.get('post_url'):
            raise APIError('\u0623\u0636\u0641 \u0631\u0627\u0628\u0637 \u0627\u0644\u0645\u0646\u0634\u0648\u0631 \u0628\u0639\u062f \u0646\u0634\u0631\u0647 \u0641\u0639\u0644\u064a\u064b\u0627.')
        if old and old['status'] in ('approved','published'):
            if status not in ('approved','published') or (old['status']=='published' and status!='published'):
                raise APIError(M['readonly'],409)
            sensitive = {'brief','caption','asset_url','course_id','description','platform','format'}
            if any(data.get(k) != old['data'].get(k) for k in sensitive) or title != old['title']:
                raise APIError(M['readonly'], 409)
    if kind == 'leads':
        if status == 'lost' and not data.get('loss_reason'):
            raise APIError('\u0623\u0636\u0641 \u0633\u0628\u0628 \u0641\u0642\u062f \u0627\u0644\u0641\u0631\u0635\u0629.')
        if status not in ('won','lost') and (not due or not data.get('next_action')):
            raise APIError('\u062d\u062f\u062f \u0645\u0648\u0639\u062f \u0627\u0644\u0645\u062a\u0627\u0628\u0639\u0629 \u0648\u0627\u0644\u062e\u0637\u0648\u0629 \u0627\u0644\u062a\u0627\u0644\u064a\u0629.')
    if kind == 'tickets' and status == 'resolved' and not data.get('resolution'):
        raise APIError('\u0623\u0636\u0641 \u0646\u062a\u064a\u062c\u0629 \u0645\u0639\u0627\u0644\u062c\u0629 \u0627\u0644\u0637\u0644\u0628.')
    if kind == 'courses':
        if not due or data.get('capacity',0) < 1:
            raise APIError(M['required'])
        if data.get('end_date') and data['end_date'] < due:
            raise APIError('\u0646\u0647\u0627\u064a\u0629 \u0627\u0644\u062f\u0648\u0631\u0629 \u062a\u0633\u0628\u0642 \u0628\u062f\u0627\u064a\u062a\u0647\u0627.')
        if data.get('trainer_id'):
            teacher = db.execute('SELECT id FROM users WHERE id=? AND active=1', (data['trainer_id'],)).fetchone()
            if not teacher:
                raise APIError(M['invalid'])
        if old:
            enrolled = sum(1 for r in all_kind(db,'enrollments') if r['data'].get('course_id') == old['id'] and r['status'] != 'cancelled')
            if data['capacity'] < enrolled:
                raise APIError(M['capacity'])
        if status in ('ready','running') and not all(data.get(k) for k in ('trainer_id','venue_ready','tools_ready','trainer_confirmed')):
            raise APIError('\u062d\u062f\u062f \u0627\u0644\u0645\u062f\u0631\u0628 \u0648\u0623\u0643\u062f \u062c\u0627\u0647\u0632\u064a\u0629 \u0627\u0644\u0642\u0627\u0639\u0629 \u0648\u0627\u0644\u0623\u062f\u0648\u0627\u062a \u0648\u0627\u0644\u0645\u062f\u0631\u0628.')
        if not is_admin(u):
            for k in ('trainer_rate','marketing_pct'):
                if k in incoming and incoming[k] != (old['data'].get(k) if old else None):
                    raise APIError(M['forbidden'],403)
    if data.get('course_id'):
        course = get_record(db, data['course_id'])
        if not course or course['kind'] != 'courses' or not can_view(db,u,course):
            raise APIError(M['invalid'])
    if kind == 'enrollments':
        if not data.get('course_id'):
            raise APIError(M['required'])
        course = get_record(db, data['course_id'])
        if course['status'] == 'cancelled' and status != 'cancelled':
            raise APIError('\u0627\u0644\u062f\u0648\u0631\u0629 \u0645\u0644\u063a\u0627\u0629.')
        count = sum(1 for r in all_kind(db,'enrollments') if r['data'].get('course_id') == course['id'] and r['status'] != 'cancelled' and (not old or r['id'] != old['id']))
        if status != 'cancelled' and count >= course['data'].get('capacity',0):
            raise APIError(M['capacity'])
        if data.get('attendance','pending') not in ('pending','present','absent') or data.get('certificate','pending') not in ('pending','eligible','issued','delivered') or data.get('result','pending') not in ('pending','passed','failed'):
            raise APIError(M['invalid'])
        if data.get('certificate') in ('issued','delivered') and (data.get('attendance') != 'present' or data.get('result') != 'passed'):
            raise APIError('\u062a\u062d\u0642\u0642 \u0645\u0646 \u0627\u0644\u062d\u0636\u0648\u0631 \u0648\u0627\u0644\u0627\u062c\u062a\u064a\u0627\u0632 \u0642\u0628\u0644 \u062a\u0633\u062c\u064a\u0644 \u0625\u0635\u062f\u0627\u0631 \u0627\u0644\u0634\u0647\u0627\u062f\u0629.')
        if old and u['role'] == 'trainer':
            permitted = {'attendance','result','trainer_note'}
            if title != old['title'] or dept != old['dept'] or owner_id != old['owner_id'] or status != old['status'] or due != old['due'] or any(k not in permitted and data.get(k) != old['data'].get(k) for k in incoming):
                raise APIError(M['forbidden'],403)
        if old:
            has_payments = any(p['data'].get('enrollment_id') == old['id'] for p in all_kind(db,'payments'))
            if has_payments and data.get('course_id') != old['data'].get('course_id'):
                raise APIError('\u0644\u0627 \u064a\u0645\u0643\u0646 \u0646\u0642\u0644 \u062a\u0633\u062c\u064a\u0644 \u0644\u0647 \u062d\u0631\u0643\u0627\u062a \u0645\u0627\u0644\u064a\u0629.')
            if data.get('fee',0) < net_enrollment(db, old['id']):
                raise APIError(M['reconcile'])
    if kind == 'payments':
        if old:
            raise APIError(M['immutable'],409)
        validate_payment(db,data)
        status = 'verified'
    if kind == 'goals':
        if data.get('target',0) <= 0 or not re.fullmatch(r'20\d{2}-\d{2}',data.get('period','')) or data.get('direction','up') not in ('up','down'):
            raise APIError(M['required'])
        if old and data.get('actual',0) != old['data'].get('actual',0) and not data.get('evidence'):
            raise APIError('\u0623\u0636\u0641 \u0645\u0635\u062f\u0631 \u0627\u0644\u0646\u062a\u064a\u062c\u0629 \u0639\u0646\u062f \u062a\u062d\u062f\u064a\u062b \u0627\u0644\u0645\u0624\u0634\u0631.')
    if kind == 'leaves':
        if not data.get('start_date') or not data.get('end_date') or data['end_date'] < data['start_date']:
            raise APIError(M['required'])
        if status in ('approved','rejected') and (not old or old['status'] != status):
            raise APIError(M['forbidden'],403)
        if old and old['status'] in ('approved','rejected'):
            raise APIError(M['readonly'],409)
        due = data['start_date']
    if kind == 'attendance':
        raise APIError(M['forbidden'],403)  # Dedicated server-time clock endpoint only.
    return {'kind':kind,'title':title,'dept':dept,'owner_id':owner_id,'status':status,'due':due,'data':data}


def all_kind(db,kind):
    return [unpack(r) for r in db.execute('SELECT * FROM records WHERE kind=? ORDER BY id', (kind,))]


def net_enrollment(db,eid):
    return sum((1 if p['data']['type']=='receipt' else -1 if p['data']['type']=='refund' else 0)*p['data']['amount'] for p in all_kind(db,'payments') if p['data'].get('enrollment_id')==eid)


def validate_payment(db,data):
    if data.get('amount',0) <= 0 or data.get('type') not in ('receipt','refund','expense','expense_return'):
        raise APIError(M['amount'])
    eid = data.get('enrollment_id')
    if eid:
        en = get_record(db,eid)
        if not en or en['kind'] != 'enrollments' or en['data'].get('course_id') != data.get('course_id'):
            raise APIError(M['invalid'])
        if data['type'] == 'receipt' and (en['status'] == 'cancelled' or data['amount']+net_enrollment(db,eid) > en['data'].get('fee',0)):
            raise APIError(M['reconcile'])
        if data['type'] == 'refund' and data['amount'] > net_enrollment(db,eid):
            raise APIError(M['reconcile'])
    if data['type'] in ('refund','expense_return'):
        original = get_record(db,data.get('reversal_of',0))
        expected = 'receipt' if data['type'] == 'refund' else 'expense'
        if not original or original['kind']!='payments' or original['data'].get('type') != expected:
            raise APIError('\u0627\u062e\u062a\u0631 \u0627\u0644\u062d\u0631\u0643\u0629 \u0627\u0644\u0623\u0635\u0644\u064a\u0629 \u0627\u0644\u062a\u064a \u062a\u0639\u0643\u0633\u0647\u0627.')
        data['category'] = original['data'].get('category','other')
        for key in ('course_id','enrollment_id'):
            if (data.get(key) or 0) != (original['data'].get(key) or 0):
                raise APIError(M['invalid'])
        reversed_amount = sum(p['data']['amount'] for p in all_kind(db,'payments') if p['data'].get('reversal_of') == original['id'])
        if data['amount']+reversed_amount > original['data']['amount']:
            raise APIError(M['reconcile'])
    elif data.get('reversal_of'):
        raise APIError(M['invalid'])
    if not data.get('reference'):
        raise APIError('\u0623\u0636\u0641 \u0645\u0631\u062c\u0639 \u0627\u0644\u062a\u062d\u0642\u0642 \u0623\u0648 \u0625\u064a\u0635\u0627\u0644 \u0627\u0644\u062d\u0631\u0643\u0629.')


def insert_record(db,r,demo=0):
    stamp=now()
    cur=db.execute('INSERT INTO records(kind,dept,owner_id,title,status,due,data,demo,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)',
        (r['kind'],r['dept'],r['owner_id'],r['title'],r['status'],r.get('due',''),jsonstr(r['data']),demo,stamp,stamp))
    return get_record(db,cur.lastrowid)


def update_record(db,r):
    db.execute('UPDATE records SET dept=?,owner_id=?,title=?,status=?,due=?,data=?,version=version+1,updated=? WHERE id=?',
        (r['dept'],r['owner_id'],r['title'],r['status'],r.get('due',''),jsonstr(r['data']),now(),r['id']))
    return get_record(db,r['id'])


def backup_db(filename=None):
    path = Path(filename) if filename else DATA_DIR/'backups'/f'lai-{datetime.now(TZ).strftime("%Y%m%d-%H%M%S")}-{secrets.token_hex(2)}.sqlite'
    with connect() as source:
        target=sqlite3.connect(path)
        try:
            source.backup(target)
        finally:
            target.close()
    return path


def automatic_backup():
    existing=list((DATA_DIR/'backups').glob(f'auto-{today()}-*.sqlite'))
    if DB_PATH.exists() and not existing:
        backup_db(DATA_DIR/'backups'/f'auto-{today()}-{secrets.token_hex(2)}.sqlite')
        backups=sorted((DATA_DIR/'backups').glob('auto-*.sqlite'),key=lambda p:p.stat().st_mtime,reverse=True)
        for p in backups[14:]:
            p.unlink(missing_ok=True)


def add_user(db,body,admin=None,signup=False):
    name=str(body.get('name','')).strip()
    username=str(body.get('username','')).strip().lower()
    if not name or len(name)>100 or not re.fullmatch(r'[a-z0-9_.-]{3,40}',username):
        raise APIError('\u0627\u0644\u0627\u0633\u0645 \u0645\u0637\u0644\u0648\u0628\u060c \u0648\u0627\u0633\u0645 \u0627\u0644\u062f\u062e\u0648\u0644 3-40 \u062d\u0631\u0641\u064b\u0627 \u0625\u0646\u062c\u0644\u064a\u0632\u064a\u064b\u0627 \u0623\u0648 \u0631\u0642\u0645\u064b\u0627 \u0628\u062f\u0648\u0646 \u0645\u0633\u0627\u0641\u0627\u062a.')
    role='trainer' if signup else body.get('role','employee')
    dept='admin' if signup else body.get('dept','admin')
    if role not in ('admin','manager','employee','trainer') or dept not in DEPTS:
        raise APIError(M['invalid'])
    hashed=password_hash(body.get('password',''))
    try:
        cur=db.execute('INSERT INTO users(name,username,password_hash,role,dept,active,title,phone,force_password,created) VALUES(?,?,?,?,?,?,?,?,?,?)',
            (name,username,hashed,role,dept,0 if signup else 1,str(body.get('title',''))[:150],str(body.get('phone',''))[:50],int(bool(admin and not signup)),now()))
    except sqlite3.IntegrityError:
        raise APIError('\u0627\u0633\u0645 \u0627\u0644\u062f\u062e\u0648\u0644 \u0645\u0633\u062a\u062e\u062f\u0645 \u0645\u0646 \u0642\u0628\u0644.')
    return dict(db.execute('SELECT * FROM users WHERE id=?',(cur.lastrowid,)).fetchone())


def safe_user(u,full=False):
    keys=['id','name','dept','role','active','title','demo']
    if full:
        keys += ['username','phone','force_password','created']
    return {k:u[k] for k in keys if k in u}


def seed_demo(db,admin):
    if db.execute('SELECT COUNT(*) FROM records').fetchone()[0]:
        raise APIError('\u062a\u0636\u0627\u0641 \u0627\u0644\u0623\u0645\u062b\u0644\u0629 \u0641\u064a \u0642\u0627\u0639\u062f\u0629 \u0641\u0627\u0631\u063a\u0629 \u0641\u0642\u0637.')
    demo_path=ROOT/'demo.json'
    sample=json.loads(demo_path.read_text(encoding='utf-8'))
    users={}
    for key, val in sample['users'].items():
        new=add_user(db,dict(val,password=secrets.token_urlsafe(32)),admin)
        db.execute('UPDATE users SET demo=1,force_password=1 WHERE id=?',(new['id'],))
        users[key]=new['id']
    refs={}
    for item in sample['records']:
        r=dict(item)
        ref=r.pop('_ref',None)
        delta=r.pop('_days',None)
        r['owner_id']=users.get(r['owner_id'],admin['id'])
        if delta is not None:
            r['due']=(datetime.now(TZ)+timedelta(days=delta)).replace(hour=16,minute=0,second=0,microsecond=0).isoformat()[:16]
        for key in ('course_id','lead_id','enrollment_id','reversal_of'):
            if isinstance(r['data'].get(key),str):
                r['data'][key]=refs[r['data'][key]]
        if isinstance(r['data'].get('trainer_id'),str):
            r['data']['trainer_id']=users[r['data']['trainer_id']]
        if r['kind']=='goals':
            r['data']['period']=today()[:7]
        if r['kind']=='tasks' and r['status']=='done':
            r['data']['completed_at']=now()
            r['data']['approved_by']=admin['id']
        result=insert_record(db,r,demo=1)
        if ref:
            refs[ref]=result['id']
    audit(db,admin,'demo_added',detail='Illustrative data only; not institute results.')


def course_financials(db):
    courses=all_kind(db,'courses'); enrol=all_kind(db,'enrollments'); payments=all_kind(db,'payments')
    results=[]
    for c in courses:
        students=[e for e in enrol if e['data'].get('course_id')==c['id'] and e['status']!='cancelled']
        pp=[p['data'] for p in payments if p['data'].get('course_id')==c['id']]
        net=sum(p['amount']*(1 if p['type']=='receipt' else -1 if p['type']=='refund' else 0) for p in pp)
        expenses=sum(p['amount']*(1 if p['type']=='expense' else -1 if p['type']=='expense_return' else 0) for p in pp)
        present=sum(e['data'].get('attendance')=='present' for e in students)
        teacher=present*c['data'].get('trainer_rate',0)
        marketing=int((Decimal(net)*Decimal(str(c['data'].get('marketing_pct',0)))/100).quantize(Decimal('1'),rounding=ROUND_HALF_UP))
        # Cost categories trainer/marketing are paid portions, not extra budgeted costs.
        teacher_paid=sum(p['amount']*(1 if p['type']=='expense' else -1 if p['type']=='expense_return' else 0) for p in pp if p.get('category')=='trainer')
        marketing_paid=sum(p['amount']*(1 if p['type']=='expense' else -1 if p['type']=='expense_return' else 0) for p in pp if p.get('category')=='marketing')
        remaining_teacher=max(0,teacher-teacher_paid)
        remaining_marketing=max(0,marketing-marketing_paid)
        results.append({'id':c['id'],'title':c['title'],'batch':c['data'].get('batch',''),'registered':len(students),'present':present,
            'contracted':sum(e['data'].get('fee',0) for e in students),'collected':net,'expenses':expenses,
            'trainer_estimate':teacher,'marketing_estimate':marketing,'trainer_remaining':remaining_teacher,'marketing_remaining':remaining_marketing,
            'cash_balance':net-expenses,'contribution_estimate':net-expenses-remaining_teacher-remaining_marketing})
    return results


class Handler(BaseHTTPRequestHandler):
    server_version='LAI-Local/1.0'
    sys_version=''
    def log_message(self,fmt,*args):
        # Never log request bodies, session tokens or credentials.
        pass

    def send_bytes(self,data,content_type='application/json; charset=utf-8',status=200,extra=None):
        self.send_response(status)
        headers={'Content-Type':content_type,'Content-Length':str(len(data)),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cross-Origin-Resource-Policy':'same-origin',
        'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"}
        if extra:
            headers.update(extra)
        for key,value in headers.items():
            self.send_header(key,value)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError):
            pass

    def send_json(self,value,status=200,extra=None):
        self.send_bytes(jsonstr(value).encode(),status=status,extra=extra)

    def guard(self,write=False):
        host=self.headers.get('Host','')
        if host not in (f'127.0.0.1:{PORT}',f'localhost:{PORT}'):
            raise APIError(M['forbidden'],403)
        origin=self.headers.get('Origin')
        if origin and origin not in (f'http://127.0.0.1:{PORT}',f'http://localhost:{PORT}'):
            raise APIError(M['forbidden'],403)
        if write and (self.headers.get('X-LAI-Client')!='local' or not self.headers.get('Content-Type','').startswith('application/json')):
            raise APIError(M['forbidden'],403)

    def body(self):
        size=int(self.headers.get('Content-Length','0'))
        if not 0 < size <= 145000000:
            raise APIError(M['invalid'],413)
        data=json.loads(self.rfile.read(size))
        if not isinstance(data,dict):
            raise APIError(M['invalid'])
        return data

    def session(self,db,write=False):
        cookie=http.cookies.SimpleCookie()
        cookie.load(self.headers.get('Cookie',''))
        token=cookie['lai_session'].value if 'lai_session' in cookie else ''
        session=SESSIONS.get(token)
        if not session or session['expires']<time.time():
            SESSIONS.pop(token,None)
            raise APIError(M['login'],401)
        row=db.execute('SELECT * FROM users WHERE id=? AND active=1',(session['uid'],)).fetchone()
        if not row:
            raise APIError(M['login'],401)
        if write and not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),session['csrf']):
            raise APIError(M['forbidden'],403)
        return dict(row),session,token

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def do_PUT(self):
        self.dispatch(True)

    def do_DELETE(self):
        self.send_json({'error':M['archive']},405)

    def dispatch(self,write):
        try:
            self.guard(write)
            url=urlparse(self.path)
            path=url.path
            if not path.startswith('/api/'):
                if write:
                    raise APIError(M['forbidden'],405)
                files={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/styles.css':'styles.css','/help.html':'help.html'}
                if path not in files:
                    raise APIError(M['missing'],404)
                file=ROOT/'static'/files[path]
                ctype=mimetypes.guess_type(file)[0] or 'text/plain'
                self.send_bytes(file.read_bytes(),ctype+'; charset=utf-8')
                return
            body=self.body() if write else {}
            # Serializes local writes, restore and backup to avoid partial or stale DB snapshots.
            with LOCK:
                with connect() as db:
                    result,extra=self.route(db,path,parse_qs(url.query),body,write)
                if isinstance(result,dict) and result.get('_restore'):
                    candidate=Path(result['_restore'])
                    backup_db()
                    os.replace(candidate,DB_PATH)
                    SESSIONS.clear()
                    result={'ok':True,'restored':True}
                if isinstance(result,tuple):
                    raw,ctype,headers=result
                    self.send_bytes(raw,ctype,extra=headers)
                else:
                    self.send_json(result,extra=extra)
        except APIError as error:
            self.send_json({'error':str(error)},error.code)
        except (json.JSONDecodeError,ValueError,TypeError,KeyError,UnicodeDecodeError) as error:
            self.send_json({'error':M['invalid']},400)
        except Exception:
            DATA_DIR.mkdir(parents=True,exist_ok=True)
            with (DATA_DIR/'errors.log').open('a',encoding='utf-8') as log:
                log.write('\n'+now()+'\n'+traceback.format_exc())
            self.send_json({'error':M['server']},500)

    def route(self,db,path,query,body,write):
        if path=='/api/status' and not write:
            return {'setup_required':db.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0,'version':APP_VERSION,'trainer_signup':db.execute("SELECT value FROM settings WHERE key='trainer_signup'").fetchone()[0]=='true'},None
        if path=='/api/setup' and write:
            if db.execute('SELECT COUNT(*) FROM users').fetchone()[0]:
                raise APIError(M['forbidden'],403)
            admin=add_user(db,dict(body,role='admin',dept='admin'))
            audit(db,admin,'setup')
            if body.get('demo'):
                seed_demo(db,admin)
            return {'ok':True},None
        if path=='/api/signup' and write:
            if db.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0 or db.execute("SELECT value FROM settings WHERE key='trainer_signup'").fetchone()[0]!='true':
                raise APIError(M['forbidden'],403)
            if db.execute('SELECT COUNT(*) FROM users WHERE active=0').fetchone()[0]>=100:
                raise APIError(M['rate'],429)
            new=add_user(db,body,signup=True)
            audit(db,new,'trainer_signup')
            return {'ok':True},None
        if path=='/api/login' and write:
            username=str(body.get('username','')).strip().lower()
            key=self.client_address[0]+':'+username
            failures=[t for t in LOGIN_FAILURES.get(key,[]) if t>time.time()-900]
            LOGIN_FAILURES[key]=failures
            if len(failures)>=8:
                raise APIError(M['rate'],429)
            row=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
            # Constant work for unknown users.
            hashed=row['password_hash'] if row else 'pbkdf2-sha256$600000$'+'00'*16+'$'+'00'*32
            if not check_password(body.get('password',''),hashed) or not row or not row['active']:
                failures.append(time.time())
                raise APIError(M['bad_login'],401)
            LOGIN_FAILURES.pop(key,None)
            token=secrets.token_urlsafe(40); csrf=secrets.token_urlsafe(32)
            for old_token,s in list(SESSIONS.items()):
                if s['expires']<time.time():
                    SESSIONS.pop(old_token,None)
            SESSIONS[token]={'uid':row['id'],'csrf':csrf,'expires':time.time()+8*3600}
            audit(db,dict(row),'login')
            return {'user':safe_user(dict(row),True),'csrf':csrf},{'Set-Cookie':f'lai_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'}
        u,s,token=self.session(db,write)
        if path=='/api/logout' and write:
            SESSIONS.pop(token,None)
            return {'ok':True},{'Set-Cookie':'lai_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'}
        if path=='/api/password' and write:
            if not check_password(body.get('current',''),u['password_hash']):
                raise APIError(M['bad_login'])
            hashed=password_hash(body.get('password',''))
            db.execute('UPDATE users SET password_hash=?,force_password=0 WHERE id=?',(hashed,u['id']))
            for key,ss in list(SESSIONS.items()):
                if ss['uid']==u['id'] and key!=token:
                    del SESSIONS[key]
            audit(db,u,'password_changed')
            return {'ok':True},None
        if u['force_password'] and write:
            raise APIError('\u063a\u064a\u0651\u0631 \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631 \u0627\u0644\u0645\u0624\u0642\u062a\u0629 \u0623\u0648\u0644\u064b\u0627.',403)
        if path=='/api/bootstrap' and not write:
            rows=[unpack(row) for row in db.execute('SELECT * FROM records ORDER BY updated DESC,id DESC')]
            records=[public_record(u,r,db) for r in rows if can_view(db,u,r)]
            users=[safe_user(dict(x),is_admin(u)) for x in db.execute('SELECT * FROM users ORDER BY active DESC,name')]
            if not is_admin(u):
                users=[x for x in users if x['active']]
            recent=[dict(x) for x in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200')]
            if not is_admin(u):
                visible={r['id'] for r in records}
                recent=[x for x in recent if x['record_id'] in visible or x['user_id']==u['id']]
                for x in recent:
                    x['detail'] = ''
            return {'user':safe_user(u,True),'csrf':s['csrf'],'users':users,'records':records,'departments':DEPTS,'audit':recent[:50],
                'settings':json.loads(db.execute("SELECT value FROM settings WHERE key='institute'").fetchone()[0]),'server_today':today(),'server_time':now(),'version':APP_VERSION,
                'finance':course_financials(db) if is_admin(u) else [],'demo':any(r['demo'] for r in records),
                'backup_files':len(list((DATA_DIR/'backups').glob('*.sqlite'))) if is_admin(u) else 0},None
        if path=='/api/records' and write:
            r=validate_record(db,u,body)
            new=insert_record(db,r)
            audit(db,u,'created',new,jsonstr({'title':new['title']}))
            return {'record':public_record(u,new,db)},None
        match=re.fullmatch(r'/api/records/(\d+)(?:/(detail|action|comment|attachment))?',path)
        if match:
            r=get_record(db,int(match[1])); command=match[2]
            if not r or not can_view(db,u,r):
                raise APIError(M['missing'],404)
            if not write:
                if command!='detail':
                    raise APIError(M['missing'],404)
                comments=[dict(x) for x in db.execute('SELECT c.*,u.name AS author FROM comments c JOIN users u ON c.user_id=u.id WHERE c.record_id=? ORDER BY c.id',(r['id'],))]
                attachments=[dict(x) for x in db.execute('SELECT id,record_id,user_id,name,mime,size,created FROM attachments WHERE record_id=? ORDER BY id',(r['id'],))]
                events=[dict(x) for x in db.execute('SELECT * FROM audit WHERE record_id=? ORDER BY id DESC LIMIT 100',(r['id'],))]
                if not is_admin(u):
                    for event in events:
                        event['detail'] = ''
                return {'record':public_record(u,r,db),'comments':comments,'attachments':attachments,'audit':events},None
            if command=='comment':
                text=str(body.get('body','')).strip()
                if not text or len(text)>5000:
                    raise APIError(M['required'])
                db.execute('INSERT INTO comments(record_id,user_id,body,created) VALUES(?,?,?,?)',(r['id'],u['id'],text,now()))
                audit(db,u,'commented',r,text[:150])
                return {'ok':True},None
            if not can_edit(db,u,r):
                raise APIError(M['forbidden'],403)
            if command=='attachment':
                if r['kind']=='content' and r['status'] in ('approved','published'):
                    raise APIError(M['readonly'],409)
                raw=base64.b64decode(body.get('content',''),validate=True)
                if not raw or len(raw)>8*1024*1024:
                    raise APIError(M['file'],413)
                filename=str(body.get('name','file')).replace('\\','/').split('/')[-1]
                filename=re.sub(r'[\x00-\x1f\x7f]','',filename)[:180] or 'file'
                cur=db.execute('INSERT INTO attachments(record_id,user_id,name,mime,size,content,created) VALUES(?,?,?,?,?,?,?)',
                   (r['id'],u['id'],filename,'application/octet-stream',len(raw),raw,now()))
                audit(db,u,'attached',r,filename)
                return {'ok':True,'id':cur.lastrowid},None
            if to_int(body.get('version',0))!=r['version']:
                raise APIError(M['conflict'],409)
            if command=='action':
                result=self.record_action(db,u,r,body)
                return {'record':public_record(u,result,db)},None
            if command:
                raise APIError(M['missing'],404)
            clean=validate_record(db,u,body,r)
            clean['id']=r['id']
            result=update_record(db,clean)
            change={'before':{'status':r['status'],'owner_id':r['owner_id'],'due':r['due'],'data':r['data']},'after':{'status':result['status'],'owner_id':result['owner_id'],'due':result['due'],'data':result['data']}}
            audit(db,u,'updated',result,jsonstr(change))
            return {'record':public_record(u,result,db)},None
        match=re.fullmatch(r'/api/attachments/(\d+)',path)
        if match and not write:
            a=db.execute('SELECT * FROM attachments WHERE id=?',(int(match[1]),)).fetchone()
            r=get_record(db,a['record_id']) if a else None
            if not r or not can_view(db,u,r):
                raise APIError(M['missing'],404)
            return (bytes(a['content']),'application/octet-stream',{'Content-Disposition':"attachment; filename*=UTF-8''"+quote(a['name'])}),None
        if path=='/api/clock' and write:
            found=next((r for r in all_kind(db,'attendance') if r['owner_id']==u['id'] and r['data'].get('day')==today()),None)
            if body.get('action')=='in':
                if found:
                    raise APIError('\u0633\u062c\u0644\u062a \u062d\u0636\u0648\u0631\u0643 \u0627\u0644\u064a\u0648\u0645 \u0628\u0627\u0644\u0641\u0639\u0644.')
                r=insert_record(db,{'kind':'attendance','dept':u['dept'],'owner_id':u['id'],'title':u['name'],'status':'present','due':today(),'data':{'day':today(),'check_in':now(),'check_out':'','note':str(body.get('note',''))[:2000]}})
            else:
                if not found or found['data'].get('check_out'):
                    raise APIError(M['invalid'])
                found['data']['check_out']=now(); found['status']='finished'
                r=update_record(db,found)
            audit(db,u,'clock_'+body.get('action',''),r)
            return {'ok':True},None
        if path=='/api/users' and write:
            if not is_admin(u):
                raise APIError(M['forbidden'],403)
            new=add_user(db,body,admin=u)
            audit(db,u,'user_created',detail=new['name'])
            return {'user':safe_user(new,True)},None
        match=re.fullmatch(r'/api/users/(\d+)',path)
        if match and write:
            if not is_admin(u):
                raise APIError(M['forbidden'],403)
            old=db.execute('SELECT * FROM users WHERE id=?',(int(match[1]),)).fetchone()
            if not old:
                raise APIError(M['missing'],404)
            role=body.get('role',old['role']); dept=body.get('dept',old['dept']); active=int(bool(body.get('active',old['active'])))
            if role not in ('admin','manager','employee','trainer') or dept not in DEPTS:
                raise APIError(M['invalid'])
            if old['role']=='admin' and old['active'] and (role!='admin' or not active) and db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]<=1:
                raise APIError(M['last_admin'])
            name=str(body.get('name',old['name'])).strip()[:100]
            if not name:
                raise APIError(M['required'])
            db.execute('UPDATE users SET name=?,role=?,dept=?,active=?,title=?,phone=? WHERE id=?',(name,role,dept,active,str(body.get('title',old['title']))[:150],str(body.get('phone',old['phone']))[:50],old['id']))
            if body.get('password'):
                db.execute('UPDATE users SET password_hash=?,force_password=1 WHERE id=?',(password_hash(body['password']),old['id']))
            if body.get('password') or not active or role!=old['role'] or dept!=old['dept']:
                for key,ss in list(SESSIONS.items()):
                    if ss['uid']==old['id']:
                        del SESSIONS[key]
            audit(db,u,'user_updated',detail=jsonstr({'id':old['id'],'name':name,'role':role,'dept':dept,'active':active,'password_reset':bool(body.get('password'))}))
            return {'ok':True},None
        if path=='/api/handoff' and write:
            lead=get_record(db,to_int(body.get('lead_id'),1))
            if not lead or lead['kind']!='leads' or not can_edit(db,u,lead):
                raise APIError(M['forbidden'],403)
            if lead['status']!='won' or lead['data'].get('handoff_id'):
                raise APIError('\u0627\u0644\u062a\u0633\u0644\u064a\u0645 \u0645\u062a\u0627\u062d \u0644\u0644\u0641\u0631\u0635\u0629 \u0627\u0644\u0645\u0643\u062a\u0633\u0628\u0629 \u0645\u0631\u0629 \u0648\u0627\u062d\u062f\u0629.')
            owner=to_int(body.get('owner_id'),1)
            target=db.execute("SELECT * FROM users WHERE id=? AND active=1 AND (dept='service' OR role='admin')",(owner,)).fetchone()
            if not target:
                raise APIError(M['invalid'])
            ticket=insert_record(db,{'kind':'tickets','dept':'service','owner_id':owner,'title':'\u0627\u0633\u062a\u0643\u0645\u0627\u0644 \u062a\u0633\u062c\u064a\u0644: '+lead['title'],'status':'open','due':valid_date(body.get('due'),True),'data':{'client_name':lead['title'],'phone':lead['data'].get('phone',''),'category':'registration','priority':'high','lead_id':lead['id'],'course_id':lead['data'].get('course_id',0),'description':str(body.get('notes',''))[:5000]+'\n'+lead['data'].get('notes','')}})
            lead['data']['handoff_id']=ticket['id'];update_record(db,lead)
            audit(db,u,'handoff',lead,'Service ticket #'+str(ticket['id']));audit(db,u,'created',ticket)
            return {'ok':True},None
        if path=='/api/export' and not write:
            kind=query.get('kind',['tasks'])[0]
            if kind not in SCHEMAS:
                raise APIError(M['invalid'])
            records=[public_record(u,r,db) for r in all_kind(db,kind) if can_view(db,u,r)]
            rows=[]
            names={x['id']:x['name'] for x in db.execute('SELECT id,name FROM users')}
            for r in records:
                row={'ID':r['id'],'title':r['title'],'department':DEPTS[r['dept']],'owner':names.get(r['owner_id'],''),'status':r['status'],'due':r['due'],'created':r['created'],'updated':r['updated'],'demo':r['demo']}
                for k,v in r['data'].items():
                    if isinstance(v,(dict,list)):
                        v=jsonstr(v)
                    if k in MONEY_FIELDS:
                        v=Decimal(v)/100;k=k+'_SAR'
                    row[k]=v
                rows.append(row)
            keys=list(dict.fromkeys(k for row in rows for k in row)) or ['ID','title','status']
            output=io.StringIO(newline='');writer=csv.DictWriter(output,fieldnames=keys);writer.writeheader()
            for row in rows:
                for k,v in row.items():
                    text=str(v)
                    if text.lstrip().startswith(('=','+','-','@','\t','\r')):
                        row[k]="'"+text
                writer.writerow(row)
            audit(db,u,'exported',detail=kind)
            return (output.getvalue().encode('utf-8-sig'),'text/csv; charset=utf-8',{'Content-Disposition':f'attachment; filename="LAI-{kind}-{today()}.csv"'}),None
        if path=='/api/backup' and write:
            if not is_admin(u):
                raise APIError(M['forbidden'],403)
            audit(db,u,'backup_downloaded');db.commit()
            file=backup_db()
            return (file.read_bytes(),'application/octet-stream',{'Content-Disposition':f'attachment; filename="{file.name}"'}),None
        if path=='/api/restore' and write:
            if not is_admin(u) or not check_password(body.get('password',''),u['password_hash']):
                raise APIError(M['forbidden'],403)
            raw=base64.b64decode(body.get('content',''),validate=True)
            if not raw.startswith(b'SQLite format 3\x00') or len(raw)>100*1024*1024:
                raise APIError(M['backup'])
            fd,name=tempfile.mkstemp(prefix='restore-',suffix='.sqlite',dir=DATA_DIR)
            os.close(fd);candidate=Path(name);candidate.write_bytes(raw)
            try:
                check=sqlite3.connect(f'file:{candidate.as_posix()}?mode=ro',uri=True)
                try:
                    if check.execute('PRAGMA quick_check').fetchone()[0]!='ok':
                        raise ValueError()
                    tables={x[0] for x in check.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if not {'settings','users','records','comments','attachments','audit'}<=tables:
                        raise ValueError()
                    if check.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0]!=SCHEMA_VERSION:
                        raise ValueError()
                    if check.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]<1:
                        raise ValueError()
                    if check.execute("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]:
                        raise ValueError()
                    for tab in ('settings','users','records','comments','attachments','audit'):
                        current_cols = [tuple(x) for x in db.execute(f'PRAGMA table_info({tab})')]
                        restored_cols = [tuple(x) for x in check.execute(f'PRAGMA table_info({tab})')]
                        if current_cols != restored_cols:
                            raise ValueError()
                    if check.execute('PRAGMA foreign_key_check').fetchall():
                        raise ValueError()
                    for row in check.execute('SELECT data FROM records'):
                        json.loads(row[0])
                finally:
                    check.close()
            except Exception:
                candidate.unlink(missing_ok=True)
                raise APIError(M['backup'])
            audit(db,u,'restore_requested')
            return {'_restore':str(candidate)},None
        if path=='/api/settings' and write:
            if not is_admin(u):
                raise APIError(M['forbidden'],403)
            settings={k:str(body.get(k,''))[:250] for k in ('name','phone','email','website')}
            if not settings['name']:
                raise APIError(M['required'])
            db.execute("UPDATE settings SET value=? WHERE key='institute'",(jsonstr(settings),))
            audit(db,u,'settings_updated')
            return {'ok':True},None
        if path=='/api/demo' and write:
            if not is_admin(u):
                raise APIError(M['forbidden'],403)
            if body.get('action')=='add':
                seed_demo(db,u)
            elif body.get('action')=='clear':
                if db.execute('SELECT COUNT(*) FROM records WHERE demo=0').fetchone()[0]:
                    raise APIError('\u062a\u0648\u062c\u062f \u0633\u062c\u0644\u0627\u062a \u062d\u0642\u064a\u0642\u064a\u0629. \u0644\u0627 \u064a\u0645\u0643\u0646 \u0645\u0633\u062d \u0627\u0644\u0623\u0645\u062b\u0644\u0629 \u0628\u0639\u062f \u0628\u062f\u0621 \u0627\u0644\u0639\u0645\u0644 \u0627\u0644\u0641\u0639\u0644\u064a.')
                db.commit();backup_db()
                db.execute('DELETE FROM records WHERE demo=1')
                db.execute('DELETE FROM users WHERE demo=1')
                audit(db,u,'demo_cleared')
            else:
                raise APIError(M['invalid'])
            return {'ok':True},None
        if path=='/api/audit' and not write:
            if not is_admin(u):
                raise APIError(M['forbidden'],403)
            return {'events':[dict(x) for x in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 1000')]},None
        raise APIError(M['missing'],404)

    def record_action(self,db,u,r,body):
        action=body.get('action');note=str(body.get('note','')).strip()[:5000]
        if action in ('approve','reject','reopen'):
            if not is_manager(u,r['dept']):
                raise APIError(M['forbidden'],403)
            if r['kind']=='tasks':
                if action in ('approve','reject') and r['status']!='review':
                    raise APIError(M['invalid'])
                if action=='approve':
                    if not r['data'].get('result'):
                        raise APIError(M['evidence'])
                    if u['id']==r['owner_id'] and not is_admin(u):
                        raise APIError('\u062a\u062d\u062a\u0627\u062c \u0645\u0647\u0645\u062a\u0643 \u0625\u0644\u0649 \u0627\u0639\u062a\u0645\u0627\u062f \u0627\u0644\u0645\u062f\u064a\u0631 \u0627\u0644\u0639\u0627\u0645.')
                    r['status']='done';r['data'].update(progress=100,completed_at=now(),approved_by=u['id'],review_note=note)
                    days=r['data'].get('repeat_days',0)
                    if days:
                        base=datetime.fromisoformat(r['due'])
                        due=base+timedelta(days=days)
                        rr={'kind':'tasks','dept':r['dept'],'owner_id':r['owner_id'],'title':r['title'],'status':'new','due':due.isoformat()[:16],
                            'data':{k:v for k,v in r['data'].items() if k not in ('completed_at','approved_by','review_note','evidence','result')}}
                        rr['data'].update(progress=0,parent_id=r['id'])
                        rr['data']['checklist']=[dict(x,done=False) for x in rr['data'].get('checklist',[])]
                        new=insert_record(db,rr,demo=r['demo']);audit(db,u,'recurrence_created',new)
                elif action=='reject':
                    if not note:
                        raise APIError('\u0623\u0636\u0641 \u0633\u0628\u0628 \u0625\u0639\u0627\u062f\u0629 \u0627\u0644\u0645\u0647\u0645\u0629.')
                    r['status']='doing';r['data']['review_note']=note
                else:
                    if r['status']!='done' or not is_admin(u) or not note:
                        raise APIError(M['forbidden'],403)
                    if any(x['data'].get('parent_id')==r['id'] for x in all_kind(db,'tasks')):
                        raise APIError('\u0647\u0630\u0647 \u0645\u0647\u0645\u0629 \u0645\u062a\u0643\u0631\u0631\u0629 \u0648\u0644\u0647\u0627 \u0646\u0633\u062e\u0629 \u062a\u0627\u0644\u064a\u0629. \u0623\u0646\u0634\u0626 \u0645\u0647\u0645\u0629 \u062a\u0635\u062d\u064a\u062d \u0645\u0633\u062a\u0642\u0644\u0629.')
                    r['status']='doing';r['data'].pop('completed_at',None);r['data'].pop('approved_by',None);r['data']['review_note']=note
            elif r['kind']=='content':
                if action in ('approve','reject') and r['status']!='review':
                    raise APIError(M['invalid'])
                if action=='approve':
                    if not r['data'].get('caption') or not r['data'].get('brief'):
                        raise APIError('\u0645\u062d\u062a\u0648\u0649 \u0627\u0644\u0646\u0634\u0631 \u0648\u0627\u0644\u0645\u0639\u0644\u0648\u0645\u0627\u062a \u0627\u0644\u0645\u0631\u062c\u0639\u064a\u0629 \u0645\u0637\u0644\u0648\u0628\u0629 \u0642\u0628\u0644 \u0627\u0644\u0627\u0639\u062a\u0645\u0627\u062f.')
                    r['status']='approved';r['data']['approved_by']=u['id']
                else:
                    if not note:
                        raise APIError(M['required'])
                    r['status']='design';r['data'].pop('approved_by',None)
                r['data']['review_note']=note
            elif r['kind']=='leaves':
                if r['owner_id']==u['id']:
                    raise APIError(M['self_approve'])
                if r['status']!='pending' or action not in ('approve','reject'):
                    raise APIError(M['invalid'])
                r['status']='approved' if action=='approve' else 'rejected'
                r['data'].update(approved_by=u['id'],decision_note=note)
            else:
                raise APIError(M['invalid'])
        else:
            raise APIError(M['invalid'])
        result=update_record(db,r);audit(db,u,action,result,note)
        return result


def main():
    global PORT
    parser=argparse.ArgumentParser(description='Leadership Artery Institute - Local Executive Workspace')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--open',action='store_true')
    args=parser.parse_args();PORT=args.port
    if not 1024<=PORT<=65535:
        raise SystemExit('Invalid port. Choose 1024-65535.')
    initialize()
    with LOCK:
        with connect() as db:
            has_users=db.execute('SELECT COUNT(*) FROM users').fetchone()[0]>0
        if has_users:
            automatic_backup()
    try:
        server=ThreadingHTTPServer(('127.0.0.1',PORT),Handler)
        server.daemon_threads=True
    except OSError:
        print(f'Port {PORT} is already in use. Close the existing server or use --port 8766.')
        if args.open:
            webbrowser.open(f'http://127.0.0.1:{PORT}')
        return
    print(f'LAI EXECUTIVE LOCAL {APP_VERSION}\nOpen: http://127.0.0.1:{PORT}\nData: {DATA_DIR}\nLocal computer only. Keep this window open. Ctrl+C to stop.')
    if args.open:
        threading.Timer(0.7,lambda:webbrowser.open(f'http://127.0.0.1:{PORT}')).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopping. Your data is saved.')
    finally:
        server.server_close()

if __name__=='__main__':
    main()
