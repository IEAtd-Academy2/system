#!/usr/bin/env python3
"""Functional + security checks against the real WSGI application.
No public hosting, certificate issuer, Docker image or Gunicorn is involved.
"""
from __future__ import annotations
import base64
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from wsgiref.util import setup_testing_defaults
from wsgiref.validate import validator

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
import test_local_regression as local_tests
PASS=local_tests.PASS
NEW=local_tests.NEW
CHECKS=[]
CHECK_HEADERS=[]

def check(name, condition=True):
    if not condition: raise AssertionError(name)
    CHECKS.append(name)
    print('PASS:', name)

class TrackingStream(io.BytesIO):
    reads=0
    def read(self, *args):
        self.reads+=1
        return super().read(*args)

class Client(local_tests.Client):
    def __init__(self, base='https://admin.example.test'):
        self.base=base
        self.csrf=''
        self.cookie=''
        self.last_headers={}
    def request(self,path,body=None,headers=None,method=None,scheme='https',raw_payload=None,declared_size=None,inject_setup=True):
        if path=='/api/setup' and body is not None and inject_setup:
            body=dict(body,setup_token=SETUP_SECRET)
        payload=raw_payload if raw_payload is not None else (json.dumps(body).encode() if body is not None else b'')
        stream=TrackingStream(payload)
        env={};setup_testing_defaults(env)
        url=urlsplit(path)
        env.update(REQUEST_METHOD=method or ('POST' if body is not None or raw_payload is not None else 'GET'),
            PATH_INFO=url.path,QUERY_STRING=url.query,HTTP_HOST='admin.example.test',
            REMOTE_ADDR='192.0.2.50',SERVER_NAME='admin.example.test',SERVER_PORT='443')
        env['wsgi.url_scheme']=scheme
        env['wsgi.input']=stream
        if env['REQUEST_METHOD'] in ('POST','PUT'):
            env.update(CONTENT_TYPE='application/json',CONTENT_LENGTH=str(declared_size if declared_size is not None else len(payload)),
                HTTP_X_LAI_CLIENT='online',HTTP_X_CSRF_TOKEN=self.csrf,HTTP_ORIGIN='https://admin.example.test')
        if self.cookie:env['HTTP_COOKIE']=self.cookie
        for key,value in (headers or {}).items():
            k=key.upper().replace('-','_')
            env[k if k in ('CONTENT_LENGTH','CONTENT_TYPE') else 'HTTP_'+k]=value
        captured={}
        def start_response(status,h,exc_info=None):
            captured['code']=int(status.split()[0]);captured['headers']=dict(h)
        iterable=VALIDATED(env,start_response)
        try: data=b''.join(iterable)
        finally:
            if hasattr(iterable,'close'):iterable.close()
        self.last_headers=captured['headers']
        if 'Set-Cookie' in self.last_headers:
            self.cookie=self.last_headers['Set-Cookie'].split(';')[0]
        return captured['code'],data,stream
    def call(self,path,body=None,status=200,raw=False,headers=None):
        code,data,_=self.request(path,body,headers=headers)
        assert code==status,(path,code,status,data[:900])
        return data if raw else json.loads(data)

_TEMP=tempfile.TemporaryDirectory(prefix='lai-online-qa-')
tmp=_TEMP.name
SETUP_SECRET=secrets.token_urlsafe(40)
os.environ.update(LAI_DATA_DIR=tmp,LAI_PUBLIC_URL='https://admin.example.test',LAI_SETUP_TOKEN=SETUP_SECRET,LAI_TRAINER_SIGNUP='1')
os.environ.pop('RENDER_EXTERNAL_URL',None)
os.environ.pop('LAI_CLIENT_IP_HEADER',None)
import wsgi
VALIDATED=validator(wsgi.application)
base='https://admin.example.test'
admin=Client(base)
st=admin.call('/api/status')
for supplied in (None,'wrong-secret'):
    b=dict(name='Attacker',username='attacker',password=PASS)
    if supplied is not None:b['setup_token']=supplied
    code,_,_=admin.request('/api/setup',b,inject_setup=False)
    check('Setup rejects '+('missing' if supplied is None else 'incorrect')+' secret',code==403)
check('Unauthorized setup leaves the database empty',admin.call('/api/status')['setup_required'])
check("Empty database requires setup",st["setup_required"])
admin.call("/api/bootstrap",status=401)
check("Unauthenticated records blocked")
admin.call("/api/setup",dict(name="Test Admin",username="admin",password=PASS,demo=False))
admin.call("/api/setup",dict(name="Other",username="other",password=PASS),status=403)
check("First-run setup cannot be repeated")
admin.login("admin");state=admin.bootstrap();uid=state["user"]["id"]
check("Admin login and secure session",state["user"]["role"]=="admin")
admin.call("/api/settings",dict(name="Bad"),status=403,headers={"X-CSRF-Token":"wrong"})
admin.call("/api/bootstrap",status=403,headers={"Host":"evil.invalid"})
admin.call("/api/settings",{},status=403,headers={"Origin":"https://evil.invalid"})
check("CSRF, DNS rebinding Host and cross-origin writes blocked")

staff={}
for username,role,dept in [("sales1","employee","sales"),("service1","employee","service"),("boss","manager","sales"),("trainer1","trainer","admin")]:
    u=admin.call("/api/users",dict(name=username,username=username,role=role,dept=dept,password=PASS))["user"]
    c=Client(base);c.login(username)
    c.call("/api/records",dict(kind="tasks",title="Blocked before reset"),status=403)
    c.call("/api/password",dict(current=PASS,password=NEW))
    c.bootstrap();staff[username]=(u,c)
check("Temporary passwords must be changed before writes")
salesperson,sales=staff["sales1"];service_user,service=staff["service1"];boss_user,boss=staff["boss"];trainer_user,trainer=staff["trainer1"]
salesid=salesperson["id"]
sales.call("/api/users",dict(name="Hacker",username="hacker",password=PASS),status=403)
sales.call("/api/backup",{},status=403)
check("Employee cannot administer users or download database")
admin.call(f"/api/users/{uid}",dict(role="employee"),status=400)
check("Last active administrator cannot be demoted")

task=admin.new("tasks","Approval workflow","sales",salesid,dict(acceptance="Verified output",priority="high",progress=0,checklist=[dict(text="Step 1",done=False)]))
other=admin.new("tasks","Other department secret","service",service_user["id"],dict(acceptance="Ready",priority="normal"))
check("Employee only sees own assigned tasks",other["id"] not in [r["id"] for r in sales.bootstrap()["records"]])
sales.call(f"/api/records/{other['id']}/detail",status=404)
check("Direct ID access cannot bypass record scope")
sales.call(f"/api/records/{task['id']}",dict(version=task["version"],status="done"),status=403)
sales.call(f"/api/records/{task['id']}",dict(version=task["version"],status="review",data={}),status=400)
check("Completion and unproven review cannot be forged")
sales.call(f"/api/records/{task['id']}",dict(version=task["version"],due="2099-12-31T16:00"),status=403)
sales.call(f"/api/records/{task['id']}",dict(version=task["version"],data={"acceptance":"Easier criterion"}),status=403)
sales.call(f"/api/records/{task['id']}",dict(version=task["version"],status="cancelled"),status=403)
check("Employees cannot move deadlines, relax acceptance or cancel assigned tasks")
task=sales.call(f"/api/records/{task['id']}",dict(version=task["version"],status="doing",data={"progress":50,"checklist":[dict(text="Step 1",done=True)]}))["record"]
sales.call(f"/api/records/{task['id']}",dict(version=1,data={"progress":60}),status=409)
check("Stale edits are rejected without overwriting")
attach=b"LAI proof of execution"
aid=sales.call(f"/api/records/{task['id']}/attachment",dict(name="proof.txt",content=base64.b64encode(attach).decode()))["id"]
check("Attachment content is persisted",admin.call(f"/api/attachments/{aid}",raw=True)==attach)
service.call(f"/api/attachments/{aid}",status=404)
check("Attachment access obeys parent record scope")
task=sales.call(f"/api/records/{task['id']}",dict(version=task["version"],status="review",data={"result":"Output delivered"}))["record"]
sales.call(f"/api/records/{task['id']}/action",dict(version=task["version"],action="approve"),status=403)
task=boss.call(f"/api/records/{task['id']}/action",dict(version=task["version"],action="approve",note="Checked"))["record"]
check("Manager approval closes proven task",task["status"]=="done" and task["data"]["approved_by"]==boss_user["id"])
sales.call(f"/api/records/{task['id']}",dict(version=task["version"],data={"result":"Changed"}),status=409)
check("Approved tasks are protected from silent edits")
boss_own=admin.new("tasks","Manager own task","sales",boss_user["id"],dict(acceptance="Check",result="Done",evidence="Reference"),status="review")
boss.call(f"/api/records/{boss_own['id']}/action",dict(version=boss_own["version"],action="approve"),status=400)
check("Manager cannot self-approve assigned task")
recurring=admin.new("tasks","Recurring","sales",salesid,dict(acceptance="Check",result="Done",evidence="Ref",repeat_days=7),status="review")
recurring=admin.call(f"/api/records/{recurring['id']}/action",dict(version=recurring["version"],action="approve"))["record"]
following=[r for r in admin.bootstrap()["records"] if r["kind"]=="tasks" and r["data"].get("parent_id")==recurring["id"]]
check("Approval creates one recurring successor",len(following)==1 and following[0]["due"]=="2099-12-22T16:00")
admin.call(f"/api/records/{recurring['id']}/action",dict(version=recurring["version"],action="approve"),status=400)
check("Duplicate approval cannot repeat the recurrence")

course=admin.new("courses","Private cost course","admin",uid,dict(capacity=2,trainer_id=trainer_user["id"],price=10000,trainer_rate=2000,marketing_pct=10,trainer_confirmed=True,venue_ready=True,tools_ready=True),status="ready")
other_course=admin.new("courses","Other trainer course","admin",uid,dict(capacity=5,price=15000,trainer_rate=99999))
check("Trainer can only view assigned courses",other_course["id"] not in [r["id"] for r in trainer.bootstrap()["records"]])
visible=next(r for r in sales.bootstrap()["records"] if r["id"]==course["id"])
check("Staff course view redacts trainer fees and marketing", "trainer_rate" not in visible["data"] and "marketing_pct" not in visible["data"])
en=service.new("enrollments","Student A","service",service_user["id"],dict(course_id=course["id"],fee=10000,phone="0551111111",attendance="pending",result="pending",certificate="pending"))
en2=service.new("enrollments","Student B","service",service_user["id"],dict(course_id=course["id"],fee=10000,attendance="pending",result="pending"))
service.call("/api/records",dict(kind="enrollments",title="Overflow",dept="service",owner_id=service_user["id"],data={"course_id":course["id"],"fee":10000}),status=400)
check("Course seat capacity enforced on server")
trainer_en=next(r for r in trainer.bootstrap()["records"] if r["id"]==en["id"])
check("Trainer sees attendance but no contact or fee", "fee" not in trainer_en["data"] and "phone" not in trainer_en["data"])
trainer.call(f"/api/records/{en['id']}",dict(version=en["version"],data={"fee":1}),status=403)
en=trainer.call(f"/api/records/{en['id']}",dict(version=en["version"],data={"attendance":"present","result":"passed","trainer_note":"Verified in class"}))["record"]
check("Trainer can record attendance and outcome",en["data"]["attendance"]=="present")
service.call(f"/api/records/{en2['id']}",dict(version=en2["version"],data={"certificate":"issued"}),status=400)
check("Certificate status requires attendance and passing result")
en=service.call(f"/api/records/{en['id']}",dict(version=en["version"],data={"certificate":"issued"}))["record"]
check("Service can track eligible certificate issuance",en["data"]["certificate"]=="issued")

p=admin.new("payments","Receipt","admin",uid,dict(type="receipt",amount=10000,course_id=course["id"],enrollment_id=en["id"],reference="BANK-001",category="training"),status="verified",due="2099-12-15")
sales.call(f"/api/records/{p['id']}/detail",status=404)
admin.call(f"/api/records/{p['id']}",dict(version=p["version"],data={"amount":1}),status=409)
check("Financial entries private and immutable")
admin.call("/api/records",dict(kind="payments",title="Overpayment",dept="admin",owner_id=uid,data={"type":"receipt","amount":1,"course_id":course["id"],"enrollment_id":en["id"],"reference":"BANK-002"}),status=400)
check("Overcollection against a registration is rejected")
refund=admin.new("payments","Partial refund","admin",uid,dict(type="refund",amount=1000,course_id=course["id"],enrollment_id=en["id"],reversal_of=p["id"],reference="REFUND-001",category="training"),status="verified")
admin.call("/api/records",dict(kind="payments",title="Over-refund",dept="admin",owner_id=uid,data={"type":"refund","amount":9500,"course_id":course["id"],"enrollment_id":en["id"],"reversal_of":p["id"],"reference":"REFUND-002"}),status=400)
check("Refund bounded by original unrefunded amount")
admin.call(f"/api/records/{en['id']}",dict(version=en["version"],data={"course_id":other_course["id"]}),status=400)
check("Paid registration cannot be moved to another course")
expense=admin.new("payments","Trainer partial payment","admin",uid,dict(type="expense",amount=1000,course_id=course["id"],reference="EXP-001",category="trainer"),status="verified")
finance=next(x for x in admin.bootstrap()["finance"] if x["id"]==course["id"])
check("Course settlement avoids trainer double-counting",finance["collected"]==9000 and finance["trainer_remaining"]==1000 and finance["marketing_remaining"]==900 and finance["contribution_estimate"]==6100)

content=admin.new("content","Approved content","media",uid,dict(brief="Confirmed facts",caption="Safe caption"),status="review")
content=admin.call(f"/api/records/{content['id']}/action",dict(version=content["version"],action="approve"))["record"]
admin.call(f"/api/records/{content['id']}",dict(version=content["version"],data={"caption":"Altered facts"}),status=409)
admin.call(f"/api/records/{content['id']}",dict(version=content["version"],status="idea"),status=409)
check("Approved content requires explicit reopening")
content=admin.call(f"/api/records/{content['id']}",dict(version=content["version"],status="published",data={"post_url":"https://example.org/post"}))["record"]
check("Publication can be tracked after approval",content["status"]=="published")
goal=admin.new("goals","Sales target","sales",salesid,dict(metric="Count confirmed",period="2099-12",target=10,actual=0,direction="up",unit="count"))
boss.call(f"/api/records/{goal['id']}",dict(version=goal["version"],data={"actual":5}),status=400)
goal=boss.call(f"/api/records/{goal['id']}",dict(version=goal["version"],data={"actual":5,"evidence":"Monthly report"}))["record"]
check("Manual result updates require evidence")
leave=sales.new("leaves","Annual leave","sales",salesid,dict(start_date="2099-12-01",end_date="2099-12-02",leave_type="annual"))
leave=boss.call(f"/api/records/{leave['id']}/action",dict(version=leave["version"],action="approve"))["record"]
own_leave=admin.new("leaves","Admin leave","admin",uid,dict(start_date="2099-12-01",end_date="2099-12-02"))
admin.call(f"/api/records/{own_leave['id']}/action",dict(version=own_leave["version"],action="approve"),status=400)
check("Leave approval separated from applicant")
sales.call("/api/clock",dict(action="in"))
sales.call("/api/clock",dict(action="in"),status=400)
sales.call("/api/clock",dict(action="out"))
check("Clock-in/out uses server time and prevents duplicate punches")
lead=sales.new("leads","Won customer","sales",salesid,dict(interest="BLS",course_id=course["id"],value=10000,notes="Agreed terms"),status="won")
sales.call("/api/handoff",dict(lead_id=lead["id"],owner_id=service_user["id"],due="2099-12-16T12:00",notes="Please verify registration"))
sales.call("/api/handoff",dict(lead_id=lead["id"],owner_id=service_user["id"],due="2099-12-16T12:00"),status=400)
check("Won lead creates linked service handoff only once")
ticket=next(x for x in service.bootstrap()["records"] if x["kind"]=="tickets" and x["data"].get("lead_id")==lead["id"])
service.call(f"/api/records/{ticket['id']}",dict(version=ticket["version"],status="resolved"),status=400)
check("Service resolution cannot omit outcome")
injection=admin.new("tasks","=HYPERLINK(\"bad\")","sales",salesid,dict(acceptance="CSV export",description="<script>alert(1)</script>"))
exported=sales.call("/api/export?kind=tasks",raw=True).decode("utf-8-sig")
check("CSV formula injection hardened","'=HYPERLINK" in exported)
trainer_details=trainer.call(f"/api/records/{course['id']}/detail")
check("Audit payloads do not leak financial data to trainer",all(not e["detail"] for e in trainer_details["audit"]))
new_signup=Client(base);new_signup.call("/api/signup",dict(name="New trainer",username="pending-trainer",password=PASS))
new_signup.call("/api/login",dict(username="pending-trainer",password=PASS),status=401)
check("Self-registered trainer requires admin activation")

backup=admin.call("/api/backup",{},raw=True)
check("Consistent SQLite backup produced",backup.startswith(b"SQLite format 3\0"))
sentinel=admin.new("tasks","After backup sentinel","admin",uid,dict(acceptance="Not in snapshot"))
admin.call("/api/restore",dict(password="incorrect-password",content=base64.b64encode(backup).decode()),status=403)
admin.call("/api/restore",dict(password=PASS,content=base64.b64encode(b"not sqlite").decode()),status=400)
check("Restore requires password and valid SQLite snapshot")
admin.call("/api/restore",dict(password=PASS,content=base64.b64encode(backup).decode()))
admin.call("/api/bootstrap",status=401)
admin.login("admin")
restored=admin.bootstrap()
check("Restore swaps data and invalidates sessions",sentinel["id"] not in [r["id"] for r in restored["records"]])
check("Backup/restore includes attachments",admin.call(f"/api/attachments/{aid}",raw=True)==attach)
check("All four departments present",set(restored["departments"])=={"sales","service","media","admin"})
check("No internal server errors",not (Path(tmp)/"errors.log").exists())

# Additional online-only protection checks.
check('Application identifies the online build',restored['mode']=='online' and restored['refresh_seconds']==15)
login=admin.login('admin')
sc=admin.last_headers['Set-Cookie']
check('Session cookie has host prefix and transport protections',all(x in sc for x in ('__Host-lai_session=','; Secure','HttpOnly','SameSite=Strict','Path=/')))
check('Session secret is absent from response JSON','__Host-lai_session' not in json.dumps(login))
check('Setup token is never returned',SETUP_SECRET not in json.dumps(admin.call('/api/status')))
code,_,_=admin.request('/api/bootstrap',headers={'Host':'evil.invalid','X-Forwarded-Host':'admin.example.test'})
check('Forwarded host cannot bypass host allowlist',code==403)
code,_,_=admin.request('/api/bootstrap',headers={'Sec-Fetch-Site':'cross-site'})
check('Cross-site fetch rejected',code==403)
code,_,_=admin.request('/api/status',scheme='http')
check('Plain HTTP rejected outside loopback development',code==426)
legacy=Client();legacy.cookie=admin.cookie.replace('__Host-lai_session=','lai_session=')
legacy.call('/api/bootstrap',status=401)
check('Legacy non-host session cookie rejected on HTTPS')
code,_,_=admin.request('/api/settings',{},headers={'X-LAI-Client':''})
check('Writes require the application header',code==403)
admin.call('/api/users',dict(name='Short password',username='weak-test',role='employee',dept='sales',password='Only11Chars'),status=400)
check('New passwords require at least 12 characters')
for path in ('/.env','/data/lai.sqlite','/app.py','/render.yaml','/static/../app.py'):
    admin.call(path,status=404)
check('Source, settings and database files are not public routes')
noauth=Client()
code,_,stream=noauth.request('/api/restore',{},declared_size=140000000)
check('Unauthorized uploads rejected before reading their body',code==401 and stream.reads==0)
code,_,stream=admin.request('/api/settings',{},declared_size=wsgi.MAX_NORMAL_REQUEST+1)
check('Ordinary body size limit enforced before read',code==413 and stream.reads==0)
code,_,stream=admin.request('/api/restore',{},declared_size=wsgi.MAX_RESTORE_REQUEST+1)
check('Online restore size limit enforced before read',code==413 and stream.reads==0)
sales.login('sales1',NEW)
code,_,stream=sales.request('/api/restore',{},declared_size=wsgi.MAX_RESTORE_REQUEST)
check('Employee restore rejected before reading content',code==403 and stream.reads==0)
code,_,_=admin.request('/api/settings',raw_payload=b'{bad json')
check('Malformed JSON returns a controlled 400',code==400)
code,_,_=admin.request('/api/settings',raw_payload=b'[]')
check('Non-object JSON rejected',code==400)
code,health,_=noauth.request('/healthz',headers={'Host':'health-probe'})
check('Public health endpoint exposes no record data',code==200 and json.loads(health)=={'status':'ok'})
code,head,_=admin.request('/',method='HEAD')
check('HEAD returns headers without a body',code==200 and head==b'')
code,_,_=admin.request('/',method='OPTIONS')
check('Unsupported methods rejected',code==405)
robots=admin.call('/robots.txt',raw=True)
check('Indexing discouraged without claiming it is authentication',b'Disallow: /' in robots and 'noindex' in admin.last_headers['X-Robots-Tag'])
admin.call('/api/bootstrap')
check('HSTS and CSP are present on secure responses','Strict-Transport-Security' in admin.last_headers and 'Content-Security-Policy' in admin.last_headers)
wsgi.CONFIG.signup=False
check('Trainer signup can be disabled',admin.call('/api/status')['trainer_signup'] is False)
noauth.call('/api/signup',dict(name='Blocked',username='blocked-signup',password=PASS),status=403)
check('Disabled public signup enforced server-side')
concurrent=admin.new('tasks','Concurrent editing','admin',uid,dict(acceptance='Version checked'))
def edit_one(title):
    c=Client();c.cookie=admin.cookie;c.csrf=admin.csrf
    return c.request(f"/api/records/{concurrent['id']}",dict(version=concurrent['version'],title=title))[0]
with ThreadPoolExecutor(max_workers=2) as pool:
    codes=list(pool.map(edit_one,['Update A','Update B']))
check('Simultaneous stale edits cannot overwrite one another',sorted(codes)==[200,409])
# Enforce one process with an OS lock, not just documentation.
env=os.environ.copy()
blocked=subprocess.run([sys.executable,'-c','import wsgi; wsgi.initialize_runtime()'],cwd=ROOT,env=env,capture_output=True,timeout=10)
check('Second online process is rejected',blocked.returncode!=0 and b'Only ONE online process' in blocked.stderr)
# Test a real v1 database produced by the unchanged local core in another process.
online_backup=admin.call('/api/backup',{},raw=True)
with tempfile.TemporaryDirectory(prefix='lai-v1-source-') as localdir:
    env=os.environ.copy();env['LAI_DATA_DIR']=localdir
    source="""import app
app.initialize()
with app.connect() as db:
    u=app.add_user(db,dict(name="Migration user",username="migrated",password="MigrationStrongPass2026",role="admin",dept="admin"))
    r=app.insert_record(db,dict(kind="tasks",dept="admin",owner_id=u["id"],title="V1 migration proof",status="new",due="2099-12-01T12:00",data={"acceptance":"Preserved"}))
    db.execute("INSERT INTO attachments(record_id,user_id,name,mime,size,content,created) VALUES(?,?,?,?,?,?,?)",(r["id"],u["id"],"proof.txt","text/plain",6,b"legacy",app.now()))
"""
    subprocess.run([sys.executable,'-c',source],cwd=ROOT,env=env,check=True,capture_output=True,timeout=15)
    raw=(Path(localdir)/'lai.sqlite').read_bytes()
    admin.call('/api/restore',dict(password=PASS,content=base64.b64encode(raw).decode()))
    migrated=Client();migrated.login('migrated','MigrationStrongPass2026')
    boot=migrated.bootstrap()
    check('Original local v1 account and records migrate',boot['records'][0]['title']=='V1 migration proof')
    check('Local v1 attachment migrates',migrated.call('/api/attachments/1',raw=True)==b'legacy')
    migrated.call('/api/restore',dict(password='MigrationStrongPass2026',content=base64.b64encode(online_backup).decode()))
admin.login('admin');admin.bootstrap()
check('Online snapshot can restore back after migration')
# Try enough cheap invalid setup attempts to trigger the auth limiter.
responses=[]
for _ in range(12):
    code,_,_=noauth.request('/api/setup',dict(name='x',username='x',password=PASS,setup_token='bad'),inject_setup=False)
    responses.append(code)
check('Public setup attempts are rate limited',429 in responses and noauth.last_headers.get('Retry-After')=='900')
check('No internal errors in online functional run',not(Path(tmp)/'errors.log').exists())
print(f'\nSUCCESS: {len(CHECKS)} WSGI checks passed.')
report=os.environ.get('LAI_TEST_REPORT')
if report:Path(report).write_text(json.dumps({'passed':len(CHECKS),'checks':CHECKS},indent=2))
