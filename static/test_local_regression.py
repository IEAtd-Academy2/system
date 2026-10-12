#!/usr/bin/env python3
"""Integration checks against an isolated local server. No external dependencies."""
from __future__ import annotations
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
PASS="StrongLocalPass!2026"
NEW="ChangedLocalPass!2026"
CHECKS=[]

def check(name,condition=True):
    if not condition:
        raise AssertionError(name)
    CHECKS.append(name)
    print("PASS:",name)

class Client:
    def __init__(self,base):
        self.base=base
        self.csrf=""
        self.jar=http.cookiejar.CookieJar()
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
    def call(self,path,body=None,status=200,raw=False,headers=None):
        h={}
        if body is not None:
            h={"Content-Type":"application/json","X-LAI-Client":"local","X-CSRF-Token":self.csrf}
        if headers: h.update(headers)
        req=urllib.request.Request(self.base+path,data=json.dumps(body).encode() if body is not None else None,headers=h)
        try:
            r=self.opener.open(req,timeout=25)
        except urllib.error.HTTPError as error:
            r=error
        payload=r.read()
        assert r.status==status,(path,r.status,status,payload[:900])
        return payload if raw else json.loads(payload)
    def login(self,username,password=PASS):
        result=self.call("/api/login",dict(username=username,password=password))
        self.csrf=result["csrf"]
        return result
    def bootstrap(self):
        r=self.call("/api/bootstrap")
        self.csrf=r["csrf"]
        return r
    def new(self,kind,title,dept,owner,data,status=None,due="2099-12-15T16:00"):
        b=dict(kind=kind,title=title,dept=dept,owner_id=owner,data=data,due=due)
        if status:b["status"]=status
        return self.call("/api/records",b)["record"]

def main():
    with tempfile.TemporaryDirectory(prefix="lai-test-") as tmp:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        env=os.environ.copy();env["LAI_DATA_DIR"]=tmp
        log=open(Path(tmp)/"server.log","wb")
        process=subprocess.Popen([sys.executable,str(ROOT/"app.py"),"--port",str(port)],env=env,stdout=log,stderr=log)
        base=f"http://127.0.0.1:{port}"
        admin=Client(base)
        try:
            for i in range(80):
                try:
                    st=admin.call("/api/status");break
                except Exception:
                    if process.poll() is not None:raise RuntimeError("Server exited")
                    time.sleep(.1)
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
            print(f"\nSUCCESS: {len(CHECKS)} integration checks passed.")
            output=os.environ.get("LAI_TEST_REPORT")
            if output:Path(output).write_text(json.dumps({"passed":len(CHECKS),"checks":CHECKS},indent=2),encoding="utf-8")
        except Exception:
            errorfile=Path(tmp)/"errors.log"
            if errorfile.exists():print(errorfile.read_text(encoding="utf-8"),file=sys.stderr)
            raise
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            log.close()
if __name__=="__main__":main()
