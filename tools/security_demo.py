"""보안 데모: 유출된 계정으로 로그인하는 상황을 재현하고, Microsoft 쪽에서 Entra ID P2와 A5가
어떻게 탐지·차단하는지 결과를 모은다. 학교 B(Microsoft 365 A5) 테넌트의 데모 계정(hack01~hack04)만 대상이다.

시나리오(계정 → 데모 정책 → 재현)
  S1 hack01  로그인 위험 시 차단       Tor(익명 IP)에서 로그인
  S2 hack02  로그인 위험 시 MFA 요구   Tor에서 로그인, IdP가 2단계 인증 후 MFA 클레임을 보냄
  S3 hack04  로그인 위험 시 MFA 요구   Tor에서 로그인, IdP 2단계 인증 없음
  S4 hack03  사용자 위험 높음 시 차단  정상 로그인으로 CAE 토큰을 받은 뒤 관리자가 침해 확인

명령
  setup    데모 그룹·조건부 액세스 정책 만들기(관리자, 멱등)
  attack   로그인 재현. --proxy socks5h://127.0.0.1:9050 이면 Tor 경유
  cae      S4: CAE 토큰으로 Graph를 주기적으로 호출하며 거부 시점 기록(--confirm 이면 관리자 침해 확인까지)
  confirm  관리자 침해 확인(사용자 위험 높음)
  report   위험 탐지·위험 사용자·로그인 기록·Defender XDR 알림 요약(관리자)
  reset    데모 계정 위험 해제(관리자)
  cleanup  데모 정책·그룹 삭제(관리자, --delete-users 면 데모 계정도 삭제)

관리자 명령은 graph_token.py 토큰 캐시를 쓴다. GRAPH_EXTRA_SCOPES 에 다음 권한을 넣는다.
  setup·cleanup: Policy.ReadWrite.ConditionalAccess, Application.Read.All, Group.ReadWrite.All
  confirm·reset·report: IdentityRiskyUser.ReadWrite.All, IdentityRiskEvent.Read.All, SecurityAlert.Read.All
비밀번호·TOTP는 --password-file/--totp-file 또는 환경 변수 DEMO_PASSWORD/DEMO_TOTP_JSON 으로 받는다.
"""
import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_signin import AAD, CLIENT_ID, UA, Browser, jwt_claims  # noqa: E402

GRAPH = "https://graph.microsoft.com/v1.0"
DEMO = "SSO 보안 데모"
ACCOUNTS = ["hack01", "hack02", "hack03", "hack04"]
GROUPS = {  # 키: (그룹 이름, mailNickname, 구성원)
    "block": (f"{DEMO} - 로그인 위험 차단", "sso-demo-signin-block", ["hack01"]),
    "mfa": (f"{DEMO} - 로그인 위험 MFA 요구", "sso-demo-signin-mfa", ["hack02", "hack04"]),
    "userrisk": (f"{DEMO} - 사용자 위험 차단", "sso-demo-userrisk-block", ["hack03"]),
}
RISK_ALL = ["low", "medium", "high"]
POLICIES = [  # (정책 이름, 그룹 키, 위험 조건, 허용 제어)
    (f"{DEMO} S1 - 로그인 위험 시 차단", "block", {"signInRiskLevels": RISK_ALL}, ["block"]),
    (f"{DEMO} S2·S3 - 로그인 위험 시 MFA 요구", "mfa", {"signInRiskLevels": RISK_ALL}, ["mfa"]),
    (f"{DEMO} S4 - 사용자 위험 높음 시 차단", "userrisk", {"userRiskLevels": ["high"]}, ["block"]),
]
CAE_CLAIMS = json.dumps({"access_token": {"xms_cc": {"values": ["cp1"]}}})


def now():
    return datetime.now(timezone.utc)


def stamp():
    return now().astimezone().strftime("%H:%M:%S")


def load_secrets(a):
    password = os.environ.get("DEMO_PASSWORD") or (open(a.password_file, encoding="utf-8").read().strip()
                                                   if a.password_file else None)
    if not password:
        raise SystemExit("비밀번호 필요: --password-file 또는 DEMO_PASSWORD")
    raw = os.environ.get("DEMO_TOTP_JSON") or (open(a.totp_file, encoding="utf-8").read() if a.totp_file else "{}")
    totp = {uid: parse_qs(urlparse(uri).query)["secret"][0] for uid, uri in json.loads(raw).items()}
    return password, totp


def tenant_of(domain, domains_file):
    domains = json.load(open(domains_file, encoding="utf-8"))
    return domains[domain]["tenantId"]


def admin(a):
    from graph_token import Graph  # 관리자 명령에서만 필요(msal)
    return Graph(tenant_of(a.domain, a.domains))


def user_ids(g, domain, uids):
    out = {}
    for uid in uids:
        found = g.get_all(f"/users?$filter=userPrincipalName eq '{uid}@{domain}'&$select=id,userPrincipalName")
        if not found:
            raise SystemExit(f"계정 없음: {uid}@{domain}")
        out[uid] = found[0]["id"]
    return out


# ---------------------------------------------------------------- setup / cleanup
def cmd_setup(a):
    g = admin(a)
    ids = user_ids(g, a.domain, ACCOUNTS)
    gid = {}
    for key, (name, nick, members) in GROUPS.items():
        found = g.get_all(f"/groups?$filter=displayName eq '{name}'&$select=id")
        if found:
            gid[key] = found[0]["id"]
            have = {m["id"] for m in g.get_all(f"/groups/{gid[key]}/members?$select=id")}
            for uid in members:
                if ids[uid] not in have:
                    g.call("POST", f"/groups/{gid[key]}/members/$ref",
                           {"@odata.id": f"{GRAPH}/directoryObjects/{ids[uid]}"})
            print(f"그룹 있음: {name}")
        else:
            gid[key] = g.call("POST", "/groups", {
                "displayName": name, "mailEnabled": False, "mailNickname": nick, "securityEnabled": True,
                "members@odata.bind": [f"{GRAPH}/directoryObjects/{ids[u]}" for u in members]})["id"]
            print(f"그룹 만듦: {name} ({', '.join(members)})")
    for name, key, risk, controls in POLICIES:
        body = {
            "displayName": name, "state": "enabled",
            "conditions": {"users": {"includeGroups": [gid[key]]}, "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": ["all"], **risk},
            "grantControls": {"operator": "OR", "builtInControls": controls},
        }
        found = [p for p in g.get_all("/identity/conditionalAccess/policies?$select=id,displayName")
                 if p["displayName"] == name]
        if found:
            g.call("PATCH", f"/identity/conditionalAccess/policies/{found[0]['id']}", body)
            print(f"정책 갱신: {name}")
        else:
            g.call("POST", "/identity/conditionalAccess/policies", body)
            print(f"정책 만듦: {name}")


def cmd_cleanup(a):
    g = admin(a)
    names = {p[0] for p in POLICIES}
    for p in g.get_all("/identity/conditionalAccess/policies?$select=id,displayName"):
        if p["displayName"] in names:
            g.call("DELETE", f"/identity/conditionalAccess/policies/{p['id']}")
            print(f"정책 삭제: {p['displayName']}")
    for name, _, _ in GROUPS.values():
        for grp in g.get_all(f"/groups?$filter=displayName eq '{name}'&$select=id"):
            g.call("DELETE", f"/groups/{grp['id']}")
            print(f"그룹 삭제: {name}")
    if a.delete_users:
        for uid, oid in user_ids(g, a.domain, ACCOUNTS).items():
            g.call("DELETE", f"/users/{oid}")
            print(f"계정 삭제: {uid}@{a.domain}")


# ---------------------------------------------------------------- 공격 재현
def egress(proxies):
    try:
        r = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=30).json()
        return {"ip": r.get("IP"), "tor": bool(r.get("IsTor"))}
    except Exception as e:  # noqa: BLE001
        return {"ip": None, "tor": None, "error": type(e).__name__}


def summarize(out):
    if out.get("result") == "success":
        return f"성공: {out.get('user')} 로그인됨"
    code = out.get("aadsts") or out.get("pgid") or out.get("result")
    msg = (out.get("strServiceExceptionMessage") or out.get("sErrTxt") or out.get("errorDescription") or "")
    return f"차단/중단: {code} {msg[:120]}".strip()


def cmd_attack(a):
    password, totp = load_secrets(a)
    proxies = {"http": a.proxy, "https": a.proxy} if a.proxy else None
    net = egress(proxies)
    print(f"[{stamp()}] 접속 경로: {'Tor' if a.proxy else '직접'}, 출구 IP {net.get('ip')} (Tor 여부: {net.get('tor')})")
    results = []
    for uid in a.accounts:
        b = Browser(password, totp)
        if proxies:
            b.s.proxies.update(proxies)
        started = now().isoformat()
        try:
            out = b.sign_in(f"{uid}@{a.domain}")
        except Exception as e:  # noqa: BLE001
            out = {"result": "exception", "error": f"{type(e).__name__}: {e}"[:300]}
        out.update({"account": uid, "started": started, "egress": net, "via": "Tor" if a.proxy else "direct"})
        results.append(out)
        print(f"[{stamp()}] {uid}: {summarize(out)} (IdP 2단계 인증: {'예' if out.get('idpMfa') else '아니오'})")
        print("      " + " | ".join(out.get("steps", [])))
    if a.json:
        print("RESULT_JSON " + json.dumps(results, ensure_ascii=False))
    if a.out:
        json.dump(results, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- S4: CAE
def confirm(g, oid):
    g.call("POST", "/identityProtection/riskyUsers/confirmCompromised", {"userIds": [oid]})


def refresh(rt, tenant="organizations"):
    return requests.post(f"{AAD}/{tenant}/oauth2/v2.0/token", headers={"User-Agent": UA}, data={
        "client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": rt,
        "scope": "https://graph.microsoft.com/.default openid profile offline_access", "claims": CAE_CLAIMS}).json()


def cmd_cae(a):
    password, totp = load_secrets(a)
    upn = f"{a.account}@{a.domain}"
    out = Browser(password, totp).sign_in(upn, scope="https://graph.microsoft.com/.default openid profile offline_access",
                                          claims=CAE_CLAIMS, keep_tokens=True)
    if out.get("result") != "success":
        raise SystemExit(f"로그인 실패: {summarize(out)}")
    at, rt = out["tokens"]["access_token"], out["tokens"]["refresh_token"]
    c = jwt_claims(at)
    print(f"[{stamp()}] {upn} 로그인, Graph 토큰 발급: 만료까지 {(c['exp'] - time.time()) / 3600:.1f}시간, "
          f"CAE 표시(xms_cc)={c.get('xms_cc')}")
    g = admin(a) if a.confirm else None
    oid = user_ids(g, a.domain, [a.account])[a.account] if g else None
    t0, confirmed_at = time.time(), None
    while time.time() - t0 < a.timeout:
        r = requests.get(f"{GRAPH}/me?$select=userPrincipalName", headers={"Authorization": "Bearer " + at}, timeout=30)
        if r.status_code == 200:
            print(f"[{stamp()}] Graph /me 200 OK ({r.json().get('userPrincipalName')})")
        else:
            www = r.headers.get("WWW-Authenticate", "")
            detail = ""
            if 'claims="' in www:
                detail = base64.b64decode(www.split('claims="')[1].split('"')[0] + "==").decode(errors="replace")
            mins = f", 침해 확인 {round((time.time() - confirmed_at) / 60, 1)}분 뒤" if confirmed_at else ""
            print(f"[{stamp()}] Graph /me {r.status_code} 토큰 거부{mins}: {www[:160]} {detail[:200]}")
            break
        if g and confirmed_at is None:
            confirm(g, oid)
            confirmed_at = time.time()
            print(f"[{stamp()}] 관리자 침해 확인(confirmCompromised) → 사용자 위험 '높음'")
        time.sleep(a.interval)
    else:
        print(f"[{stamp()}] {a.timeout}초 동안 거부되지 않음")
    tok = refresh(rt)
    print(f"[{stamp()}] 새 토큰 요청(refresh token): {tok.get('error') or '발급됨'} "
          f"{(tok.get('error_description') or '').splitlines()[0][:160] if tok.get('error_description') else ''}")
    again = Browser(password, totp).sign_in(upn)
    print(f"[{stamp()}] 새 로그인 시도: {summarize(again)}")


def cmd_confirm(a):
    g = admin(a)
    for uid, oid in user_ids(g, a.domain, a.accounts).items():
        confirm(g, oid)
        print(f"침해 확인: {uid}@{a.domain}")


def cmd_reset(a):
    g = admin(a)
    ids = user_ids(g, a.domain, a.accounts)
    g.call("POST", "/identityProtection/riskyUsers/dismiss", {"userIds": list(ids.values())})
    print(f"위험 해제: {', '.join(ids)}")


# ---------------------------------------------------------------- report
def cmd_report(a):
    g = admin(a)
    since = (now() - timedelta(hours=a.hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ids = user_ids(g, a.domain, a.accounts)
    upns = {f"{u}@{a.domain}".lower() for u in ids}
    report = {"since": since, "users": {}}
    for uid, oid in ids.items():
        try:
            ru = g.call("GET", f"/identityProtection/riskyUsers/{oid}")
        except RuntimeError:
            ru = {}
        dets = g.get_all(f"/identityProtection/riskDetections?$filter=userId eq '{oid}' and activityDateTime ge {since}")
        sis = g.call("GET", f"/auditLogs/signIns?$filter=userId eq '{oid}' and createdDateTime ge {since}&$top=20")["value"]
        report["users"][uid] = {"riskyUser": ru, "detections": dets, "signIns": sis}
        print(f"\n== {uid}: 사용자 위험 {ru.get('riskLevel', 'none')} / {ru.get('riskState', '-')} ({ru.get('riskDetail', '-')})")
        for d in sorted(dets, key=lambda x: x["activityDateTime"]):
            loc = d.get("location") or {}
            print(f"  탐지 {d['activityDateTime'][11:19]} {d['riskEventType']} 위험 {d['riskLevel']} "
                  f"({d['detectionTimingType']}, {d.get('source')}) {d.get('ipAddress')} {loc.get('countryOrRegion') or ''}")
        for s in sorted(sis, key=lambda x: x["createdDateTime"]):
            pols = [f"{p['displayName']}={p['result']}" for p in s.get("appliedConditionalAccessPolicies", [])
                    if p["displayName"].startswith(DEMO) or p["result"] not in ("notApplied", "notEnabled")]
            st = s.get("status") or {}
            print(f"  로그인 {s['createdDateTime'][11:19]} {s.get('ipAddress')} {(s.get('location') or {}).get('countryOrRegion') or ''} "
                  f"오류 {st.get('errorCode')} 위험 {s.get('riskLevelDuringSignIn')} {s.get('riskEventTypes_v2')} "
                  f"CA {s.get('conditionalAccessStatus')} {pols}")
    try:
        alerts = g.get_all(f"/security/alerts_v2?$filter=createdDateTime ge {since}")
    except RuntimeError as e:
        alerts, report["alertsError"] = [], str(e)[:200]
    mine = []
    for al in alerts:
        names = {(ev.get("userAccount") or {}).get("userPrincipalName", "").lower() for ev in al.get("evidence", [])}
        if names & upns:
            mine.append(al)
    report["alerts"] = mine
    print(f"\n== Defender XDR 알림 {len(mine)}건" + (f" (조회 오류: {report['alertsError']})" if report.get("alertsError") else ""))
    for al in sorted(mine, key=lambda x: x["createdDateTime"]):
        print(f"  {al['createdDateTime'][11:19]} [{al.get('serviceSource')}] {al.get('title')} "
              f"심각도 {al.get('severity')} 상태 {al.get('status')} 인시던트 {al.get('incidentId')}")
    if a.out:
        json.dump(report, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["setup", "attack", "cae", "confirm", "report", "reset", "cleanup"])
    ap.add_argument("--domain", default="school2.joowon.me", help="데모 계정 학교 도메인(Microsoft 365 A5 테넌트)")
    ap.add_argument("--domains", default=os.path.join(here, "..", "idp", "data", "domains.json"))
    ap.add_argument("--accounts", nargs="*", default=None)
    ap.add_argument("--account", default="hack03", help="cae 대상 계정")
    ap.add_argument("--proxy", help="예: socks5h://127.0.0.1:9050 (Tor)")
    ap.add_argument("--password-file")
    ap.add_argument("--totp-file")
    ap.add_argument("--confirm", action="store_true", help="cae: 첫 호출 뒤 관리자 침해 확인까지 실행")
    ap.add_argument("--interval", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--hours", type=float, default=6, help="report: 조회 기간(시간)")
    ap.add_argument("--delete-users", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.accounts is None:
        a.accounts = {"attack": ["hack01", "hack02", "hack04"], "confirm": ["hack03"]}.get(a.command, ACCOUNTS)
    {"setup": cmd_setup, "attack": cmd_attack, "cae": cmd_cae, "confirm": cmd_confirm, "report": cmd_report,
     "reset": cmd_reset, "cleanup": cmd_cleanup}[a.command](a)


if __name__ == "__main__":
    main()
