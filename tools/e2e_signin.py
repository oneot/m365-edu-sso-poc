"""로그인 종단 시험: Microsoft 로그인 → 테스트 IdP → Microsoft → 토큰 발급까지 브라우저처럼 따라간다.

앱(공개 클라이언트)의 인증 코드 흐름을 흉내 내고, 결과 토큰의 테넌트·사용자를 확인한다.
화면 자동화 없이 HTTP 요청만 쓰며, Microsoft 로그인 페이지의 $Config 값으로 다음 단계를 정한다.

사용: python e2e_signin.py --password-file <IdP 테스트 비밀번호 파일> --totp-file <TOTP 비밀값 JSON>
                           [--domains ../idp/data/domains.json] [--admin-token-file <비밀값 파일>]
                           [--only A1 R1 ...] [--out <결과 JSON>]
"""
import argparse
import base64
import os
import hashlib
import hmac
import html
import json
import re
import secrets
import struct
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests

AAD = "https://login.microsoftonline.com"
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI(Microsoft 공개 클라이언트)
REDIRECT = "http://localhost:8400"
IDP = "https://auth.joowon.me"
LOGIN_UI_HOSTS = {"auth.joowon.me", "login.joowon.me", "oneot.github.io"}
# Chrome UA면 장치 SSO 확인 페이지(AADSTS50168)가 끼어들어 Firefox UA를 쓴다.
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0"
D1, D2, DR = "school1.joowon.me", "school2.joowon.me", "id.joowon.me"
DOMAINS = {}  # main()에서 domains.json 을 읽어 채운다(테넌트 ID → 학교 이름)


def tenant_of(domain):
    return DOMAINS.get(domain, {}).get("tenantId", "organizations")


TOTP_LAST = {}  # 아이디별 마지막으로 쓴 TOTP 구간(IdP가 같은 코드 재사용을 거부하므로 다음 구간까지 기다린다)


def totp_now(uid, secret):
    counter = int(time.time() // 30)
    while counter <= TOTP_LAST.get(uid, -1):
        time.sleep(30 - time.time() % 30 + 0.5)
        counter = int(time.time() // 30)
    TOTP_LAST[uid] = counter
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt_claims(token):
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def ests_config(text):
    m = re.search(r"\$Config=(\{.*?\});\s*(?://\]\]>|\n|</script>)", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def first_form(text):
    m = re.search(r"<form\b([^>]*)>(.*?)</form>", text, re.S | re.I)
    if not m:
        return None
    action = re.search(r'action="([^"]*)"', m.group(1))
    method = re.search(r'method="([^"]*)"', m.group(1), re.I)
    fields = {}
    for inp in re.finditer(r"<input\b([^>]*)>", m.group(2), re.I):
        name = re.search(r'name="([^"]*)"', inp.group(1))
        value = re.search(r'value="([^"]*)"', inp.group(1))
        if name:
            fields[html.unescape(name.group(1))] = html.unescape(value.group(1)) if value else ""
    return {"action": html.unescape(action.group(1)) if action else "", "method": (method.group(1) if method else "get").lower(),
            "fields": fields}


def error_info(cfg):
    keys = ("iErrorCode", "sErrorCode", "strServiceExceptionMessage", "sErrTxt", "strMainMessage")
    info = {k: cfg.get(k) for k in keys if cfg.get(k)}
    msg = str(cfg.get("strServiceExceptionMessage") or "")
    code = re.search(r"AADSTS\d+", msg)
    if code:
        info["aadsts"] = code.group(0)
    elif cfg.get("iErrorCode"):
        info["aadsts"] = f"AADSTS{cfg.get('iErrorCode')}"
    return info


class Browser:
    def __init__(self, password, totp):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8"})
        self.password = password
        self.totp = totp

    def sign_in(self, upn, *, domain_hint=None, prompt=None, idp_user=None, choose=None, tenant="organizations",
                hint=True):
        verifier = secrets.token_urlsafe(48)
        params = {
            "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT, "response_mode": "query",
            "scope": "openid profile offline_access", "state": secrets.token_hex(8), "nonce": secrets.token_hex(8),
            "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256",
        }
        if hint:
            params["login_hint"] = upn
        if domain_hint:
            params["domain_hint"] = domain_hint
        if prompt:
            params["prompt"] = prompt
        trace = {"steps": [], "idpLogin": False}
        r = self.s.get(f"{AAD}/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}", allow_redirects=False)
        outcome = self._drive(r, upn, idp_user or upn.split("@")[0], choose, trace)
        if outcome.get("code"):
            tok = self.s.post(f"{AAD}/{tenant}/oauth2/v2.0/token", data={
                "client_id": CLIENT_ID, "grant_type": "authorization_code", "code": outcome["code"],
                "redirect_uri": REDIRECT, "code_verifier": verifier, "scope": "openid profile offline_access"}).json()
            if "id_token" in tok:
                c = jwt_claims(tok["id_token"])
                outcome = {"result": "success", "tid": c.get("tid"), "user": c.get("preferred_username"), "name": c.get("name")}
            else:
                outcome = {"result": "token_error", "error": tok.get("error"), "desc": (tok.get("error_description") or "")[:200]}
        outcome["steps"] = trace["steps"]
        outcome["idpLogin"] = trace["idpLogin"]
        outcome["idpMfa"] = bool(trace.get("idpMfa"))
        if trace.get("company"):
            outcome["company"] = trace["company"]
        return outcome

    def idp_initiated(self, idp_user, domain, app=0):
        trace = {"steps": [], "idpLogin": False}
        r = self.s.post(f"{IDP}/login", data={"username": idp_user, "password": self.password}, allow_redirects=False)
        trace["idpLogin"] = True
        r = self.s.get(f"{IDP}/portal/launch?{urlencode({'domain': domain, 'app': app})}", allow_redirects=False)
        out = self._drive(r, None, idp_user, None, trace, stop_on_leave=True)
        out["steps"] = trace["steps"]
        out["idpLogin"], out["idpMfa"] = True, bool(trace.get("idpMfa"))
        return out

    def portal_link(self, idp_user, url):
        """IdP 포털에 로그인한 뒤 포털의 앱 링크(login_hint 포함)를 누른 것처럼 따라간다."""
        trace = {"steps": [], "idpLogin": True}
        self.s.post(f"{IDP}/login", data={"username": idp_user, "password": self.password}, allow_redirects=False)
        out = self._drive(self.s.get(url, allow_redirects=False), None, idp_user, None, trace)
        out["steps"] = trace["steps"]
        out["idpLogin"], out["idpMfa"] = True, bool(trace.get("idpMfa"))
        return out

    def _drive(self, r, upn, idp_user, choose, trace, stop_on_leave=False):
        for _ in range(30):
            host = urlparse(r.url).netloc
            if r.status_code in (301, 302, 303, 307, 308):
                loc = urljoin(r.url, r.headers["Location"])
                trace["steps"].append(f"{r.status_code}->{urlparse(loc).netloc}{urlparse(loc).path}")
                if loc.startswith(REDIRECT):
                    q = parse_qs(urlparse(loc).query)
                    if "code" in q:
                        return {"code": q["code"][0]}
                    return {"result": "error", "error": q.get("error", [""])[0],
                            "errorDescription": q.get("error_description", [""])[0][:400]}
                lp = urlparse(loc)
                if lp.netloc in LOGIN_UI_HOSTS and (lp.path.rstrip("/").endswith("/login") or lp.netloc != "auth.joowon.me"):
                    q = parse_qs(lp.query)
                    k = q.get("k", [None])[0]
                    api, origin = IDP, None
                    if lp.netloc != "auth.joowon.me":
                        # GitHub Pages 로그인 화면: 화면을 받아 오고, 화면의 스크립트처럼 api/login 으로 전송
                        page = self.s.get(loc)
                        if page.status_code != 200 or 'id="loginForm"' not in page.text:
                            return {"result": "login_ui_error", "status": page.status_code}
                        api = q.get("api", [IDP])[0]
                        if api != IDP:
                            return {"result": "login_ui_unexpected_api", "api": api}
                        origin = f"{lp.scheme}://{lp.netloc}"
                        trace["steps"].append(f"Pages 로그인 화면({lp.netloc}, 학교 표시={q.get('school', ['-'])[0]})")
                    trace["idpLogin"] = True
                    trace["steps"].append(f"IdP 로그인({idp_user})")
                    data = {"username": idp_user, "password": self.password}
                    if k:
                        data["k"] = k
                    r = self.s.post(f"{api}/login", data=data, allow_redirects=False,
                                    headers={"Origin": origin, "Referer": loc} if origin else None)
                    continue
                if stop_on_leave and lp.netloc not in ("login.microsoftonline.com", "auth.joowon.me"):
                    return {"result": "landed", "url": f"{lp.scheme}://{lp.netloc}{lp.path}"}
                r = self.s.get(loc, allow_redirects=False)
                continue

            text = r.text
            if host == "auth.joowon.me" and 'name="code"' in text and "2단계 인증" in text:
                form = first_form(text)
                secret = self.totp.get(idp_user)
                if not secret:
                    return {"result": "mfa_secret_missing"}
                trace["steps"].append(f"IdP 2단계 인증(TOTP, {idp_user})")
                trace["idpMfa"] = True
                r = self.s.post(urljoin(r.url, form["action"]), data={**form["fields"], "code": totp_now(idp_user, secret)},
                                allow_redirects=False)
                continue
            if host == "auth.joowon.me":
                if "어느 학교로 로그인할까요" in text:
                    k = re.search(r'name="k" value="([^"]+)"', text).group(1)
                    options = re.findall(r'name="domain" value="([^"]+)"', text)
                    pick = choose or options[0]
                    trace["steps"].append(f"학교 선택({pick})")
                    r = self.s.post(f"{IDP}/saml/continue", data={"k": k, "domain": pick}, allow_redirects=False)
                    continue
                form = first_form(text)
                if form and "SAMLResponse" in form["fields"]:
                    trace["steps"].append("SAML 응답 → login.srf")
                    r = self.s.post(form["action"], data=form["fields"], allow_redirects=False)
                    continue
                msg = re.search(r'<p class="sub">(.*?)</p>', text, re.S)
                return {"result": "idp_message", "message": html.unescape(msg.group(1)).strip() if msg else text[:200]}

            post_form = first_form(text)
            if post_form and "id_token" in post_form["fields"] and host == "login.microsoftonline.com":
                # 웹 앱(form_post)으로 넘어가는 마지막 단계: 앱에 전달되는 토큰의 테넌트·사용자 확인
                c = jwt_claims(post_form["fields"]["id_token"])
                trace["steps"].append(f"토큰 전달 → {urlparse(post_form['action']).netloc}")
                return {"result": "success", "tid": c.get("tid"), "user": c.get("preferred_username") or c.get("upn"),
                        "app": urlparse(post_form["action"]).netloc}
            cfg = ests_config(text)
            if cfg:
                pgid = cfg.get("pgid") or cfg.get("sPageId") or "?"
                err = error_info(cfg)
                if err.get("aadsts") or err.get("strServiceExceptionMessage"):
                    trace["steps"].append(f"ESTS 오류 페이지({pgid})")
                    return {"result": "aad_error", "pgid": pgid, **err}
                if pgid == "CmsiInterrupt":
                    # 도메인 확인 대화상자(Domain Confirmation Dialog). 사용자 이름 입력 없이 조용히 로그인될 때
                    # 로그인할 조직을 확인시키는 화면으로, SAML 응답을 받아들인 뒤에 뜬다.
                    trace["steps"].append(f"도메인 확인 대화상자({cfg.get('sCompanyDisplayName')}, {cfg.get('sPOST_Username')})")
                    trace["company"] = cfg.get("sCompanyDisplayName")
                    r = self.s.post(urljoin(AAD, cfg.get("urlPost") or "/appverify"), data={
                        "ContinueAuth": "true", "i19": "1000", "canary": cfg.get("canary"), "iscsrfspeedbump": "false",
                        "flowToken": cfg.get("sFT"), "hpgrequestid": cfg.get("sessionId"), "ctx": cfg.get("sCtx")},
                        allow_redirects=False)
                    continue
                if pgid == "KmsiInterrupt":
                    trace["steps"].append("로그인 상태 유지(KMSI)")
                    r = self.s.post(f"{AAD}/kmsi", data={
                        "LoginOptions": "1", "type": "28", "ctx": cfg.get("sCtx"), "hpgrequestid": cfg.get("sessionId"),
                        "flowToken": cfg.get("sFT"), "canary": cfg.get("canary"), "i19": "1000"}, allow_redirects=False)
                    continue
                if cfg.get("urlGetCredentialType") and upn and not trace.get("gct"):
                    trace["gct"] = True
                    gct = self.s.post(cfg["urlGetCredentialType"], json={
                        "username": upn, "isOtherIdpSupported": True, "checkPhones": False, "isRemoteNGCSupported": True,
                        "isCookieBannerShown": False, "isFidoSupported": True, "originalRequest": cfg.get("sCtx"),
                        "flowToken": cfg.get("sFT")}).json()
                    fed = (gct.get("Credentials") or {}).get("FederationRedirectUrl")
                    trace["steps"].append(f"계정 입력→도메인 확인(IfExistsResult={gct.get('IfExistsResult')}, 페더레이션={'예' if fed else '아니오'})")
                    if not fed:
                        return {"result": "no_federation_redirect", "gct": {k: gct.get(k) for k in ("IfExistsResult", "ThrottleStatus")}}
                    props = gct.get("EstsProperties") or {}
                    if props.get("SamlRequest"):
                        # 로그인 페이지 스크립트처럼 SAML 요청을 IdP 주소로 POST
                        trace["steps"].append(f"직접 입력 경로: SAML 요청 POST → {urlparse(fed).netloc}")
                        r = self.s.post(fed, data={"SAMLRequest": props["SamlRequest"], "RelayState": props.get("RelayState", ""),
                                                   "username": upn}, allow_redirects=False)
                    else:
                        r = self.s.get(fed, allow_redirects=False)
                    continue
                return {"result": "stopped", "pgid": pgid, "company": cfg.get("sCompanyDisplayName"),
                        "user": cfg.get("sPOST_Username"), "stsErrorCode": cfg.get("stsErrorCode"),
                        "keys": sorted(k for k in cfg if k.startswith(("url", "s", "i")))[:40]}

            form = first_form(text)
            if form and form["action"]:
                trace["steps"].append(f"자동 전송 폼 → {urlparse(urljoin(r.url, form['action'])).netloc}")
                target = urljoin(r.url, form["action"])
                if form["method"] == "post":
                    r = self.s.post(target, data=form["fields"], allow_redirects=False)
                else:
                    r = self.s.get(target, params=form["fields"], allow_redirects=False)
                continue
            return {"result": "unknown_page", "host": host, "status": r.status_code, "snippet": re.sub(r"\s+", " ", text[:300])}
        return {"result": "too_many_steps"}


SCENARIOS = [
    # (id, 설명, 기대, 실행 함수). 같은 브라우저를 이어 쓰는 시나리오는 FRESH_SESSION 에서 뺀다.
    ("A1", "학교 A 학생, domain_hint 로 바로 IdP", "성공(학교 A)", lambda b: b.sign_in(f"student01@{D1}", domain_hint=D1)),
    ("A2", "학교 B 학생, 앱처럼 계정만 입력(학교 B는 2단계 인증 필요)", "성공(학교 B)", lambda b: b.sign_in(f"student02@{D2}")),
    ("A3", "MS 로그인 화면에 아이디 직접 입력(login_hint 없음)", "성공(학교 A)",
     lambda b: b.sign_in(f"teacher01@{D1}", hint=False)),
    ("B1", "겸임교사 학교 A 로그인", "성공(학교 A)", lambda b: b.sign_in(f"multi01@{D1}")),
    ("B1b", "같은 브라우저로 학교 B", "성공(학교 B), 비밀번호 재입력 없이 2단계 인증만", lambda b: b.sign_in(f"multi01@{D2}")),
    ("B2a", "등록 안 된 Issuer", "거부(AADSTS50107)", lambda b: b.sign_in(f"badissuer01@{D1}")),
    ("B2b", "서명 변조", "거부", lambda b: b.sign_in(f"badsig01@{D1}")),
    ("C1", "Entra 쪽 ImmutableID 없음(organizations 엔드포인트)", "거부", lambda b: b.sign_in(f"nomap01@{D1}")),
    ("C1b", "Entra 쪽 ImmutableID 없음(학교 A 테넌트 지정)", "거부", lambda b: b.sign_in(f"nomap01@{D1}", tenant=tenant_of(D1))),
    ("C7", "IdP 2단계 인증 계정(mfa 플래그)", "성공(학교 A)", lambda b: b.sign_in(f"mfa01@{D1}")),
    ("F0", "교사 로그인", "성공(학교 A)", lambda b: b.sign_in(f"teacher01@{D1}")),
    ("F1", "같은 브라우저, 앱이 prompt=login(재인증) 요구", "관찰", lambda b: b.sign_in(f"teacher01@{D1}", prompt="login")),
    ("R1", "4번: 통합 아이디 → 학교 B(다른 테넌트)", "관찰", lambda b: b.sign_in(f"student02@{DR}")),
    ("R2", "4번: 통합 아이디 → 학교 A(같은 테넌트)", "관찰", lambda b: b.sign_in(f"student01@{DR}")),
    ("R3", "4번: 겸임교사 통합 아이디 → 학교 B 선택", "관찰", lambda b: b.sign_in(f"multi01@{DR}", choose=D2)),
    ("R4", "4번: MS 로그인 화면에 통합 아이디 직접 입력 → 학교 B", "관찰",
     lambda b: b.sign_in(f"student02@{DR}", hint=False)),
    ("P1", "IdP 포털 링크 → Microsoft 365 웹(학교 A)", "성공(학교 A)",
     lambda b: b.portal_link("student01", f"https://www.office.com/?auth=2&login_hint=student01%40{D1}")),
    ("P2", "IdP 포털 링크 → Microsoft 365 웹(학교 B, 2단계 인증)", "성공(학교 B)",
     lambda b: b.portal_link("multi01", f"https://www.office.com/?auth=2&login_hint=multi01%40{D2}")),
    ("I1", "IdP 시작(포털 버튼) → Microsoft 365, 학교 A", "관찰", lambda b: b.idp_initiated("student01", D1, 0)),
    ("I2", "IdP 시작(포털 버튼) → Microsoft 365, 학교 B", "관찰", lambda b: b.idp_initiated("multi01", D2, 0)),
]
FRESH_SESSION = {"A1", "A2", "A3", "B1", "B2a", "B2b", "C1", "C1b", "C7", "F0", "R1", "R2", "R3", "R4", "P1", "P2", "I1", "I2"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--totp-file", required=True)
    ap.add_argument("--admin-token-file")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--out")
    ap.add_argument("--domains", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "idp", "data",
                                                       "domains.json"))
    args = ap.parse_args()
    DOMAINS.update(json.load(open(args.domains, encoding="utf-8")))
    schools = {v["tenantId"]: v.get("schoolName", d) for d, v in DOMAINS.items() if v.get("mode") == "school"}
    password = open(args.password_file, encoding="utf-8").read().strip()
    totp = {uid: parse_qs(urlparse(uri).query)["secret"][0]
            for uid, uri in json.load(open(args.totp_file, encoding="utf-8")).items()}

    results, browser = [], None
    for sid, desc, expect, fn in SCENARIOS:
        if args.only and sid not in args.only:
            continue
        if sid in FRESH_SESSION or browser is None:
            browser = Browser(password, totp)
        started = time.time()
        try:
            out = fn(browser)
        except Exception as e:  # noqa: BLE001
            out = {"result": "exception", "error": f"{type(e).__name__}: {e}"[:300]}
        out.update({"id": sid, "desc": desc, "expect": expect, "seconds": round(time.time() - started, 1)})
        if out.get("tid"):
            out["tenant"] = schools.get(out["tid"], out["tid"])
        results.append(out)
        summary = (out.get("tenant") or out.get("aadsts") or out.get("message") or out.get("pgid") or out.get("url")
                   or out.get("errorDescription", "")[:160])
        print(f"[{sid}] {desc}: {out.get('result')} {summary} {out.get('user') or ''} {out.get('app') or ''} "
              f"(IdP 비밀번호 {'입력' if out.get('idpLogin') else '생략'}, IdP 2단계 {'예' if out.get('idpMfa') else '아니오'})")
        print("      " + " | ".join(out.get("steps", [])))

    if args.admin_token_file:
        token = dict(line.strip().split("=", 1) for line in open(args.admin_token_file) if "=" in line)["ADMIN_TOKEN"]
        entries = requests.get(f"{IDP}/admin/log.json", params={"token": token}, timeout=30).json()["entries"]
        reqs = [e for e in entries if e["event"] == "authn_request"]
        print(f"\n[IdP 기록] 로그인 요청 {len(reqs)}건, 방식: {sorted({e['binding'] for e in reqs})}, "
              f"전달 파라미터: {sorted({k for e in reqs for k in e.get('paramKeys', [])})}, "
              f"ForceAuthn 요청: {sum(1 for e in reqs if e.get('forceAuthn'))}건")
        results.append({"id": "IDP_LOG", "authnRequests": reqs[:50],
                        "responses": [e for e in entries if e["event"] in ("saml_response", "idp_initiated")][:50]})
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
