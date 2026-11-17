"""로그인 종단 시험: Microsoft 로그인 → 테스트 IdP → Microsoft → 토큰 발급까지 브라우저처럼 따라간다.

앱(공개 클라이언트)의 인증 코드 흐름을 흉내 내고, 결과 토큰의 테넌트·사용자를 확인한다.
화면 자동화 없이 HTTP 요청만 쓰며, Microsoft 로그인 페이지의 $Config 값으로 다음 단계를 정한다.

사용: python e2e_signin.py --password-file <IdP 테스트 비밀번호 파일> --totp-file <Entra 인증 앱 비밀값 JSON>
                           [--domains ../idp/data/domains.json] [--admin-token-file <비밀값 파일>]
                           [--only A1 R13 ...] [--out <결과 JSON>]
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
IDP_HOST = "auth.joowon.me"
IDP = f"https://{IDP_HOST}"
# Chrome UA면 장치 SSO 확인 페이지(AADSTS50168)가 끼어들어 Firefox UA를 쓴다.
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0"
D1, D2 = "school1.joowon.me", "school2.joowon.me"
DR = "joowon.me"  # SEN 아이디 도메인(라우팅 전용 테넌트에 페더레이션, SEN의 @senedu.kr 역할)
DOMAINS = {}  # main()에서 domains.json 을 읽어 채운다(테넌트 ID → 학교 이름)


def tenant_of(domain):
    return DOMAINS.get(domain, {}).get("tenantId", "organizations")


TOTP_LAST = {}  # 계정별 마지막으로 쓴 TOTP 구간(같은 코드를 다시 쓰지 않도록 다음 구간까지 기다린다)


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


def load_totp(raw):
    """Entra 인증 앱 비밀값 JSON(학교 계정 UPN → otpauth 주소 또는 base32 비밀값)."""
    out = {}
    for upn, v in json.loads(raw or "{}").items():
        out[upn.lower()] = parse_qs(urlparse(v).query)["secret"][0] if v.startswith("otpauth://") else v
    return out


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
    keys = ("iErrorCode", "sErrorCode", "strServiceExceptionMessage", "sErrTxt", "strMainMessage", "correlationId")
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
        """totp: Entra에 등록한 인증 앱 비밀값(학교 계정 UPN → base32). MFA는 Entra가 수행한다."""
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8"})
        self.password = password
        self.totp = {k.lower(): v for k, v in totp.items()}

    def _entra_mfa(self, cfg, trace):
        """Entra MFA(인증 앱 코드). 로그인 페이지 스크립트처럼 SAS BeginAuth → EndAuth → ProcessAuth 순서로 보낸다."""
        user = (cfg.get("sPOST_Username") or "").lower()
        methods = [p.get("authMethodId") for p in cfg.get("arrUserProofs") or []]
        secret = self.totp.get(user)
        if "PhoneAppOTP" not in methods or not secret:
            trace["steps"].append(f"Entra MFA 요구({user}, 등록 수단 {methods or '없음'})")
            return {"result": "entra_mfa_required", "user": user, "methods": methods}
        headers = {"Content-Type": "application/json; charset=UTF-8", "canary": cfg.get("apiCanary") or "",
                   "hpgrequestid": cfg.get("sessionId") or "", "hpgid": str(cfg.get("hpgid") or ""),
                   "hpgact": str(cfg.get("hpgact") or ""), "client-request-id": cfg.get("correlationId") or ""}
        begin = self.s.post(cfg["urlBeginAuth"], headers=headers, json={
            "AuthMethodId": "PhoneAppOTP", "Method": "BeginAuth", "ctx": cfg.get("sCtx"), "flowToken": cfg.get("sFT")}).json()
        if not begin.get("Success"):
            return {"result": "entra_mfa_error", "stage": "BeginAuth", "value": begin.get("ResultValue")}
        poll_start = int(time.time() * 1000)
        end = {}
        for attempt in range(3):
            code = totp_now(user, secret)
            end = self.s.post(cfg["urlEndAuth"], headers=headers, json={
                "Method": "EndAuth", "SessionId": begin["SessionId"], "FlowToken": begin["FlowToken"], "Ctx": begin["Ctx"],
                "AuthMethodId": "PhoneAppOTP", "AdditionalAuthData": code, "PollCount": attempt + 1}).json()
            if end.get("Success"):
                break
            trace["steps"].append(f"Entra MFA 코드 거부({end.get('ResultValue')}), 다음 코드로 재시도")
        if not end.get("Success"):
            return {"result": "entra_mfa_error", "stage": "EndAuth", "value": end.get("ResultValue")}
        trace["steps"].append(f"Entra MFA(인증 앱 코드, {user})")
        trace["entraMfa"] = True
        return self.s.post(cfg["urlPost"], allow_redirects=False, data={
            "type": "19", "GeneralVerify": "false", "request": end.get("Ctx") or begin["Ctx"],
            "mfaLastPollStart": str(poll_start), "mfaLastPollEnd": str(int(time.time() * 1000)),
            "mfaAuthMethod": "PhoneAppOTP", "otc": code, "login": user,
            "flowToken": end.get("FlowToken") or begin["FlowToken"], "hpgrequestid": cfg.get("sessionId") or "",
            "sacxt": "", "hideSmsInMfaProofs": "false", "canary": cfg.get("canary") or "", "i19": "2000"})

    def sign_in(self, upn, *, domain_hint=None, prompt=None, idp_user=None, tenant="organizations",
                hint=True, pre_login=False, scope="openid profile offline_access", claims=None, keep_tokens=False):
        """pre_login: 앱을 열기 전에 IdP(포털)에 먼저 로그인해 둔 상태를 만든다.
        claims: 클라이언트 기능 선언 등 claims 요청(예: CAE의 cp1). keep_tokens: 결과에 토큰을 담는다."""
        idp_user = idp_user or upn.split("@")[0]
        if pre_login:
            self.s.post(f"{IDP}/login", data={"username": idp_user, "password": self.password}, allow_redirects=False)
        verifier = secrets.token_urlsafe(48)
        params = {
            "client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT, "response_mode": "query",
            "scope": scope, "state": secrets.token_hex(8), "nonce": secrets.token_hex(8),
            "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256",
        }
        if claims:
            params["claims"] = claims
        if hint and upn:
            params["login_hint"] = upn
        if domain_hint:
            params["domain_hint"] = domain_hint
        if prompt:
            params["prompt"] = prompt
        trace = {"steps": [], "idpLogin": False}
        r = self.s.get(f"{AAD}/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}", allow_redirects=False)
        outcome = self._drive(r, upn, idp_user, trace)
        if outcome.get("code"):
            data = {"client_id": CLIENT_ID, "grant_type": "authorization_code", "code": outcome["code"],
                    "redirect_uri": REDIRECT, "code_verifier": verifier, "scope": scope}
            if claims:
                data["claims"] = claims
            tok = self.s.post(f"{AAD}/{tenant}/oauth2/v2.0/token", data=data).json()
            if "id_token" in tok:
                c = jwt_claims(tok["id_token"])
                outcome = {"result": "success", "tid": c.get("tid"), "user": c.get("preferred_username"), "name": c.get("name")}
                if keep_tokens:
                    outcome["tokens"] = {k: tok.get(k) for k in ("access_token", "refresh_token", "expires_in")}
            else:
                outcome = {"result": "token_error", "error": tok.get("error"),
                           "errorDescription": (tok.get("error_description") or "")[:200]}
        outcome["steps"] = trace["steps"]
        outcome["idpLogin"] = trace["idpLogin"]
        outcome["entraMfa"] = bool(trace.get("entraMfa"))
        if trace.get("company"):
            outcome["company"] = trace["company"]
        return outcome

    def landing(self, idp_user, url=None):
        """앱 요청 없이 SEN에 로그인한 뒤(루트 1) SEN 포털의 'Microsoft 365로 이동하기'를 따라간다.
        url을 주면 포털 단추 대신 그 링크를 따라간다."""
        self.s.post(f"{IDP}/login", data={"username": idp_user, "password": self.password}, allow_redirects=False)
        if not url:
            page = self.s.get(f"{IDP}/", allow_redirects=False)
            m = re.search(r'id="goM365" href="([^"]+)"', page.text)
            if not m:
                return {"result": "no_landing", "status": page.status_code, "steps": [], "idpLogin": True, "entraMfa": False}
            url = html.unescape(m.group(1))
        trace = {"steps": [f"SEN 로그인 → {urlparse(url).netloc}"], "idpLogin": True}
        out = self._drive(self.s.get(url, allow_redirects=False), None, idp_user, trace)
        out["steps"] = trace["steps"]
        out["idpLogin"], out["entraMfa"] = True, bool(trace.get("entraMfa"))
        return out

    def _drive(self, r, upn, idp_user, trace):
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
                if lp.netloc == IDP_HOST and lp.path.rstrip("/") == "/login":
                    # SEN 로그인 화면(IdP가 직접 보냄): 화면을 받아 온 뒤 화면의 폼처럼 /login 으로 전송
                    k = parse_qs(lp.query).get("k", [None])[0]
                    page = self.s.get(loc)
                    if page.status_code != 200 or 'id="loginForm"' not in page.text:
                        return {"result": "login_ui_error", "status": page.status_code}
                    trace["idpLogin"] = True
                    trace["steps"].append(f"IdP 로그인({idp_user})")
                    data = {"username": idp_user, "password": self.password}
                    if k:
                        data["k"] = k
                    r = self.s.post(f"{IDP}/login", data=data, allow_redirects=False)
                    continue
                r = self.s.get(loc, allow_redirects=False)
                continue

            text = r.text
            if host == IDP_HOST:
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
                if pgid == "ConvergedTFA":
                    nxt = self._entra_mfa(cfg, trace)
                    if isinstance(nxt, dict):
                        return nxt
                    r = nxt
                    continue
                if pgid == "ConvergedProofUpRedirect" and cfg.get("fIsRegistrationCampaignInterrupt") \
                        and cfg.get("urlSkipMfaRegistration"):
                    # 등록 캠페인: MFA를 마친 뒤 패스키나 Microsoft Authenticator 등록을 권하는 화면('나중에' 가능)
                    trace["steps"].append("등록 캠페인(패스키·Authenticator 등록 권유): 나중에")
                    r = self.s.post(cfg["urlSkipMfaRegistration"], data={"flowtoken": cfg.get("sFT")}, allow_redirects=False)
                    continue
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
    ("A2", "학교 B 학생, 앱처럼 계정만 입력", "성공(학교 B)", lambda b: b.sign_in(f"student02@{D2}")),
    ("A3", "MS 로그인 화면에 아이디 직접 입력(login_hint 없음)", "성공(학교 A)",
     lambda b: b.sign_in(f"teacher01@{D1}", hint=False)),
    ("B2a", "등록 안 된 Issuer", "거부(AADSTS50107)", lambda b: b.sign_in(f"badissuer01@{D1}")),
    ("B2b", "서명 변조", "거부", lambda b: b.sign_in(f"badsig01@{D1}")),
    ("C1", "Entra 쪽 ImmutableID 없음(organizations 엔드포인트)", "거부", lambda b: b.sign_in(f"nomap01@{D1}")),
    ("C1b", "Entra 쪽 ImmutableID 없음(학교 A 테넌트 지정)", "거부", lambda b: b.sign_in(f"nomap01@{D1}", tenant=tenant_of(D1))),
    ("C7", "학교 A의 MFA 필수 계정(Entra 사용자별 MFA)", "성공(학교 A), Entra MFA", lambda b: b.sign_in(f"mfa01@{D1}")),
    ("C8", "학교 B의 MFA 필수 계정(Entra 사용자별 MFA)", "성공(학교 B), Entra MFA", lambda b: b.sign_in(f"mfa02@{D2}")),
    ("F0", "교사 로그인", "성공(학교 A)", lambda b: b.sign_in(f"teacher01@{D1}")),
    ("F1", "같은 브라우저, 앱이 prompt=login(재인증) 요구", "관찰", lambda b: b.sign_in(f"teacher01@{D1}", prompt="login")),
    ("P1", "SEN 포털 'Microsoft 365로 이동하기'(학교 A)", "성공(학교 A)", lambda b: b.landing("student01")),
    ("P2", "SEN 포털 'Microsoft 365로 이동하기'(학교 B)", "성공(학교 B)", lambda b: b.landing("student02")),
    # --- 루트 2: SEN 아이디(라우팅 전용 테넌트에 페더레이션한 joowon.me) ---
    ("R5", "학교 B 테넌트를 지정한 앱(SharePoint 등)에 SEN 아이디", "성공(학교 B)",
     lambda b: b.sign_in(f"student02@{DR}", tenant=tenant_of(D2))),
    ("R6", "라우팅 전용 테넌트를 지정한 앱에 학교 B 학생 SEN 아이디", "거부(AADSTS50020)",
     lambda b: b.sign_in(f"student02@{DR}", tenant=tenant_of(DR))),
    ("R7", "공용 PC — student01이 IdP에 로그인된 브라우저에서 student02 SEN 아이디 입력", "student02로 로그인",
     lambda b: shared_pc(b)),
    ("R8", "SEN 아이디 로그인(무음 SSO 준비)", "성공(학교 B)", lambda b: b.sign_in(f"student02@{DR}")),
    ("R8b", "무음 SSO(prompt=none) + 학교 계정 힌트", "성공(학교 B)",
     lambda b: b.sign_in(f"student02@{D2}", prompt="none")),
    ("R8c", "무음 SSO(prompt=none) + 힌트 없음", "성공(학교 B)",
     lambda b: b.sign_in(None, prompt="none", idp_user="student02")),
    ("R8a", "무음 SSO(prompt=none) + SEN 아이디 힌트", "AADSTS50058(힌트와 로그인된 계정이 다름)",
     lambda b: b.sign_in(f"student02@{DR}", prompt="none")),
    ("R9", "포털 링크용 domain_hint=SEN 아이디 도메인(IdP에 이미 로그인)", "성공(학교 B), IdP 비밀번호 생략",
     lambda b: b.sign_in(None, domain_hint=DR, idp_user="student02", pre_login=True)),
    ("R10", "Microsoft 365 웹 링크, login_hint=SEN 아이디(IdP에 이미 로그인)", "성공(학교 B)",
     lambda b: b.landing("student02", f"https://m365.cloud.microsoft/login?es=Click&login_hint=student02%40{DR}")),
    ("R11", "잘못된 구현: IdP가 라우팅 도메인 Issuer로 응답(teacher01 SEN 아이디 직접 입력)", "거부(AADSTS90072)",
     lambda b: b.sign_in(f"teacher01@{DR}", hint=False)),
    ("R12", "MFA 필수 계정의 SEN 아이디 → 학교 B", "성공(학교 B), Entra MFA",
     lambda b: b.sign_in(f"mfa02@{DR}")),
    ("R13", "MS 로그인 화면에 SEN 아이디 직접 입력(student01@joowon.me) → 학교 A", "성공(학교 A)",
     lambda b: b.sign_in(f"student01@{DR}", hint=False)),
    ("R14", "MS 로그인 화면에 SEN 아이디 직접 입력(student02@joowon.me) → 학교 B(다른 테넌트)", "성공(학교 B)",
     lambda b: b.sign_in(f"student02@{DR}", hint=False)),
]
FRESH_SESSION = {"A1", "A2", "A3", "B2a", "B2b", "C1", "C1b", "C7", "C8", "F0", "P1", "P2",
                 "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R14"}


def shared_pc(b):
    """공용 PC: 앞 학생(student01)의 IdP 세션이 남은 브라우저에서 다음 학생이 자기 SEN 아이디를 입력."""
    first = b.sign_in(f"student01@{D1}")
    out = b.sign_in(f"student02@{DR}")
    out["steps"] = [f"앞 사용자 로그인: {first.get('user')}"] + out.get("steps", [])
    return out


def ok_user(user, mfa=False):
    """성공 + 기대한 학교 계정 + Entra MFA 여부(MFA 필수 계정만 True)."""
    return lambda o: (o.get("result") == "success" and (o.get("user") or "").lower() == user.lower()
                      and bool(o.get("entraMfa")) == mfa)


def ok_error(code=None):
    return lambda o: o.get("result") in ("aad_error", "error", "token_error") and (
        code is None or code in json.dumps(o, ensure_ascii=False))


# 자동 판정. 없으면 '관찰'
VERDICT = {
    "A1": ok_user(f"student01@{D1}"), "A2": ok_user(f"student02@{D2}"), "A3": ok_user(f"teacher01@{D1}"),
    "B2a": ok_error("AADSTS50107"), "B2b": ok_error("AADSTS500069"), "C1": ok_error(), "C1b": ok_error(),
    "C7": ok_user(f"mfa01@{D1}", mfa=True), "C8": ok_user(f"mfa02@{D2}", mfa=True),
    "F0": ok_user(f"teacher01@{D1}"), "F1": ok_user(f"teacher01@{D1}"),
    "P1": ok_user(f"student01@{D1}"), "P2": ok_user(f"student02@{D2}"),
    "R5": ok_user(f"student02@{D2}"), "R6": ok_error("AADSTS50020"), "R7": ok_user(f"student02@{D2}"),
    "R8": ok_user(f"student02@{D2}"), "R8b": ok_user(f"student02@{D2}"), "R8c": ok_user(f"student02@{D2}"),
    "R8a": ok_error("AADSTS50058"),
    "R9": ok_user(f"student02@{D2}"), "R10": ok_user(f"student02@{D2}"), "R11": ok_error("AADSTS90072"),
    "R12": ok_user(f"mfa02@{D2}", mfa=True), "R13": ok_user(f"student01@{D1}"), "R14": ok_user(f"student02@{D2}"),
}


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
    totp = load_totp(open(args.totp_file, encoding="utf-8").read())

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
        # 판정은 시나리오 설명(expect 등)을 붙이기 전에 한다. 붙인 뒤에 하면 기대 오류 코드가 설명 문구에서 맞아 버린다.
        check = VERDICT.get(sid)
        verdict = "관찰" if check is None else ("통과" if check(out) else "실패")
        out.update({"id": sid, "desc": desc, "expect": expect, "seconds": round(time.time() - started, 1),
                    "verdict": verdict})
        if out.get("tid"):
            out["tenant"] = schools.get(out["tid"], out["tid"])
        results.append(out)
        summary = (out.get("tenant") or out.get("aadsts") or out.get("message") or out.get("pgid") or out.get("url")
                   or out.get("errorDescription", "")[:160])
        print(f"[{sid}] ({out['verdict']}) {desc}: {out.get('result')} {summary} {out.get('user') or ''} {out.get('app') or ''} "
              f"(IdP 비밀번호 {'입력' if out.get('idpLogin') else '생략'}, Entra MFA {'예' if out.get('entraMfa') else '아니오'})")
        print("      " + " | ".join(out.get("steps", [])))

    if args.admin_token_file:
        token = dict(line.strip().split("=", 1) for line in open(args.admin_token_file) if "=" in line)["ADMIN_TOKEN"]
        entries = requests.get(f"{IDP}/admin/log.json", params={"token": token}, timeout=30).json()["entries"]
        reqs = [e for e in entries if e["event"] == "authn_request"]
        print(f"\n[IdP 기록] 로그인 요청 {len(reqs)}건, 방식: {sorted({e['binding'] for e in reqs})}, "
              f"전달 파라미터: {sorted({k for e in reqs for k in e.get('paramKeys', [])})}, "
              f"ForceAuthn 요청: {sum(1 for e in reqs if e.get('forceAuthn'))}건")
        results.append({"id": "IDP_LOG", "authnRequests": reqs[:50],
                        "responses": [e for e in entries if e["event"] == "saml_response"][:50]})
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
