"""시연 영상 녹화: 헤드리스 Chromium으로 SSO·거부·④ 라우팅·보안 시나리오를 녹화해 MP4(H.264)와 포스터를 만든다.

- 브라우저: Playwright 내장 Chromium. 설치된 Chrome은 회사 정책(SSO 확장)이 다른 계정을 끼워 넣을 수 있어 쓰지 않는다.
- 시나리오마다 새 프로필(쿠키 없음), 1280×720. 영상 앞뒤에 시나리오 설명과 실행 결과 화면을 넣는다.
  결과 화면은 실제 실행 결과(받은 토큰의 계정·학교, Microsoft 오류 코드)로 채운다.
- 시험용 앱(Microsoft Azure CLI 공개 클라이언트)의 마지막 주소(http://localhost:8400)는 가로채서
  받은 토큰의 계정·학교를 보여 주는 결과 화면으로 바꾼다(토큰 교환은 이 스크립트가 PKCE로 한다).
- 관리 포털 시나리오는 --portal-profile(미리 로그인해 둔 전용 프로필)을 쓰고,
  --mask-file 의 규칙으로 화면 글자(테넌트 ID, 관리자 계정, 접속 IP 등)를 가린다.

사용:
  python record_demos.py --list
  python record_demos.py --password-file <파일> --totp-file <JSON> --out-dir <폴더> [--only A1 R1 ...]
         [--proxy socks5://127.0.0.1:9050] [--portal-profile <폴더> --mask-file <JSON>]
  비밀번호·TOTP는 환경 변수 DEMO_PASSWORD / DEMO_TOTP_JSON 으로도 받는다.
  S4(관리자 침해 확인)는 graph_token.py 토큰 캐시를 쓰고, GRAPH_EXTRA_SCOPES 에 IdentityRiskyUser.ReadWrite.All 이 필요하다.
"""
import argparse
import html
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, quote, urlencode, urlparse

import requests
from playwright.sync_api import sync_playwright

from e2e_signin import AAD, CLIENT_ID, D1, D2, DR, DROOT, IDP, IDP_HOST, REDIRECT, b64url, jwt_claims, totp_now

LOGIN_HOST = "login.joowon.me"
MS_HOSTS = ("login.microsoftonline.com", "login.microsoft.com", "login.windows.net")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/157.0.0.0 Safari/537.36")
W, H = 1280, 720
KST = timezone(timedelta(hours=9))
DEBUG = bool(os.environ.get("DEMO_DEBUG"))
BASE_SCOPE = "openid profile offline_access"
GRAPH_SCOPE = "https://graph.microsoft.com/.default openid profile offline_access"
CAE_CLAIMS = json.dumps({"access_token": {"xms_cc": {"values": ["cp1"]}}})
FONT = "-apple-system, BlinkMacSystemFont, 'Apple SD Gothic Neo', 'Malgun Gothic', 'NanumGothic', 'Noto Sans KR', sans-serif"
GROUPS = {
    "sso": "기본 SSO",
    "reject": "위조·오류 거부",
    "route": "④ 통합 아이디(라우팅)",
    "attack": "보안 데모: 위험 로그인 탐지·차단",
    "portal": "보안 데모: 관리 포털 화면",
}
APPS = {  # 이름: (표시 이름, 주소, 앱 화면 판별 호스트, 화면이 다 그려질 때까지 기다리는 초)
    "outlook": ("Outlook 웹", "https://outlook.office.com/mail/", ("outlook.office.com", "outlook.cloud.microsoft"), 14),
    "teams": ("Teams 웹", "https://teams.microsoft.com/v2/", ("teams.microsoft.com", "teams.cloud.microsoft"), 25),
    "m365": ("Microsoft 365 웹", "https://www.office.com/?auth=2", ("m365.cloud.microsoft", "www.microsoft365.com"), 12),
    "myapps": ("내 앱(My Apps)", "https://myapps.microsoft.com/", ("myapps.microsoft.com", "myapplications.microsoft.com"), 10),
}
ACCOUNT_BUTTONS = ["#O365_MainLink_Me", "#mectrl_main_trigger", "#idna-me-control-avatar-trigger",
                   "[data-tid='me-control-avatar-trigger']", "button[aria-label*='계정 관리자']",
                   "button[aria-label*='Account manager']", "button[aria-label*='프로필']"]
STS_TEXT = {
    "50107": "등록되지 않은 Issuer(페더레이션 영역 없음)",
    "500069": "SAML 응답 서명 검증 실패",
    "90019": "ImmutableID로 사용자를 찾지 못함",
    "90072": "이 테넌트에 없는 계정",
    "5000820": "Federated Token Validation: Issuer 도메인과 사용자 도메인 불일치",
    "50020": "이 테넌트에 없는 계정(다른 테넌트 사용자)",
    "50058": "로그인된 계정과 힌트가 다름(무음 로그인 불가)",
    "53003": "조건부 액세스 정책으로 차단",
    "53004": "위험 세션이라 MFA 등록이 막혀 차단",
    "530032": "사용자 위험으로 차단",
}
CFG_JS = """() => { const c = window.$Config; if (!c) return null;
  return {pgid: c.pgid || c.sPageId || null, err: c.sErrorCode || (c.iErrorCode ? String(c.iErrorCode) : null),
          sts: c.stsErrorCode ? String(c.stsErrorCode) : null,
          msg: c.strServiceExceptionMessage || c.sErrTxt || null, user: c.sPOST_Username || null}; }"""
ERROR_PAGES = {"ConvergedError", "ConvergedConditionalAccess", "ConvergedProofUpRedirect", "ConvergedTFA"}
TRANSIENT = {"50168", "399218"}  # 기기 SSO 확인, 도메인 확인 대화상자
SIGNIN_PAGES = {"ConvergedSignIn", "KmsiInterrupt", "CmsiInterrupt"}  # 이전 무음 시도의 오류 코드가 남아 있어도 정상 화면
MASK_JS = """(rules) => {
  const res = rules.map(([p, f, r]) => [new RegExp(p, f), r]);
  const fix = (n) => { let t = n.nodeValue; if (!t) return; const o = t; for (const [re, r] of res) t = t.replace(re, r);
                       if (t !== o) n.nodeValue = t; };
  const walk = (root) => { const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT); let n; while ((n = w.nextNode())) fix(n); };
  const start = () => { walk(document.documentElement);
    new MutationObserver((ms) => { for (const m of ms) { if (m.type === 'characterData') fix(m.target);
      else m.addedNodes.forEach((n) => n.nodeType === 3 ? fix(n) : (n.nodeType === 1 && walk(n))); } })
      .observe(document.documentElement, {subtree: true, childList: true, characterData: true}); };
  if (document.documentElement) start(); else document.addEventListener('DOMContentLoaded', start);
}"""


def esc(s):
    return html.escape(str(s))


def page_html(body, bg="#ffffff", fg="#1b1f24"):
    return (f"<!doctype html><html lang='ko'><meta charset='utf-8'><style>*{{box-sizing:border-box}}"
            f"body{{margin:0;width:{W}px;height:{H}px;overflow:hidden;font-family:{FONT};background:{bg};color:{fg}}}"
            ".wrap{padding:64px 80px;height:100%;display:flex;flex-direction:column}"
            ".badge{display:inline-block;padding:6px 14px;border-radius:999px;background:#2563eb;color:#fff;font-size:20px;font-weight:600}"
            ".grp{margin-left:12px;font-size:20px;opacity:.75}"
            "h1{font-size:44px;line-height:1.25;margin:28px 0 24px}"
            ".row{font-size:24px;line-height:1.6;margin:4px 0}.k{opacity:.65;margin-right:12px}"
            ".foot{margin-top:auto;font-size:18px;opacity:.55}"
            ".ok{color:#16a34a}.bad{color:#dc2626}.warn{color:#d97706}"
            "table{border-collapse:collapse;font-size:20px;width:100%}td,th{padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:left}"
            f"</style><body>{body}</body></html>")


def ffmpeg_exe():
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except ImportError:
        exe = shutil.which("ffmpeg")
        if not exe:
            raise SystemExit("ffmpeg 필요: pip install imageio-ffmpeg")
        return exe


def convert(src, mp4, jpg, marks, timelapse=None):
    """녹화(WebM)에서 설명 화면 시작~끝 구간을 잘라 H.264 MP4로 바꾸고 포스터 이미지를 만든다."""
    ff = ffmpeg_exe()
    start = max(0.0, marks.get("start", 0.0) - 0.05)
    end = marks.get("end")
    cuts = [start]
    if timelapse:
        cuts += [timelapse[0], timelapse[1]]
    segs = []
    bounds = cuts + [end]
    for i in range(len(bounds) - 1):
        a, b = bounds[i], bounds[i + 1]
        speed = timelapse[2] if timelapse and i == 1 else 1
        end_part = f":end={b:.3f}" if b is not None else ""
        segs.append(f"[0:v]trim=start={a:.3f}{end_part},setpts=(PTS-STARTPTS)/{speed}[s{i}]")
    fc = ";".join(segs) + ";" + "".join(f"[s{i}]" for i in range(len(segs))) + f"concat=n={len(segs)}:v=1:a=0[v]"
    subprocess.run([ff, "-y", "-loglevel", "error", "-i", src, "-filter_complex", fc, "-map", "[v]", "-r", "25",
                    "-c:v", "libx264", "-preset", "slow", "-crf", "24", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
                    mp4], check=True)
    key = marks.get("key", (end or start + 3) - 4)
    subprocess.run([ff, "-y", "-loglevel", "error", "-ss", f"{max(key, start):.2f}", "-i", src, "-frames:v", "1",
                    "-q:v", "4", jpg], check=True)
    out = subprocess.run([ff, "-i", mp4], capture_output=True, text=True).stderr
    m = re.search(r"Duration: (\d+):(\d+):([\d.]+)", out)
    return round(int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3)), 1) if m else None


class Run:
    """시나리오 한 번 실행(브라우저 컨텍스트 하나, 영상 하나)."""

    def __init__(self, rec, sc, ctx, page):
        self.rec, self.sc, self.ctx, self.page = rec, sc, ctx, page
        self.t0 = time.monotonic()
        self.marks, self.steps, self.pending, self.results = {}, [], {}, {}
        self.trace, self.outcomes, self.timelapse, self.via = {}, [], None, None
        self.result_lines, self.matched = [], None

    # ---- 기록
    def mark(self, name):
        self.marks[name] = time.monotonic() - self.t0

    def step(self, text):
        self.steps.append(text)

    # ---- 설명 화면
    def intro(self):
        sc = self.sc
        rows = "".join(f"<div class='row'><span class='k'>{esc(k)}</span>{esc(v)}</div>" for k, v in sc.get("info", []))
        if self.via:
            rows += f"<div class='row'><span class='k'>접속 경로</span>{esc(self.via)}</div>"
        rows += f"<div class='row'><span class='k'>확인할 것</span>{esc(sc['check'])}</div>"
        body = (f"<div class='wrap'><div><span class='badge'>{esc(sc['id'])}</span><span class='grp'>{esc(GROUPS[sc['group']])}</span></div>"
                f"<h1>{esc(sc['title'])}</h1>{rows}"
                f"<div class='foot'>학교별 Microsoft 365 SSO PoC · 테스트 환경(joowon.me, 데모 테넌트) · 헤드리스 Chromium 녹화</div></div>")
        self.page.set_content(page_html(body, bg="#0f172a", fg="#f8fafc"))
        self.mark("start")
        self.page.wait_for_timeout(3200)

    def end(self):
        sc = self.sc
        lines = "".join(f"<div class='row'>{line}</div>" for line in self.result_lines)
        verdict = ("<span class='ok'>예상과 일치</span>" if self.matched else "<span class='bad'>예상과 다름</span>"
                   if self.matched is False else "관찰")
        body = (f"<div class='wrap'><div><span class='badge'>{esc(sc['id'])} 결과</span><span class='grp'>{esc(sc['title'])}</span></div>"
                f"<h1>실행 결과</h1>{lines}"
                f"<div class='row' style='margin-top:18px'><span class='k'>예상</span>{esc(sc['expect'])} · {verdict}</div>"
                f"<div class='foot'>녹화 {datetime.now(KST):%Y-%m-%d %H:%M} KST · 결과는 실제 토큰·Microsoft 응답에서 읽은 값</div></div>")
        self.page.set_content(page_html(body, bg="#0f172a", fg="#f8fafc"))
        self.page.wait_for_timeout(4200)
        self.mark("end")

    # ---- 시험용 앱(Azure CLI 공개 클라이언트) 로그인
    def authorize(self, upn=None, *, domain_hint=None, prompt=None, tenant="organizations", hint=True,
                  scope=BASE_SCOPE, claims=None, keep=False):
        verifier, state = secrets.token_urlsafe(48), secrets.token_hex(8)
        params = {"client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT, "response_mode": "query",
                  "scope": scope, "state": state, "nonce": secrets.token_hex(8),
                  "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
        if hint and upn:
            params["login_hint"] = upn
        if domain_hint:
            params["domain_hint"] = domain_hint
        if prompt:
            params["prompt"] = prompt
        if claims:
            params["claims"] = claims
        self.pending[state] = {"verifier": verifier, "tenant": tenant, "scope": scope, "claims": claims, "keep": keep}
        return f"{AAD}/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}", state

    def complete(self, query):
        """시험용 앱의 리디렉션(http://localhost:8400/?code=…)을 받아 토큰을 교환하고 결과 화면 HTML을 돌려준다."""
        q = parse_qs(query)
        state = q.get("state", [""])[0]
        p = self.pending.get(state, {})
        if "code" in q and p:
            data = {"client_id": CLIENT_ID, "grant_type": "authorization_code", "code": q["code"][0],
                    "redirect_uri": REDIRECT, "code_verifier": p["verifier"], "scope": p["scope"]}
            if p.get("claims"):
                data["claims"] = p["claims"]
            try:
                tok = requests.post(f"{AAD}/{p['tenant']}/oauth2/v2.0/token", data=data, headers={"User-Agent": UA},
                                    proxies=self.rec.proxies, timeout=40).json()
            except Exception as e:  # noqa: BLE001
                tok = {"error": "token_request_failed", "error_description": f"{type(e).__name__}"}
            if "id_token" in tok:
                c = jwt_claims(tok["id_token"])
                res = {"result": "success", "user": c.get("preferred_username"), "tid": c.get("tid"),
                       "school": self.rec.school_of(c.get("tid")), "name": c.get("name")}
                if p.get("keep"):
                    res["tokens"] = {k: tok.get(k) for k in ("access_token", "refresh_token")}
            else:
                res = {"result": "error", "error": tok.get("error"), "desc": (tok.get("error_description") or "")}
        else:
            res = {"result": "error", "error": q.get("error", [""])[0], "desc": q.get("error_description", [""])[0]}
        if res["result"] == "error":
            m = re.search(r"AADSTS(\d+)", res.get("desc", ""))
            res["code"] = m.group(1) if m else None
            res["desc"] = res.get("desc", "").split("\r\n")[0].split("\n")[0][:220]
        res.update({k: self.trace.get(k) for k in ("password", "mfa", "chose")})
        self.results[state] = res
        return self.result_page(res)

    def result_page(self, res):
        if res["result"] == "success":
            head = "<div class='row ok' style='font-size:30px;font-weight:700'>✅ 로그인 성공</div>"
            rows = [("로그인한 계정", res.get("user")), ("토큰을 발급한 테넌트", res.get("school")),
                    ("이름", res.get("name"))]
        else:
            head = "<div class='row bad' style='font-size:30px;font-weight:700'>⛔ 로그인 실패</div>"
            rows = [("오류", f"AADSTS{res.get('code')} {STS_TEXT.get(res.get('code') or '', '')}" if res.get("code")
                     else res.get("error")), ("Microsoft 응답", res.get("desc"))]
        rows += [("SEN 비밀번호 입력", "예" if res.get("password") else "아니오(SEN 세션 사용)"),
                 ("SEN 2단계 인증", "예" if res.get("mfa") else "아니오")]
        if res.get("chose"):
            rows.append(("SEN 학교 선택", res["chose"]))
        body = ("<div class='wrap' style='padding:56px 80px'><div style='font-size:20px;opacity:.6'>시험용 앱 · Microsoft 공개 클라이언트</div>"
                "<h1 style='margin:12px 0 28px'>앱 로그인 결과</h1>" + head +
                "<table style='margin-top:20px'>" + "".join(f"<tr><th style='width:300px'>{esc(k)}</th><td>{esc(v)}</td></tr>"
                                                            for k, v in rows if v) +
                "</table><div class='foot'>앱이 받은 ID 토큰(preferred_username, tid)과 Microsoft 응답을 그대로 표시</div></div>")
        return page_html(body)

    def cli(self, upn=None, *, idp_user=None, typed=False, choose=None, label=None, **kw):
        url, state = self.authorize(upn, hint=not typed, **kw)
        opts = ", ".join(f"{k}={v}" for k, v in kw.items() if k in ("domain_hint", "prompt") and v)
        self.step(label or f"앱 로그인 시작: {upn or '(힌트 없음)'}{' 직접 입력' if typed else ''}{' · ' + opts if opts else ''}")
        self.new_trace()  # 무음 로그인은 goto 직후 바로 결과가 오므로 미리 초기화
        self.page.goto(url, wait_until="commit")
        out = self.drive(typed=upn if typed else None, idp_user=idp_user or (upn or "").split("@")[0], choose=choose,
                         state=state, account=upn)
        self.outcomes.append(out)
        return out

    # ---- 사람이 하는 순서대로 화면 진행
    def new_trace(self):
        self.trace = {"password": False, "mfa": False, "chose": None}

    def drive(self, *, typed=None, idp_user=None, choose=None, state=None, app=None, account=None, timeout=150):
        page, tr = self.page, self.trace
        seen_login, typed_done, mfa_tries, done_pages, last_url = False, False, 0, set(), None
        deadline = time.time() + timeout
        while time.time() < deadline:
            page.wait_for_timeout(600)
            try:
                page.wait_for_load_state("domcontentloaded", timeout=10000)
                url = page.url
            except Exception:  # noqa: BLE001  화면 전환 중
                continue
            host, path = urlparse(url).netloc, urlparse(url).path
            if DEBUG and url != last_url:
                last_url = url
                print(f"  · {time.monotonic() - self.t0:5.1f}s {host}{path[:60]}", flush=True)
            if url.startswith(REDIRECT):
                if state in self.results:
                    self.mark("key")
                    page.wait_for_timeout(3500)
                    return dict(self.results[state])
                continue
            if app and seen_login and any(h in host for h in APPS[app][2]):
                page.wait_for_timeout(APPS[app][3] * 1000)
                self.mark("key")
                self.step(f"{APPS[app][0]} 화면 진입")
                shown = None
                for sel in ACCOUNT_BUTTONS:
                    loc = page.locator(sel)
                    try:
                        if loc.count() and loc.first.is_visible():
                            loc.first.click()
                            shown = sel
                            break
                    except Exception:  # noqa: BLE001
                        pass
                if not shown:
                    page.mouse.click(W - 30, 24)
                page.wait_for_timeout(4500)
                text = page.locator("body").inner_text(timeout=5000) if page.locator("body").count() else ""
                return {"result": "app", "app": app, "accountShown": bool(account and account.lower() in text.lower()),
                        "password": tr["password"], "mfa": tr["mfa"], "chose": tr["chose"]}
            if host in MS_HOSTS:
                seen_login = True
                try:
                    cfg = page.evaluate(CFG_JS)
                except Exception:  # noqa: BLE001
                    cfg = None
                pgid = (cfg or {}).get("pgid")
                msg = (cfg or {}).get("msg") or ""
                if pgid == "KmsiInterrupt" and ("kmsi", url) not in done_pages:
                    done_pages.add(("kmsi", url))
                    page.wait_for_timeout(900)
                    self._click(["#idSIButton9", "button:has-text('예')", "input[value='예']"])
                    self.step("로그인 상태 유지: 예")
                    continue
                if pgid == "CmsiInterrupt" and ("cmsi", url) not in done_pages:
                    done_pages.add(("cmsi", url))
                    page.wait_for_timeout(1500)
                    self._click(["#idSIButton9", "button:has-text('계속')", "input[type=submit]", "button[type=submit]"])
                    self.step("도메인 확인 대화상자: 계속")
                    continue
                if pgid in ("KmsiInterrupt", "CmsiInterrupt"):
                    continue
                code = (cfg or {}).get("sts") or (re.search(r"AADSTS(\d+)", msg).group(1) if "AADSTS" in msg else None)
                if code in TRANSIENT:
                    continue  # 기기 SSO 확인 같은 중간 화면: 페이지 스크립트가 알아서 다음으로 넘어감
                box = page.locator("input[name=loginfmt]")
                try:
                    box_visible = bool(box.count() and box.first.is_visible())
                except Exception:  # noqa: BLE001
                    box_visible = False
                if typed and not typed_done and box_visible:
                    box.first.click()
                    box.first.fill("")
                    box.first.press_sequentially(typed, delay=55)
                    page.wait_for_timeout(500)
                    self.step(f"Microsoft 로그인 화면에 {typed} 입력")
                    self._click(["#idSIButton9", "input[type=submit]", "button[type=submit]"])
                    typed_done = True
                    continue
                if box_visible and not typed and ("next", url) not in done_pages:
                    try:
                        prefilled = box.first.input_value()
                    except Exception:  # noqa: BLE001
                        prefilled = ""
                    if prefilled:
                        # 앱이 다시 로그인하라고 요구(prompt=login)하면 Microsoft가 아이디를 채운 화면을 보여 준다
                        done_pages.add(("next", url))
                        page.wait_for_timeout(1200)
                        self.step(f"Microsoft 로그인 화면(아이디 {prefilled} 미리 채워짐): 다음")
                        self._click(["#idSIButton9", "input[type=submit]", "button[type=submit]"])
                        continue
                if cfg and (pgid in ERROR_PAGES or (code and not box_visible and pgid not in SIGNIN_PAGES)):
                    page.wait_for_timeout(2500)
                    if page.url != url:
                        continue  # 오류 코드를 담은 중간 화면(앱이 처리)이 다음 화면으로 넘어감
                    code = code or (cfg.get("err") if pgid in ERROR_PAGES else None)
                    self.mark("key")
                    if DEBUG:
                        print(f"  · 오류 화면 pgid={pgid} code={code}", flush=True)
                    self.step(f"Microsoft 차단·오류 화면(AADSTS{code})")
                    page.wait_for_timeout(4500)
                    return {"result": "blocked", "code": code, "pgid": pgid, "desc": msg.split("\n")[0][:220],
                            "password": tr["password"], "mfa": tr["mfa"], "chose": tr["chose"]}
                if account and pgid not in ("KmsiInterrupt", "CmsiInterrupt"):
                    heading = page.get_by_role("heading", name=re.compile("계정 선택|Pick an account"))
                    tile = page.locator(f"[data-test-id='{account}'], div[role='button']:has-text('{account}')")
                    try:
                        if heading.count() and tile.count() and tile.first.is_visible():
                            page.wait_for_timeout(800)
                            tile.first.click()
                            self.step(f"계정 선택: {account}")
                            continue
                    except Exception:  # noqa: BLE001
                        pass
            elif host == LOGIN_HOST:
                seen_login = True
                pw_box = page.locator("#password")
                try:
                    ready = pw_box.count() and pw_box.first.is_visible() and not pw_box.first.input_value()
                except Exception:  # noqa: BLE001
                    ready = False
                if ready:
                    page.wait_for_timeout(700)
                    user_box = page.locator("#username")
                    prefilled = user_box.input_value()
                    if not prefilled:
                        user_box.click()
                        user_box.press_sequentially(idp_user, delay=55)
                    pw_box.first.click()
                    pw_box.first.press_sequentially(self.rec.password, delay=40)
                    page.wait_for_timeout(400)
                    page.locator("button[type=submit]").first.click()
                    tr["password"] = True
                    self.step(f"SEN 로그인 화면: {'미리 채워진 ' + prefilled if prefilled else idp_user + ' 입력'} + 비밀번호")
                    page.wait_for_timeout(1500)
                    continue
            elif host == IDP_HOST:
                seen_login = True
                if path.startswith("/portal"):
                    continue  # 포털 링크를 누른 뒤 다음 화면으로 넘어가는 중
                if page.locator("button[name=domain]").count():
                    pick = choose or page.locator("button[name=domain]").first.get_attribute("value")
                    page.wait_for_timeout(1500)
                    btn = page.locator(f"button[name=domain][value='{pick}']")
                    btn.hover()
                    page.wait_for_timeout(600)
                    btn.click()
                    tr["chose"] = self.rec.school_of_domain(pick)
                    self.step(f"SEN 학교 선택: {tr['chose']}")
                    continue
                code_box = page.locator("input[name=code]")
                if code_box.count() and mfa_tries < 3 and (mfa_tries == 0 or page.locator(".alert").count()):
                    page.wait_for_timeout(1000)
                    code_box.fill("")
                    code_box.press_sequentially(totp_now(idp_user, self.rec.totp[idp_user]), delay=120)
                    page.wait_for_timeout(500)
                    page.locator("button[type=submit]").first.click()
                    tr["mfa"] = True
                    mfa_tries += 1
                    self.step("SEN 2단계 인증(인증 앱 6자리)")
                    page.wait_for_timeout(1500)
                    continue
                msg = page.locator("p.sub")
                if msg.count() and not page.locator("form").count():
                    self.mark("key")
                    return {"result": "idp_message", "desc": msg.first.inner_text()}
        self.mark("key")
        if DEBUG:
            page.screenshot(path=os.path.join(self.rec.out, f"timeout-{self.sc['id']}.png"))
            try:
                print("  · timeout cfg:", page.evaluate(CFG_JS), flush=True)
            except Exception:  # noqa: BLE001
                pass
        return {"result": "timeout", "url": f"{urlparse(page.url).netloc}{urlparse(page.url).path}"}

    def _click(self, selectors):
        for sel in selectors:
            loc = self.page.locator(sel)
            try:
                if loc.count() and loc.first.is_visible():
                    loc.first.click()
                    return sel
            except Exception:  # noqa: BLE001
                pass
        return None

    # ---- SEN 포털
    def sen_login(self, idp_user):
        self.step(f"SEN 포털 로그인({idp_user})")
        self.page.goto(f"{IDP}/login", wait_until="commit")
        page = self.page
        page.wait_for_selector("#password", timeout=30000)
        page.wait_for_timeout(800)
        page.locator("#username").click()
        page.locator("#username").press_sequentially(idp_user, delay=55)
        page.locator("#password").click()
        page.locator("#password").press_sequentially(self.rec.password, delay=40)
        page.wait_for_timeout(400)
        page.locator("button[type=submit]").first.click()
        page.wait_for_url(f"{IDP}/portal**", timeout=30000)
        page.wait_for_timeout(2500)

    def portal_click(self, school, label, initiated=False):
        sel = (f"section.tenant:has(h2:text-is('{school}')) a.btn{'.alt' if initiated else ':not(.alt)'}"
               f":has-text('{label}')")
        link = self.page.locator(sel).first
        link.hover()
        self.page.wait_for_timeout(900)
        self.step(f"SEN 포털: {school} · {label}{' (IdP 시작)' if initiated else ''}")
        link.click()

    def app(self, name, *, typed=None, idp_user=None, account=None, choose=None, goto=True, url=None):
        self.new_trace()
        if goto:
            self.step(f"{APPS[name][0]} 접속")
            self.page.goto(url or APPS[name][1], wait_until="commit")
        out = self.drive(typed=typed, idp_user=idp_user, choose=choose, app=name, account=account or typed)
        self.outcomes.append(out)
        return out


# ---------------------------------------------------------------- 결과 판정·요약
def success_line(out):
    extra = []
    if out.get("chose"):
        extra.append(f"학교 선택 {out['chose']}")
    extra.append("SEN 비밀번호 입력" if out.get("password") else "SEN 비밀번호 입력 없음")
    if out.get("mfa"):
        extra.append("SEN 2단계 인증")
    return f"<span class='ok'>✅ 성공</span> — {esc(out.get('user'))} · 토큰 테넌트 {esc(out.get('school'))} ({esc(', '.join(extra))})"


def fail_line(out):
    code = out.get("code")
    text = STS_TEXT.get(code or "", "")
    return f"<span class='bad'>⛔ 차단</span> — AADSTS{esc(code)} {esc(text)}" if code else f"<span class='bad'>⛔ {esc(out.get('result'))}</span>"


def app_line(out, account):
    if out.get("result") != "app":
        return fail_line(out)
    return (f"<span class='ok'>✅ {esc(APPS[out['app']][0])} 진입</span> — 계정 표시 {esc(account)}"
            f"{'' if out.get('accountShown') else ' (계정 메뉴에서 확인 못 함)'}")


def expect_success(user, school, password=None, mfa=None):
    def check(out):
        return (out.get("result") == "success" and (out.get("user") or "").lower() == user.lower()
                and out.get("school") == school and (password is None or bool(out.get("password")) == password)
                and (mfa is None or bool(out.get("mfa")) == mfa))
    return check


def expect_code(code):
    return lambda out: out.get("result") in ("blocked", "error") and out.get("code") == code


def expect_app(account):
    return lambda out: out.get("result") == "app" and out.get("accountShown")


def describe(out, account=None):
    if out.get("result") == "success":
        return success_line(out)
    if out.get("result") == "app":
        return app_line(out, account or "")
    return fail_line(out)


# ---------------------------------------------------------------- 시나리오
def one(fn_flow, check):
    """흐름 하나 + 판정."""
    def run(r):
        out = fn_flow(r)
        r.result_lines.append(describe(out, (r.sc.get("info") or [("", "")])[0][1]))
        r.matched = check(out)
        return out
    return run


def chain(*parts):
    """같은 브라우저에서 이어지는 흐름 여러 개. parts: (설명, 흐름, 판정)"""
    def run(r):
        oks = []
        for desc, flow, check in parts:
            out = flow(r)
            oks.append(check(out))
            r.result_lines.append(f"<span class='k'>{esc(desc)}</span>{describe(out)}")
        r.matched = all(oks)
    return run


def app_flow(name, typed_id, *, account=None, choose=None, idp_user=None):
    """실제 앱에 아이디를 입력해 로그인. account: 앱 계정 메뉴에 보여야 할 학교 계정(없으면 입력한 아이디)."""
    account = account or typed_id

    def run(r):
        out = r.app(name, typed=typed_id, idp_user=idp_user or typed_id.split("@")[0], account=account, choose=choose)
        r.result_lines.append(app_line(out, account))
        r.matched = expect_app(account)(out)
    return run


def portal_app(idp_user, school, label, account, initiated=False):
    def run(r):
        r.sen_login(idp_user)
        r.portal_click(school, label, initiated)
        out = r.app("m365", goto=False, idp_user=idp_user, account=account)
        r.result_lines.append(app_line(out, account))
        r.matched = expect_app(account)(out)
    return run


def portal_url(idp_user, url, account):
    def run(r):
        r.sen_login(idp_user)
        r.step("SEN 포털 링크(Microsoft 365 웹)")
        r.page.goto(url, wait_until="commit")
        out = r.app("m365", goto=False, idp_user=idp_user, account=account)
        r.result_lines.append(app_line(out, account))
        r.matched = expect_app(account)(out)
    return run


def sen_then_cli(idp_user, **kw):
    def flow(r):
        r.sen_login(idp_user)
        return r.cli(None, idp_user=idp_user, **kw)
    return flow


A, B = "학교 A", "학교 B"


def scenarios(rec):
    t = rec.tenant_of
    S = []

    def add(sid, group, title, info, check, expect, fn, **extra):
        S.append({"id": sid, "group": group, "title": title, "info": info, "check": check, "expect": expect, "fn": fn,
                  **extra})

    # 기본 SSO
    add("A1", "sso", "앱이 학교를 지정(domain_hint) → 학교 A", [("계정", f"student01@{D1}")],
        "앱이 학교 도메인을 지정하면 Microsoft 화면 없이 SEN 로그인으로 바로 넘어가는지", "성공(학교 A)",
        one(lambda r: r.cli(f"student01@{D1}", domain_hint=D1), expect_success(f"student01@{D1}", A, password=True)))
    add("A2", "sso", "Outlook 웹에서 학교 B 계정 입력", [("계정", f"student02@{D2}"), ("앱", "Outlook 웹")],
        "학교 계정을 입력하면 SEN 로그인을 거쳐 학교 B 메일함이 열리는지", "Outlook 진입(학교 B 계정)",
        app_flow("outlook", f"student02@{D2}"))
    add("A3", "sso", "Teams 웹에서 학교 A 계정 입력", [("계정", f"teacher01@{D1}"), ("앱", "Teams 웹")],
        "Microsoft 로그인 화면에 아이디를 직접 입력하는 흐름", "Teams 진입(학교 A 계정)",
        app_flow("teams", f"teacher01@{D1}"))
    add("B1", "sso", "겸임교사: 학교 A 로그인 뒤 같은 브라우저로 학교 B", [("계정", f"multi01@{D1}, multi01@{D2}")],
        "두 번째 학교는 SEN 비밀번호를 다시 묻지 않는지", "둘 다 성공, 학교 B는 비밀번호 입력 없음",
        chain(("학교 A", lambda r: r.cli(f"multi01@{D1}"), expect_success(f"multi01@{D1}", A, password=True)),
              ("학교 B", lambda r: r.cli(f"multi01@{D2}"), expect_success(f"multi01@{D2}", B, password=False))))
    add("C7", "sso", "학교 A의 MFA 필수 계정", [("계정", f"mfa01@{D1}"), ("Entra", "사용자별 MFA 적용")],
        "SEN 2단계 인증 결과(MFA 클레임)로 Entra의 MFA 요구가 충족되는지", "성공(학교 A), SEN 2단계 인증",
        one(lambda r: r.cli(f"mfa01@{D1}"), expect_success(f"mfa01@{D1}", A, mfa=True)))
    add("C8", "sso", "학교 B의 MFA 필수 계정", [("계정", f"mfa02@{D2}"), ("Entra", "사용자별 MFA 적용")],
        "다른 테넌트에서도 SEN 2단계 인증으로 MFA 요구가 충족되는지", "성공(학교 B), SEN 2단계 인증",
        one(lambda r: r.cli(f"mfa02@{D2}"), expect_success(f"mfa02@{D2}", B, mfa=True)))
    add("F1", "sso", "앱이 재인증(prompt=login)을 요구할 때", [("계정", f"teacher01@{D1}")],
        "재인증 요구가 SEN에 전달되는지(전달되지 않으면 SEN 세션으로 통과)", "관찰: 비밀번호 입력 없이 통과",
        chain(("첫 로그인", lambda r: r.cli(f"teacher01@{D1}"), expect_success(f"teacher01@{D1}", A, password=True)),
              ("prompt=login", lambda r: r.cli(f"teacher01@{D1}", prompt="login"),
               expect_success(f"teacher01@{D1}", A, password=False))))
    add("P1", "sso", "SEN 포털 링크 → Microsoft 365 웹(학교 A)", [("계정", "student01 (SEN 포털)")],
        "SEN 포털에서 학교 앱 링크를 누르면 비밀번호 없이 들어가는지", "Microsoft 365 진입(학교 A)",
        portal_app("student01", A, "Microsoft 365", f"student01@{D1}"))
    add("P2", "sso", "SEN 포털 링크 → Microsoft 365 웹(겸임교사, 학교 B)", [("계정", "multi01 (SEN 포털)")],
        "여러 학교 소속이면 포털에서 학교별 링크로 들어가는지", "Microsoft 365 진입(학교 B)",
        portal_app("multi01", B, "Microsoft 365", f"multi01@{D2}"))
    add("I1", "sso", "SEN이 먼저 보내는 로그인(IdP 시작) → 학교 A", [("계정", "student01 (SEN 포털)")],
        "요청 없이 보낸 SAML 응답을 Entra가 받아 주는지(문서에 없는 실험)", "Microsoft 365 진입(학교 A)",
        portal_app("student01", A, "Microsoft 365", f"student01@{D1}", initiated=True))
    add("I2", "sso", "SEN이 먼저 보내는 로그인(IdP 시작) → 학교 B", [("계정", "multi01 (SEN 포털)")],
        "다른 테넌트에도 IdP 시작 로그인이 되는지", "Microsoft 365 진입(학교 B)",
        portal_app("multi01", B, "Microsoft 365", f"multi01@{D2}", initiated=True))
    # 거부
    add("B2a", "reject", "등록되지 않은 Issuer로 보낸 응답", [("계정", f"badissuer01@{D1}")],
        "학교 도메인에 등록되지 않은 Issuer는 Entra가 거부하는지", "거부(AADSTS50107)",
        one(lambda r: r.cli(f"badissuer01@{D1}"), expect_code("50107")))
    add("B2b", "reject", "서명이 변조된 응답", [("계정", f"badsig01@{D1}")],
        "서명 검증에 실패한 SAML 응답을 거부하는지", "거부(AADSTS500069)",
        one(lambda r: r.cli(f"badsig01@{D1}"), expect_code("500069")))
    add("C1", "reject", "Entra 쪽에 ImmutableID가 없는 계정", [("계정", f"nomap01@{D1}")],
        "SEN이 보낸 고유키와 맞는 Entra 사용자가 없으면 거부하는지", "거부(AADSTS90019)",
        one(lambda r: r.cli(f"nomap01@{D1}"), expect_code("90019")))
    add("R11", "reject", "잘못된 구현: 라우팅 도메인 Issuer로 응답", [("계정", f"teacher01@{DR}")],
        "통합 아이디로 들어왔을 때 학교 도메인이 아닌 Issuer로 답하면 막히는지", "거부(AADSTS5000820)",
        one(lambda r: r.cli(f"teacher01@{DR}"), expect_code("5000820")))
    add("R6", "reject", "라우팅 테넌트를 지정한 앱에 학교 B 학생", [("계정", f"student02@{DR}")],
        "테넌트가 고정된 앱(라우팅 테넌트)에서는 다른 학교 학생이 거부되는지", "거부(AADSTS50020)",
        one(lambda r: r.cli(f"student02@{DR}", tenant=t(DR)), expect_code("50020")))
    # ④ 라우팅
    add("R1", "route", "통합 아이디 → 학교 B(다른 테넌트)", [("계정", f"student02@{DR}")],
        "라우팅 테넌트에 페더레이션한 아이디로 시작해도 학교 B 계정으로 로그인되는지", "성공(학교 B)",
        one(lambda r: r.cli(f"student02@{DR}"), expect_success(f"student02@{D2}", B)))
    add("R2", "route", "통합 아이디 → 학교 A(같은 테넌트)", [("계정", f"student01@{DR}")],
        "라우팅 테넌트와 같은 테넌트의 학교 계정으로 로그인되는지", "성공(학교 A)",
        one(lambda r: r.cli(f"student01@{DR}"), expect_success(f"student01@{D1}", A)))
    add("R3", "route", "겸임교사 통합 아이디 → 학교 선택", [("계정", f"multi01@{DR}")],
        "여러 학교 소속이면 SEN이 학교를 고르게 하는지", "학교 B 선택 후 성공",
        one(lambda r: r.cli(f"multi01@{DR}", choose=D2), expect_success(f"multi01@{D2}", B)))
    add("R4", "route", "Microsoft 로그인 화면에 통합 아이디 직접 입력", [("계정", f"student02@{DR}")],
        "사용자가 통합 아이디를 직접 입력해도 학교 B로 로그인되는지", "성공(학교 B)",
        one(lambda r: r.cli(f"student02@{DR}", typed=True), expect_success(f"student02@{D2}", B)))
    add("R5", "route", "학교 B 테넌트를 지정한 앱에 통합 아이디", [("계정", f"student02@{DR}")],
        "SharePoint처럼 테넌트가 고정된 앱에서도 되는지", "성공(학교 B)",
        one(lambda r: r.cli(f"student02@{DR}", tenant=t(D2)), expect_success(f"student02@{D2}", B)))
    add("R7", "route", "공용 PC: 앞 학생 세션이 남은 브라우저에서 다른 학생", [("계정", f"student01@{D1} → student02@{DR}")],
        "SEN이 입력한 아이디와 세션 사용자가 다르면 다시 로그인시키는지", "두 번째 학생으로 로그인",
        chain(("앞 학생", lambda r: r.cli(f"student01@{D1}"), expect_success(f"student01@{D1}", A)),
              ("다음 학생", lambda r: r.cli(f"student02@{DR}"), expect_success(f"student02@{D2}", B, password=True))))
    add("R8", "route", "무음 로그인(prompt=none)", [("계정", f"student02@{DR}")],
        "통합 아이디로 로그인한 뒤 앱의 무음 로그인이 어떤 힌트로 되는지", "학교 계정·힌트 없음은 성공, 통합 아이디 힌트는 AADSTS50058",
        chain(("로그인", lambda r: r.cli(f"student02@{DR}"), expect_success(f"student02@{D2}", B)),
              ("무음+학교 계정", lambda r: r.cli(f"student02@{D2}", prompt="none"), expect_success(f"student02@{D2}", B)),
              ("무음+힌트 없음", lambda r: r.cli(None, prompt="none", idp_user="student02"), expect_success(f"student02@{D2}", B)),
              ("무음+통합 아이디", lambda r: r.cli(f"student02@{DR}", prompt="none"), expect_code("50058"))))
    add("R9", "route", "SEN 포털 로그인 상태에서 domain_hint=라우팅 도메인", [("계정", "student02 (SEN 포털)")],
        "포털에서 라우팅 도메인만 지정해도 비밀번호 없이 학교 B로 가는지", "성공(학교 B), 비밀번호 입력 없음",
        one(sen_then_cli("student02", domain_hint=DR), expect_success(f"student02@{D2}", B, password=False)))
    add("R10", "route", "포털 링크(login_hint=통합 아이디) → Microsoft 365 웹", [("계정", f"student02@{DR}")],
        "통합 아이디를 힌트로 넣은 앱 링크로 학교 B Microsoft 365에 들어가는지", "Microsoft 365 진입(학교 B)",
        portal_url("student02", f"https://www.office.com/?auth=2&login_hint={quote('student02@' + DR)}", f"student02@{D2}"))
    add("R12", "route", "MFA 필수 계정의 통합 아이디", [("계정", f"mfa02@{DR}")],
        "통합 아이디로 들어와도 SEN 2단계 인증 후 학교 B로 가는지", "성공(학교 B), SEN 2단계 인증",
        one(lambda r: r.cli(f"mfa02@{DR}"), expect_success(f"mfa02@{D2}", B, mfa=True)))
    add("R13", "route", "SEN 아이디 그대로 입력(student01@joowon.me) → 학교 A", [("계정", f"student01@{DROOT}")],
        "SEN 아이디(@senedu.kr 역할)를 그대로 입력해도 학교 계정으로 로그인되는지", "성공(학교 A)",
        one(lambda r: r.cli(f"student01@{DROOT}", typed=True), expect_success(f"student01@{D1}", A)))
    add("R14", "route", "SEN 아이디 그대로 입력(student02@joowon.me) → 학교 B", [("계정", f"student02@{DROOT}")],
        "다른 테넌트 학교로도 가는지", "성공(학교 B)",
        one(lambda r: r.cli(f"student02@{DROOT}", typed=True), expect_success(f"student02@{D2}", B)))
    add("R15", "route", "겸임교사 SEN 아이디 그대로 입력 → 학교 선택", [("계정", f"multi01@{DROOT}")],
        "SEN 아이디 입력 + 학교 선택", "학교 B 선택 후 성공",
        one(lambda r: r.cli(f"multi01@{DROOT}", typed=True, choose=D2), expect_success(f"multi01@{D2}", B)))
    add("RO", "route", "Outlook 웹에 통합 아이디 입력", [("계정", f"student02@{DR}"), ("앱", "Outlook 웹")],
        "실제 앱에서 통합 아이디로 학교 B 메일함이 열리는지", "Outlook 진입(학교 B 계정)",
        app_flow("outlook", f"student02@{DR}", account=f"student02@{D2}", idp_user="student02"))
    add("RT", "route", "Teams 웹에 통합 아이디 입력 → 학교 선택", [("계정", f"multi01@{DR}"), ("앱", "Teams 웹")],
        "실제 앱에서 학교 선택 후 학교 A Teams가 열리는지", "Teams 진입(학교 A 계정)",
        app_flow("teams", f"multi01@{DR}", account=f"multi01@{D1}", choose=D1, idp_user="multi01"))
    # 보안 데모(학교 B, Microsoft 365 A5)
    add("S0", "attack", "대조군: 평소 위치에서 로그인", [("계정", f"hack01@{D2}"), ("정책", "로그인 위험 시 차단")],
        "평소 접속에서는 위험 탐지 없이 로그인되는지", "내 앱 진입",
        app_flow("myapps", f"hack01@{D2}"))
    add("S1", "attack", "유출 계정으로 Tor 로그인 → 차단", [("계정", f"hack01@{D2}"), ("정책", "로그인 위험 시 차단")],
        "익명 IP 실시간 탐지 → 위험 기반 조건부 액세스 차단", "차단(AADSTS53003)",
        one(lambda r: r.app("myapps", typed=f"hack01@{D2}", idp_user="hack01"), expect_code("53003")), tor=True)
    add("S2", "attack", "Tor 로그인 + SEN 2단계 인증 → 통과", [("계정", f"hack02@{D2}"), ("정책", "로그인 위험 시 MFA 요구")],
        "SEN MFA 클레임이 위험 기반 MFA 요구를 충족해 통과되는지(고위험을 '차단'으로 둬야 하는 이유)", "내 앱 진입",
        app_flow("myapps", f"hack02@{D2}"), tor=True)
    add("S3", "attack", "Tor 로그인, SEN 2단계 인증 없음 → 차단", [("계정", f"hack04@{D2}"), ("정책", "로그인 위험 시 MFA 요구")],
        "MFA를 충족할 수 없는 위험 세션이 차단되는지", "차단(AADSTS53004)",
        one(lambda r: r.app("myapps", typed=f"hack04@{D2}", idp_user="hack04"), expect_code("53004")), tor=True)
    add("S4", "attack", "관리자 침해 확인 → 기존 토큰 거부(CAE)·새 로그인 차단", [("계정", f"hack03@{D2}"),
                                                                     ("정책", "사용자 위험 높음 시 차단")],
        "24시간짜리 토큰이 침해 확인 후 수 분 안에 거부되는지", "토큰 거부(401), 새 로그인 차단(AADSTS530032)",
        cae_flow)
    portal_scenarios(add)
    return S


# ---------------------------------------------------------------- 관리 포털 화면
def frame_with_text(page, text):
    for f in page.frames:
        try:
            loc = f.get_by_text(text, exact=False)
            if loc.count():
                return f, loc.first
        except Exception:  # noqa: BLE001
            pass
    return None, None


def close_popups(page):
    """포털 알림·설문 팝업 닫기(블레이드 닫기 버튼은 건드리지 않음)."""
    for label in ("닫기", "Close", "알림 해제", "해제", "Dismiss"):
        loc = page.locator(f"button[aria-label='{label}'], [role=button][aria-label='{label}']")
        for i in range(min(loc.count(), 3)):
            try:
                if loc.nth(i).is_visible():
                    loc.nth(i).click()
            except Exception:  # noqa: BLE001
                pass


def portal_view(url, wait_text, note, *, scroll_text=None, open_text=None):
    """관리 포털 화면 녹화: 목록이 나올 때까지 기다린 뒤(대기 구간은 빨리 감기) 보여 주고, 필요하면 항목을 연다."""
    def run(r):
        r.step(f"관리 포털 열기: {r.sc['title']}")
        r.page.goto(url, wait_until="commit")
        r.marks["tl_start"] = time.monotonic() - r.t0 + 2
        deadline, loc = time.time() + 240, None
        while time.time() < deadline and not loc:
            r.page.wait_for_timeout(2000)
            _, loc = frame_with_text(r.page, wait_text)
        r.marks["tl_end"] = time.monotonic() - r.t0
        close_popups(r.page)
        if loc and scroll_text:
            _, target = frame_with_text(r.page, scroll_text)
            try:
                (target or loc).scroll_into_view_if_needed(timeout=5000)
            except Exception:  # noqa: BLE001
                pass
        r.page.wait_for_timeout(2500)
        r.mark("key")
        r.page.wait_for_timeout(5000)
        if loc and open_text:
            _, item = frame_with_text(r.page, open_text)
            try:
                item.click(timeout=5000)
                r.step(f"항목 열기: {open_text}")
                r.page.wait_for_timeout(9000)
                close_popups(r.page)
                r.mark("key")
                r.page.wait_for_timeout(3000)
            except Exception:  # noqa: BLE001
                pass
        r.result_lines.append(f"<span class='ok'>✅ {esc(note)}</span>" if loc else
                              "<span class='bad'>⛔ 화면을 불러오지 못함</span>")
        r.matched = bool(loc)
        span = r.marks["tl_end"] - r.marks["tl_start"]
        if span > 6:
            r.timelapse = (r.marks["tl_start"], r.marks["tl_end"], max(1.0, round(span / 3, 1)))
            r.step(f"포털 로딩 {span:.0f}초를 빨리 감기")
    return run


ENTRA_IP = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/"


def portal_scenarios(add):
    add("V1", "portal", "Entra ID 보호: 위험한 로그인", [("화면", "Microsoft Entra 관리 센터 › ID 보호 › 위험한 로그인")],
        "Tor 출구 IP에서 들어온 데모 계정 로그인이 위험한 로그인으로 기록되는지", "데모 계정의 익명 IP 로그인 표시",
        portal_view(ENTRA_IP + "RiskySignIns/fromNav/Identity", "보안데모",
                    "데모 계정(보안데모01·04)의 Tor IP 로그인이 '위험 노출'로 기록됨"), portal=True)
    add("V2", "portal", "Entra ID 보호: 위험 검색", [("화면", "Microsoft Entra 관리 센터 › ID 보호 › 위험 검색")],
        "어떤 탐지(익명 IP 주소, 관리자 침해 확인)가 실시간·오프라인으로 기록되는지", "탐지 유형·위험 수준 표시",
        portal_view(ENTRA_IP + "RiskDetections/fromNav/Identity", "보안데모", "익명 IP 주소 탐지(실시간)와 관리자 침해 확인 기록"),
        portal=True)
    add("V3", "portal", "Entra ID 보호: 위험한 사용자", [("화면", "Microsoft Entra 관리 센터 › ID 보호 › 위험한 사용자")],
        "탐지가 사용자 위험으로 이어지고, SEN MFA로 해소된 계정은 위험이 남지 않는지", "데모 계정 위험 상태 표시",
        portal_view(ENTRA_IP + "RiskyUsers/fromNav/Identity", "보안데모", "데모 계정의 사용자 위험 수준·상태",
                    scroll_text="보안데모"), portal=True)
    add("V4", "portal", "조건부 액세스: 데모용 위험 기반 정책", [("화면", "Microsoft Entra 관리 센터 › 조건부 액세스 › 정책")],
        "데모 계정 그룹에만 적용한 위험 기반 정책 3개", "정책 목록 표시",
        portal_view("https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies/fromNav/Identity",
                    "SSO 보안 데모", "로그인 위험 차단·MFA 요구, 사용자 위험 높음 차단 정책(데모 그룹만 대상)",
                    scroll_text="SSO 보안 데모 S4"), portal=True)
    add("V5", "portal", "Microsoft Defender XDR: 인시던트", [("화면", "Microsoft Defender 포털 › 인시던트")],
        "Entra ID 보호 알림이 사용자별 인시던트로 묶이는지(A5)", "익명 IP 인시던트 표시",
        portal_view("https://security.microsoft.com/incidents", "Anonymous IP", "사용자별 'Anonymous IP address' 인시던트",
                    open_text="Anonymous IP address involving one user"), portal=True)


# ---------------------------------------------------------------- S4: CAE
MONITOR = """<div class='wrap' style='padding:44px 64px'>
<div style='font-size:20px;opacity:.6'>시험용 앱 · Microsoft Graph 호출 기록(CAE 토큰)</div>
<h1 style='margin:10px 0 18px;font-size:36px'>hack03 · 20초마다 Graph /me 호출</h1>
<div id='info' class='row'></div>
<table id='t' style='margin-top:14px'><tr><th style='width:140px'>시각</th><th style='width:160px'>경과</th><th>결과</th></tr></table>
<div class='foot' id='foot'></div></div>
<script>function addRow(r){const tr=document.createElement('tr');tr.innerHTML='<td>'+r.t+'</td><td>'+r.e+'</td><td class="'+(r.c||'')+'">'+r.m+'</td>';
const t=document.getElementById('t');t.appendChild(tr);while(t.rows.length>12)t.deleteRow(1);}</script>"""


def cae_flow(r):
    from graph_token import Graph  # 관리자 토큰(침해 확인)
    upn = f"hack03@{D2}"
    out = r.cli(upn, scope=GRAPH_SCOPE, claims=CAE_CLAIMS, keep=True)
    if out.get("result") != "success":
        r.result_lines.append(fail_line(out))
        r.matched = False
        return
    at, rt = out["tokens"]["access_token"], out["tokens"]["refresh_token"]
    c = jwt_claims(at)
    g = Graph(r.rec.tenant_of(D2))
    oid = g.get_all(f"/users?$filter=userPrincipalName eq '{upn}'&$select=id")[0]["id"]
    r.page.set_content(page_html(MONITOR))
    r.page.evaluate("t => document.getElementById('info').textContent = t",
                    f"토큰 만료까지 {(c['exp'] - time.time()) / 3600:.1f}시간 · CAE 지원 표시(xms_cc=cp1)")
    r.step("CAE 토큰으로 Graph 호출 시작")

    def row(text, cls="", elapsed=""):
        r.page.evaluate("r => addRow(r)", {"t": datetime.now(KST).strftime("%H:%M:%S"), "e": elapsed, "m": text, "c": cls})

    confirmed, t_conf = False, None
    deadline = time.time() + 1800

    def call_me():
        for attempt in range(4):
            try:
                return requests.get("https://graph.microsoft.com/v1.0/me?$select=userPrincipalName",
                                    headers={"Authorization": "Bearer " + at}, timeout=30)
            except requests.RequestException:
                if attempt == 3:
                    raise
                r.page.wait_for_timeout(3000)

    while time.time() < deadline:
        res = call_me()
        el = f"{(time.time() - t_conf) / 60:.1f}분" if t_conf else ""
        if res.status_code == 200:
            row(f"200 OK · {res.json().get('userPrincipalName')}", "ok", el)
        else:
            row(f"{res.status_code} 토큰 거부(CAE claims challenge)", "bad", el)
            r.marks["tl_end"] = time.monotonic() - r.t0 - 1.5
            r.mark("key")
            r.step(f"토큰 거부: 침해 확인 {el} 뒤")
            r.page.wait_for_timeout(2500)
            break
        if not confirmed:
            r.page.wait_for_timeout(2500)
            g.call("POST", "/identityProtection/riskyUsers/confirmCompromised", {"userIds": [oid]})
            t_conf, confirmed = time.time(), True
            row("관리자: 침해 확인(Entra ID 보호) → 사용자 위험 '높음'", "warn", "0.0분")
            r.step("관리자 침해 확인(Graph confirmCompromised)")
            r.page.wait_for_timeout(4000)
            r.marks["tl_start"] = time.monotonic() - r.t0
        r.page.wait_for_timeout(20000)
    tok = requests.post(f"{AAD}/organizations/oauth2/v2.0/token", headers={"User-Agent": UA}, data={
        "client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": rt, "scope": GRAPH_SCOPE,
        "claims": CAE_CLAIMS}, timeout=60).json()
    m = re.search(r"AADSTS(\d+)", tok.get("error_description") or "")
    row(f"새 토큰 요청(refresh token): {'AADSTS' + m.group(1) + ' ' + STS_TEXT.get(m.group(1), '') if m else tok.get('error') or '발급됨'}",
        "bad" if m else "", "")
    r.page.wait_for_timeout(4000)
    again = r.cli(upn, label="새 로그인 시도")
    minutes = (r.marks.get("tl_end", 0) - r.marks.get("tl_start", 0)) / 60 + 0.1
    r.result_lines += [f"<span class='bad'>⛔ 기존 토큰 거부</span> — 침해 확인 약 {minutes:.1f}분 뒤 401(CAE)",
                       f"<span class='bad'>⛔ 새 토큰 요청 차단</span> — AADSTS{m.group(1) if m else '?'}",
                       fail_line(again).replace("⛔ 차단", "⛔ 새 로그인 차단")]
    r.matched = bool(m and m.group(1) == "530032" and again.get("code") == "530032")
    if r.marks.get("tl_start") and r.marks.get("tl_end"):
        span = r.marks["tl_end"] - r.marks["tl_start"]
        r.timelapse = (r.marks["tl_start"], r.marks["tl_end"], max(1.0, round(span / 24, 1)))
        r.step(f"대기 구간 {span / 60:.1f}분을 {r.timelapse[2]}배속으로 표시")


# ---------------------------------------------------------------- 녹화기
class Recorder:
    def __init__(self, args):
        self.args = args
        self.password = os.environ.get("DEMO_PASSWORD") or (open(args.password_file, encoding="utf-8").read().strip()
                                                            if args.password_file else "")
        raw = os.environ.get("DEMO_TOTP_JSON") or (open(args.totp_file, encoding="utf-8").read() if args.totp_file else "{}")
        self.totp = {u: parse_qs(urlparse(x).query)["secret"][0] for u, x in json.loads(raw).items()}
        self.domains = json.load(open(args.domains, encoding="utf-8")) if os.path.exists(args.domains) else {}
        self.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        self.out = args.out_dir
        os.makedirs(os.path.join(self.out, "videos"), exist_ok=True)
        os.makedirs(os.path.join(self.out, "posters"), exist_ok=True)
        self.manifest_path = os.path.join(self.out, "manifest.json")
        self.manifest = json.load(open(self.manifest_path, encoding="utf-8")) if os.path.exists(self.manifest_path) else {}
        self.current = None
        if not (args.publish or args.list):
            self._serve()

    def _serve(self):
        """시험용 앱 리디렉션 주소(http://localhost:8400)에서 결과 화면을 보여 주는 로컬 서버."""
        rec = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                run = rec.current
                body = (run.complete(urlparse(self.path).query) if run else "<p>no run</p>").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        port = urlparse(REDIRECT).port or 80
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def tenant_of(self, domain):
        return self.domains.get(domain, {}).get("tenantId", "organizations")

    def school_of(self, tid):
        for v in self.domains.values():
            if v.get("tenantId") == tid and v.get("mode") == "school":
                return v.get("schoolName")
        return tid if not self.domains else "다른 테넌트"

    def school_of_domain(self, domain):
        return self.domains.get(domain, {}).get("schoolName", domain)

    def egress(self):
        try:
            j = requests.get("https://check.torproject.org/api/ip", proxies=self.proxies, timeout=30).json()
            return j.get("IP"), bool(j.get("IsTor"))
        except Exception:  # noqa: BLE001
            return None, None

    def record(self, pw, sc):
        tmp = tempfile.mkdtemp(prefix="rec-")
        opts = dict(viewport={"width": W, "height": H}, record_video_dir=tmp, record_video_size={"width": W, "height": H},
                    locale="ko-KR", timezone_id="Asia/Seoul", user_agent=UA)
        if sc.get("portal"):
            # 관리 포털: 미리 로그인해 둔 전용 프로필, 화면 글자 가리기(테넌트 ID·관리자 계정·접속 IP)
            browser = None
            opts.pop("user_agent")
            ctx = pw.chromium.launch_persistent_context(self.args.portal_profile, headless=not self.args.headed, **opts)
            rules = json.load(open(self.args.mask_file, encoding="utf-8"))["rules"] if self.args.mask_file else []
            ctx.add_init_script(f"({MASK_JS})({json.dumps(rules)})")
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
        else:
            browser = pw.chromium.launch(headless=not self.args.headed,
                                         proxy={"server": self.args.proxy} if self.args.proxy else None)
            ctx = browser.new_context(**opts)
            page = ctx.new_page()
        run = Run(self, sc, ctx, page)
        self.current = run
        if self.args.proxy:
            ip, is_tor = self.egress()
            run.via = f"Tor 출구 IP {ip}" if is_tor else f"프록시 {ip}"
        elif sc["group"] == "attack":
            run.via = "평소 위치(Tor 아님)"
        error = None
        try:
            run.intro()
            sc["fn"](run)
        except Exception as e:  # noqa: BLE001
            error = f"{type(e).__name__}: {e}"[:300]
            run.result_lines.append(f"<span class='bad'>녹화 오류</span> {esc(error[:120])}")
            run.matched = False
            run.mark("key")
        try:
            run.end()
        except Exception:  # noqa: BLE001
            run.mark("end")
        video = page.video
        ctx.close()
        if browser:
            browser.close()
        mp4 = os.path.join(self.out, "videos", f"{sc['id']}.mp4")
        jpg = os.path.join(self.out, "posters", f"{sc['id']}.jpg")
        duration = convert(video.path(), mp4, jpg, run.marks, run.timelapse)
        shutil.rmtree(tmp, ignore_errors=True)
        entry = {"id": sc["id"], "group": sc["group"], "groupName": GROUPS[sc["group"]], "title": sc["title"],
                 "info": sc.get("info", []), "check": sc["check"], "expect": sc["expect"],
                 "result": [html.unescape(re.sub(r"<[^>]+>", "", x)) for x in run.result_lines], "matched": run.matched,
                 "steps": run.steps, "via": run.via, "video": f"videos/{sc['id']}.mp4", "poster": f"posters/{sc['id']}.jpg",
                 "duration": duration, "recordedAt": datetime.now(KST).strftime("%Y-%m-%d %H:%M"),
                 "timelapse": run.timelapse[2] if run.timelapse else None, "error": error}
        self.manifest[sc["id"]] = entry
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(self.manifest, f, ensure_ascii=False, indent=2)
        return entry


def publish(rec, scs, site, reason):
    """녹화 결과를 시연 사이트 폴더로 옮긴다. 예상과 일치(또는 관찰)한 영상만 올리고, 나머지는 보류 목록에 둔다."""
    os.makedirs(os.path.join(site, "videos"), exist_ok=True)
    os.makedirs(os.path.join(site, "posters"), exist_ok=True)
    os.makedirs(os.path.join(site, "data"), exist_ok=True)
    items, pending = [], []
    for sc in scs:
        e = rec.manifest.get(sc["id"])
        if e and e.get("matched") is not False and not e.get("error"):
            e = {**e, "result": [html.unescape(x) for x in e.get("result", [])]}
            for key in ("video", "poster"):
                shutil.copy2(os.path.join(rec.out, e[key]), os.path.join(site, e[key]))
            items.append(e)
        else:
            pending.append({"id": sc["id"], "group": sc["group"], "title": sc["title"], "reason": reason})
            for key, ext in (("videos", "mp4"), ("posters", "jpg")):
                stale = os.path.join(site, key, f"{sc['id']}.{ext}")
                if os.path.exists(stale):
                    os.remove(stale)
    data = {"generatedAt": datetime.now(KST).strftime("%Y-%m-%d %H:%M"), "items": items, "pending": pending}
    with open(os.path.join(site, "data", "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"게시 {len(items)}개, 보류 {len(pending)}개: {' '.join(p['id'] for p in pending)}")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=os.path.join(here, "..", "out", "demo"))
    ap.add_argument("--password-file")
    ap.add_argument("--totp-file")
    ap.add_argument("--domains", default=os.path.join(here, "..", "idp", "data", "domains.json"))
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--proxy", help="예: socks5://127.0.0.1:9050 (Tor)")
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--portal-profile", help="관리 포털에 미리 로그인해 둔 Chromium 프로필 폴더(V 시나리오)")
    ap.add_argument("--mask-file", help="포털 화면에서 가릴 문자열 규칙 JSON({\"rules\": [[정규식, 플래그, 대체]]})")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--publish", help="시연 사이트 폴더(영상·포스터·data/manifest.json 복사)")
    ap.add_argument("--pending-reason", default="녹화 보류(다음 녹화 예정)")
    a = ap.parse_args()
    if a.publish:
        a.password_file = a.password_file or os.devnull
    rec = Recorder(a)
    scs = scenarios(rec)
    if a.publish:
        publish(rec, scs, a.publish, a.pending_reason)
        return
    if a.list:
        for sc in scs:
            print(f"{sc['id']:5} {GROUPS[sc['group']]:<22} {sc['title']}")
        return
    picked = [sc for sc in scs if (sc["id"] in a.only if a.only else
                                   bool(sc.get("tor")) == bool(a.proxy) and bool(sc.get("portal")) == bool(a.portal_profile))]
    if any(sc.get("portal") for sc in picked) and not a.portal_profile:
        raise SystemExit("관리 포털 시나리오는 --portal-profile 이 필요합니다")
    with sync_playwright() as pw:
        for sc in picked:
            started = time.time()
            e = rec.record(pw, sc)
            mark = {True: "일치", False: "다름", None: "관찰"}[e["matched"]]
            print(f"[{e['id']}] {mark} {e['duration']}초 ({time.time() - started:.0f}초 소요) | {' / '.join(e['result'])}"
                  f"{' | 오류 ' + e['error'] if e['error'] else ''}", flush=True)


if __name__ == "__main__":
    main()
