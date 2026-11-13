"""테스트용 SAML 2.0 IdP (Microsoft 365 다중 테넌트 도메인 페더레이션 PoC).

IdP 한 벌로 여러 테넌트를 처리한다.
- 테넌트(학교) 구분: 로그인 주소의 도메인  /saml/m365/<domain>/sso
- Entra 요구사항: 도메인마다 고유한 Issuer  {IDP_BASE_URL}/saml/m365/<domain>
- 서명 인증서: 모든 도메인 공통 1개(교체용 next 인증서 지원)
- 2단계 인증: 학교 도메인에 requireMfa 가 있거나 계정에 mfa 플래그가 있으면 TOTP를 요구하고,
  실제로 통과한 세션에만 MFA 수행 표시(AuthnContextClassRef multipleauthn)를 붙인다.
"""
import base64
import collections
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from urllib.parse import quote, urlencode

from flask import Flask, Response, abort, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

import saml_core as sc

HERE = os.path.dirname(os.path.abspath(__file__))
PENDING_TTL = 15 * 60
FAIL_WINDOW, FAIL_LIMIT = 10 * 60, 30
TOTP_STEP = 30
VERSION = "2026-11-13.post-csp"


def totp_at(secret_b32, counter, digits=6):
    """RFC 6238 TOTP(SHA-1, 30초, 6자리). 일반 인증 앱과 같은 방식."""
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    return f"{(struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** digits:0{digits}d}"


def _b64_env(name):
    v = os.environ.get(name, "")
    return base64.b64decode(v).decode() if v else ""


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _env_config():
    keys_dir = os.environ.get("KEYS_DIR", "")
    def pem(env_b64, file_name):
        if os.environ.get(env_b64):
            return _b64_env(env_b64)
        if keys_dir and os.path.exists(os.path.join(keys_dir, file_name)):
            return _read(os.path.join(keys_dir, file_name))
        return ""
    return {
        "IDP_BASE_URL": os.environ.get("IDP_BASE_URL", "https://auth.joowon.me").rstrip("/"),
        # IdP 아이디의 도메인 표시(예: 학번@joowon.me). Entra 도메인과는 무관한 IdP 내부 아이디다.
        "ID_DOMAIN": os.environ.get("IDP_ID_DOMAIN", "joowon.me"),
        "LOGIN_UI_URL": os.environ.get("LOGIN_UI_URL", "").strip(),
        "DATA_DIR": os.environ.get("DATA_DIR", os.path.join(HERE, "data")),
        "SECRET_KEY": os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        "ADMIN_TOKEN": os.environ.get("ADMIN_TOKEN", ""),
        "ACTIVE_SIGNING": os.environ.get("ACTIVE_SIGNING", "current"),
        "KEYS": {
            "current": (pem("SIGNING_KEY_B64", "current.key"), pem("SIGNING_CERT_B64", "current.pem")),
            "next": (pem("NEXT_SIGNING_KEY_B64", "next.key"), pem("NEXT_SIGNING_CERT_B64", "next.pem")),
        },
    }


def create_app(overrides=None):
    cfg = {**_env_config(), **(overrides or {})}
    data_dir = cfg["DATA_DIR"]
    domains = {k.lower(): v for k, v in json.loads(_read(os.path.join(data_dir, "domains.json"))).items()}
    users = json.loads(_read(os.path.join(data_dir, "users.json")))
    links = json.loads(_read(os.path.join(data_dir, "links.json")))
    if not cfg["KEYS"].get(cfg["ACTIVE_SIGNING"], ("", ""))[0]:
        raise RuntimeError(f"서명 키가 없습니다: {cfg['ACTIVE_SIGNING']}")

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config.update(
        SECRET_KEY=cfg["SECRET_KEY"],
        SESSION_COOKIE_NAME="idp_session",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        # Entra가 POST로 로그인 요청을 보내도 기존 로그인 세션이 전달되도록 None
        SESSION_COOKIE_SAMESITE="None",
        PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=8),
    )

    log_buffer = collections.deque(maxlen=1000)
    pending, failures = {}, collections.defaultdict(collections.deque)
    last_totp = {}
    lock = threading.Lock()

    def log(event, **fields):
        entry = {"t": sc.fmt(sc.utcnow()), "event": event, **fields}
        log_buffer.appendleft(entry)
        print(json.dumps(entry, ensure_ascii=False), flush=True)

    def issuer_for(domain):
        return f"{cfg['IDP_BASE_URL']}/saml/m365/{domain}"

    def public_base():
        return request.host_url.rstrip("/")

    def put_pending(item):
        k = secrets.token_urlsafe(18)
        now = time.time()
        with lock:
            for old in [key for key, v in pending.items() if now - v["t"] > PENDING_TTL]:
                pending.pop(old, None)
            pending[k] = {**item, "t": now}
        return k

    def get_pending(k):
        with lock:
            item = pending.get(k or "")
        if item and time.time() - item["t"] <= PENDING_TTL:
            return item
        return None

    def message(text, status=200, title="안내"):
        return render_template("message.html", title=title, text=text), status

    def to_login(k=None, err=None, school=None, user=None):
        params = {key: v for key, v in {"k": k, "err": err, "school": school, "user": user}.items() if v}
        if cfg["LOGIN_UI_URL"]:
            params["api"] = public_base()
            return redirect(f"{cfg['LOGIN_UI_URL']}?{urlencode(params)}")
        return redirect(url_for("login", **params))

    def post_to_entra(fields):
        resp = Response(render_template("post.html", action=sc.ENTRA_ACS,
                                        fields={k: v for k, v in fields.items() if v is not None}))
        # Entra는 SAML 응답을 받은 뒤 앱의 리디렉션 주소(다른 출처, 네이티브 앱의 http://localhost 포함)로 바로 보낼 수 있다.
        # 브라우저는 form-action을 그 리디렉션에도 적용하므로, 이 화면만은 form-action을 제한하지 않는다.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; "
            "img-src 'self' data:; script-src 'self'; frame-ancestors 'none'")
        return resp

    def normalize_id(raw):
        v = (raw or "").strip().lower()
        suffix = "@" + cfg["ID_DOMAIN"]
        return v[: -len(suffix)] if v.endswith(suffix) else v

    @app.context_processor
    def template_globals():
        return {"id_domain": cfg["ID_DOMAIN"]}

    def rate_limited(ip):
        now = time.time()
        with lock:
            q = failures[ip]
            while q and now - q[0] > FAIL_WINDOW:
                q.popleft()
            return len(q) >= FAIL_LIMIT

    def record_failure(ip):
        with lock:
            failures[ip].append(time.time())

    def needs_mfa(user, domain):
        return bool(user.get("flags", {}).get("mfa") or domains.get(domain, {}).get("requireMfa"))

    def hint_matches(uid, domain, hint):
        """Entra가 넘긴 username(사용자가 입력한 아이디)이 지금 IdP 세션 사용자와 같은지."""
        if domains.get(domain, {}).get("mode") == "route":
            return hint.split("@")[0] == uid
        return any(a["upn"].lower() == hint for a in users.get(uid, {}).get("accounts", []))

    def prefill_for(domain, hint):
        # 라우팅 도메인은 입력값의 앞부분이 곧 IdP 아이디. 학교 도메인은 아이디 노출을 막으려고 채우지 않는다.
        if hint and domains.get(domain, {}).get("mode") == "route":
            return hint.split("@")[0]
        return None

    def check_totp(uid, secret, code):
        code = (code or "").strip().replace(" ", "")
        if not (len(code) == 6 and code.isdigit()):
            return False
        now = int(time.time() // TOTP_STEP)
        for counter in (now - 1, now, now + 1):
            if hmac.compare_digest(totp_at(secret, counter), code):
                with lock:
                    if counter <= last_totp.get(uid, -1):
                        return False  # 이미 쓴 코드(재사용 방지)
                    last_totp[uid] = counter
                return True
        return False

    def step_up(uid, **params):
        if not users[uid].get("totpSecret"):
            log("mfa_unavailable", uid=uid, **params)
            return message("이 학교는 2단계 인증이 필요하지만 등록된 인증 수단이 없습니다. 관리자에게 문의해 주세요.", 403)
        log("mfa_required", uid=uid, **params)
        return redirect(url_for("mfa", **params))

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; "
            "img-src 'self' data:; script-src 'self'; form-action 'self' https://login.microsoftonline.com; "
            "frame-ancestors 'none'",
        )
        return resp

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": VERSION, "activeSigning": cfg["ACTIVE_SIGNING"], "domains": sorted(domains),
                "time": sc.fmt(sc.utcnow())}

    @app.get("/")
    def home():
        return redirect(url_for("portal") if session.get("uid") else url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            if cfg["LOGIN_UI_URL"]:
                return to_login(k=request.args.get("k"), err=request.args.get("err"),
                                school=request.args.get("school"), user=request.args.get("user"))
            return render_template("login.html", k=request.args.get("k", ""), err=request.args.get("err", ""),
                                   school=request.args.get("school", ""), user=request.args.get("user", ""))

        ip = (request.remote_addr or "?")
        too_many = rate_limited(ip)
        k = request.form.get("k") or None
        p = get_pending(k) if k else None
        school = domains.get(p["domain"], {}).get("schoolName") if p else None
        if too_many:
            log("login_blocked", ip=ip)
            return to_login(k=k, err="locked", school=school)

        uid = normalize_id(request.form.get("username"))
        user = users.get(uid)
        if not user or not check_password_hash(user["passwordHash"], request.form.get("password", "")):
            record_failure(ip)
            log("login_fail", uid=uid, ip=ip, pending=bool(p))
            return to_login(k=k, err="1", school=school, user=uid)

        session.clear()
        session.permanent = True
        session["uid"] = uid
        session["auth_time"] = sc.fmt(sc.utcnow())
        if p:
            with lock:
                p["logged_in"] = True
        log("login_ok", uid=uid, ip=ip, pending=bool(p), via=request.headers.get("Origin") or "same-origin")
        if k and not p:
            return message("로그인 요청이 만료됐습니다. 앱이나 사이트에서 다시 시작해 주세요.", 400)
        return redirect(url_for("saml_continue", k=k) if p else url_for("portal"))

    @app.get("/logout")
    def logout():
        log("logout", uid=session.get("uid"))
        session.clear()
        return to_login()

    @app.route("/saml/m365/<domain>/sso", methods=["GET", "POST"])
    def sso(domain):
        domain = domain.lower()
        if domain not in domains:
            abort(404)
        binding = "redirect" if request.method == "GET" else "post"
        src = request.args if binding == "redirect" else request.form
        saml_request, relay = src.get("SAMLRequest"), src.get("RelayState")
        if not saml_request:
            return message("SAMLRequest가 없습니다. Microsoft 365 로그인 화면에서 시작해 주세요.", 400)
        try:
            req = sc.parse_authn_request(saml_request, binding)
        except Exception as e:  # noqa: BLE001
            log("authn_request_invalid", domain=domain, binding=binding, error=str(e)[:200])
            return message("로그인 요청을 해석하지 못했습니다.", 400)

        hint = (src.get("username") or src.get("login_hint") or "").strip().lower()
        log("authn_request", domain=domain, binding=binding, requestId=req["id"], sp=req["issuer"],
            forceAuthn=req["force_authn"], isPassive=req["is_passive"], signed=req["signed"],
            nameIdFormat=req["nameid_format"], paramKeys=sorted(src.keys()),
            username=hint or None, relayStateLen=len(relay or ""),
            userAgent=(request.headers.get("User-Agent") or "")[:120], hasSession=bool(session.get("uid")))
        uid = session.get("uid")
        mismatch = bool(uid and hint and not hint_matches(uid, domain, hint))
        need_login = not uid or req["force_authn"] or mismatch
        k = put_pending({"domain": domain, "request_id": req["id"], "relay": relay, "binding": binding, "hint": hint,
                         "needs_login": need_login})

        if req["is_passive"] and need_login:
            xml = sc.build_status_response(issuer=issuer_for(domain), in_response_to=req["id"],
                                           second_level=sc.STATUS_NO_PASSIVE)
            log("saml_no_passive", domain=domain, requestId=req["id"], mismatch=mismatch)
            return post_to_entra({"SAMLResponse": base64.b64encode(xml).decode(), "RelayState": relay})
        if mismatch:
            # 공용 PC 등: 브라우저에 남은 다른 사용자의 세션으로 응답하지 않고, 입력한 아이디로 다시 로그인시킨다.
            log("hint_mismatch", domain=domain, sessionUid=uid, hint=hint)
            return to_login(k=k, err="switch", school=domains[domain].get("schoolName"), user=prefill_for(domain, hint))
        if need_login:
            return to_login(k=k, school=domains[domain].get("schoolName"), user=prefill_for(domain, hint))
        return redirect(url_for("saml_continue", k=k))

    @app.route("/saml/continue", methods=["GET", "POST"])
    def saml_continue():
        k = request.values.get("k")
        p = get_pending(k)
        if not p:
            return message("로그인 요청이 만료됐습니다. 앱이나 사이트에서 다시 시작해 주세요.", 400)
        uid = session.get("uid")
        if not uid or uid not in users or (p.get("needs_login") and not p.get("logged_in")):
            return to_login(k=k, school=domains[p["domain"]].get("schoolName"), user=prefill_for(p["domain"], p.get("hint")))
        user = users[uid]
        dcfg = domains[p["domain"]]
        accounts = user.get("accounts", [])

        if dcfg.get("mode") == "route":
            chosen = (request.form.get("domain") if request.method == "POST" else None) or p.get("chosen")
            if chosen:
                target = next((a for a in accounts if a["domain"] == chosen), None)
            elif len(accounts) == 1:
                target = accounts[0]
            else:
                choices = [{"domain": a["domain"], "upn": a["upn"],
                            "school": domains.get(a["domain"], {}).get("schoolName", a["domain"])} for a in accounts]
                log("route_choose", uid=uid, options=[c["domain"] for c in choices])
                return render_template("choose.html", k=k, choices=choices, name=user.get("name", uid))
        else:
            target = next((a for a in accounts if a["domain"] == p["domain"]), None)

        if not target:
            log("no_linked_account", uid=uid, domain=p["domain"])
            return message("이 학교(테넌트)에 연결된 계정이 없습니다. 다른 아이디로 로그인해 주세요.", 403)
        if needs_mfa(user, target["domain"]) and not session.get("mfa"):
            with lock:
                p["chosen"] = target["domain"]
            return step_up(uid, k=k, domain=target["domain"])

        flags = user.get("flags", {})
        mfa_done = bool(session.get("mfa"))
        if flags.get("badIssuer"):
            issuer = issuer_for("unregistered.invalid")
        elif flags.get("routeIssuerFromRequest") and dcfg.get("mode") == "route":
            # 시험용: 라우팅 도메인 자신의 Issuer로 응답(학교 계정과 realm이 달라 교차 도메인 로그인이 됨)
            issuer = issuer_for(p["domain"])
        else:
            issuer = issuer_for(target["domain"])
        key, cert = cfg["KEYS"][cfg["ACTIVE_SIGNING"]]
        auth_time = dt.datetime.strptime(session.get("auth_time"), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc) \
            if session.get("auth_time") else None
        xml = sc.build_response(issuer=issuer, in_response_to=p["request_id"], name_id=target["immutableId"],
                                upn=target["upn"], key_pem=key, cert_pem=cert, mfa=mfa_done,
                                auth_instant=auth_time, tamper=bool(flags.get("badSignature")))
        with lock:
            pending.pop(k, None)
        log("saml_response", uid=uid, requestDomain=p["domain"], targetDomain=target["domain"],
            routed=target["domain"] != p["domain"], upn=target["upn"], issuer=issuer, inResponseTo=p["request_id"],
            signing=cfg["ACTIVE_SIGNING"], mfa=mfa_done, tamper=bool(flags.get("badSignature")),
            typed=p.get("hint") or None,
            typedOverridden=bool(p.get("hint") and not hint_matches(uid, p["domain"], p["hint"])))
        return post_to_entra({"SAMLResponse": base64.b64encode(xml).decode(), "RelayState": p["relay"]})

    @app.route("/mfa", methods=["GET", "POST"])
    def mfa():
        uid = session.get("uid")
        k = request.values.get("k") or ""
        domain = (request.values.get("domain") or "").lower()
        app_index = request.values.get("app") or ""
        if not uid or uid not in users:
            return to_login(k=k or None)
        secret = users[uid].get("totpSecret")
        if not secret:
            return message("등록된 2단계 인증 수단이 없습니다.", 403)

        def done():
            if k:
                return redirect(url_for("saml_continue", k=k))
            if domain and app_index.isdigit():
                return redirect(url_for("launch", domain=domain, app=app_index))
            return redirect(url_for("portal"))

        if session.get("mfa"):
            return done()
        view = {"k": k, "domain": domain, "app_index": app_index,
                "school": domains.get(domain, {}).get("schoolName", ""), "name": users[uid].get("name", uid)}
        if request.method == "GET":
            return render_template("mfa.html", err="", **view)
        ip = request.remote_addr or "?"
        if rate_limited(ip):
            log("mfa_blocked", uid=uid, ip=ip)
            return render_template("mfa.html", err="locked", **view), 429
        if not check_totp(uid, secret, request.form.get("code")):
            record_failure(ip)
            log("mfa_fail", uid=uid, ip=ip, domain=domain or None)
            return render_template("mfa.html", err="1", **view), 401
        session["mfa"] = True
        log("mfa_ok", uid=uid, domain=domain or None)
        return done()

    @app.get("/portal")
    def portal():
        uid = session.get("uid")
        if not uid or uid not in users:
            return to_login()
        user = users[uid]
        rows = []
        for a in user.get("accounts", []):
            d = domains.get(a["domain"], {})
            values = {"upn": quote(a["upn"]), "domain": a["domain"], "tenantId": d.get("tenantId", "")}
            rows.append({"school": d.get("schoolName", a["domain"]), "upn": a["upn"],
                         "links": [{"label": l["label"], "url": l["url"].format(**values),
                                    "launch": url_for("launch", domain=a["domain"], app=i)}
                                   for i, l in enumerate(links)]})
        return render_template("portal.html", name=user.get("name", uid), uid=uid, rows=rows)

    @app.get("/portal/launch")
    def launch():
        """IdP 시작 방식(요청 없이 보내는 SAML 응답). Entra가 받아 주는지 PoC로 확인하는 실험 경로."""
        uid = session.get("uid")
        if not uid or uid not in users:
            return to_login()
        domain = (request.args.get("domain") or "").lower()
        account = next((a for a in users[uid].get("accounts", []) if a["domain"] == domain), None)
        try:
            target = links[int(request.args.get("app", "0"))]["target"]
        except (ValueError, IndexError):
            abort(400)
        if not account or domains.get(domain, {}).get("mode") != "school":
            abort(403)
        if needs_mfa(users[uid], domain) and not session.get("mfa"):
            return step_up(uid, domain=domain, app=request.args.get("app", "0"))
        key, cert = cfg["KEYS"][cfg["ACTIVE_SIGNING"]]
        xml = sc.build_response(issuer=issuer_for(domain), in_response_to=None, name_id=account["immutableId"],
                                upn=account["upn"], key_pem=key, cert_pem=cert, mfa=bool(session.get("mfa")))
        log("idp_initiated", uid=uid, domain=domain, upn=account["upn"], relayState=target, mfa=bool(session.get("mfa")))
        return post_to_entra({"SAMLResponse": base64.b64encode(xml).decode(), "RelayState": target})

    @app.route("/saml/m365/slo", methods=["GET", "POST"])
    def slo():
        binding = "redirect" if request.method == "GET" else "post"
        src = request.args if binding == "redirect" else request.form
        info = sc.describe_logout_request(src["SAMLRequest"], binding) if src.get("SAMLRequest") else {}
        log("logout_request", binding=binding, paramKeys=sorted(src.keys()), uid=session.get("uid"), **info)
        session.clear()
        return message("로그아웃되었습니다. 창을 닫아도 됩니다.")

    @app.get("/saml/m365/<domain>/metadata")
    def metadata(domain):
        domain = domain.lower()
        if domain not in domains:
            abort(404)
        certs = [c for _, c in cfg["KEYS"].values() if c]
        xml = sc.build_metadata(entity_id=issuer_for(domain), sso_url=f"{issuer_for(domain)}/sso",
                                slo_url=f"{cfg['IDP_BASE_URL']}/saml/m365/slo", certs_pem=certs)
        return Response(xml, mimetype="application/samlmetadata+xml")

    def admin_ok():
        token = cfg["ADMIN_TOKEN"]
        given = request.args.get("token") or request.headers.get("X-Admin-Token", "")
        return bool(token) and secrets.compare_digest(given, token)

    @app.get("/admin/log")
    def admin_log():
        if not admin_ok():
            abort(404)
        return render_template("admin_log.html", entries=list(log_buffer))

    @app.get("/admin/log.json")
    def admin_log_json():
        if not admin_ok():
            abort(404)
        return {"entries": list(log_buffer)}

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
