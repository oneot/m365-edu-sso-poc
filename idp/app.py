"""테스트용 SAML 2.0 IdP (Microsoft 365 다중 테넌트 도메인 페더레이션 PoC).

IdP 한 벌로 여러 테넌트를 처리한다.
- 테넌트(학교) 구분: 로그인 주소의 도메인  /saml/m365/<domain>/sso
- Entra 요구사항: 도메인마다 고유한 Issuer  {IDP_BASE_URL}/saml/m365/<domain>
- 서명 인증서: 모든 도메인 공통 1개(교체용 next 인증서 지원)
- 인증: IdP는 1차 인증(아이디·비밀번호)만 한다. MFA는 Entra가 직접 수행하므로
  (도메인 federatedIdpMfaBehavior=rejectMfaByFederatedIdp) MFA 수행 표시(multipleauthn)를 보내지 않는다.
- 로그인 화면: IdP가 /login에서 직접 보낸다. 비밀번호 입력 화면에도 보안 헤더(다른 사이트의 iframe 삽입 차단 등)가 붙는다.
- 앱 요청 없이 로그인하면(루트 1) 학교 계정으로 Microsoft 365 웹에 바로 들어간다.
"""
import base64
import collections
import datetime as dt
import json
import os
import secrets
import threading
import time
from urllib.parse import quote

from flask import Flask, Response, abort, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

import saml_core as sc

HERE = os.path.dirname(os.path.abspath(__file__))
PENDING_TTL = 15 * 60
FAIL_WINDOW, FAIL_LIMIT = 10 * 60, 30
VERSION = "2026-11-17.slo-end-session"
# Microsoft 365 계정 관리자가 다른 계정으로 바꿀 때 쓰는 주소다. 브라우저에 다른 Microsoft 계정(예: Edge 프로필의
# 회사 계정)이 로그인돼 있어도 이 학교 계정으로 로그인을 새로 시작한다. 첫 화면 주소(/?login_hint=)는 그런 브라우저에서
# 힌트를 무시하고 기존 계정으로 열릴 수 있다.
M365_HOME = "https://m365.cloud.microsoft/login?es=Click&login_hint={upn}"


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
    # Microsoft 로그아웃으로 끝난 사용자: uid → 끝난 시각. 그 전에 시작한 SEN 세션은 쓰지 않는다.
    # 이 기록은 메모리에만 있으므로, 서버가 시작되기 전에 만든 세션도 쓰지 않는다(재시작 뒤 다시 로그인).
    ended, started = {}, time.time()
    uid_by_immutable_id = {a["immutableId"]: uid for uid, u in users.items() for a in u.get("accounts", [])}
    lock = threading.Lock()

    def log(event, **fields):
        entry = {"t": sc.fmt(sc.utcnow()), "event": event, **fields}
        log_buffer.appendleft(entry)
        print(json.dumps(entry, ensure_ascii=False), flush=True)

    def issuer_for(domain):
        return f"{cfg['IDP_BASE_URL']}/saml/m365/{domain}"

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

    def school_label(domain):
        # 라우팅 도메인(SEN 아이디)은 아직 학교가 정해지지 않았으므로 로그인 화면에 학교 이름을 띄우지 않는다.
        d = domains.get(domain or "", {})
        return None if d.get("mode") == "route" else d.get("schoolName")

    def to_login(k=None, err=None, school=None, user=None):
        params = {key: v for key, v in {"k": k, "err": err, "school": school, "user": user}.items() if v}
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

    @app.before_request
    def drop_ended_session():
        uid = session.get("uid")
        if uid and session.get("iat", 0) <= max(ended.get(uid, 0), started):
            log("session_ended", uid=uid)
            session.clear()

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
        uid = session.get("uid")
        if not uid or uid not in users:
            return to_login()
        # SEN 아이디 하나에는 학교 계정이 하나다(학교 테넌트 1곳).
        accounts = users[uid].get("accounts", [])
        if not accounts:
            return message("연결된 학교 계정이 없습니다.", 403)
        log("land_m365", uid=uid, upn=accounts[0]["upn"])
        # 로그인 폼을 보낸 뒤의 리디렉션에는 로그인 화면의 form-action이 적용되므로, 이 화면에서 새로 이동한다.
        return render_template("go.html", href=M365_HOME.format(upn=quote(accounts[0]["upn"])))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html", k=request.args.get("k", ""), err=request.args.get("err", ""),
                                   school=request.args.get("school", ""), user=request.args.get("user", ""))

        ip = (request.remote_addr or "?")
        too_many = rate_limited(ip)
        k = request.form.get("k") or None
        p = get_pending(k) if k else None
        school = school_label(p["domain"]) if p else None
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
        session["iat"] = time.time()
        if p:
            with lock:
                p["logged_in"] = True
        log("login_ok", uid=uid, ip=ip, pending=bool(p), via=request.headers.get("Origin") or "same-origin")
        if k and not p:
            return message("로그인 요청이 만료됐습니다. 앱이나 사이트에서 다시 시작해 주세요.", 400)
        return redirect(url_for("saml_continue", k=k) if p else url_for("home"))

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
            return to_login(k=k, err="switch", school=school_label(domain), user=prefill_for(domain, hint))
        if need_login:
            return to_login(k=k, school=school_label(domain), user=prefill_for(domain, hint))
        return redirect(url_for("saml_continue", k=k))

    @app.route("/saml/continue", methods=["GET", "POST"])
    def saml_continue():
        k = request.values.get("k")
        p = get_pending(k)
        if not p:
            return message("로그인 요청이 만료됐습니다. 앱이나 사이트에서 다시 시작해 주세요.", 400)
        uid = session.get("uid")
        if not uid or uid not in users or (p.get("needs_login") and not p.get("logged_in")):
            return to_login(k=k, school=school_label(p["domain"]), user=prefill_for(p["domain"], p.get("hint")))
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

        flags = user.get("flags", {})
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
                                upn=target["upn"], key_pem=key, cert_pem=cert,
                                auth_instant=auth_time, tamper=bool(flags.get("badSignature")))
        with lock:
            pending.pop(k, None)
        log("saml_response", uid=uid, requestDomain=p["domain"], targetDomain=target["domain"],
            routed=target["domain"] != p["domain"], upn=target["upn"], issuer=issuer, inResponseTo=p["request_id"],
            signing=cfg["ACTIVE_SIGNING"], tamper=bool(flags.get("badSignature")),
            typed=p.get("hint") or None,
            typedOverridden=bool(p.get("hint") and not hint_matches(uid, p["domain"], p["hint"])))
        return post_to_entra({"SAMLResponse": base64.b64encode(xml).decode(), "RelayState": p["relay"]})

    @app.route("/saml/m365/slo", methods=["GET", "POST"])
    def slo():
        binding = "redirect" if request.method == "GET" else "post"
        src = request.args if binding == "redirect" else request.form
        info = sc.describe_logout_request(src["SAMLRequest"], binding) if src.get("SAMLRequest") else {}
        # Microsoft는 로그아웃 화면 안에서 이 요청을 보내므로 브라우저가 SEN 쿠키를 붙이지 않을 수 있다.
        # 그래서 NameID(ImmutableID)로 사용자를 찾아, 그 사용자가 이 시각 전에 시작한 SEN 세션을 서버에서 끝낸다.
        target = uid_by_immutable_id.get(info.get("name_id", "")) \
            if info.get("type") == "LogoutRequest" and info.get("issuer") == sc.ENTRA_SP_ENTITY_ID else None
        if target:
            with lock:
                ended[target] = time.time()
        log("logout_request", binding=binding, paramKeys=sorted(src.keys()), uid=session.get("uid"), endedUid=target,
            fetchDest=request.headers.get("Sec-Fetch-Dest"), fetchSite=request.headers.get("Sec-Fetch-Site"), **info)
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
