import base64
import datetime as dt
import html
import json
import os
import re
import sys
import time
import zlib
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLVerifier
from werkzeug.security import generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import saml_core as sc  # noqa: E402
from app import create_app, totp_at  # noqa: E402

BASE = "https://auth.test"
PW = "test-password"
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
D1, D2, DR = "school1.example.edu", "school2.example.edu", "id.example.edu"


def _keypair(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


KEYS = {"current": _keypair("current"), "next": _keypair("next")}


def _account(uid, domain):
    return {"domain": domain, "upn": f"{uid}@{domain}", "immutableId": f"imm{uid}"}


@pytest.fixture()
def data_dir(tmp_path):
    (tmp_path / "domains.json").write_text(json.dumps({
        D1: {"mode": "school", "tenantId": "t1", "schoolName": "학교 A"},
        D2: {"mode": "school", "tenantId": "t2", "schoolName": "학교 B", "requireMfa": True},
        DR: {"mode": "route", "tenantId": "t1", "schoolName": "통합"},
    }), encoding="utf-8")
    h = generate_password_hash(PW)
    users = {
        "student01": {"name": "학생01", "passwordHash": h, "accounts": [_account("student01", D1)], "flags": {}},
        "student02": {"name": "학생02", "passwordHash": h, "accounts": [_account("student02", D2)], "flags": {},
                      "totpSecret": SECRET},
        "nosecret02": {"name": "x", "passwordHash": h, "accounts": [_account("nosecret02", D2)], "flags": {}},
        "multi01": {"name": "겸임", "passwordHash": h, "accounts": [_account("multi01", D1), _account("multi01", D2)],
                    "flags": {}, "totpSecret": SECRET},
        "badissuer01": {"name": "x", "passwordHash": h, "accounts": [_account("badissuer01", D1)],
                        "flags": {"badIssuer": True}},
        "xdomain01": {"name": "x", "passwordHash": h, "accounts": [_account("xdomain01", D1)],
                      "flags": {"routeIssuerFromRequest": True}},
        "mfa01": {"name": "m", "passwordHash": h, "accounts": [_account("mfa01", D1)], "flags": {"mfa": True},
                  "totpSecret": SECRET},
    }
    (tmp_path / "users.json").write_text(json.dumps(users), encoding="utf-8")
    links_src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "links.json")
    (tmp_path / "links.json").write_text(open(links_src, encoding="utf-8").read(), encoding="utf-8")
    return str(tmp_path)


def make_app(data_dir, **overrides):
    cfg = {"DATA_DIR": data_dir, "KEYS": KEYS, "IDP_BASE_URL": BASE, "LOGIN_UI_URL": "", "SECRET_KEY": "s",
           "ADMIN_TOKEN": "admintoken", "ACTIVE_SIGNING": "current"}
    cfg.update(overrides)
    return create_app(cfg)


@pytest.fixture()
def app(data_dir):
    return make_app(data_dir)


@pytest.fixture()
def client(app):
    return app.test_client()


def authn_request(req_id="_req1", force=False, passive=False):
    attrs = f'ID="{req_id}" Version="2.0" IssueInstant="2026-11-12T00:00:00.000Z"'
    if force:
        attrs += ' ForceAuthn="true"'
    if passive:
        attrs += ' IsPassive="true"'
    return (f'<samlp:AuthnRequest {attrs} xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">urn:federation:MicrosoftOnline</Issuer>'
            '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>'
            '</samlp:AuthnRequest>').encode()


def redirect_param(xml):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return base64.b64encode(c.compress(xml) + c.flush()).decode()


def get(client, path, **kw):
    return client.get(path, base_url=BASE, **kw)


def post(client, path, **kw):
    return client.post(path, base_url=BASE, **kw)


def start_sso(client, domain, req_id="_req1", relay="RS-123", username=None, **kw):
    qs = {"SAMLRequest": redirect_param(authn_request(req_id, **kw)), "RelayState": relay}
    if username:
        qs["username"] = username
    return get(client, f"/saml/m365/{domain}/sso", query_string=qs)


def qs_of(location):
    return {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}


def k_from(location):
    q = parse_qs(urlparse(location).query)
    return q.get("k", [None])[0] or parse_qs(urlparse(q["next"][0]).query)["k"][0]


def login(client, uid, k=None):
    data = {"username": uid + "@joowon.me", "password": PW}
    if k:
        data["k"] = k
    return post(client, "/login", data=data)


def saml_from(resp):
    body = resp.get_data(as_text=True)
    m = re.search(r'name="SAMLResponse" value="([^"]+)"', body)
    assert m, body[:500]
    relay = re.search(r'name="RelayState" value="([^"]*)"', body)
    xml = base64.b64decode(html.unescape(m.group(1)))
    return etree.fromstring(xml), xml, (html.unescape(relay.group(1)) if relay else None)


def text(root, path):
    return root.findtext(path, namespaces={"saml": sc.NS_SAML, "samlp": sc.NS_SAMLP})


def current_code(offset=0):
    return totp_at(SECRET, int(time.time() // 30) + offset)


def pass_mfa(client, resp, code=None):
    assert resp.status_code == 302 and "/mfa" in resp.location, resp.status_code
    assert "인증 코드" in get(client, resp.location).get_data(as_text=True)
    q = {k: v[0] for k, v in parse_qs(urlparse(resp.location).query).items()}
    r = post(client, "/mfa", data={**q, "code": code or current_code()})
    assert r.status_code == 302, r.status_code
    return get(client, r.location)


def full_flow(client, domain, uid, req_id="_req1"):
    r = start_sso(client, domain, req_id)
    assert r.status_code == 302 and "/login" in r.location
    r = login(client, uid, k_from(r.location))
    assert r.status_code == 302 and "/saml/continue" in r.location
    return get(client, r.location)


# --- saml_core ---

def test_signed_response_structure():
    key, cert = KEYS["current"]
    xml = sc.build_response(issuer=f"{BASE}/saml/m365/{D1}", in_response_to="_r", name_id="imm", upn="u@" + D1,
                            key_pem=key, cert_pem=cert)
    XMLVerifier().verify(xml, x509_cert=cert, expect_references=1)
    root = etree.fromstring(xml)
    assertion = root.find(f"{{{sc.NS_SAML}}}Assertion")
    assert [etree.QName(c).localname for c in assertion][:2] == ["Issuer", "Signature"]
    assert root.get("Destination") == sc.ENTRA_ACS and root.get("InResponseTo") == "_r"
    assert text(root, ".//saml:Audience") == sc.ENTRA_SP_ENTITY_ID
    nameid = root.find(f".//{{{sc.NS_SAML}}}NameID")
    assert nameid.text == "imm" and nameid.get("Format") == sc.NAMEID_PERSISTENT
    assert text(root, ".//saml:Attribute[@Name='IDPEmail']/saml:AttributeValue") == "u@" + D1


def test_tampered_response_fails_verification():
    key, cert = KEYS["current"]
    xml = sc.build_response(issuer="x", in_response_to="_r", name_id="n", upn="u@x", key_pem=key, cert_pem=cert,
                            tamper=True)
    with pytest.raises(Exception):
        XMLVerifier().verify(xml, x509_cert=cert)


def test_parse_request_both_bindings():
    xml = authn_request("_abc", force=True)
    r = sc.parse_authn_request(redirect_param(xml), "redirect")
    assert (r["id"], r["issuer"], r["force_authn"]) == ("_abc", sc.ENTRA_SP_ENTITY_ID, True)
    assert sc.parse_authn_request(base64.b64encode(xml).decode(), "post")["id"] == "_abc"


# --- 앱 흐름 ---

def test_sso_flow_uses_domain_issuer_and_echoes_relaystate(client):
    root, xml, relay = saml_from(full_flow(client, D1, "student01"))
    XMLVerifier().verify(xml, x509_cert=KEYS["current"][1])
    assert text(root, "saml:Issuer") == f"{BASE}/saml/m365/{D1}"
    assert root.get("InResponseTo") == "_req1" and relay == "RS-123"
    assert text(root, ".//saml:NameID") == "immstudent01"
    assert text(root, ".//saml:AuthnContextClassRef") == sc.AC_PASSWORD


def test_second_tenant_uses_existing_session(client):
    full_flow(client, D1, "multi01")
    r = start_sso(client, D2, "_req2")
    assert r.status_code == 302 and "/saml/continue" in r.location
    root, _, _ = saml_from(pass_mfa(client, get(client, r.location)))  # 학교 B는 2단계 인증만 추가로 요구
    assert text(root, "saml:Issuer") == f"{BASE}/saml/m365/{D2}"
    assert text(root, ".//saml:Attribute/saml:AttributeValue") == f"multi01@{D2}"
    assert text(root, ".//saml:AuthnContextClassRef") == sc.AC_MFA


def test_route_domain_single_account_answers_with_school_issuer(client):
    root, _, _ = saml_from(pass_mfa(client, full_flow(client, DR, "student02")))
    assert text(root, "saml:Issuer") == f"{BASE}/saml/m365/{D2}"


def test_route_domain_multi_account_shows_chooser(client):
    r = full_flow(client, DR, "multi01")
    body = r.get_data(as_text=True)
    assert "어느 학교로 로그인할까요" in body
    k = re.search(r'name="k" value="([^"]+)"', body).group(1)
    root, _, _ = saml_from(pass_mfa(client, post(client, "/saml/continue", data={"k": k, "domain": D2})))
    assert text(root, "saml:Issuer") == f"{BASE}/saml/m365/{D2}"  # 2단계 인증 뒤에도 고른 학교 유지


def test_unlinked_tenant_is_refused(client):
    r = full_flow(client, D1, "student02")
    assert r.status_code == 403


def test_bad_issuer_flag(client):
    root, _, _ = saml_from(full_flow(client, D1, "badissuer01"))
    assert text(root, "saml:Issuer") == f"{BASE}/saml/m365/unregistered.invalid"


def test_route_issuer_from_request_flag_only_affects_route_domain(client):
    root, _, _ = saml_from(full_flow(client, DR, "xdomain01"))
    assert text(root, "saml:Issuer") == f"{BASE}/saml/m365/{DR}"
    assert text(root, ".//saml:Attribute/saml:AttributeValue") == f"xdomain01@{D1}"
    r = start_sso(client, D1, "_req2")  # 같은 세션으로 학교 도메인에서 시작하면 학교 Issuer 그대로
    root, _, _ = saml_from(get(client, r.location))
    assert text(root, "saml:Issuer") == f"{BASE}/saml/m365/{D1}"


def test_mfa_flag_sets_authn_context(client):
    root, _, _ = saml_from(pass_mfa(client, full_flow(client, D1, "mfa01")))
    assert text(root, ".//saml:AuthnContextClassRef") == sc.AC_MFA


def test_wrong_and_reused_totp_rejected(app):
    c = app.test_client()
    r = full_flow(c, D2, "student02")
    q = {k: v[0] for k, v in parse_qs(urlparse(r.location).query).items()}
    bad = "000000" if current_code() != "000000" else "111111"
    assert post(c, "/mfa", data={**q, "code": bad}).status_code == 401
    code = current_code()
    saml_from(pass_mfa(c, r, code))
    c2 = app.test_client()
    r2 = full_flow(c2, D2, "student02", "_req2")
    q2 = {k: v[0] for k, v in parse_qs(urlparse(r2.location).query).items()}
    assert post(c2, "/mfa", data={**q2, "code": code}).status_code == 401


def test_require_mfa_without_secret_is_refused(client):
    assert full_flow(client, D2, "nosecret02").status_code == 403


def test_launch_steps_up_for_mfa_school(client):
    full_flow(client, D1, "multi01")
    r = get(client, f"/portal/launch?domain={D2}&app=0")
    root, _, relay = saml_from(pass_mfa(client, r))
    assert root.get("InResponseTo") is None and text(root, ".//saml:AuthnContextClassRef") == sc.AC_MFA


def test_passive_request_without_session_returns_nopassive(client):
    root, _, _ = saml_from(start_sso(client, D1, passive=True))
    assert root.find(f".//{{{sc.NS_SAMLP}}}StatusCode/{{{sc.NS_SAMLP}}}StatusCode").get("Value") == sc.STATUS_NO_PASSIVE
    assert root.find(f"{{{sc.NS_SAML}}}Assertion") is None


def test_force_authn_requires_login_again(client):
    full_flow(client, D1, "student01")
    r = start_sso(client, D1, "_req9", force=True)
    assert r.status_code == 302 and "/login" in r.location


def test_login_failure_returns_error(client):
    r = start_sso(client, D1)
    k = k_from(r.location)
    r = post(client, "/login", data={"username": "student01", "password": "wrong", "k": k})
    assert r.status_code == 302 and "err=1" in r.location


def test_external_login_ui_redirect(data_dir):
    c = make_app(data_dir, LOGIN_UI_URL="https://login.test/").test_client()
    r = start_sso(c, D1)
    q = parse_qs(urlparse(r.location).query)
    assert r.location.startswith("https://login.test/?")
    assert q["k"][0] and q["api"][0] == BASE and q["school"][0] == "학교 A"
    r = post(c, "/login", data={"username": "student01", "password": "wrong", "k": q["k"][0]})
    assert r.location.startswith("https://login.test/?") and "err=1" in r.location


def test_admin_log_requires_token(client):
    assert get(client, "/admin/log.json").status_code == 404
    full_flow(client, D1, "student01")
    entries = get(client, "/admin/log.json?token=admintoken").get_json()["entries"]
    events = [e["event"] for e in entries]
    assert {"authn_request", "login_ok", "saml_response"} <= set(events)
    req = next(e for e in entries if e["event"] == "authn_request")
    assert req["binding"] == "redirect" and "SAMLRequest" in req["paramKeys"]


def test_metadata_per_domain(client):
    root = etree.fromstring(get(client, f"/saml/m365/{D2}/metadata").data)
    assert root.get("entityID") == f"{BASE}/saml/m365/{D2}"
    assert len(root.findall(f".//{{{sc.NS_DS}}}X509Certificate")) == 2


def test_idp_initiated_launch(client):
    full_flow(client, D1, "student01")
    root, xml, relay = saml_from(get(client, f"/portal/launch?domain={D1}&app=1"))
    XMLVerifier().verify(xml, x509_cert=KEYS["current"][1])
    assert root.get("InResponseTo") is None and relay == "https://teams.microsoft.com/"


# --- Entra가 넘기는 username(입력한 아이디) 처리 ---

def test_route_hint_prefills_login(client):
    r = start_sso(client, DR, username=f"Student02@{DR}")
    assert r.status_code == 302 and "/login" in r.location
    assert qs_of(r.location)["user"] == "student02"


def test_school_hint_is_not_prefilled(client):
    r = start_sso(client, D1, username=f"student01@{D1}")
    assert "user" not in qs_of(r.location)


def test_shared_pc_hint_mismatch_forces_login(client):
    full_flow(client, D1, "student01")
    r = start_sso(client, DR, "_req2", username=f"student02@{DR}")
    q = qs_of(r.location)
    assert "/login" in r.location and q["err"] == "switch" and q["user"] == "student02"
    # 로그인 화면을 건너뛰고 바로 이어 가려 해도 막힌다
    assert "/login" in get(client, f"/saml/continue?k={q['k']}").location
    r = login(client, "student02", q["k"])
    root, _, _ = saml_from(pass_mfa(client, get(client, r.location)))
    assert text(root, ".//saml:Attribute/saml:AttributeValue") == f"student02@{D2}"


def test_school_hint_mismatch_forces_login_without_prefill(client):
    full_flow(client, D1, "multi01")
    r = start_sso(client, D1, "_req2", username=f"student01@{D1}")
    q = qs_of(r.location)
    assert "/login" in r.location and q["err"] == "switch" and "user" not in q


def test_matching_hint_reuses_session(client):
    full_flow(client, D1, "multi01")
    assert "/saml/continue" in start_sso(client, D1, "_req2", username=f"MULTI01@{D1}").location
    assert "/saml/continue" in start_sso(client, DR, "_req3", username=f"multi01@{DR}").location


def test_passive_request_with_other_user_returns_nopassive(client):
    full_flow(client, D1, "student01")
    root, _, _ = saml_from(start_sso(client, DR, "_req2", username=f"student02@{DR}", passive=True))
    assert root.find(f".//{{{sc.NS_SAMLP}}}StatusCode/{{{sc.NS_SAMLP}}}StatusCode").get("Value") == sc.STATUS_NO_PASSIVE


def test_force_authn_cannot_be_skipped(client):
    full_flow(client, D1, "student01")
    r = start_sso(client, D1, "_req9", force=True)
    assert "/login" in get(client, f"/saml/continue?k={qs_of(r.location)['k']}").location
