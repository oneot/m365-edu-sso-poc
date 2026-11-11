"""SAML 2.0(SP-Lite) 응답 생성·서명과 AuthnRequest 해석.

Microsoft Entra ID 도메인 페더레이션 요건에 맞춘다.
- 어설션 서명 필수(RSA-SHA256, exclusive c14n, enveloped), 서명 위치는 Issuer 바로 뒤
- NameID: persistent 형식, 값은 Entra 사용자의 onPremisesImmutableId
- IDPEmail 속성: Entra 사용자의 UPN
- Audience: urn:federation:MicrosoftOnline, 응답 수신 주소: https://login.microsoftonline.com/login.srf
"""
import base64
import datetime as dt
import uuid
import zlib

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree
from signxml import (
    CanonicalizationMethod,
    DigestAlgorithm,
    SignatureConstructionMethod,
    SignatureMethod,
    XMLSigner,
)

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"

ENTRA_SP_ENTITY_ID = "urn:federation:MicrosoftOnline"
ENTRA_ACS = "https://login.microsoftonline.com/login.srf"
NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
AC_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
AC_MFA = "http://schemas.microsoft.com/claims/multipleauthn"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
STATUS_NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
_MAX_REQUEST_BYTES = 64 * 1024


def new_id():
    return "_" + uuid.uuid4().hex


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def fmt(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def decode_request(saml_request, binding):
    raw = base64.b64decode(saml_request, validate=False)
    if len(raw) > _MAX_REQUEST_BYTES:
        raise ValueError("SAMLRequest가 너무 큽니다")
    if binding == "redirect":
        try:
            out = zlib.decompressobj(-15).decompress(raw, _MAX_REQUEST_BYTES)
            return out
        except zlib.error:
            return raw
    return raw


def parse_authn_request(saml_request, binding):
    root = etree.fromstring(decode_request(saml_request, binding), parser=_PARSER)
    if root.tag != f"{{{NS_SAMLP}}}AuthnRequest":
        raise ValueError("SAML AuthnRequest가 아닙니다")
    policy = root.find(f"{{{NS_SAMLP}}}NameIDPolicy")
    return {
        "id": root.get("ID"),
        "issuer": (root.findtext(f"{{{NS_SAML}}}Issuer") or "").strip(),
        "issue_instant": root.get("IssueInstant"),
        "destination": root.get("Destination"),
        "acs_url": root.get("AssertionConsumerServiceURL"),
        "force_authn": root.get("ForceAuthn") == "true",
        "is_passive": root.get("IsPassive") == "true",
        "nameid_format": policy.get("Format") if policy is not None else None,
        "signed": root.find(f"{{{NS_DS}}}Signature") is not None,
    }


def describe_logout_request(saml_request, binding):
    try:
        root = etree.fromstring(decode_request(saml_request, binding), parser=_PARSER)
    except Exception:  # 기록용이라 실패해도 로그아웃은 진행
        return {"parse_error": True}
    return {
        "type": etree.QName(root).localname,
        "id": root.get("ID"),
        "issuer": (root.findtext(f"{{{NS_SAML}}}Issuer") or "").strip(),
        "name_id": (root.findtext(f"{{{NS_SAML}}}NameID") or "").strip(),
    }


def _el(parent, ns, tag, text=None, **attrs):
    e = etree.SubElement(parent, f"{{{ns}}}{tag}", {k: v for k, v in attrs.items() if v is not None})
    if text is not None:
        e.text = text
    return e


def build_assertion(*, issuer, name_id, upn, in_response_to, mfa=False, auth_instant=None, now=None,
                    lifetime=dt.timedelta(minutes=10)):
    t = now or utcnow()
    aid = new_id()
    a = etree.Element(f"{{{NS_SAML}}}Assertion", nsmap={"saml": NS_SAML}, ID=aid, IssueInstant=fmt(t), Version="2.0")
    _el(a, NS_SAML, "Issuer", issuer)
    # signxml이 이 자리에 서명을 넣는다. SAML 스키마상 서명은 Issuer 바로 뒤에 와야 한다.
    etree.SubElement(a, f"{{{NS_DS}}}Signature", nsmap={"ds": NS_DS}, Id="placeholder")
    subject = _el(a, NS_SAML, "Subject")
    _el(subject, NS_SAML, "NameID", name_id, Format=NAMEID_PERSISTENT)
    sc = _el(subject, NS_SAML, "SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    _el(sc, NS_SAML, "SubjectConfirmationData", InResponseTo=in_response_to,
        NotOnOrAfter=fmt(t + dt.timedelta(minutes=5)), Recipient=ENTRA_ACS)
    cond = _el(a, NS_SAML, "Conditions", NotBefore=fmt(t - dt.timedelta(minutes=2)), NotOnOrAfter=fmt(t + lifetime))
    _el(_el(cond, NS_SAML, "AudienceRestriction"), NS_SAML, "Audience", ENTRA_SP_ENTITY_ID)
    attr = _el(_el(a, NS_SAML, "AttributeStatement"), NS_SAML, "Attribute", Name="IDPEmail")
    _el(attr, NS_SAML, "AttributeValue", upn)
    authn = _el(a, NS_SAML, "AuthnStatement", AuthnInstant=fmt(auth_instant or t), SessionIndex=aid)
    _el(_el(authn, NS_SAML, "AuthnContext"), NS_SAML, "AuthnContextClassRef", AC_MFA if mfa else AC_PASSWORD)
    return a, aid


def sign_assertion(assertion, assertion_id, key_pem, cert_pem):
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        signature_algorithm=SignatureMethod.RSA_SHA256,
        digest_algorithm=DigestAlgorithm.SHA256,
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )
    return signer.sign(assertion, key=key_pem, cert=cert_pem, reference_uri=assertion_id)


def _response_shell(issuer, in_response_to, now):
    resp = etree.Element(f"{{{NS_SAMLP}}}Response", nsmap={"samlp": NS_SAMLP, "saml": NS_SAML},
                         ID=new_id(), Version="2.0", IssueInstant=fmt(now), Destination=ENTRA_ACS)
    if in_response_to:
        resp.set("InResponseTo", in_response_to)
    _el(resp, NS_SAML, "Issuer", issuer)
    return resp


def build_response(*, issuer, in_response_to, name_id, upn, key_pem, cert_pem, mfa=False, auth_instant=None,
                   tamper=False, now=None):
    """서명된 SAML Response XML(bytes)을 만든다. tamper=True면 서명 뒤 값을 바꿔 서명 검증이 실패하게 한다."""
    t = now or utcnow()
    assertion, aid = build_assertion(issuer=issuer, name_id=name_id, upn=upn, in_response_to=in_response_to,
                                     mfa=mfa, auth_instant=auth_instant, now=t)
    signed = sign_assertion(assertion, aid, key_pem, cert_pem)
    if tamper:
        value = signed.find(f".//{{{NS_SAML}}}AttributeValue")
        value.text = "tampered." + value.text
    resp = _response_shell(issuer, in_response_to, t)
    status = _el(resp, NS_SAMLP, "Status")
    _el(status, NS_SAMLP, "StatusCode", Value=STATUS_SUCCESS)
    resp.append(signed)
    return etree.tostring(resp, encoding="utf-8")


def build_status_response(*, issuer, in_response_to, second_level=None, message=None, now=None):
    """실패 상태 응답(예: IsPassive 요청인데 로그인 세션이 없을 때 NoPassive)."""
    resp = _response_shell(issuer, in_response_to, now or utcnow())
    status = _el(resp, NS_SAMLP, "Status")
    top = _el(status, NS_SAMLP, "StatusCode", Value=STATUS_RESPONDER)
    if second_level:
        _el(top, NS_SAMLP, "StatusCode", Value=second_level)
    if message:
        _el(status, NS_SAMLP, "StatusMessage", message)
    return etree.tostring(resp, encoding="utf-8")


def cert_der_b64(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode()


def build_metadata(*, entity_id, sso_url, slo_url, certs_pem):
    ed = etree.Element(f"{{{NS_MD}}}EntityDescriptor", nsmap={"md": NS_MD, "ds": NS_DS}, entityID=entity_id)
    idp = _el(ed, NS_MD, "IDPSSODescriptor", protocolSupportEnumeration=NS_SAMLP, WantAuthnRequestsSigned="false")
    for pem in certs_pem:
        kd = _el(idp, NS_MD, "KeyDescriptor", use="signing")
        x509data = _el(_el(kd, NS_DS, "KeyInfo"), NS_DS, "X509Data")
        _el(x509data, NS_DS, "X509Certificate", cert_der_b64(pem))
    _el(idp, NS_MD, "SingleLogoutService", Binding=BINDING_REDIRECT, Location=slo_url)
    _el(idp, NS_MD, "NameIDFormat", NAMEID_PERSISTENT)
    _el(idp, NS_MD, "SingleSignOnService", Binding=BINDING_REDIRECT, Location=sso_url)
    _el(idp, NS_MD, "SingleSignOnService", Binding=BINDING_POST, Location=sso_url)
    return etree.tostring(ed, encoding="utf-8", xml_declaration=True)
