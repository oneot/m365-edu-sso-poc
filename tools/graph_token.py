"""Microsoft Graph 위임 토큰 도우미(PoC 전용).

- 클라이언트: Microsoft Graph Command Line Tools(Graph PowerShell과 같은 공개 클라이언트)
- 토큰 캐시: msal-extensions 암호화 저장소(macOS 키체인). 비밀번호는 다루지 않음.
- 테넌트별 계정을 한 캐시에 함께 보관해, 테넌트를 오가도 다시 로그인하지 않음.

사용:
  python graph_token.py login <tenantId> [loginHint]   # 브라우저 로그인(처음 1회)
  python graph_token.py token <tenantId>               # 캐시에서 액세스 토큰 출력
"""
import os
import sys

import msal
import requests
from msal_extensions import PersistedTokenCache, build_encrypted_persistence

CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Command Line Tools
SCOPES = [
    "https://graph.microsoft.com/" + s
    for s in (
        "Domain.ReadWrite.All",
        "Domain-InternalFederation.ReadWrite.All",
        "User.ReadWrite.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "Organization.Read.All",
        "Policy.Read.All",
        "AuditLog.Read.All",
        "LicenseAssignment.ReadWrite.All",
    )
]
# 추가 권한(쉼표 구분, 예: Policy.ReadWrite.AuthenticationMethod). 필요한 테넌트에서만 켠다.
SCOPES += ["https://graph.microsoft.com/" + s.strip()
           for s in os.environ.get("GRAPH_EXTRA_SCOPES", "").split(",") if s.strip()]
# 토큰 캐시(암호화 저장). 경로는 MSAL_CACHE_PATH 로 바꿀 수 있다.
CACHE_PATH = os.environ.get("MSAL_CACHE_PATH") or os.path.expanduser("~/.m365-edu-sso-poc/msal_cache.bin")
GRAPH = "https://graph.microsoft.com/v1.0"

_cache = None


def _get_cache():
    global _cache
    if _cache is None:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        _cache = PersistedTokenCache(build_encrypted_persistence(CACHE_PATH))
    return _cache


def _app(tenant):
    return msal.PublicClientApplication(
        CLIENT_ID, authority=f"https://login.microsoftonline.com/{tenant}", token_cache=_get_cache()
    )


def get_token(tenant, login_hint=None, interactive=False):
    app = _app(tenant)
    accounts = [a for a in app.get_accounts() if a.get("home_account_id", "").endswith("." + tenant)]
    for account in accounts:
        result = app.acquire_token_silent(SCOPES, account=account)
        if result and "access_token" in result:
            return result["access_token"]
    if not interactive:
        raise RuntimeError(f"캐시된 토큰 없음: {tenant}. 'login'을 먼저 실행하세요.")
    result = app.acquire_token_interactive(SCOPES, login_hint=login_hint, prompt="select_account")
    if "access_token" not in result:
        raise RuntimeError(f"로그인 실패: {result.get('error')}: {result.get('error_description')}")
    claims = result.get("id_token_claims", {})
    if claims.get("tid") != tenant:
        raise RuntimeError(f"다른 테넌트 계정으로 로그인됨: tid={claims.get('tid')}")
    return result["access_token"]


class Graph:
    def __init__(self, tenant):
        self.tenant = tenant
        self.s = requests.Session()

    def _headers(self):
        return {"Authorization": "Bearer " + get_token(self.tenant), "Content-Type": "application/json"}

    def call(self, method, path, body=None, ok=(200, 201, 204)):
        url = path if path.startswith("https://") else GRAPH + path
        r = self.s.request(method, url, headers=self._headers(), json=body, timeout=60)
        if r.status_code not in ok:
            raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:500]}")
        return r.json() if r.content else None

    def get_all(self, path):
        out, url = [], path
        while url:
            page = self.call("GET", url)
            out.extend(page.get("value", []))
            url = page.get("@odata.nextLink")
        return out


if __name__ == "__main__":
    cmd, tenant = sys.argv[1], sys.argv[2]
    if cmd == "login":
        get_token(tenant, login_hint=sys.argv[3] if len(sys.argv) > 3 else None, interactive=True)
        org = Graph(tenant).call("GET", "/organization?$select=id,displayName")["value"][0]
        print(f"로그인 완료: {org['displayName']} ({org['id']})")
    elif cmd == "token":
        print(get_token(tenant))
    else:
        raise SystemExit("usage: graph_token.py login|token <tenantId> [loginHint]")
