# 학교별 Microsoft 365 테넌트 SSO PoC

학교마다 따로 있는 Microsoft 365 테넌트를 그대로 두고, **SAML 2.0 IdP 한 벌**에 도메인 페더레이션으로 연결하는 PoC입니다.
학생·교사는 IdP 계정(`아이디@joowon.me`) 하나로 로그인하고, 각 학교 테넌트의 Microsoft 365에 SSO로 들어갑니다.

> 테스트 전용입니다. 실제 업무 계정을 쓰지 마세요.

## 구성

| 폴더 | 내용 |
|---|---|
| `idp/` | 테스트 IdP(Flask). 도메인별 Issuer·로그인 주소, 응답 서명, 학교 선택, 포털, 기록 |
| `pages/` | 로그인 화면(GitHub Pages). 로그인 처리·서명은 `idp/`가 맡음 |
| `graph/` | Microsoft Graph 일괄 설정 스크립트(현황 점검, ImmutableID, 페더레이션, 인증서 교체, 원복) |
| `tools/` | 토큰 도우미, 테넌트 준비, 테스트 데이터·계정 생성, 배포, 로그인 종단 시험 |
| `tests/` | Graph 스크립트 오프라인 시험(가짜 테넌트) |

```text
학생 ─▶ Teams·Office ─▶ Microsoft 로그인(학교 계정 입력)
          ▲                     │ 도메인이 페더레이션됨
          │                     ▼
          │        auth.joowon.me/saml/m365/<학교 도메인>/sso
          │                     │ 로그인 필요 시
          │                     ▼
          │        login.joowon.me (GitHub Pages 로그인 화면)
          │                     │ 아이디@joowon.me + 비밀번호
          └──── 서명된 SAML 응답(학교 도메인 Issuer, NameID=ImmutableID, IDPEmail=UPN)
```

## 핵심 설계

- **테넌트 구분**: Microsoft는 모든 테넌트가 같은 SP 식별값(`urn:federation:MicrosoftOnline`)을 쓰고 요청에 사용자 정보가 없다. 그래서 IdP는 **로그인 주소의 도메인**으로 학교 테넌트를 구분한다.
- **도메인별 Issuer**: Entra ID는 페더레이션 도메인마다 고유한 Issuer를 요구한다. IdP는 응답마다 `https://auth.joowon.me/saml/m365/<도메인>`을 Issuer로 쓴다.
- **늘지 않는 것**: IdP 서버 대수, 서명 인증서(1개를 모든 도메인에 등록), Microsoft 쪽 SP 등록(1개).
- **라우팅 실험**: `id.joowon.me`은 학생이 학교와 무관한 아이디로 앱에 로그인할 때 IdP가 학교 테넌트로 돌려 보내는 방식(문서에 없는 동작)을 시험하는 도메인이다.
- **2단계 인증(TOTP)**: 학교 도메인에 `requireMfa: true`가 있거나 계정에 `mfa` 플래그가 있으면, IdP가 그 학교로 응답하기 전에 인증 앱 6자리 코드를 받는다(이미 통과한 세션은 생략, 같은 코드 재사용 불가). 실제로 통과한 세션에만 MFA 수행 표시(`multipleauthn`)를 넣는다.

## 테스트 계정 역할

| IdP 아이디 | 연결 | 확인하려는 것 |
|---|---|---|
| `student01`, `teacher01` | 학교 A | 기본 로그인 |
| `student02` | 학교 B | 기본 로그인(학교 B는 2단계 인증 필요) |
| `multi01` | 학교 A·B | 두 학교 SSO, 라우팅 시 학교 선택 |
| `mfa01` | 학교 A | 계정 단위 2단계 인증 → MFA 수행 표시(`multipleauthn`) |
| `nomap01` | 학교 A | Entra 쪽 ImmutableID 없음 → 거부 |
| `badissuer01` | 학교 A | 등록 안 된 Issuer → 거부 |
| `badsig01` | 학교 A | 서명 변조 → 거부 |

## PoC 결과 (2026-11-12)

자동 시험 `tools/e2e_signin.py`로 Microsoft 로그인부터 토큰 발급까지 실제 테넌트에서 확인했다.
학교 A는 MFA 정책이 없는 테넌트, 학교 B는 조건부 액세스로 전체 사용자 MFA가 필수인 테넌트다.

| ID | 시나리오 | 결과 |
|---|---|---|
| A1 | 앱 시작(domain_hint) → 학교 A | 성공, 토큰 테넌트 = 학교 A |
| A2 | 앱 시작(login_hint) → 학교 B | 성공(IdP 2단계 인증 후), 토큰 테넌트 = 학교 B |
| A3 | Microsoft 로그인 화면에 학교 아이디 직접 입력 | 성공 |
| B1 → B1b | 겸임교사가 학교 A 로그인 뒤 같은 브라우저로 학교 B | 성공, 학교 B는 비밀번호 없이 2단계 인증만 |
| B2a | 등록 안 된 Issuer | 거부(AADSTS50107) |
| B2b | 서명 변조 | 거부(AADSTS500069) |
| C1 / C1b | Entra 쪽 ImmutableID 없음 | 거부(AADSTS90019 / 테넌트 지정 시 AADSTS90072) |
| C7 | 계정 단위 2단계 인증(학교 A) | 성공 |
| F0 → F1 | 앱이 재인증(prompt=login) 요구 | IdP에 전달되지 않음, IdP 세션으로 바로 통과 |
| R1 | ④ 통합 아이디 → 학교 B(다른 테넌트) | 성공, 토큰 테넌트 = 학교 B |
| R2 | ④ 통합 아이디 → 학교 A(같은 테넌트) | 성공 |
| R3 | ④ 겸임교사 통합 아이디 → 학교 선택(학교 B) | 성공 |
| R4 | ④ Microsoft 로그인 화면에 통합 아이디 직접 입력 | 성공, 토큰 테넌트 = 학교 B |
| P1 / P2 | IdP 포털 링크 → Microsoft 365 웹 | 성공(학교 A / 학교 B) |
| I1 / I2 | IdP 시작(요청 없이 보내는 응답) → Microsoft 365 | Entra가 받아들여 로그인 세션 생성. Microsoft 365 웹은 로그인된 계정 타일을 보여 줌 |
| 인증서 교체 | IdP 서명을 next 인증서로 전환(테넌트에는 next 등록만 된 상태) | 두 테넌트 모두 성공 |

확인한 동작

- Entra는 IdP에 HTTP POST로 요청한다. 요청은 서명이 없고 NameID 형식은 persistent이며 ForceAuthn이 없다. 폼 값은 `SAMLRequest`, `RelayState`, `username`(login_hint)이다.
- 사용자 이름 입력 없이 조용히 로그인되면(앱·포털 시작 + IdP 세션) Microsoft의 [도메인 확인 대화상자](https://support.microsoft.com/en-us/office/domain-confirmation-dialog)가 한 번 뜬다. 아이디를 직접 입력하면 뜨지 않는다.
- MFA 필수 테넌트에서 IdP가 MFA 수행 표시를 보내지 않으면 Entra MFA 등록 화면으로 넘어가 로그인이 끝나지 않는다. 표시를 보내면 Entra 로그인 로그에 "MFA requirement satisfied by claim in the token"이 남는다.
- ④ 라우팅은 테넌트 A에 페더레이션한 도메인으로 시작한 로그인에 학교 B 도메인 Issuer로 답해도 학교 B로 로그인됐다. 문서에 없는 동작이므로 운영 채택 전에 Microsoft 확인이 필요하다.
- `promptLoginBehavior`를 `nativeSupport`로 바꿔도 재인증 요구가 IdP에 전달되지 않았다. 재인증 주기는 IdP 세션 수명으로 통제해야 한다.
- 인증서 교체는 next 사전 등록 → IdP 서명 전환 → 테넌트별 승격 순서로, 테넌트마다 시점을 맞추지 않아도 된다.

남은 확인(사람이 직접): Teams·Office 데스크톱/모바일 앱 로그인, 조건부 액세스 로그인 빈도, 로그아웃(SLO).

## 실행

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r idp/requirements.txt msal msal-extensions requests pytest

# IdP 단위 시험
cd idp && python -m pytest -q && cd ..

# Graph 스크립트 오프라인 시험(PowerShell 7)
pwsh -NoProfile -File tests/Test-Offline.ps1

# 테넌트 로그인(브라우저, 처음 1회) → 하위 도메인 추가와 인증용 TXT 확인
python tools/graph_token.py login <tenantId> <관리자 UPN>
python tools/prep_tenant.py <tenantId> school1.example.edu

# 테스트 데이터(비밀번호·해시·2단계 인증 비밀값은 저장소 밖에 보관)
#   --totp-file 에 인증 앱 등록용 otpauth 주소가 저장된다
cp idp/data/domains.sample.json idp/data/domains.json   # 값 수정
python tools/make_test_data.py --domains idp/data/domains.json --out-dir out --password-file ~/poc-test-password.txt \
  --totp-file ~/poc-totp.json

# 테넌트 테스트 계정 생성·라이선스(ImmutableID는 graph 스크립트 SetImmutableId로 설정)
python tools/provision_users.py --users out/entra-users.json --skus <tenantId>=<skuPartNumber>

# 배포(Azure App Service). 서명 키·비밀값 경로는 환경 변수로 넘긴다.
SUB=... RG=... APP=... KEYS_DIR=... SECRETS_FILE=... LOGIN_UI_URL=https://login.example.edu/ tools/deploy_idp.sh

# 로그인 종단 시험(실제 테넌트)
python tools/e2e_signin.py --password-file ~/poc-test-password.txt --totp-file ~/poc-totp.json --out out/e2e.json
```

페더레이션 설정은 `graph/README.md`를 참고합니다. 여러 테넌트를 다시 로그인하지 않고 처리하려면 `-AuthMode AccessToken -AccessTokenProvider { param($t) & ./.venv/bin/python ./tools/graph_token.py token $t }`를 씁니다.

## 보안

- 서명 키, 세션 키, 관리자 토큰, 테스트 비밀번호와 해시, 테넌트별 설정(`idp/data/users.json`, `domains.json`)은 저장소에 올리지 않는다.
- 관리자 기록 화면(`/admin/log`)은 토큰이 있어야 열린다.
- 페더레이션은 PoC용 하위 도메인에만 적용하고, 각 테넌트의 기존 도메인과 관리자 계정은 건드리지 않는다.

## 정리

1. `graph/Invoke-SenM365Federation.ps1 -Mode Rollback`으로 페더레이션 해제
2. 테스트 계정·하위 도메인 삭제
3. Azure 리소스 그룹 삭제, GitHub Pages 사용자 지정 도메인 해제
4. DNS 레코드(`auth`, `asuid.auth`, `school1`, `school2`, `id`, `login`) 삭제
