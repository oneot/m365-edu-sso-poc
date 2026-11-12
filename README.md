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
| `tools/` | 토큰 도우미, 테넌트 준비, 테스트 데이터·계정 생성, 배포, 로그인 종단 시험, 브라우저 시연 |
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
- **라우팅 실험**: 루트 `joowon.me`(IdP 아이디 도메인, SEN의 `@senedu.kr` 역할)와 `id.joowon.me`는 학생이 학교와 무관한 아이디로 앱에 로그인할 때 IdP가 학교 테넌트로 돌려 보내는 방식(문서에 없는 동작)을 시험하는 도메인이다. 둘 다 학교 A 테넌트(라우팅 테넌트 역할)에 페더레이션되어 있다. 결과는 아래 '④ 라우팅 도메인 심층 PoC' 절 참고.
- **2단계 인증(TOTP)**: 계정에 `mfa` 플래그가 있으면(또는 학교 도메인에 `requireMfa: true`), IdP가 그 학교로 응답하기 전에 인증 앱 6자리 코드를 받는다(이미 통과한 세션은 생략, 같은 코드 재사용 불가). 실제로 통과한 세션에만 MFA 수행 표시(`multipleauthn`)를 넣는다.
- **MFA 시나리오**: 테넌트는 기본적으로 MFA를 요구하지 않고, 테넌트마다 한 계정(`mfa01`, `mfa02`)만 Entra 사용자별 MFA(`perUserMfaState: enforced`)로 MFA 필수다. IdP는 이 두 계정에만 2단계 인증을 하고 MFA 수행 표시를 보내 Entra의 요구를 충족한다.

## 테스트 계정 역할

| IdP 아이디 | 연결 | 확인하려는 것 |
|---|---|---|
| `student01` | 학교 A | 기본 로그인 |
| `teacher01` | 학교 A | 기본 로그인. 통합 아이디로 들어오면 일부러 라우팅 도메인 Issuer로 응답(R11) |
| `student02` | 학교 B | 기본 로그인 |
| `multi01` | 학교 A·B | 두 학교 SSO, 라우팅 시 학교 선택 |
| `mfa01` | 학교 A | 학교 A의 MFA 필수 계정(Entra 사용자별 MFA + IdP 2단계 인증) |
| `mfa02` | 학교 B | 학교 B의 MFA 필수 계정(Entra 사용자별 MFA + IdP 2단계 인증) |
| `nomap01` | 학교 A | Entra 쪽 ImmutableID 없음 → 거부 |
| `badissuer01` | 학교 A | 등록 안 된 Issuer → 거부 |
| `badsig01` | 학교 A | 서명 변조 → 거부 |
| `hack01` | 학교 B | 보안 데모 S1: 유출 계정으로 Tor 로그인 → 로그인 위험 정책(차단) |
| `hack02` | 학교 B | 보안 데모 S2: Tor 로그인 + IdP 2단계 인증 → 로그인 위험 정책(MFA 요구) |
| `hack04` | 학교 B | 보안 데모 S3: Tor 로그인, IdP 2단계 인증 없음 → 로그인 위험 정책(MFA 요구) |
| `hack03` | 학교 B | 보안 데모 S4: 관리자 침해 확인 → 사용자 위험 정책(차단), CAE 세션 종료 |

## PoC 결과 (2026-11-12)

자동 시험 `tools/e2e_signin.py`로 Microsoft 로그인부터 토큰 발급까지 실제 테넌트에서 확인했다.
학교 A는 Microsoft 365 E5 데모 테넌트, 학교 B는 Microsoft 365 A5(Education) 데모 테넌트다. 두 테넌트 모두 기본적으로 MFA를 요구하지 않고,
테넌트마다 한 계정(`mfa01`, `mfa02`)만 Entra 사용자별 MFA로 MFA 필수다.

> Microsoft 파트너·벤더 테넌트에는 Microsoft가 "Multifactor authentication for Microsoft partners and vendors" 조건부 액세스 정책(전체 사용자 MFA)을 자동으로 만든다.
> 학교 A에는 이 정책에 활성 사용자 전체 동적 그룹(`ALL`) 제외가 이미 있었고, 학교 B에도 같은 제외를 추가해 기본 MFA를 껐다. 그다음 위 두 계정에만 사용자별 MFA를 켰다.

| ID | 시나리오 | 결과 |
|---|---|---|
| A1 | 앱 시작(domain_hint) → 학교 A | 성공, 토큰 테넌트 = 학교 A |
| A2 | 앱 시작(login_hint) → 학교 B | 성공, 토큰 테넌트 = 학교 B |
| A3 | Microsoft 로그인 화면에 학교 아이디 직접 입력 | 성공 |
| B1 → B1b | 겸임교사가 학교 A 로그인 뒤 같은 브라우저로 학교 B | 성공, 학교 B는 비밀번호 입력 없이 바로 |
| B2a | 등록 안 된 Issuer | 거부(AADSTS50107) |
| B2b | 서명 변조 | 거부(AADSTS500069) |
| C1 / C1b | Entra 쪽 ImmutableID 없음 | 거부(AADSTS90019 / 테넌트 지정 시 AADSTS90072) |
| C7 / C8 | MFA 필수 계정(학교 A `mfa01`, 학교 B `mfa02`) | 성공. 이 두 계정만 IdP 2단계 인증을 거치고, 나머지 계정은 거치지 않음 |
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
- Entra가 MFA를 요구하는 계정(조건부 액세스 또는 사용자별 MFA)에 IdP가 MFA 수행 표시를 보내지 않으면 Entra MFA 등록 화면으로 넘어가 로그인이 끝나지 않는다. 표시를 보내면 Entra 로그인 로그에 "MFA requirement satisfied by claim in the token"이 남는다.
- ④ 라우팅은 테넌트 A에 페더레이션한 도메인으로 시작한 로그인에 학교 B 도메인 Issuer로 답해도 학교 B로 로그인됐다. 문서에 없는 동작이므로 운영 채택 전에 Microsoft 확인이 필요하다.
- `promptLoginBehavior`를 `nativeSupport`로 바꿔도 재인증 요구가 IdP에 전달되지 않았다. 재인증 주기는 IdP 세션 수명으로 통제해야 한다.
- 인증서 교체는 next 사전 등록 → IdP 서명 전환 → 테넌트별 승격 순서로, 테넌트마다 시점을 맞추지 않아도 된다.

앱 확인(사람이 직접): Teams·Outlook 앱 로그인 정상.

남은 확인: Windows 기기 로그인(아래 'Windows 기기 로그인' 절), 조건부 액세스 로그인 빈도, 로그아웃(SLO).

## ④ 라우팅 도메인 심층 PoC (2026-11-12)

```text
학생 ─ 통합 아이디(학번@id 도메인, 실제로는 @senedu.kr) 입력
   ▼ Entra 홈 영역 검색: id 도메인은 라우팅 테넌트에서 IdP로 페더레이션됨
IdP ─ 학생 확인 → 학교 계정 찾기(여럿이면 선택) → 학교 도메인 Issuer로 응답(NameID=학교 계정 ImmutableID)
   ▼ Entra가 Issuer로 학교 테넌트를 찾아 학교 계정으로 로그인
```

| ID | 시나리오 | 결과 |
|---|---|---|
| R5 | 학교 B 테넌트를 지정한 앱(SharePoint처럼 테넌트 고정 주소) | 성공 |
| R6 | 라우팅 테넌트를 지정한 앱에 학교 B 학생 | 거부(AADSTS50020), 예상대로 |
| R7 | 공용 PC: 앞 학생의 IdP 세션이 남은 브라우저에서 다른 학생이 통합 아이디 입력 | 수정 전 **앞 학생으로 로그인됨** → IdP 수정 후 다시 로그인 요구, 입력한 학생으로 로그인 |
| R8b / R8c | 무음 SSO(prompt=none) + 학교 계정 힌트 / 힌트 없음 | 성공 |
| R8a | 무음 SSO + 통합 아이디 힌트 | AADSTS50058(로그인된 계정과 힌트가 다름) |
| R9 | 포털 링크 `domain_hint=라우팅 도메인`(IdP 로그인 상태) | 성공, 비밀번호 입력 없음 |
| R10 | Microsoft 365 웹 링크 `login_hint=통합 아이디` | 성공 |
| R11 | 잘못된 구현: IdP가 라우팅 도메인 Issuer로 응답 | 거부(AADSTS5000820, Federated Token Validation) |
| R12 | MFA 필수 계정(`mfa02`)이 통합 아이디로 로그인 | 성공, IdP 2단계 인증 후 학교 B |
| R13 / R14 | Microsoft 로그인 화면에 IdP 아이디 그대로 입력(`student01@joowon.me`, `student02@joowon.me`) | 성공(학교 A / 학교 B), SEN 로그인 화면에 아이디가 미리 채워짐 |
| R15 | 겸임교사 IdP 아이디 그대로(`multi01@joowon.me`) | 학교 선택 화면 뒤 성공(학교 B) |
| 브라우저 | Outlook 웹(student02 → 학교 B), Teams 웹(multi01 → 학교 선택 → 학교 A), Microsoft 365 웹(포털 링크) | 모두 학교 계정으로 앱 진입(`tools/browser_route_demo.py`) |

확인한 동작

- Entra는 토큰 Issuer의 realm 루트 도메인과 매핑된 사용자 UPN의 루트 도메인을 비교한다([Federated Token Validation Policy](https://learn.microsoft.com/en-us/entra/identity/users/strengthen-federated-sign-in-security), 기본 적용). ④는 학교 도메인 Issuer로 답하므로 통과하고, 라우팅 도메인 Issuer로 답하면 막힌다.
- 로그인 기록은 학생의 학교 테넌트에만 남는다. 라우팅 테넌트에는 남지 않는다.
- 로그인 힌트로 시작하면 도메인 확인 대화상자에 라우팅 테넌트의 회사 브랜딩과 학교 계정이 함께 표시된다("school2…을(를) 신뢰합니까?").
- Entra는 사용자가 입력한 아이디를 `username`으로 IdP에 넘긴다. IdP는 이 값이 세션 사용자와 다르면 다시 로그인시켜야 한다(R7).
- 앱에 표시되는 계정은 학교 계정이다. 통합 아이디를 무음 로그인 힌트로 쓰는 앱은 AADSTS50058 뒤 대화형 로그인으로 넘어간다.

공개 자료 조사

- ④를 허용하거나 금지하는 공식 문장은 없다. 다만 IssuerUri는 "used by Microsoft Entra ID to identify the domain that the token is associated with"([다중 도메인](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-multiple-domains))이고, [AD FS 1대·다수 테넌트 가이드](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-single-adfs-multitenant-federation)도 Issuer를 사용자 UPN 접미사로 정한다. ④와 같은 원리다.
- [SAML 2.0 IdP 문서](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-saml-idp): 타사 IdP의 구성·문제 해결은 Microsoft 지원 대상이 아니고, 지원 클라이언트가 제한적이다.
- MSAL(iOS/macOS, .NET)은 loginHint와 다른 계정이 돌아와도 오류를 내지 않는다(소스 코드 기준). 사용자 이름으로 캐시를 찾는 앱은 실패한다. Outlook(메일 주소로 계정 찾기), OneDrive, Windows WAM은 공개 근거가 없다.
- 같은 구조의 공개 선례는 찾지 못했다. SWITCH edu-ID(스위스)는 학교 도메인을 입력하는 기본안 구조이고, 덴마크 EasyIQ는 Microsoft 로그인 밖(자체 링크)에서 학교를 찾는다.

④를 쓸 때의 설계 요건

1. 응답 Issuer는 반드시 학생 학교 도메인의 Issuer(R11).
2. Entra가 넘기는 `username`을 세션 사용자와 비교(R7).
3. 학교가 여럿이면 학교 선택 화면(R3).
4. 라우팅 테넌트에는 도메인 인증·페더레이션만 필요하고 사용자는 필요 없다.
5. 학교별 도메인 페더레이션(기본안)은 그대로 필요하다. ④는 그 위의 편의 계층이고, 끄면 학교 계정 입력으로 돌아간다.
6. 운영 전 Microsoft 지원 범위 확인, AADSTS5000820·50107 모니터링.

남은 확인(사람이 직접): OneDrive 앱, Windows 로그인 화면에 통합 아이디 입력.

## Windows 기기 로그인(PoC 미시험)

SAML 2.0 IdP 계정으로 Windows 11에 로그인할 수 있다. 다만 **기기 가입은 SAML로 할 수 없고**, Windows 판·가입 방식 조건이 있다. 이 PoC는 Windows 기기에서 시험하지 않았다.

| 항목 | 공식 문서 내용 | 이 설계에서 |
|---|---|---|
| 기기 가입 | 페더레이션 계정으로 기기를 Entra에 가입하는 프로토콜은 WS-Fed만 지원. SAML IdP는 프로비저닝 패키지(PPKG)나 Autopilot 자체 배포 모드로 가입 | 학생이 첫 설정 화면에서 SEN 계정으로 직접 가입하는 방식은 불가. 학교·교육청이 일괄 가입 |
| 1인 1기기 | Federated sign-in. Windows 11 Education·Pro Education 22H2(KB5022913) 이상, Windows 11 SE | 공유 PC 모드, '마지막 로그인 사용자 표시 안 함', Take a Test 키오스크와 함께 쓸 수 없음 |
| 공용 기기 | Web sign-in. Windows 11 22H2(KB5030310) 이상, **Entra 가입 기기만**(하이브리드·도메인 가입 불가). Pro·Enterprise·Education 모두 지원 | 페더레이션되지 않은 계정(로컬 계정 포함)은 로그인 불가. 프로필 자동 삭제 정책 권장 |
| 공통 설정 | `ConfigureWebSignInAllowedUrls`에 IdP 도메인 등록. 선호 테넌트(`PreferredAadTenantDomainName`)를 넣으면 계정 선택 화면 생략 | 학교 기기마다 자기 학교 도메인을 선호 테넌트로 설정 |
| 계정 일치 | IdP가 보낸 ImmutableID로 Entra 사용자를 찾음(대소문자 구분). 페더레이션 사용자의 값을 바꾸려면 클라우드 전용으로 돌렸다가 다시 페더레이션 | PoC와 같은 조건 |
| Windows 11 SE | 2026년 10월 지원 종료 | SE 기기는 교체 계획 필요 |

시험할 것: 학교 계정·통합 아이디(④)로 로그인 화면 진입, 공용 PC에서 학생 교대 로그인, Windows Hello for Business 등록 뒤 로그인, 로그아웃 뒤 IdP 세션 처리.

근거: [Configure federated sign-in for Windows devices](https://learn.microsoft.com/en-us/education/windows/federated-sign-in), [Web sign-in for Windows](https://learn.microsoft.com/en-us/windows/security/identity-protection/web-sign-in/)

## 운영 보안 기준(Microsoft 쪽)

학교 테넌트 약 1,400개(계정 약 100만 개)를 IdP 하나에 페더레이션해 운영할 때 Microsoft 쪽에 갖출 보안 기준이다. SEN IdP 자체의 보안(자격 증명 보호, MFA, 서명키 보관)은 IdP 쪽 기준으로 따로 정한다.

### 신뢰 구조의 변화

| 항목 | 현재(학교별 Entra 계정) | 페더레이션 이후 |
|---|---|---|
| 자격 증명 확인 | 학교 테넌트의 Entra ID | SEN IdP |
| Entra의 신뢰 근거 | 비밀번호·MFA를 직접 확인 | SEN 서명키로 서명된 SAML 토큰(Issuer, ImmutableID, MFA 클레임) |
| Entra가 보는 신호 | 비밀번호 시도, 토큰, 로그인 환경 | 토큰, 로그인 환경(IP·기기·위치). 비밀번호 시도는 보이지 않음 |
| 침해 영향 범위 | 계정·학교 단위 | 서명키나 IdP가 침해되면 페더레이션된 전 학교 테넌트 |

| 구분 | SEN IdP | Entra ID(학교 테넌트) |
|---|---|---|
| 인증 | 자격 증명 확인, MFA, 비밀번호 공격 방어 | IdP 토큰 검증(서명, Issuer, 도메인 일치) |
| 키·설정 | 서명키 보관·교체·폐기 | 페더레이션 설정 보호(관리자 권한 통제, 변경 감시) |
| 탐지·대응 | IdP 로그인 이상 탐지 | 토큰·로그인 위험 탐지, 위험 기반 차단, 세션 폐기 |

### 위협 근거(공개 자료)

| 위협 | 근거 |
|---|---|
| 서명키 탈취·토큰 위조 | Microsoft 디지털 방어 보고서 2025: 신원 보안에서 가장 치명적인 시나리오는 서명키 탈취다. 쿠팡(과기정통부 조사 결과, 2026.2): 인증시스템 서명키로 인증 토큰을 위·변조해 3,367만 건이 유출됐다. 관문 서버에 위·변조 검증 절차가 없었고, 퇴사자 키 갱신 절차가 미비했다 |
| 페더레이션 설정 악용 | Octo Tempest(2023), Storm-0501(2024·2025): 관리자 권한으로 페더레이션 도메인을 추가·변경한 뒤, MFA 충족 클레임을 넣은 위조 SAML 토큰으로 임의 사용자로 로그인했다. Storm-0501은 ImmutableID로 대상 사용자를 지정했다 |
| 토큰 탈취·AiTM 피싱 | 디지털 방어 보고서 2026: 2026년 상반기 AiTM 피싱·토큰 탈취 비중이 두 배 이상 늘었고, AiTM이 피싱 기법의 44.6%다 |
| 교육 분야 계정 탈취 | 교육부: 2025년 교육기관 사이버침해 86,738건(전년 대비 36% 증가). 2026년 9~10월 477개 교육기관의 교육용 계정 11.3만 개가 정확한 아이디·비밀번호 로그인으로 탈취됐다(교육부 집계, 보도). PowerSchool(2024.12): MFA 없는 지원 포털 계정 하나로 학생 정보가 대량 유출됐다. 디지털 방어 보고서 2026: 공공 부문 중 연구·교육이 최다 표적이다(38%) |

### 위협별 통제

| 위협 | 통제 | 기준 |
|---|---|---|
| 서명키 탈취·토큰 위조 | ID 보호 `Token issuer anomaly`(SAML 토큰 발급자 침해 징후) → 사용자 위험 → 위험 기반 조건부 액세스로 차단. 사용자 위험이 높으면 CAE 지원 클라이언트에서 Exchange·SharePoint·Teams 접근이 수 분 안에 끊긴다 | P2 |
| 유출 자격 증명으로 IdP 통과 | `Unfamiliar sign-in properties`·`Atypical travel`·`Verified threat actor IP`(실시간), `Malicious IP address` → 로그인 위험 정책으로 차단 | P2 |
| 세션 토큰 재사용 | `Anomalous token` → 차단·세션 폐기 | P2 |
| 학교 관리자 계정 탈취 → 페더레이션 변경 | PIM(상시 관리자 권한 없음, 승인·시간 제한 활성화). 감사 로그 `Set domain authentication`·`Set federation settings on domain`·`Verify domain` 감시 | P2 |
| 약 1,400개 테넌트 관제 | 위험 사용자·위험 탐지 Graph API, 위험 사용자 알림, 위험 로그인 90일 보관 | P2 |
| AiTM 피싱 | AiTM 탐지, Defender XDR 공격 자동 차단(세션 폐기 등), 교직원 피싱 모의훈련 | A5 |
| 기기 감염(인포스틸러) | Defender for Endpoint P2(EDR) | A5 |
| 사고 조사 | Audit(Premium): Entra·Exchange·OneDrive·SharePoint 감사 기록 1년 보관(표준 180일) | A5 |

### 기준

- **필수: Entra ID P2.** 위 통제 가운데 위험 탐지, 위험 기반 차단, PIM, 위험 정보 API는 P2부터 제공된다.
- **권장: A5.** P2 범위에 AiTM 탐지, 공격 자동 차단, 기기 EDR, 감사 기록 1년 보관이 더해진다.

| 기능 | A3 | A3 + Entra ID P2 | A5 |
|---|---|---|---|
| SAML 페더레이션·조건부 액세스 | ○ | ○ | ○ |
| 위험 탐지(토큰·로그인) | 제한(상세·이력 없음) | ○ | ○ |
| 위험 기반 차단·Microsoft 관리형 위험 정책 | × | ○ | ○ |
| PIM | × | ○ | ○ |
| 위험 정보 Graph API·알림 | × | ○ | ○ |
| 위험 로그인 보관 | 30일 | 90일 | 90일 |
| AiTM 탐지 | × | × | ○ |
| 공격 자동 차단 | × | × | ○ |
| 피싱 모의훈련 | × | × | ○ |
| 기기 EDR | × | × | ○ |
| 감사 기록 보관 | 180일 | 180일 | 1년 |

A3는 Microsoft 365 A3(Entra ID P1) 기준이다. Office 365 A3는 Entra ID Free라 조건부 액세스가 없다.

### 설계·운영 요구사항

1. 고위험 로그인은 'MFA 요구'가 아니라 '차단'으로 설정한다. `federatedIdpMfaBehavior`가 `acceptIfMfaDoneByFederatedIdp`(이 PoC 설정)이면 IdP가 보낸 MFA 클레임이 Entra의 MFA 요구를 충족하므로, 위조 토큰에는 MFA 요구가 효과가 없다(Octo Tempest 기법). 보안 데모 S2에서 IdP MFA 클레임으로 위험 로그인이 통과하고 위험 탐지까지 자동 해소되는 것을 확인했다.
2. 위험할 때 SEN IdP에 추가 인증을 요구하려면 `enforceMfaByFederatedIdp`와 SEN IdP의 추가 인증 처리가 필요하다(이 PoC에서 미검증).
3. 비밀번호 기반 탐지(`Leaked credentials`, `Password spray`)는 비밀번호가 Entra에 없어 적용되지 않는다. 비밀번호 공격 방어는 SEN IdP가 맡는다.
4. Microsoft 관리형 위험 정책은 P2 테넌트에 보고 전용으로 생성되고, 그대로 두면 30일 이후 자동으로 켜진다. 위험 로그인 정책은 MFA를 등록하지 않은 사용자의 위험 로그인을 차단하므로(보안 데모 S3), SEN MFA 클레임이 없는 학생에게 미치는 영향을 보고 전용 기간에 확인한다.
5. P2 기능은 P2가 할당된 사용자에게 적용된다.
6. 서명키는 정기적으로 교체하고(`nextSigningCertificate` 사전 등록 방식, 이 PoC에서 검증), 담당자가 바뀌면 폐기·재발급한다.
7. A5 테넌트는 Defender 포털을 한 번 열어 Defender XDR을 켜고, Entra ID Protection 알림 수집을 'High and medium risk detections'로 바꾼다(기본값은 높음만). IdP MFA 클레임으로 위험이 해소되면 인시던트도 자동 종료되므로, 자동 종료된 익명 IP 인시던트도 검토한다(보안 데모 S5).
8. 확인 필요
   - 학교 라이선스가 Microsoft 365 A3인지 Office 365 A3인지
   - AiTM 탐지의 문서상 요건(Microsoft 365 E5)이 A5에도 적용되는지
   - A5 학생 사용 혜택의 Defender for Office 365는 Plan 1이라 피싱 모의훈련 대상은 교직원

### 출처

- 위협: [Microsoft 디지털 방어 보고서 2025](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/bade/documents/products-and-services/en-us/security/Microsoft-Digital-Defense-Report-2025-v5-21Nov25.pdf)(p.17), [2026](https://aka.ms/Microsoft-Digital-Defense-Report-2026)(p.45·64·85), [Octo Tempest](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/), [Storm-0501(2024)](https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/), [Storm-0501(2025)](https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/), [쿠팡 조사 결과(과기정통부)](https://m.korea.kr/briefing/policyBriefingView.do?newsId=156744092), [교육부 2025 침해 통계](https://www.moe.go.kr/boardCnts/viewRenew.do?boardID=294&boardSeq=105948&lev=0&searchType=null&statusYN=W&page=1&s=moe&m=020402&opType=N), [교육용 계정 집계(한국일보)](https://www.hankookilbo.com/news/article/A2026102217490005554), [PowerSchool(TechCrunch)](https://techcrunch.com/2025/01/17/malware-stole-internal-powerschool-passwords-from-engineers-hacked-computer/)
- 기능·라이선스: [ID 보호 라이선스](https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection), [위험 탐지 목록](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks), [위험 기반 조건부 액세스](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-sign-in), [CAE](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation), [PIM 라이선스](https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals), [관리형 정책](https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies), [로그 보존](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention), [감사 활동 목록](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities), [공격 자동 차단](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption), [Audit](https://learn.microsoft.com/en-us/purview/audit-solutions-overview), [교육용 A3](https://learn.microsoft.com/en-us/microsoft-365/education/guide/0-start-standard/standard-license)·[A5](https://learn.microsoft.com/en-us/microsoft-365/education/guide/0-start-advanced/advanced-license), [federatedIdpMfaBehavior](https://learn.microsoft.com/en-us/graph/api/resources/internaldomainfederation)

## 보안 데모: 위험 로그인 탐지·차단(2026-11-12)

학교 B 테넌트(Microsoft 365 A5, Entra ID P2 포함)에서 계정 유출을 가정한 로그인을 재현했다. 재현 방법은 Microsoft의 위험 시뮬레이션 방법(Tor 익명 IP, 관리자 침해 확인)을 따랐고, 데모용 조건부 액세스 정책은 데모 계정 그룹에만 적용했다. 익명 IP 탐지(위험 중간)가 확실히 정책에 걸리도록 데모 정책은 '낮음 이상'으로 두었다. 공격자는 SEN 아이디·비밀번호를 가진 것으로 가정하므로 SEN IdP 로그인은 모두 통과한다.

| 계정 | 데모 정책(조건부 액세스) | 재현 |
|---|---|---|
| `hack01` | 로그인 위험 낮음 이상 → 차단 | Tor 경유 로그인 |
| `hack02` | 로그인 위험 낮음 이상 → MFA 요구 | Tor 경유 로그인, IdP 2단계 인증까지 통과 |
| `hack04` | 로그인 위험 낮음 이상 → MFA 요구 | Tor 경유 로그인, IdP 2단계 인증 없음 |
| `hack03` | 사용자 위험 높음 → 차단 | 평소 위치에서 로그인해 CAE 토큰을 받은 뒤 관리자가 침해 확인 |

| ID | 시나리오 | 결과 | Microsoft 쪽 기록 |
|---|---|---|---|
| S0 | 대조군: 평소 위치에서 4개 계정 로그인 | 모두 성공 | 로그인 위험 없음, 데모 정책 미적용 |
| S1 | `hack01` Tor 로그인 | 차단(AADSTS53003) | ID 보호 `anonymizedIPAddress` 실시간 탐지(위험 중간) → S1 정책 `failure` |
| S2 | `hack02` Tor 로그인 + IdP 2단계 인증 | 로그인 성공 | 같은 탐지. 'MFA 요구'가 IdP MFA 클레임으로 충족되고, 탐지 3건이 `remediated`(`userPassedMFADrivenByRiskBasedPolicy`)로 자동 해소돼 사용자 위험이 남지 않음 |
| S3 | `hack04` Tor 로그인, IdP 2단계 인증 없음 | 차단(AADSTS53004) | 위험 세션이라 MFA 등록이 막힘 → 정책 `failure`, 사용자 위험 중간으로 남음 |
| S4 | `hack03` 관리자 침해 확인 | 만료까지 24시간 남은 CAE 토큰이 8.6분 뒤 거부(401 claims challenge). 새 토큰·새 로그인 차단(AADSTS530032) | `adminConfirmedUserCompromised`(위험 높음) → CAE 중요 이벤트, S4 정책 |
| S5 | Defender XDR(A5): S1~S3 알림·인시던트 | 공격 약 3분 뒤 'Anonymous IP address' 알림이 사용자별 인시던트로 생성됨. `hack01`·`hack04` 인시던트는 활성, `hack02` 인시던트 3건은 자동으로 '해결됨' | Entra ID Protection 알림(`azureAdIdentityProtection`, 위험 중간). `hack02`는 IdP MFA 클레임으로 위험이 해소돼 인시던트도 자동 종료 |

확인한 동작

- 익명 IP 탐지는 실시간이라 로그인 중에 정책이 적용된다. Entra는 SEN 로그인 뒤 SAML 응답을 보낸 브라우저의 IP(Tor 출구)로 위험을 평가한다.
- Tor 로그인(S1·S3)에서 이 데모 테넌트의 Microsoft 관리형 위험 재인증 정책(파트너·벤더용, 보고 전용)이 `reportOnlyInterrupted`로 기록됐다. 켜져 있었다면 재인증을 요구했을 것이다. 학교 테넌트(P2, 보안 기본값 꺼짐)에는 같은 성격의 관리형 정책 'Multifactor authentication and reauthentication for risky sign-ins'가 보고 전용으로 생성된다.
- IdP MFA 클레임은 위험 기반 'MFA 요구'를 충족하고 위험도 해소한다(S2). 그래서 고위험은 '차단'으로 설정한다(운영 보안 기준 요구사항 1).
- 관리자 침해 확인 뒤 Microsoft Graph도 CAE로 기존 토큰을 거부했다(8.6분). 위험 반영과 CAE 전파에 수 분이 걸린다.
- Defender XDR은 관리자가 Defender 포털에 처음 들어가면 켜진다(이 테넌트는 약 30분 걸림). Entra ID Protection 알림 수집 기본값은 '높음만'(2025-12-11부터)이라, 위험 '중간' 탐지(익명 IP 등)를 인시던트로 보려면 설정 → Microsoft Defender XDR → Alert service settings에서 'High and medium risk detections'로 바꿔야 한다.
- IdP MFA 클레임으로 위험이 해소되면 Defender XDR 인시던트도 자동으로 '해결됨'이 된다(S2·S5). 활성 목록만 보면 놓치므로, 자동 해결된 익명 IP 인시던트도 검토 대상에 넣는다.
- S1~S3는 3회 실행(Tor 출구 IP는 매번 다름) 모두 같은 결과였다.
- 새 계정으로 재현할 수 없는 탐지: 처음 보는 로그인 환경(30일 이력 필요), 비정상 이동(14일·10회 이력 필요). 토큰 발급자 이상, AiTM, 공격 자동 차단은 안전하게 재현할 방법이 없다(Microsoft 문서: 그 밖의 탐지는 안전하게 시뮬레이션할 수 없음).

발표 시연 순서

1. Tor Browser(조직이 Tor를 제한하면 가상 머신)로 `https://myapps.microsoft.com` 접속 → `hack01@school2.joowon.me` → SEN 로그인 → 차단 화면
2. Entra 관리 센터 → ID 보호 → 위험한 로그인·위험 탐지에서 익명 IP 탐지, 로그인 로그의 조건부 액세스 탭에서 S1 정책 `failure` 확인
3. `hack02`로 같은 순서 → 로그인 성공, 위험 탐지가 '수정됨'으로 바뀐 것 확인(고위험을 '차단'으로 두는 이유)
4. 터미널에서 `security_demo.py cae --confirm` 실행 → 수 분 뒤 401, 새 로그인 차단
5. Defender 포털 → 인시던트에서 사용자별 'Anonymous IP address involving one user' 확인(`hack01`·`hack04` 활성, `hack02` 자동 해결)
6. 끝나면 `security_demo.py reset`으로 데모 계정 위험 해제(S4를 다시 하려면 먼저 실행)

근거: [위험 시뮬레이션](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-simulate-risk), [위험 탐지 목록](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks), [CAE](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation), [Defender XDR 켜기](https://learn.microsoft.com/en-us/defender-xdr/m365d-enable), [알림 서비스 설정](https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts)

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

# ④ 실제 웹앱 브라우저 시연(헤드리스 Chrome, 임시 프로필, 단계별 화면 저장)
pip install playwright
python tools/browser_route_demo.py --password-file ~/poc-test-password.txt --totp-file ~/poc-totp.json --out-dir out/route-demo

# 보안 데모(학교 B). 필요한 관리자 권한은 tools/security_demo.py 머리말 참고(GRAPH_EXTRA_SCOPES)
python tools/provision_users.py --users out/entra-users.json --skus <tenantId>=M365EDU_A5_STUDENT \
  --immutableid-csv out/immutableid.csv          # 페더레이션된 도메인에 데모 계정 생성
python tools/security_demo.py setup              # 데모 그룹·조건부 액세스 정책
python tools/security_demo.py attack --accounts hack01 hack02 hack03 hack04 \
  --password-file ~/poc-test-password.txt --totp-file ~/poc-totp.json    # S0 대조군
SUB=... RG=... PASSWORD_FILE=~/poc-test-password.txt TOTP_FILE=~/poc-totp.json \
  tools/run_tor_attack.sh                        # S1~S3: Azure 컨테이너에서 Tor 경유 로그인(회사 기기에 Tor 설치 없음)
python tools/security_demo.py cae --confirm --password-file ~/poc-test-password.txt   # S4
python tools/security_demo.py report             # 위험 탐지·로그인 기록·Defender 알림
python tools/security_demo.py reset              # 데모 계정 위험 해제
```

페더레이션 설정은 `graph/README.md`를 참고합니다. 여러 테넌트를 다시 로그인하지 않고 처리하려면 `-AuthMode AccessToken -AccessTokenProvider { param($t) & ./.venv/bin/python ./tools/graph_token.py token $t }`를 씁니다.

## 보안

- 서명 키, 세션 키, 관리자 토큰, 테스트 비밀번호와 해시, 테넌트별 설정(`idp/data/users.json`, `domains.json`)은 저장소에 올리지 않는다.
- 관리자 기록 화면(`/admin/log`)은 토큰이 있어야 열린다.
- 페더레이션은 PoC용 하위 도메인에만 적용하고, 각 테넌트의 기존 도메인과 관리자 계정은 건드리지 않는다.

## 정리

1. `graph/Invoke-SenM365Federation.ps1 -Mode Rollback`으로 페더레이션 해제
2. 테스트 계정·도메인(`school1`·`school2`·`id` 하위 도메인, 루트 `joowon.me`) 삭제, 사용자별 MFA 해제
3. 학교 B 테넌트: 파트너·벤더 MFA 정책 2개의 `ALL` 그룹 제외를 되돌리고 그룹 삭제
4. Azure 리소스 그룹 삭제, GitHub Pages 사용자 지정 도메인 해제
5. joowon.me DNS 레코드(`auth`, `asuid.auth`, `school1`, `school2`, `id`, `login`, 루트 TXT `MS=ms…`) 삭제
6. 보안 데모: `security_demo.py reset`(위험 해제), `security_demo.py cleanup --delete-users`(데모 정책·그룹·계정 삭제). Defender XDR의 Entra ID Protection 알림 설정은 필요하면 기본값('High risk detections')으로 되돌린다.
