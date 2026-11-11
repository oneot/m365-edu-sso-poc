# SEN스쿨 ↔ Microsoft 365 도메인 페더레이션 스크립트 (초안 v0.1)

학교별 Microsoft 365 테넌트의 기존 도메인을 SEN스쿨 IdP에 SAML 2.0으로 페더레이션하는 작업을 일괄 점검·구성하는 PowerShell 스크립트 초안입니다. 실제 테넌트에서는 아직 실행해 보지 않았습니다. PoC 테넌트에서 먼저 검증하세요.

## 파일

| 파일 | 설명 |
| --- | --- |
| `Invoke-SenM365Federation.ps1` | 본 스크립트. Graph v1.0 REST를 `Invoke-MgGraphRequest`로 호출 |
| `federation.config.sample.psd1` | IdP 설정값(Issuer·로그인 URL 템플릿, 인증서 경로, MFA 동작) 예시 |
| `tenants.sample.csv` | 대상 목록: `TenantId, SchoolName, DomainName, Wave` |
| `immutableid.sample.csv` | ImmutableID 매핑: `TenantId, UserPrincipalName, ImmutableId` |

## 준비

- PowerShell 7.2 이상, `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
- 설정 파일을 복사해 값을 채웁니다. `IssuerUriTemplate`과 `PassiveSignInUriTemplate`의 `{domain}`은 학교 루트 도메인으로 바뀝니다.
  - Issuer는 도메인마다 고유해야 하며, 테넌트가 달라도 같은 값을 쓸 수 없습니다.
  - 로그인 URL에 도메인을 넣는 이유: Entra ID가 IdP로 보내는 SAML 인증 요청에는 사용자 정보가 없습니다. URL로 대상 학교 테넌트를 구분합니다.
- 인증서는 공개 인증서(.cer)만 넣습니다. 개인 키가 든 파일은 거부합니다.

## 권한

테넌트마다 아래 권한이 필요합니다. 위임 방식은 로그인한 계정의 역할과 앱의 위임 권한이 모두 있어야 합니다.

| 모드 | Graph 권한(위임·애플리케이션 공통 이름) | 로그인 계정 역할(최소) |
| --- | --- | --- |
| Inventory | Domain.Read.All, User.Read.All, RoleManagement.Read.Directory | Global Reader |
| SetImmutableId | Domain.Read.All, User.ReadWrite.All | User Administrator(관리자 역할이 없는 사용자 대상). 관리자 역할을 가진 사용자는 Privileged Authentication Administrator 이상 |
| Federate | Domain.ReadWrite.All, Domain-InternalFederation.ReadWrite.All, User.Read.All, RoleManagement.Read.Directory | Domain Name Administrator(+ 사전 점검 조회용 Global Reader) |
| SetNextCert, PromoteNextCert | Domain.Read.All, Domain-InternalFederation.ReadWrite.All | Domain Name Administrator |
| Rollback | Domain.ReadWrite.All, Domain-InternalFederation.ReadWrite.All | Domain Name Administrator |

- 페더레이션 설정의 최소 권한은 `Domain-InternalFederation.ReadWrite.All`이고, Domain Name Administrator로 실행할 수 있습니다. 도메인 `authenticationType`을 바꿀 때도 이 권한이 필요합니다(Graph 문서).
- `onPremisesImmutableId` 변경은 '민감 작업'이라 역할 제한이 있습니다(Graph 문서).
- 위임 방식은 테넌트마다 Microsoft Graph Command Line Tools(또는 기관 등록 앱)에 대한 관리자 동의가 한 번 필요합니다. 앱 인증서 방식은 다중 테넌트 앱에 대한 관리자 동의가 테넌트마다 필요합니다.
- GDAP는 Partner Center(CSP) 기능입니다. LSP가 CSP 자격과 학교 테넌트 GDAP 관계를 갖고 있는지, 위 역할을 GDAP로 받을 수 있는지 먼저 확인하세요.

## 실행 순서

```powershell
# 1. 현황·준비 상태 점검(읽기 전용)
./Invoke-SenM365Federation.ps1 -Mode Inventory -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1

# 2. IdP 매핑표 생성(오프라인) → IdP에 적재
./Invoke-SenM365Federation.ps1 -Mode ExportIdpMap -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1

# 3. 페더레이션 전에 ImmutableID 설정(먼저 -WhatIf)
./Invoke-SenM365Federation.ps1 -Mode SetImmutableId -TenantsCsv ./tenants.csv -ImmutableIdCsv ./immutableid.csv -WhatIf
./Invoke-SenM365Federation.ps1 -Mode SetImmutableId -TenantsCsv ./tenants.csv -ImmutableIdCsv ./immutableid.csv -Confirm:$false

# 4. 페더레이션(먼저 -WhatIf). Wave 열로 단계 적용
./Invoke-SenM365Federation.ps1 -Mode Federate -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1 -Wave 0 -WhatIf
./Invoke-SenM365Federation.ps1 -Mode Federate -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1 -Wave 0 -Confirm:$false

# 5. 서명 인증서 교체: 새 인증서 선등록 → IdP가 새 키로 서명 시작 → 승격
./Invoke-SenM365Federation.ps1 -Mode SetNextCert -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1 -Confirm:$false
./Invoke-SenM365Federation.ps1 -Mode PromoteNextCert -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1 -Confirm:$false

# 6. 원복(PoC 테넌트 전용 권장)
./Invoke-SenM365Federation.ps1 -Mode Rollback -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1
```

여러 테넌트를 무인으로 돌릴 때는 `-AuthMode AppCertificate -ClientId <앱 ID> -Certificate <X509Certificate2>`(macOS·Linux) 또는 `-CertificateThumbprint`(Windows 인증서 저장소)를 씁니다.

이미 받아 둔 위임 토큰을 쓰려면 `-AuthMode AccessToken -AccessTokenProvider { param($t) <토큰을 출력하는 명령> $t }`를 씁니다. 스크립트는 `/organization`으로 토큰의 테넌트가 대상과 같은지 확인합니다. 예: `{ param($t) & ./.venv/bin/python ./tools/graph_token.py token $t }`

## 출력(`./out`)

| 파일 | 내용 |
| --- | --- |
| `<Mode>-result_*.csv` | 건별 결과(OK, SKIP, FAIL, WHATIF, DECLINED) |
| `inventory-domains_*.csv` | 테넌트별 도메인, 인증 유형, 사용자 수, ImmutableID 설정 수, 동기화 사용자 수 |
| `readiness_*.csv` | 대상 도메인별 준비 상태(Ready, AlreadyFederated, Blocked)와 차단 사유 |
| `unmapped-users_*.csv` | ImmutableID가 없는 활성 사용자. 전환하면 로그인할 수 없습니다 |
| `idp-map_*.csv` | IdP 적재용 매핑표 |

## 안전장치

- 쓰기 모드는 건마다 확인을 요청합니다. `-WhatIf`로 계획만 볼 수 있습니다.
- 연결된 테넌트 ID가 대상과 다르면 중단합니다.
- 다른 IdP로 이미 페더레이션된 도메인, 하위 도메인, `onmicrosoft.com` 도메인은 대상에서 제외합니다.
- ImmutableID가 없는 활성 사용자가 있으면 `Federate`를 막습니다(`-AllowUnmappedUsers`로 해제).
- 페더레이션 영향을 받지 않는 관리형 도메인(onmicrosoft.com 포함) UPN의 활성 전역 관리자(비상 계정)가 없으면 `Federate`를 막습니다.
- Entra Connect로 동기화되는 사용자가 있으면 `Federate`를 막습니다(별도 검토 대상).
- `SetImmutableId`는 기존 값을 덮어쓰지 않고, 테넌트 안에서 값이 겹치면 거부합니다.
- 같은 Issuer로 이미 설정된 도메인은 건너뛰므로 다시 실행해도 안전합니다.

## 알려진 제한

- 가짜 테넌트 5개로 Graph 호출을 흉내 낸 오프라인 테스트(`tests/Test-Offline.ps1`, 34개 검사)를 통과했습니다. 실제 테넌트 실행 결과는 저장소 README의 PoC 결과를 참고하세요.
- 학교 도메인이 기본 도메인이면 경고만 표시합니다. MS 문서상 페더레이션 도메인은 기본 도메인으로 지정할 수 없어, 기본 도메인을 먼저 바꿔야 하는지는 PoC에서 확인해야 합니다.
- 기본 도메인 변경, 사용자 생성, 페더레이션 후 ImmutableID 변경은 포함하지 않습니다. 페더레이션 도메인 사용자는 생성할 때 ImmutableID를 넣어야 하며, M365 관리 센터에서는 만들 수 없습니다(MS 문서).
- 관리자 역할을 가진 사용자의 ImmutableID는 User Administrator로 바꿀 수 없어 FAIL로 기록됩니다.
- Entra Connect로 동기화되는 테넌트는 차단합니다(별도 설계 필요).
- 테넌트마다 전체 사용자를 조회하므로 사용자 수가 많으면 시간이 걸립니다.
- 1,400개 테넌트를 위임 방식으로 돌리면 로그인을 반복해야 합니다. 무인 실행은 앱 인증서 방식이나 AccessToken 방식을 권장합니다.

## 근거 문서

- [Use a SAML 2.0 Identity Provider for Single Sign On](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-saml-idp): SP-Lite 요건, 지원 클라이언트, 전환·원복 영향
- [Create internalDomainFederation](https://learn.microsoft.com/en-us/graph/api/domain-post-federationconfiguration?view=graph-rest-1.0): 권한, 최소 역할, 속성
- [Update internalDomainFederation](https://learn.microsoft.com/en-us/graph/api/internaldomainfederation-update?view=graph-rest-1.0), [Update domain](https://learn.microsoft.com/en-us/graph/api/domain-update?view=graph-rest-1.0)
- [Federating multiple Microsoft Entra IDs with single AD FS](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-single-adfs-multitenant-federation): 도메인별 고유 Issuer, 설정 후 authenticationType 변경 예시
- [Multiple Domain Support for Federating](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-multiple-domains): 하위 도메인은 상위 도메인 Issuer 사용
- [user resource type](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0): `onPremisesImmutableId` 제약('$'·'_' 불가, 페더레이션 도메인 사용자 생성 시 필수)
- [Working with users: Sensitive actions](https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#sensitive-actions): ImmutableID 변경 가능 역할
- [Can't assign federated domain to user in M365 Admin Center](https://learn.microsoft.com/en-us/troubleshoot/microsoft-365/admin/domain-management/cannot-assign-federated-domain-to-user): 관리 센터 생성 불가, 기본 도메인 지정 불가
- [Configure federation between Google Workspace and Microsoft Entra ID](https://learn.microsoft.com/en-us/education/windows/configure-aad-google-trust): 교육용 SAML 페더레이션 선례
- [GDAP supported workloads](https://learn.microsoft.com/en-us/partner-center/customers/gdap-supported-workloads)
