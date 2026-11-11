#Requires -Version 7.2
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }

<#
.SYNOPSIS
    SEN스쿨 IdP와 학교별 Microsoft 365(Entra ID) 테넌트 사이의 SAML 2.0 도메인 페더레이션을
    일괄 점검·구성합니다. (초안 v0.1, 2026-10-21)

.DESCRIPTION
    Microsoft Graph v1.0 REST API를 Invoke-MgGraphRequest로 직접 호출합니다.
    필요한 모듈은 Microsoft.Graph.Authentication 하나입니다.

    -Mode
      Inventory        읽기 전용. 도메인·사용자·ImmutableId·기존 페더레이션 현황과 전환 준비 상태를 CSV로 저장
      ExportIdpMap     오프라인. IdP에 등록할 도메인별 Issuer·로그인 URL 매핑표 생성
      SetImmutableId   쓰기. 매핑 CSV대로 onPremisesImmutableId 설정(아직 관리형인 도메인의 사용자만)
      Federate         쓰기. 사전 점검을 통과한 도메인에 federationConfiguration 생성 후 Federated 상태 확인
      SetNextCert      쓰기. 교체 예정 IdP 서명 인증서를 nextSigningCertificate로 미리 등록
      PromoteNextCert  쓰기. IdP가 새 키로 서명을 시작한 뒤 signingCertificate를 새 인증서로 교체
                       (기존 인증서는 유예용으로 nextSigningCertificate에 남김)
      Rollback         쓰기. federationConfiguration 삭제 후 Managed 상태 확인(PoC 테넌트 전용 권장)

    쓰기 모드는 모두 -WhatIf를 지원하고, 기본값으로 건마다 확인을 요청합니다(ConfirmImpact High).
    대량 실행은 -WhatIf 결과를 검토한 뒤 -Confirm:$false 로 실행하세요.

.EXAMPLE
    ./Invoke-SenM365Federation.ps1 -Mode Inventory -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1

.EXAMPLE
    ./Invoke-SenM365Federation.ps1 -Mode Federate -TenantsCsv ./tenants.csv -ConfigPath ./federation.config.psd1 -Wave 1 -WhatIf

.NOTES
    초안입니다. 운영 테넌트에 쓰기 전에 PoC 테넌트에서 Inventory → -WhatIf → 실제 실행 순서로 검증하세요.
    근거 문서와 실행 순서는 README.md에 있습니다.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Inventory', 'ExportIdpMap', 'SetImmutableId', 'Federate', 'SetNextCert', 'PromoteNextCert', 'Rollback')]
    [string] $Mode,

    # 열: TenantId, SchoolName, DomainName, Wave(선택)
    [Parameter(Mandatory)]
    [string] $TenantsCsv,

    [string] $ConfigPath,

    # 열: TenantId, UserPrincipalName, ImmutableId (SetImmutableId 모드)
    [string] $ImmutableIdCsv,

    # 지정하면 TenantsCsv에서 Wave 열이 같은 행만 처리
    [string] $Wave,

    [ValidateSet('Delegated', 'AppCertificate', 'AccessToken')]
    [string] $AuthMode = 'Delegated',

    # Delegated: 기관 자체 등록 앱을 쓸 때 지정(생략 시 Microsoft Graph Command Line Tools)
    # AppCertificate: 다중 테넌트 앱의 클라이언트 ID(필수)
    [string] $ClientId,
    [string] $CertificateThumbprint,
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

    # AccessToken: 테넌트 ID를 받아 Graph 액세스 토큰 문자열을 돌려주는 스크립트 블록
    #   예) { param($t) & ./.venv/bin/python ./tools/graph_token.py token $t }
    [scriptblock] $AccessTokenProvider,

    [string] $OutDir = (Join-Path (Get-Location) 'out'),

    # Federate: ImmutableId가 없는 활성 사용자가 있어도 진행(해당 사용자는 전환 후 로그인 불가)
    [switch] $AllowUnmappedUsers,

    # Federate: 비상 전역 관리자(페더레이션 대상 밖 관리형 도메인 계정) 확인을 건너뜀(권장하지 않음)
    [switch] $SkipBreakGlassCheck
)

$ErrorActionPreference = 'Stop'
$script:Cmdlet = $PSCmdlet
$GraphBase = 'https://graph.microsoft.com/v1.0'
$GlobalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
$ImmutableIdPattern = '^[A-Za-z0-9]{1,64}$'   # SAML IdP 문서: NameID(=ImmutableID) 최대 64자 영숫자
$MfaBehaviors = @('acceptIfMfaDoneByFederatedIdp', 'enforceMfaByFederatedIdp', 'rejectMfaByFederatedIdp')

$ScopesByMode = @{
    Inventory       = @('Domain.Read.All', 'User.Read.All', 'RoleManagement.Read.Directory')
    SetImmutableId  = @('Domain.Read.All', 'User.ReadWrite.All')
    Federate        = @('Domain.ReadWrite.All', 'Domain-InternalFederation.ReadWrite.All', 'User.Read.All', 'RoleManagement.Read.Directory')
    SetNextCert     = @('Domain.Read.All', 'Domain-InternalFederation.ReadWrite.All')
    PromoteNextCert = @('Domain.Read.All', 'Domain-InternalFederation.ReadWrite.All')
    Rollback        = @('Domain.ReadWrite.All', 'Domain-InternalFederation.ReadWrite.All')
}

$script:Results = [System.Collections.Generic.List[object]]::new()
$script:DomainRows = [System.Collections.Generic.List[object]]::new()
$script:ReadinessRows = [System.Collections.Generic.List[object]]::new()
$script:UnmappedRows = [System.Collections.Generic.List[object]]::new()

#region 공통 함수

function Get-PropValue {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Add-Result {
    param([string] $TenantId, [string] $SchoolName, [string] $Domain, [string] $Target,
          [string] $Action, [ValidateSet('OK', 'SKIP', 'FAIL', 'WHATIF', 'DECLINED')] [string] $Status, [string] $Detail)
    $script:Results.Add([pscustomobject]@{
        Time = (Get-Date).ToString('s'); Mode = $Mode; TenantId = $TenantId; SchoolName = $SchoolName
        Domain = $Domain; Target = $Target; Action = $Action; Status = $Status; Detail = $Detail
    })
    $color = switch ($Status) { 'OK' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'DarkGray' } default { 'Yellow' } }
    Write-Host ("[{0}] {1} {2} {3} {4}" -f $Status, $SchoolName, $Domain, $Target, $Detail) -ForegroundColor $color
}

function Get-NotPerformedStatus {
    if ($WhatIfPreference) { return 'WHATIF' }
    return 'DECLINED'
}

function Invoke-Graph {
    param(
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')] [string] $Method = 'GET',
        [Parameter(Mandatory)] [string] $Path,
        [object] $Body
    )
    $uri = if ($Path -match '^https://') { $Path } else { $GraphBase + $Path }
    $req = @{ Method = $Method; Uri = $uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $req.Body = $Body | ConvertTo-Json -Depth 10 -Compress
        $req.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @req
}

function Get-GraphAll {
    param([Parameter(Mandatory)] [string] $Path)
    $next = $Path
    while ($next) {
        $resp = Invoke-Graph -Path $next
        foreach ($v in @(Get-PropValue $resp 'value')) { if ($null -ne $v) { $v } }
        $next = Get-PropValue $resp '@odata.nextLink'
    }
}

function Connect-Tenant {
    param([Parameter(Mandatory)] [string] $TenantId, [string[]] $Scopes)
    if ($AuthMode -eq 'AccessToken') {
        if (-not $AccessTokenProvider) { throw '-AuthMode AccessToken에는 -AccessTokenProvider가 필요합니다.' }
        $token = [string](@(& $AccessTokenProvider $TenantId) | Select-Object -Last 1)
        if ([string]::IsNullOrWhiteSpace($token)) { throw "토큰을 받지 못했습니다: $TenantId" }
        Connect-MgGraph -AccessToken (ConvertTo-SecureString $token.Trim() -AsPlainText -Force) -NoWelcome -ErrorAction Stop | Out-Null
        $orgId = [string](@(Get-PropValue (Invoke-Graph -Path '/organization?$select=id') 'value')[0].id)
        if ($orgId -ne $TenantId) { throw "토큰의 테넌트($orgId)가 대상 테넌트($TenantId)와 다릅니다." }
        return
    }
    $p = @{ TenantId = $TenantId; NoWelcome = $true; ErrorAction = 'Stop' }
    if ($AuthMode -eq 'AppCertificate') {
        if (-not $ClientId) { throw '-AuthMode AppCertificate에는 -ClientId가 필요합니다.' }
        $p.ClientId = $ClientId
        if ($Certificate) { $p.Certificate = $Certificate }
        elseif ($CertificateThumbprint) { $p.CertificateThumbprint = $CertificateThumbprint }
        else { throw '-Certificate 또는 -CertificateThumbprint가 필요합니다.' }
    }
    else {
        $p.Scopes = $Scopes
        if ($ClientId) { $p.ClientId = $ClientId }
    }
    Connect-MgGraph @p | Out-Null
    $ctx = Get-MgContext
    if (-not $ctx -or $ctx.TenantId -ne $TenantId) {
        throw "연결된 테넌트($($ctx.TenantId))가 대상 테넌트($TenantId)와 다릅니다."
    }
}

function Get-UpnSuffix([string] $Upn) { return ($Upn -split '@')[-1].ToLowerInvariant() }

function Resolve-Template([string] $Template, [string] $Domain) {
    return $Template.Replace('{domain}', $Domain.ToLowerInvariant())
}

function Get-CertBase64 {
    param([string] $Path, [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Label 경로가 설정 파일에 없습니다." }
    $full = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path (Split-Path -Parent $ConfigPath) $Path }
    if (-not (Test-Path $full)) { throw "$Label 파일이 없습니다: $full" }
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($full)
    if ($cert.HasPrivateKey) { throw "$Label 에 개인 키가 들어 있습니다. 공개 인증서(.cer)만 사용하세요." }
    $now = Get-Date
    if ($cert.NotAfter -lt $now) { throw "$Label 이 만료되었습니다($($cert.NotAfter))." }
    if ($cert.NotAfter -lt $now.AddDays(60)) { Write-Warning "$Label 만료가 60일 이내입니다($($cert.NotAfter))." }
    Write-Host "$Label : $($cert.Subject), 만료 $($cert.NotAfter.ToString('yyyy-MM-dd')), 지문 $($cert.Thumbprint)"
    return [Convert]::ToBase64String($cert.RawData)
}

function Get-TenantSnapshot {
    param([switch] $IncludeRoles)
    $domains = @(Get-GraphAll '/domains')
    $users = @(Get-GraphAll '/users?$select=id,userPrincipalName,onPremisesImmutableId,accountEnabled,userType,onPremisesSyncEnabled&$top=999')
    $gaIds = $null
    if ($IncludeRoles) {
        try {
            $gaIds = @(Get-GraphAll "/directoryRoles(roleTemplateId='$GlobalAdminRoleTemplateId')/members?`$select=id" | ForEach-Object { $_.id })
        }
        catch {
            Write-Warning "전역 관리자 목록을 읽지 못했습니다: $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{ Domains = $domains; Users = $users; GlobalAdminIds = $gaIds }
}

# 루트 도메인을 페더레이션하면 isRoot=false 인 하위 도메인도 같은 설정을 상속합니다.
function Get-AffectedDomainSet {
    param($Domains, [string] $Root)
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $Domains) {
        $id = [string]$d.id
        if ($id -ieq $Root -or ((-not $d.isRoot) -and $id.EndsWith(".$Root", [StringComparison]::OrdinalIgnoreCase))) {
            [void]$set.Add($id)
        }
    }
    return , $set
}

function Get-EffectiveAuthType {
    param($Domains, [string] $Suffix)
    foreach ($d in $Domains) {
        $id = [string]$d.id
        if (($id -ieq $Suffix -or $Suffix.EndsWith(".$id", [StringComparison]::OrdinalIgnoreCase)) -and $d.authenticationType -eq 'Federated') {
            return 'Federated'
        }
    }
    return 'Managed'
}

function Get-FederationConfig([string] $Domain) {
    return @(Get-GraphAll "/domains/$Domain/federationConfiguration") | Select-Object -First 1
}

function Test-FederationReadiness {
    param($Snapshot, [string] $TenantId, [string] $SchoolName, [string] $Domain, [string] $ExpectedIssuer)
    $issues = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $state = 'Ready'
    $issuerNow = ''
    $d = $Snapshot.Domains | Where-Object { $_.id -ieq $Domain } | Select-Object -First 1

    if (-not $d) {
        $issues.Add('테넌트에 해당 도메인 없음')
    }
    else {
        if ($Domain -like '*.onmicrosoft.com') { $issues.Add('onmicrosoft.com 도메인은 페더레이션 불가') }
        if (-not $d.isVerified) { $issues.Add('미검증 도메인') }
        if (-not $d.isRoot) { $issues.Add('하위 도메인(상위 루트 도메인 설정을 상속)') }
        if ($d.isDefault) { $warnings.Add('기본 도메인임(MS 문서: 페더레이션 도메인은 기본 도메인으로 지정 불가). 기본 도메인 변경 필요 여부 확인') }
        if ($d.authenticationType -eq 'Federated') {
            $fed = Get-FederationConfig $Domain
            $issuerNow = [string](Get-PropValue $fed 'issuerUri')
            if ($ExpectedIssuer -and $issuerNow -eq $ExpectedIssuer) { $state = 'AlreadyFederated' }
            else { $issues.Add("이미 다른 IdP로 페더레이션됨(issuer=$issuerNow)") }
        }
    }

    $affected = Get-AffectedDomainSet $Snapshot.Domains $Domain
    $members = @($Snapshot.Users | Where-Object { $_.userType -ne 'Guest' -and $affected.Contains((Get-UpnSuffix $_.userPrincipalName)) })
    $enabled = @($members | Where-Object { $_.accountEnabled })
    $unmapped = @($enabled | Where-Object { [string]::IsNullOrEmpty($_.onPremisesImmutableId) })
    $synced = @($members | Where-Object { $_.onPremisesSyncEnabled })

    if ($state -ne 'AlreadyFederated') {
        if ($unmapped.Count -gt 0 -and -not $AllowUnmappedUsers) { $issues.Add("ImmutableId 없는 활성 사용자 $($unmapped.Count)명") }
        if ($synced.Count -gt 0) { $issues.Add("온-프레미스 동기화 사용자 $($synced.Count)명(Entra Connect 사용 테넌트는 별도 검토)") }
    }

    $breakGlass = '확인 불가'
    if ($null -ne $Snapshot.GlobalAdminIds) {
        # 비상 계정: 이번 페더레이션 영향을 받지 않는 관리형 도메인(onmicrosoft.com 포함) UPN의 활성 전역 관리자
        $bg = @($Snapshot.Users | Where-Object {
                $suffix = Get-UpnSuffix $_.userPrincipalName
                $_.accountEnabled -and ($Snapshot.GlobalAdminIds -contains $_.id) -and -not $affected.Contains($suffix) -and
                ((Get-EffectiveAuthType $Snapshot.Domains $suffix) -eq 'Managed') })
        $breakGlass = [string]$bg.Count
        if ($bg.Count -eq 0 -and -not $SkipBreakGlassCheck -and $state -ne 'AlreadyFederated') {
            $issues.Add('페더레이션 대상 밖(관리형 도메인)의 활성 전역 관리자(비상 계정) 없음')
        }
    }
    elseif (-not $SkipBreakGlassCheck -and $state -ne 'AlreadyFederated') {
        $issues.Add('전역 관리자 목록 확인 불가(RoleManagement.Read.Directory 권한 필요)')
    }

    if ($issues.Count -gt 0) { $state = 'Blocked' }

    foreach ($u in $unmapped) {
        $script:UnmappedRows.Add([pscustomobject]@{ TenantId = $TenantId; SchoolName = $SchoolName; Domain = $Domain; UserPrincipalName = $u.userPrincipalName })
    }

    $row = [pscustomobject]@{
        TenantId = $TenantId; SchoolName = $SchoolName; Domain = $Domain; State = $state
        Issues = ($issues -join '; '); Warnings = ($warnings -join '; '); AffectedDomains = (@($affected) -join ' ')
        MemberUsers = $members.Count; EnabledUsers = $enabled.Count; UnmappedEnabledUsers = $unmapped.Count
        SyncedUsers = $synced.Count; BreakGlassGlobalAdmins = $breakGlass
        CurrentIssuer = $issuerNow; ExpectedIssuer = $ExpectedIssuer
    }
    $script:ReadinessRows.Add($row)
    return $row
}

#endregion

#region 모드별 처리

function Invoke-InventoryTenant {
    param([string] $TenantId, [string] $SchoolName, $Rows)
    $snap = Get-TenantSnapshot -IncludeRoles
    $members = @($snap.Users | Where-Object { $_.userType -ne 'Guest' })
    $targets = @($Rows | ForEach-Object { $_.DomainName.Trim().ToLowerInvariant() })

    foreach ($d in $snap.Domains) {
        $id = ([string]$d.id).ToLowerInvariant()
        $du = @($members | Where-Object { (Get-UpnSuffix $_.userPrincipalName) -eq $id })
        $issuer = ''
        if ($d.authenticationType -eq 'Federated' -and $d.isRoot) {
            try { $issuer = [string](Get-PropValue (Get-FederationConfig $id) 'issuerUri') } catch { $issuer = '(읽기 실패)' }
        }
        $script:DomainRows.Add([pscustomobject]@{
            TenantId = $TenantId; SchoolName = $SchoolName; Domain = $id
            IsVerified = $d.isVerified; IsDefault = $d.isDefault; IsInitial = $d.isInitial; IsRoot = $d.isRoot
            AuthenticationType = $d.authenticationType
            Users = $du.Count
            EnabledUsers = @($du | Where-Object { $_.accountEnabled }).Count
            WithImmutableId = @($du | Where-Object { -not [string]::IsNullOrEmpty($_.onPremisesImmutableId) }).Count
            SyncedUsers = @($du | Where-Object { $_.onPremisesSyncEnabled }).Count
            FederationIssuer = $issuer
            IsTarget = ($targets -contains $id)
        })
    }

    foreach ($r in $Rows) {
        $domain = $r.DomainName.Trim().ToLowerInvariant()
        $expected = if ($script:Config) { Resolve-Template $script:Config.IssuerUriTemplate $domain } else { '' }
        $ready = Test-FederationReadiness -Snapshot $snap -TenantId $TenantId -SchoolName $SchoolName -Domain $domain -ExpectedIssuer $expected
        $status = if ($ready.State -eq 'Blocked') { 'FAIL' } else { 'OK' }
        Add-Result $TenantId $SchoolName $domain '' 'Readiness' $status ("$($ready.State) $($ready.Issues) $($ready.Warnings)").Trim()
    }
}

function Invoke-SetImmutableIdTenant {
    param([string] $TenantId, [string] $SchoolName, $MapRows)
    $snap = Get-TenantSnapshot
    $byUpn = @{}
    $byImm = @{}
    foreach ($u in $snap.Users) {
        $byUpn[$u.userPrincipalName.ToLowerInvariant()] = $u
        if ($u.onPremisesImmutableId) { $byImm[[string]$u.onPremisesImmutableId] = $u }
    }

    foreach ($r in $MapRows) {
        $upn = $r.UserPrincipalName.Trim().ToLowerInvariant()
        $imm = $r.ImmutableId.Trim()
        $suffix = Get-UpnSuffix $upn
        $u = $byUpn[$upn]
        if (-not $u) { Add-Result $TenantId $SchoolName $suffix $upn 'SetImmutableId' 'FAIL' '사용자 없음'; continue }
        if ($u.onPremisesSyncEnabled) { Add-Result $TenantId $SchoolName $suffix $upn 'SetImmutableId' 'SKIP' '온-프레미스 동기화 사용자(동기화 엔진이 값을 관리)'; continue }
        if ((Get-EffectiveAuthType $snap.Domains $suffix) -eq 'Federated') {
            Add-Result $TenantId $SchoolName $suffix $upn 'SetImmutableId' 'SKIP' '이미 페더레이션된 도메인. 전환 전에 설정해야 함(README 참고)'
            continue
        }
        $current = [string]$u.onPremisesImmutableId
        if ($current -ceq $imm) { Add-Result $TenantId $SchoolName $suffix $upn 'SetImmutableId' 'SKIP' '이미 같은 값'; continue }
        if ($current) { Add-Result $TenantId $SchoolName $suffix $upn 'SetImmutableId' 'FAIL' "기존 값과 다름($current). 덮어쓰지 않음"; continue }
        if ($byImm.ContainsKey($imm) -and $byImm[$imm].id -ne $u.id) {
            Add-Result $TenantId $SchoolName $suffix $upn 'SetImmutableId' 'FAIL' "다른 사용자($($byImm[$imm].userPrincipalName))가 같은 값 사용 중"
            continue
        }
        if ($script:Cmdlet.ShouldProcess("$SchoolName / $upn", "onPremisesImmutableId = $imm")) {
            Invoke-Graph -Method PATCH -Path "/users/$($u.id)" -Body @{ onPremisesImmutableId = $imm } | Out-Null
            $byImm[$imm] = $u
            Add-Result $TenantId $SchoolName $suffix $upn 'SetImmutableId' 'OK' $imm
        }
        else {
            Add-Result $TenantId $SchoolName $suffix $upn 'SetImmutableId' (Get-NotPerformedStatus) $imm
        }
    }
}

function Invoke-FederateTenant {
    param([string] $TenantId, [string] $SchoolName, $Rows)
    $cfg = $script:Config
    $snap = Get-TenantSnapshot -IncludeRoles
    foreach ($r in $Rows) {
        $domain = $r.DomainName.Trim().ToLowerInvariant()
        $issuer = Resolve-Template $cfg.IssuerUriTemplate $domain
        $passive = Resolve-Template $cfg.PassiveSignInUriTemplate $domain
        $ready = Test-FederationReadiness -Snapshot $snap -TenantId $TenantId -SchoolName $SchoolName -Domain $domain -ExpectedIssuer $issuer
        if ($ready.State -eq 'AlreadyFederated') { Add-Result $TenantId $SchoolName $domain $issuer 'Federate' 'SKIP' '이미 같은 Issuer로 페더레이션됨'; continue }
        if ($ready.State -eq 'Blocked') { Add-Result $TenantId $SchoolName $domain $issuer 'Federate' 'FAIL' "사전 점검 실패: $($ready.Issues)"; continue }
        if ($ready.Warnings) { Write-Warning "$SchoolName / ${domain}: $($ready.Warnings)" }

        $body = [ordered]@{
            '@odata.type'                         = '#microsoft.graph.internalDomainFederation'
            displayName                           = $cfg.DisplayName
            issuerUri                             = $issuer
            passiveSignInUri                      = $passive
            signOutUri                            = $cfg.SignOutUri
            signingCertificate                    = $script:SigningCertB64
            preferredAuthenticationProtocol       = 'saml'
            federatedIdpMfaBehavior               = $cfg.FederatedIdpMfaBehavior
            isSignedAuthenticationRequestRequired = [bool]$cfg.IsSignedAuthenticationRequestRequired
        }
        if ($script:NextCertB64) { $body.nextSigningCertificate = $script:NextCertB64 }

        $what = "도메인 페더레이션 생성(영향 사용자 $($ready.EnabledUsers)명, issuer=$issuer)"
        if (-not $script:Cmdlet.ShouldProcess("$SchoolName / $domain", $what)) {
            Add-Result $TenantId $SchoolName $domain $issuer 'Federate' (Get-NotPerformedStatus) "영향 사용자 $($ready.EnabledUsers)명, 로그인 URL $passive"
            continue
        }
        try {
            Invoke-Graph -Method POST -Path "/domains/$domain/federationConfiguration" -Body $body | Out-Null
            $d = Invoke-Graph -Path "/domains/$domain"
            if ($d.authenticationType -ne 'Federated') {
                # 일부 문서(다중 테넌트 AD FS)는 설정 생성 뒤 인증 유형을 별도로 바꿉니다. 상태를 보고 필요할 때만 변경합니다.
                Invoke-Graph -Method PATCH -Path "/domains/$domain" -Body @{ authenticationType = 'Federated' } | Out-Null
                $d = Invoke-Graph -Path "/domains/$domain"
            }
            $fed = Get-FederationConfig $domain
            $ok = ($d.authenticationType -eq 'Federated') -and ((Get-PropValue $fed 'issuerUri') -eq $issuer)
            $status = if ($ok) { 'OK' } else { 'FAIL' }
            Add-Result $TenantId $SchoolName $domain $issuer 'Federate' $status "authenticationType=$($d.authenticationType); issuer=$(Get-PropValue $fed 'issuerUri')"
        }
        catch {
            Add-Result $TenantId $SchoolName $domain $issuer 'Federate' 'FAIL' $_.Exception.Message
        }
    }
}

function Invoke-CertTenant {
    param([string] $TenantId, [string] $SchoolName, $Rows, [ValidateSet('Next', 'Promote')] [string] $Stage)
    foreach ($r in $Rows) {
        $domain = $r.DomainName.Trim().ToLowerInvariant()
        $issuer = Resolve-Template $script:Config.IssuerUriTemplate $domain
        try {
            $fed = Get-FederationConfig $domain
            if (-not $fed) { Add-Result $TenantId $SchoolName $domain $issuer "Cert$Stage" 'FAIL' '페더레이션 설정 없음'; continue }
            if ($fed.issuerUri -ne $issuer) { Add-Result $TenantId $SchoolName $domain $issuer "Cert$Stage" 'FAIL' "SEN스쿨 IdP 설정이 아님(issuer=$($fed.issuerUri))"; continue }

            if ($Stage -eq 'Next') {
                if ((Get-PropValue $fed 'nextSigningCertificate') -eq $script:NextCertB64) { Add-Result $TenantId $SchoolName $domain $issuer 'CertNext' 'SKIP' '이미 등록됨'; continue }
                $body = @{ nextSigningCertificate = $script:NextCertB64 }
                $what = 'nextSigningCertificate 등록'
            }
            else {
                if ($fed.signingCertificate -eq $script:NextCertB64) { Add-Result $TenantId $SchoolName $domain $issuer 'CertPromote' 'SKIP' '이미 교체됨'; continue }
                $body = @{ signingCertificate = $script:NextCertB64; nextSigningCertificate = $fed.signingCertificate }
                $what = 'signingCertificate를 새 인증서로 교체(기존 인증서는 next로 유예)'
            }
            if ($script:Cmdlet.ShouldProcess("$SchoolName / $domain", $what)) {
                Invoke-Graph -Method PATCH -Path "/domains/$domain/federationConfiguration/$($fed.id)" -Body $body | Out-Null
                Add-Result $TenantId $SchoolName $domain $issuer "Cert$Stage" 'OK' $what
            }
            else {
                Add-Result $TenantId $SchoolName $domain $issuer "Cert$Stage" (Get-NotPerformedStatus) $what
            }
        }
        catch {
            Add-Result $TenantId $SchoolName $domain $issuer "Cert$Stage" 'FAIL' $_.Exception.Message
        }
    }
}

function Invoke-RollbackTenant {
    param([string] $TenantId, [string] $SchoolName, $Rows)
    foreach ($r in $Rows) {
        $domain = $r.DomainName.Trim().ToLowerInvariant()
        $issuer = Resolve-Template $script:Config.IssuerUriTemplate $domain
        try {
            $d = Invoke-Graph -Path "/domains/$domain"
            $fed = Get-FederationConfig $domain
            if (-not $fed -and $d.authenticationType -eq 'Managed') { Add-Result $TenantId $SchoolName $domain $issuer 'Rollback' 'SKIP' '이미 Managed'; continue }
            if ($fed -and $fed.issuerUri -ne $issuer) { Add-Result $TenantId $SchoolName $domain $issuer 'Rollback' 'FAIL' "다른 IdP 설정(issuer=$($fed.issuerUri)). 변경하지 않음"; continue }

            $what = '페더레이션 해제(Managed 전환). MS 문서상 최대 2시간 소요, 사용자별 새 비밀번호 지정이 필요할 수 있음'
            if (-not $script:Cmdlet.ShouldProcess("$SchoolName / $domain", $what)) {
                Add-Result $TenantId $SchoolName $domain $issuer 'Rollback' (Get-NotPerformedStatus) $what
                continue
            }
            if ($fed) { Invoke-Graph -Method DELETE -Path "/domains/$domain/federationConfiguration/$($fed.id)" | Out-Null }
            $d = Invoke-Graph -Path "/domains/$domain"
            if ($d.authenticationType -ne 'Managed') {
                Invoke-Graph -Method PATCH -Path "/domains/$domain" -Body @{ authenticationType = 'Managed' } | Out-Null
                $d = Invoke-Graph -Path "/domains/$domain"
            }
            $status = if ($d.authenticationType -eq 'Managed') { 'OK' } else { 'FAIL' }
            Add-Result $TenantId $SchoolName $domain $issuer 'Rollback' $status "authenticationType=$($d.authenticationType). 사용자 비밀번호 상태를 확인하세요"
        }
        catch {
            Add-Result $TenantId $SchoolName $domain $issuer 'Rollback' 'FAIL' $_.Exception.Message
        }
    }
}

#endregion

#region 입력 검증

$tenants = @(Import-Csv -Path $TenantsCsv)
foreach ($col in 'TenantId', 'SchoolName', 'DomainName') {
    if ($tenants.Count -gt 0 -and -not ($tenants[0].PSObject.Properties.Name -contains $col)) { throw "TenantsCsv에 '$col' 열이 없습니다." }
}
if ($Wave) { $tenants = @($tenants | Where-Object { (Get-PropValue $_ 'Wave') -eq $Wave }) }
if ($tenants.Count -eq 0) { throw '처리할 테넌트 행이 없습니다.' }

$inputErrors = [System.Collections.Generic.List[string]]::new()
foreach ($t in $tenants) {
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($t.TenantId, [ref]$guid)) { $inputErrors.Add("TenantId 형식 오류: $($t.TenantId)") }
    $dn = $t.DomainName.Trim().ToLowerInvariant()
    if ($dn -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') { $inputErrors.Add("DomainName 형식 오류: $($t.DomainName)") }
    if ($dn -like '*.onmicrosoft.com') { $inputErrors.Add("onmicrosoft.com 도메인은 대상이 될 수 없음: $dn") }
}
$dupDomains = @($tenants | Group-Object { $_.DomainName.Trim().ToLowerInvariant() } | Where-Object Count -gt 1)
foreach ($g in $dupDomains) { $inputErrors.Add("DomainName 중복: $($g.Name)") }

$script:Config = $null
$needsConfig = $Mode -in 'ExportIdpMap', 'Federate', 'SetNextCert', 'PromoteNextCert', 'Rollback'
if ($ConfigPath) {
    $ConfigPath = (Resolve-Path $ConfigPath).Path
    $script:Config = Import-PowerShellDataFile -Path $ConfigPath
}
elseif ($needsConfig) {
    throw "-Mode $Mode 에는 -ConfigPath가 필요합니다."
}

if ($script:Config) {
    $c = $script:Config
    if (-not $c.IssuerUriTemplate -or $c.IssuerUriTemplate -notlike '*{domain}*') { $inputErrors.Add('IssuerUriTemplate에 {domain}이 있어야 합니다(Issuer는 도메인마다 고유해야 함).') }
    if ($c.PassiveSignInUriTemplate -notlike 'https://*') { $inputErrors.Add('PassiveSignInUriTemplate은 https:// 로 시작해야 합니다.') }
    elseif ($c.PassiveSignInUriTemplate -notlike '*{domain}*') { Write-Warning 'PassiveSignInUriTemplate에 {domain}이 없습니다. IdP가 대상 학교 테넌트를 URL로 구분할 수 없습니다.' }
    if ($c.SignOutUri -notlike 'https://*') { $inputErrors.Add('SignOutUri는 https:// 로 시작해야 합니다.') }
    if ([string]::IsNullOrWhiteSpace($c.DisplayName)) { $inputErrors.Add('DisplayName이 비어 있습니다.') }
    if ($c.FederatedIdpMfaBehavior -notin $MfaBehaviors) { $inputErrors.Add("FederatedIdpMfaBehavior 값 오류: $($c.FederatedIdpMfaBehavior)") }
    $dupIssuers = @($tenants | Group-Object { Resolve-Template $c.IssuerUriTemplate $_.DomainName.Trim() } | Where-Object Count -gt 1)
    foreach ($g in $dupIssuers) { $inputErrors.Add("Issuer 중복: $($g.Name)") }
}

$mapByTenant = @{}
if ($Mode -eq 'SetImmutableId') {
    if (-not $ImmutableIdCsv) { throw '-Mode SetImmutableId에는 -ImmutableIdCsv가 필요합니다.' }
    $map = @(Import-Csv -Path $ImmutableIdCsv)
    foreach ($col in 'TenantId', 'UserPrincipalName', 'ImmutableId') {
        if ($map.Count -gt 0 -and -not ($map[0].PSObject.Properties.Name -contains $col)) { throw "ImmutableIdCsv에 '$col' 열이 없습니다." }
    }
    $tenantIds = @($tenants | ForEach-Object { $_.TenantId.ToLowerInvariant() })
    foreach ($m in $map) {
        if ($m.ImmutableId -notmatch $ImmutableIdPattern) { $inputErrors.Add("ImmutableId 형식 오류(영숫자 1~64자): $($m.UserPrincipalName) = '$($m.ImmutableId)'") }
        if ($tenantIds -notcontains $m.TenantId.ToLowerInvariant()) { $inputErrors.Add("TenantsCsv(또는 Wave)에 없는 테넌트: $($m.TenantId) / $($m.UserPrincipalName)") }
    }
    foreach ($g in @($map | Group-Object { "$($_.TenantId.ToLowerInvariant())|$($_.ImmutableId)" } | Where-Object Count -gt 1)) {
        $inputErrors.Add("같은 테넌트 안에서 ImmutableId 중복: $($g.Name)")
    }
    foreach ($g in @($map | Group-Object { "$($_.TenantId.ToLowerInvariant())|$($_.UserPrincipalName.Trim().ToLowerInvariant())" } | Where-Object Count -gt 1)) {
        $inputErrors.Add("같은 테넌트 안에서 UPN 중복: $($g.Name)")
    }
    foreach ($g in ($map | Group-Object { $_.TenantId.ToLowerInvariant() })) { $mapByTenant[$g.Name] = $g.Group }
}

if ($inputErrors.Count -gt 0) {
    $inputErrors | Select-Object -First 50 | ForEach-Object { Write-Host "입력 오류: $_" -ForegroundColor Red }
    throw "입력 검증 실패 $($inputErrors.Count)건. 수정 후 다시 실행하세요."
}

$script:SigningCertB64 = $null
$script:NextCertB64 = $null
if ($Mode -eq 'Federate') {
    $script:SigningCertB64 = Get-CertBase64 $script:Config.SigningCertificatePath '현재 서명 인증서'
    if ($script:Config.NextSigningCertificatePath) { $script:NextCertB64 = Get-CertBase64 $script:Config.NextSigningCertificatePath '다음 서명 인증서' }
}
if ($Mode -in 'SetNextCert', 'PromoteNextCert') {
    $script:NextCertB64 = Get-CertBase64 $script:Config.NextSigningCertificatePath '다음 서명 인증서'
}

#endregion

#region 실행

New-Item -ItemType Directory -Force -Path $OutDir -WhatIf:$false -Confirm:$false | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if ($Mode -eq 'ExportIdpMap') {
    $c = $script:Config
    $idpMap = foreach ($t in $tenants) {
        $dn = $t.DomainName.Trim().ToLowerInvariant()
        [pscustomobject]@{
            DomainName = $dn; TenantId = $t.TenantId; SchoolName = $t.SchoolName
            IssuerUri = Resolve-Template $c.IssuerUriTemplate $dn
            PassiveSignInUri = Resolve-Template $c.PassiveSignInUriTemplate $dn
            SignOutUri = $c.SignOutUri
            SpEntityId = 'urn:federation:MicrosoftOnline'
            AcsUrl = 'https://login.microsoftonline.com/login.srf'
            NameIdFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
        }
    }
    $path = Join-Path $OutDir "idp-map_$stamp.csv"
    $idpMap | Export-Csv -Path $path -NoTypeInformation -Encoding utf8BOM -WhatIf:$false -Confirm:$false
    Write-Host "IdP 매핑표 $(@($idpMap).Count)건: $path"
    Write-Host '하위 도메인 사용자는 상위(루트) 도메인의 Issuer를 써야 합니다.'
    return
}

$groups = @($tenants | Group-Object { $_.TenantId.ToLowerInvariant() })
$i = 0
foreach ($g in $groups) {
    $i++
    $tenantId = $g.Name
    $school = $g.Group[0].SchoolName
    Write-Progress -Activity "$Mode" -Status "$school ($i/$($groups.Count))" -PercentComplete ([int](100 * $i / $groups.Count))
    try {
        Connect-Tenant -TenantId $tenantId -Scopes $ScopesByMode[$Mode]
        switch ($Mode) {
            'Inventory' { Invoke-InventoryTenant -TenantId $tenantId -SchoolName $school -Rows $g.Group }
            'SetImmutableId' {
                $rows = $mapByTenant[$tenantId]
                if ($rows) { Invoke-SetImmutableIdTenant -TenantId $tenantId -SchoolName $school -MapRows $rows }
                else { Add-Result $tenantId $school '' '' 'SetImmutableId' 'SKIP' '매핑 행 없음' }
            }
            'Federate' { Invoke-FederateTenant -TenantId $tenantId -SchoolName $school -Rows $g.Group }
            'SetNextCert' { Invoke-CertTenant -TenantId $tenantId -SchoolName $school -Rows $g.Group -Stage Next }
            'PromoteNextCert' { Invoke-CertTenant -TenantId $tenantId -SchoolName $school -Rows $g.Group -Stage Promote }
            'Rollback' { Invoke-RollbackTenant -TenantId $tenantId -SchoolName $school -Rows $g.Group }
        }
    }
    catch {
        Add-Result $tenantId $school '' '' 'Tenant' 'FAIL' $_.Exception.Message
    }
    finally {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
Write-Progress -Activity "$Mode" -Completed

$resultPath = Join-Path $OutDir "$Mode-result_$stamp.csv"
$script:Results | Export-Csv -Path $resultPath -NoTypeInformation -Encoding utf8BOM -WhatIf:$false -Confirm:$false
if ($script:DomainRows.Count -gt 0) { $script:DomainRows | Export-Csv -Path (Join-Path $OutDir "inventory-domains_$stamp.csv") -NoTypeInformation -Encoding utf8BOM -WhatIf:$false -Confirm:$false }
if ($script:ReadinessRows.Count -gt 0) { $script:ReadinessRows | Export-Csv -Path (Join-Path $OutDir "readiness_$stamp.csv") -NoTypeInformation -Encoding utf8BOM -WhatIf:$false -Confirm:$false }
if ($script:UnmappedRows.Count -gt 0) { $script:UnmappedRows | Export-Csv -Path (Join-Path $OutDir "unmapped-users_$stamp.csv") -NoTypeInformation -Encoding utf8BOM -WhatIf:$false -Confirm:$false }

Write-Host ''
Write-Host "결과: $resultPath"
$script:Results | Group-Object Status | Sort-Object Name | ForEach-Object { Write-Host ("  {0,-8} {1}" -f $_.Name, $_.Count) }

#endregion
