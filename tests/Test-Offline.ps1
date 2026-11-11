$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$script = Join-Path (Split-Path -Parent $here) 'graph/Invoke-SenM365Federation.ps1'
$work = Join-Path $here 'offline'
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $work, "$work/certs" | Out-Null

function New-TestCert([string] $cn, [string] $path) {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$cn", $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddYears(2))
    [IO.File]::WriteAllBytes($path, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [Convert]::ToBase64String($cert.RawData)
}
$curB64 = New-TestCert 'SEN IdP current' "$work/certs/current.cer"
$nextB64 = New-TestCert 'SEN IdP next' "$work/certs/next.cer"

$cfgBase = @"
@{
  DisplayName = 'SEN스쿨'
  IssuerUriTemplate = 'https://idp.senedu.kr/saml/m365/{domain}'
  PassiveSignInUriTemplate = 'https://idp.senedu.kr/saml/m365/{domain}/sso'
  SignOutUri = 'https://idp.senedu.kr/saml/m365/slo'
  SigningCertificatePath = './certs/current.cer'
  NextSigningCertificatePath = '__NEXT__'
  FederatedIdpMfaBehavior = 'acceptIfMfaDoneByFederatedIdp'
  IsSignedAuthenticationRequestRequired = `$false
}
"@
$cfgBase.Replace('__NEXT__', '') | Set-Content "$work/config.psd1"
$cfgBase.Replace('__NEXT__', './certs/next.cer') | Set-Content "$work/config-rollover.psd1"

$A = 'aaaaaaaa-0000-0000-0000-000000000001'
$B = 'bbbbbbbb-0000-0000-0000-000000000002'
$C = 'cccccccc-0000-0000-0000-000000000003'
$D = 'dddddddd-0000-0000-0000-000000000004'
$E = 'eeeeeeee-0000-0000-0000-000000000005'
@"
TenantId,SchoolName,DomainName,Wave
$A,A초,school-a.example.com,1
$B,B중,school-b.example.com,1
$C,C고,school-c.example.com,2
$D,D초,school-d.example.com,3
$E,E중,school-e.example.com,3
"@ | Set-Content "$work/tenants.csv"
@"
TenantId,UserPrincipalName,ImmutableId
$A,t1@school-a.example.com,aaaa1111
$A,s1@stu.school-a.example.com,aaaa2222
$A,nobody@school-a.example.com,aaaa3333
$A,s3@school-a.example.com,aaaa1111x
$B,b1@school-b.example.com,bbbb9999
"@ | Set-Content "$work/map.csv"

function Dom($id, $verified, $default, $initial, $root, $auth) {
    @{ id = $id; isVerified = $verified; isDefault = $default; isInitial = $initial; isRoot = $root; authenticationType = $auth }
}
function Usr($id, $upn, $imm, $enabled, $type = 'Member', $sync = $null) {
    @{ id = $id; userPrincipalName = $upn; onPremisesImmutableId = $imm; accountEnabled = $enabled; userType = $type; onPremisesSyncEnabled = $sync }
}

$global:Mock = @{
    Current = $null
    Calls   = [System.Collections.Generic.List[string]]::new()
    Tenants = @{
        $A = @{
            Domains = [ordered]@{
                'a.onmicrosoft.com'        = Dom 'a.onmicrosoft.com' $true $false $true $true 'Managed'
                'school-a.example.com'     = Dom 'school-a.example.com' $true $true $false $true 'Managed'
                'stu.school-a.example.com' = Dom 'stu.school-a.example.com' $true $false $false $false 'Managed'
            }
            Fed     = @{}
            Users   = @(
                (Usr 'a-u1' 'admin@a.onmicrosoft.com' $null $true)
                (Usr 'a-u2' 't1@school-a.example.com' 'aaaa1111' $true)
                (Usr 'a-u3' 's1@stu.school-a.example.com' $null $true)
                (Usr 'a-u4' 's2@school-a.example.com' $null $false)
                (Usr 'a-u5' 's3@school-a.example.com' 'aaaa5555' $true)
                (Usr 'a-u6' 'guest_x.com#EXT#@a.onmicrosoft.com' $null $true 'Guest')
            )
            GA      = @('a-u1')
        }
        $B = @{
            Domains = [ordered]@{
                'b.onmicrosoft.com'    = Dom 'b.onmicrosoft.com' $true $false $true $true 'Managed'
                'school-b.example.com' = Dom 'school-b.example.com' $true $true $false $true 'Federated'
            }
            Fed     = @{ 'school-b.example.com' = @{ id = 'fed-b'; issuerUri = 'https://other-idp.example.net/b'; signingCertificate = 'X'; nextSigningCertificate = $null } }
            Users   = @(
                (Usr 'b-u1' 'admin@b.onmicrosoft.com' $null $true)
                (Usr 'b-u2' 'b1@school-b.example.com' 'bbbb0001' $true)
            )
            GA      = @('b-u1')
        }
        $C = @{
            Domains = [ordered]@{ 'c.onmicrosoft.com' = Dom 'c.onmicrosoft.com' $true $true $true $true 'Managed' }
            Fed     = @{}
            Users   = @((Usr 'c-u1' 'admin@c.onmicrosoft.com' $null $true))
            GA      = $null
        }
        # 전역 관리자가 다른 커스텀 도메인(관리형)에만 있음 → 비상 계정으로 인정
        $D = @{
            Domains = [ordered]@{
                'd.onmicrosoft.com'    = Dom 'd.onmicrosoft.com' $true $false $true $true 'Managed'
                'other-d.example.com'  = Dom 'other-d.example.com' $true $true $false $true 'Managed'
                'school-d.example.com' = Dom 'school-d.example.com' $true $false $false $true 'Managed'
            }
            Fed     = @{}
            Users   = @((Usr 'd-u1' 'admin@other-d.example.com' $null $true), (Usr 'd-u2' 'd1@school-d.example.com' 'dddd0001' $true))
            GA      = @('d-u1')
        }
        # 전역 관리자가 페더레이션 대상 도메인에만 있음 → 차단
        $E = @{
            Domains = [ordered]@{
                'e.onmicrosoft.com'    = Dom 'e.onmicrosoft.com' $true $true $true $true 'Managed'
                'school-e.example.com' = Dom 'school-e.example.com' $true $false $false $true 'Managed'
            }
            Fed     = @{}
            Users   = @((Usr 'e-u1' 'admin@school-e.example.com' 'eeee0001' $true))
            GA      = @('e-u1')
        }
    }
}

function global:Connect-MgGraph {
    param($TenantId, $Scopes, $ClientId, $Certificate, $CertificateThumbprint, $AccessToken, [switch] $NoWelcome, $ErrorAction)
    if ($AccessToken) { $TenantId = [System.Net.NetworkCredential]::new('', $AccessToken).Password }
    $global:Mock.Current = $TenantId
    $global:Mock.Calls.Add("CONNECT $TenantId [$($Scopes -join ',')]")
}
function global:Get-MgContext { if ($global:Mock.Current) { [pscustomobject]@{ TenantId = $global:Mock.Current } } }
function global:Disconnect-MgGraph { param($ErrorAction) $global:Mock.Current = $null }
function global:Invoke-MgGraphRequest {
    param($Method = 'GET', $Uri, $Body, $ContentType, $OutputType, $ErrorAction)
    $t = $global:Mock.Tenants[$global:Mock.Current]
    $path = $Uri -replace '^https://graph\.microsoft\.com/v1\.0', ''
    $global:Mock.Calls.Add("$Method $path")
    $b = if ($Body) { $Body | ConvertFrom-Json -AsHashtable } else { $null }
    function Out($o) { $o | ConvertTo-Json -Depth 10 | ConvertFrom-Json }
    function NotFound { throw "Response status code does not indicate success: NotFound (Not Found)." }

    if ($path -like '/organization*' -and $Method -eq 'GET') { return Out @{ value = @(@{ id = $global:Mock.Current }) } }
    if ($path -eq '/domains' -and $Method -eq 'GET') { return Out @{ value = @($t.Domains.Values) } }
    if ($path -match '^/domains/([^/]+)$') {
        $d = $t.Domains[$Matches[1]]; if (-not $d) { NotFound }
        if ($Method -eq 'GET') { return Out $d }
        if ($Method -eq 'PATCH') { $d.authenticationType = $b.authenticationType; return }
    }
    if ($path -match '^/domains/([^/]+)/federationConfiguration$') {
        $dn = $Matches[1]; if (-not $t.Domains[$dn]) { NotFound }
        if ($Method -eq 'GET') { return Out @{ value = @(if ($t.Fed[$dn]) { $t.Fed[$dn] }) } }
        if ($Method -eq 'POST') {
            foreach ($k in 'issuerUri', 'passiveSignInUri', 'signingCertificate', 'preferredAuthenticationProtocol') { if (-not $b[$k]) { throw "400 missing $k" } }
            if ($b.preferredAuthenticationProtocol -ne 'saml') { throw '400 protocol' }
            foreach ($tt in $global:Mock.Tenants.Values) { foreach ($f in $tt.Fed.Values) { if ($f.issuerUri -eq $b.issuerUri) { throw '400 issuer already in use' } } }
            $b.id = "fed-$dn"; $b.Remove('@odata.type'); $t.Fed[$dn] = $b
            return Out $b
        }
    }
    if ($path -match '^/domains/([^/]+)/federationConfiguration/([^/]+)$') {
        $dn = $Matches[1]; $f = $t.Fed[$dn]; if (-not $f -or $f.id -ne $Matches[2]) { NotFound }
        if ($Method -eq 'PATCH') { foreach ($k in $b.Keys) { $f[$k] = $b[$k] }; return }
        if ($Method -eq 'DELETE') { $t.Fed.Remove($dn); return }
    }
    if ($path -like '/users`?*' -and $Method -eq 'GET') {
        if ($path -like '*page=2*') { return Out @{ value = @($t.Users | Select-Object -Skip 2) } }
        return Out @{ value = @($t.Users | Select-Object -First 2); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?page=2' }
    }
    if ($path -match '^/users/([^/?]+)$' -and $Method -eq 'PATCH') {
        $u = $t.Users | Where-Object { $_.id -eq $Matches[1] }; if (-not $u) { NotFound }
        $u.onPremisesImmutableId = $b.onPremisesImmutableId; return
    }
    if ($path -like '/directoryRoles(*' -and $Method -eq 'GET') {
        if ($null -eq $t.GA) { throw 'Forbidden: Insufficient privileges' }
        return Out @{ value = @($t.GA | ForEach-Object { @{ id = $_ } }) }
    }
    throw "MOCK: unhandled $Method $path"
}

$fails = [System.Collections.Generic.List[string]]::new()
function Check($cond, $msg) { if ($cond) { Write-Host "  PASS $msg" -ForegroundColor Green } else { Write-Host "  FAIL $msg" -ForegroundColor Red; $fails.Add($msg) } }
function LastResult($mode) { Import-Csv (Get-ChildItem "$work/out/$mode-result_*.csv" | Sort-Object LastWriteTime | Select-Object -Last 1) }
function Run([string] $label, [hashtable] $p) {
    Write-Host "`n=== $label ===" -ForegroundColor Cyan
    Start-Sleep -Milliseconds 1100   # 결과 파일 타임스탬프 구분
    & $script @p -TenantsCsv "$work/tenants.csv" -OutDir "$work/out" 6>&1 | Out-Host
}
$writes = { @($global:Mock.Calls | Where-Object { $_ -match '^(POST|PATCH|DELETE)' }).Count }

Run 'Inventory' @{ Mode = 'Inventory'; ConfigPath = "$work/config.psd1" }
$r = LastResult 'Inventory'
Check (($r | Where-Object Domain -eq 'school-a.example.com').Detail -like '*ImmutableId 없는 활성 사용자 1명*') 'A: 하위 도메인 사용자 s1 미매핑 1명 감지(비활성 s2·게스트 제외)'
Check (($r | Where-Object Domain -eq 'school-b.example.com').Detail -like '*다른 IdP*') 'B: 타 IdP 페더레이션 차단'
Check (($r | Where-Object Domain -eq 'school-a.example.com').Detail -like '*기본 도메인임*') 'A: 기본 도메인 경고 표시'
Check (($r | Where-Object Domain -eq 'school-c.example.com').Detail -like '*도메인 없음*전역 관리자 목록 확인 불가*') 'C: 도메인 없음 + 관리자 확인 불가'
$inv = Import-Csv (Get-ChildItem "$work/out/inventory-domains_*.csv" | Select-Object -Last 1)
Check (@($inv).Count -eq 11) "도메인 인벤토리 11행(실제 $(@($inv).Count))"
Check (($r | Where-Object Domain -eq 'school-d.example.com').Detail -like 'Ready*') 'D: 다른 관리형 도메인의 전역 관리자를 비상 계정으로 인정'
Check (($r | Where-Object Domain -eq 'school-e.example.com').Detail -like '*비상 계정*') 'E: 대상 도메인에만 전역 관리자가 있으면 차단'
Check ((& $writes) -eq 0) 'Inventory는 쓰기 호출 없음'

Run 'ExportIdpMap' @{ Mode = 'ExportIdpMap'; ConfigPath = "$work/config.psd1"; Wave = '1' }
$m = Import-Csv (Get-ChildItem "$work/out/idp-map_*.csv" | Select-Object -Last 1)
Check (@($m).Count -eq 2 -and $m[0].PassiveSignInUri -eq 'https://idp.senedu.kr/saml/m365/school-a.example.com/sso') 'IdP 매핑표(Wave 1, 2행, 도메인별 로그인 URL)'

$global:Mock.Calls.Clear()
Run 'SetImmutableId -WhatIf' @{ Mode = 'SetImmutableId'; ImmutableIdCsv = "$work/map.csv"; WhatIf = $true }
Check ((& $writes) -eq 0) 'WhatIf: 쓰기 호출 없음'
$r = LastResult 'SetImmutableId'
Check (@($r | Where-Object Status -eq 'WHATIF').Count -eq 1) 'WhatIf: s1 1건만 WHATIF'

$global:Mock.Calls.Clear()
Run 'SetImmutableId' @{ Mode = 'SetImmutableId'; ImmutableIdCsv = "$work/map.csv"; Confirm = $false }
$r = LastResult 'SetImmutableId'
Check (($r | Where-Object Target -eq 's1@stu.school-a.example.com').Status -eq 'OK') 's1 설정 OK'
Check (($r | Where-Object Target -eq 't1@school-a.example.com').Status -eq 'SKIP') 't1 같은 값 SKIP'
Check (($r | Where-Object Target -eq 'nobody@school-a.example.com').Status -eq 'FAIL') '없는 사용자 FAIL'
Check (($r | Where-Object Target -eq 's3@school-a.example.com').Detail -like '*기존 값과 다름*') '기존 값 다르면 덮어쓰지 않음'
Check (($r | Where-Object Target -eq 'b1@school-b.example.com').Detail -like '*페더레이션된 도메인*') '페더레이션된 도메인 사용자 SKIP'
Check ((& $writes) -eq 1) "쓰기 호출 1건(실제 $(& $writes))"

$global:Mock.Calls.Clear()
Run 'Federate -WhatIf' @{ Mode = 'Federate'; ConfigPath = "$work/config.psd1"; WhatIf = $true }
$r = LastResult 'Federate'
Check ((& $writes) -eq 0) 'Federate WhatIf: 쓰기 없음'
Check (($r | Where-Object Domain -eq 'school-a.example.com').Status -eq 'WHATIF') 'A: 매핑 후 준비 완료(WHATIF)'

$global:Mock.Calls.Clear()
Run 'Federate' @{ Mode = 'Federate'; ConfigPath = "$work/config.psd1"; Confirm = $false }
$r = LastResult 'Federate'
$fa = $global:Mock.Tenants[$A].Fed['school-a.example.com']
Check (($r | Where-Object Domain -eq 'school-a.example.com').Status -eq 'OK') 'A: 페더레이션 OK'
Check ($global:Mock.Tenants[$A].Domains['school-a.example.com'].authenticationType -eq 'Federated') 'A: authenticationType Federated(PATCH 경로 확인)'
Check ($fa.issuerUri -eq 'https://idp.senedu.kr/saml/m365/school-a.example.com' -and $fa.passiveSignInUri -like '*/school-a.example.com/sso' -and $fa.signingCertificate -eq $curB64) 'A: Issuer·로그인 URL·인증서 값'
Check (($r | Where-Object Domain -eq 'school-b.example.com').Status -eq 'FAIL' -and ($r | Where-Object Domain -eq 'school-c.example.com').Status -eq 'FAIL') 'B·C: 차단 유지'
Check (($r | Where-Object Domain -eq 'school-d.example.com').Status -eq 'OK' -and ($r | Where-Object Domain -eq 'school-e.example.com').Status -eq 'FAIL') 'D 페더레이션 OK, E 차단'

Run 'Federate 재실행' @{ Mode = 'Federate'; ConfigPath = "$work/config.psd1"; Confirm = $false }
Check ((LastResult 'Federate' | Where-Object Domain -eq 'school-a.example.com').Status -eq 'SKIP') 'A: 재실행 시 SKIP(멱등)'

Run 'SetNextCert' @{ Mode = 'SetNextCert'; ConfigPath = "$work/config-rollover.psd1"; Confirm = $false }
Check ($global:Mock.Tenants[$A].Fed['school-a.example.com'].nextSigningCertificate -eq $nextB64) 'A: nextSigningCertificate 등록'
Check (($global:Mock.Tenants[$B].Fed['school-b.example.com'].nextSigningCertificate) -eq $null) 'B: 타 IdP 설정은 변경 안 함'

Run 'PromoteNextCert' @{ Mode = 'PromoteNextCert'; ConfigPath = "$work/config-rollover.psd1"; Confirm = $false }
$fa = $global:Mock.Tenants[$A].Fed['school-a.example.com']
Check ($fa.signingCertificate -eq $nextB64 -and $fa.nextSigningCertificate -eq $curB64) 'A: 서명 인증서 교체, 기존 인증서는 next로 유예'

Run 'Rollback' @{ Mode = 'Rollback'; ConfigPath = "$work/config.psd1"; Confirm = $false }
$r = LastResult 'Rollback'
Check (($r | Where-Object Domain -eq 'school-a.example.com').Status -eq 'OK' -and -not $global:Mock.Tenants[$A].Fed['school-a.example.com'] -and $global:Mock.Tenants[$A].Domains['school-a.example.com'].authenticationType -eq 'Managed') 'A: 롤백 OK(설정 삭제 + Managed)'
Check (($r | Where-Object Domain -eq 'school-b.example.com').Detail -like '*다른 IdP*' -and $global:Mock.Tenants[$B].Fed['school-b.example.com']) 'B: 타 IdP 설정 보존'

Run 'Inventory (AccessToken 인증)' @{ Mode = 'Inventory'; ConfigPath = "$work/config.psd1"; AuthMode = 'AccessToken'; AccessTokenProvider = { param($t) $t } }
$r = LastResult 'Inventory'
Check (@($r).Count -eq 5 -and ($r | Where-Object Domain -eq 'school-c.example.com').Detail -like '*도메인 없음*') 'AccessToken 인증으로 5개 테넌트 점검'
Check (@($global:Mock.Calls | Where-Object { $_ -like 'GET /organization*' }).Count -ge 5) 'AccessToken 인증 시 /organization으로 테넌트 확인'

Write-Host "`n=== 입력 검증 ===" -ForegroundColor Cyan
"TenantId,UserPrincipalName,ImmutableId`n$A,x@school-a.example.com,bad_value`n$A,y@school-a.example.com,dup1`n$A,z@school-a.example.com,dup1" | Set-Content "$work/badmap.csv"
try { & $script -Mode SetImmutableId -TenantsCsv "$work/tenants.csv" -ImmutableIdCsv "$work/badmap.csv" -OutDir "$work/out" -Confirm:$false 6>$null; Check $false '잘못된 매핑 CSV 거부' }
catch { Check ($_.Exception.Message -like '*입력 검증 실패 2건*') "잘못된 매핑 CSV 거부: $($_.Exception.Message)" }
"TenantId,SchoolName,DomainName`n$A,A,school-a.example.com`n$B,B,SCHOOL-A.example.com" | Set-Content "$work/badtenants.csv"
try { & $script -Mode Inventory -TenantsCsv "$work/badtenants.csv" -OutDir "$work/out" 6>$null; Check $false '중복 도메인 거부' }
catch { Check ($_.Exception.Message -like '*입력 검증 실패*') '중복 도메인(대소문자 무시) 거부' }

Write-Host ''
if ($fails.Count) { Write-Host "실패 $($fails.Count)건" -ForegroundColor Red; exit 1 } else { Write-Host '모든 검사 통과' -ForegroundColor Green }
