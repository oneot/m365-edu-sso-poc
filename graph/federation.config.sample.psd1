@{
    # Entra 로그인 흐름에서 쓰는 IdP 표시 이름
    DisplayName                           = 'SEN스쿨'

    # Issuer는 도메인마다 고유해야 합니다(테넌트가 달라도 중복 불가).
    # {domain}은 학교 루트 도메인(소문자)으로 바뀝니다. 호스트는 예시입니다.
    IssuerUriTemplate                     = 'https://idp.senedu.kr/saml/m365/{domain}'

    # Entra가 사용자를 보내는 IdP 로그인 URL입니다.
    # 도메인을 URL에 넣으면 IdP가 어느 학교 테넌트로 응답할지 URL만 보고 정할 수 있습니다.
    # (Entra가 보내는 AuthnRequest에는 사용자 정보가 없습니다.)
    PassiveSignInUriTemplate              = 'https://idp.senedu.kr/saml/m365/{domain}/sso'

    SignOutUri                            = 'https://idp.senedu.kr/saml/m365/slo'

    # IdP 토큰 서명 인증서(공개 인증서 .cer, DER 또는 PEM). 이 설정 파일 기준 상대 경로를 쓸 수 있습니다.
    SigningCertificatePath                = './certs/idp-signing-current.cer'

    # 교체 예정 인증서. SetNextCert/PromoteNextCert 모드에 필요합니다.
    # Federate 실행 때 값이 있으면 nextSigningCertificate로 함께 등록합니다.
    NextSigningCertificatePath            = ''

    # acceptIfMfaDoneByFederatedIdp | enforceMfaByFederatedIdp | rejectMfaByFederatedIdp
    FederatedIdpMfaBehavior               = 'acceptIfMfaDoneByFederatedIdp'

    # $true면 Entra가 AuthnRequest에 서명합니다. IdP가 서명 검증을 지원하면 PoC에서 켜 보세요.
    IsSignedAuthenticationRequestRequired = $false
}
