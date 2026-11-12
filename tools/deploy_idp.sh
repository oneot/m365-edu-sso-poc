#!/usr/bin/env bash
# 테스트 IdP를 Azure App Service(Linux, Python)에 배포한다.
# 비밀값은 저장소 밖에 두고 경로·값을 환경 변수로 넘긴다.
#
# 필요한 환경 변수
#   SUB, RG, APP           Azure 구독·리소스 그룹·웹앱 이름
#   KEYS_DIR               current.key/current.pem, next.key/next.pem 이 있는 폴더
#   SECRETS_FILE           SECRET_KEY, ADMIN_TOKEN 을 보관할 파일(없으면 새로 만든다)
#   LOGIN_UI_URL           (선택) GitHub Pages 로그인 화면 주소. 비우면 서버 내장 로그인 화면 사용
#   IDP_BASE_URL           (선택) 기본값 https://auth.joowon.me
#   IDP_ID_DOMAIN          (선택) IdP 아이디 도메인 표시, 기본값 joowon.me
#   SKIP_SETTINGS=1        (선택) 앱 설정은 그대로 두고 코드·데이터만 배포(빌드 중 재시작 방지)
set -euo pipefail
: "${SUB:?}" "${RG:?}" "${APP:?}" "${KEYS_DIR:?}" "${SECRETS_FILE:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
IDP="$HERE/idp"
for f in domains.json users.json links.json; do
  [ -f "$IDP/data/$f" ] || { echo "없음: $IDP/data/$f (tools/make_test_data.py 로 생성)"; exit 1; }
done

if [ ! -f "$SECRETS_FILE" ]; then
  umask 077
  printf 'SECRET_KEY=%s\nADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 16)" > "$SECRETS_FILE"
fi
# shellcheck disable=SC1090
. "$SECRETS_FILE"
b64() { base64 < "$1" | tr -d '\n'; }

if [ -z "${SKIP_SETTINGS:-}" ]; then
az webapp config appsettings set -g "$RG" -n "$APP" --subscription "$SUB" --output none --settings \
  SCM_DO_BUILD_DURING_DEPLOYMENT=true \
  IDP_BASE_URL="${IDP_BASE_URL:-https://auth.joowon.me}" IDP_ID_DOMAIN="${IDP_ID_DOMAIN:-joowon.me}" \
  LOGIN_UI_URL="${LOGIN_UI_URL:-}" \
  ACTIVE_SIGNING="${ACTIVE_SIGNING:-current}" \
  SECRET_KEY="$SECRET_KEY" ADMIN_TOKEN="$ADMIN_TOKEN" \
  SIGNING_KEY_B64="$(b64 "$KEYS_DIR/current.key")" SIGNING_CERT_B64="$(b64 "$KEYS_DIR/current.pem")" \
  NEXT_SIGNING_KEY_B64="$(b64 "$KEYS_DIR/next.key")" NEXT_SIGNING_CERT_B64="$(b64 "$KEYS_DIR/next.pem")"

az webapp config set -g "$RG" -n "$APP" --subscription "$SUB" --output none \
  --startup-file "gunicorn --bind=0.0.0.0:8000 --workers 1 --threads 8 --timeout 120 --access-logfile - wsgi:app"
fi

PKG="$(mktemp -d)/idp.zip"
(cd "$IDP" && zip -qr "$PKG" app.py wsgi.py saml_core.py requirements.txt templates static data \
  -x '*/__pycache__/*' 'data/*.sample.json')
# az webapp deploy 는 기본 구독의 테넌트 토큰으로 Kudu를 호출해 403이 날 수 있어, 대상 구독 토큰으로 직접 배포한다.
TOKEN="$(az account get-access-token --subscription "$SUB" --query accessToken -o tsv)"
SCM="https://$(az webapp show -g "$RG" -n "$APP" --subscription "$SUB" --query "enabledHostNames[?contains(@, '.scm.')] | [0]" -o tsv)"
latest() { curl -s -H "Authorization: Bearer $TOKEN" "$SCM/api/deployments/latest" |
           python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id"), d.get("status"), d.get("complete"))' 2>/dev/null || true; }
before="$(latest | cut -d' ' -f1)"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/zip" \
  --data-binary @"$PKG" "$SCM/api/publish?type=zip&async=true")
rm -f "$PKG"
case "$code" in 200|202) ;; *) echo "배포 요청 실패: HTTP $code"; exit 1;; esac
for _ in $(seq 1 120); do
  read -r id status complete <<< "$(latest)"
  if [ -n "$id" ] && [ "$id" != "$before" ] && [ "$complete" = "True" ]; then
    [ "$status" = 4 ] && break
    echo "배포 실패: $SCM/api/deployments/$id"; exit 1
  fi
  sleep 5
done
echo "배포 완료: ${IDP_BASE_URL:-https://auth.joowon.me}/healthz"
