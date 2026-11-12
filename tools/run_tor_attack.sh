#!/usr/bin/env bash
# 보안 데모 S1~S3: Tor(익명 IP) 경유 로그인을 Azure Container Instances에서 한 번 실행하고 결과를 출력한다.
# 회사 기기에 Tor를 설치하지 않고, Microsoft 문서의 '익명 IP 주소' 시뮬레이션을 재현하기 위한 것이다.
#
# 필요한 환경 변수
#   SUB, RG                  컨테이너를 만들 Azure 구독·리소스 그룹
#   PASSWORD_FILE, TOTP_FILE 데모 계정 비밀번호 파일, TOTP 비밀값 JSON(hack* 항목만 전달)
# 선택
#   ACCOUNTS (기본 "hack01 hack02 hack04"), REF(기본 main), LOCATION(기본 koreacentral), IMAGE(기본 python:3.12-slim)
set -euo pipefail
: "${SUB:?}" "${RG:?}" "${PASSWORD_FILE:?}" "${TOTP_FILE:?}"
NAME="sso-demo-tor-$(date +%m%d%H%M%S)"
ACCOUNTS="${ACCOUNTS:-hack01 hack02 hack04}"
PW="$(tr -d '\r\n' < "$PASSWORD_FILE")"
TOTP="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps({k: v for k, v in d.items() if k.startswith("hack")}))' "$TOTP_FILE")"
RUN="set -e
export DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1
apt-get update -qq && apt-get install -y -qq --no-install-recommends tor git ca-certificates >/dev/null
tor --RunAsDaemon 1 --SocksPort 9050 --Log 'notice file /tmp/tor.log'
for i in \$(seq 1 150); do grep -q 'Bootstrapped 100' /tmp/tor.log 2>/dev/null && break; sleep 2; done
grep -o 'Bootstrapped 100.*' /tmp/tor.log | head -1
pip install -q --root-user-action=ignore 'requests[socks]'
git clone -q https://github.com/oneot/m365-edu-sso-poc /app && cd /app && git checkout -q ${REF:-main} && cd tools
python security_demo.py attack --proxy socks5h://127.0.0.1:9050 --accounts $ACCOUNTS --json"

az container create --subscription "$SUB" -g "$RG" -n "$NAME" --location "${LOCATION:-koreacentral}" \
  --image "${IMAGE:-python:3.12-slim}" --os-type Linux --cpu 1 --memory 1.5 --restart-policy Never \
  --environment-variables RUN_B64="$(printf '%s' "$RUN" | base64 | tr -d '\n')" \
  --secure-environment-variables DEMO_PASSWORD="$PW" DEMO_TOTP_JSON="$TOTP" \
  --command-line "bash -c 'echo \$RUN_B64 | base64 -d | bash'" --output none
echo "컨테이너 실행: $NAME (Tor 연결·로그인 재현에 수 분 걸림)"
for _ in $(seq 1 120); do
  state=$(az container show --subscription "$SUB" -g "$RG" -n "$NAME" --query "containers[0].instanceView.currentState.state" -o tsv)
  [ "$state" = "Terminated" ] && break
  sleep 10
done
az container logs --subscription "$SUB" -g "$RG" -n "$NAME"
az container delete --subscription "$SUB" -g "$RG" -n "$NAME" --yes --output none
echo "컨테이너 삭제: $NAME"
