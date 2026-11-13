#!/usr/bin/env bash
# 보안 데모(S1~S3)용 Tor 프록시: Azure Container Instances에서 Tor를 띄우고, 이 PC는 SSH 터널로만 쓴다.
#   - 회사 기기에 Tor를 설치하지 않는다. 컨테이너 sshd는 키 인증만 받고 127.0.0.1:9050(Tor)로의 전달만 허용한다.
#   - 터널이 열려 있는 동안 record_demos.py --proxy socks5://127.0.0.1:9050 으로 녹화한다.
#
# 사용
#   SUB=... RG=... KEY=<ssh 개인 키(공개 키는 KEY.pub)> tools/tor_tunnel.sh up     # 컨테이너 생성 + 터널(백그라운드 아님, Ctrl+C로 종료)
#   SUB=... RG=... tools/tor_tunnel.sh down                                         # 컨테이너 삭제
set -euo pipefail
: "${SUB:?}" "${RG:?}"
NAME="${NAME:-sso-demo-tor}"
case "${1:-}" in
up)
  : "${KEY:?}"
  PUB="$(cat "$KEY.pub")"
  RUN="set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq --no-install-recommends tor openssh-server >/dev/null
mkdir -p /run/sshd /root/.ssh && echo '$PUB' > /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
tor --RunAsDaemon 1 --SocksPort 127.0.0.1:9050 --Log 'notice file /tmp/tor.log'
for i in \$(seq 1 150); do grep -q 'Bootstrapped 100' /tmp/tor.log 2>/dev/null && break; sleep 2; done
grep -o 'Bootstrapped 100.*' /tmp/tor.log | head -1
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=prohibit-password \
  -o AllowTcpForwarding=local -o PermitOpen=127.0.0.1:9050 -o X11Forwarding=no -o AllowAgentForwarding=no -o PermitTTY=no"
  az container create --subscription "$SUB" -g "$RG" -n "$NAME" --location "${LOCATION:-koreacentral}" \
    --image python:3.12-slim --os-type Linux --cpu 1 --memory 1 --restart-policy Never --ip-address Public --ports 22 \
    --environment-variables RUN_B64="$(printf '%s' "$RUN" | base64 | tr -d '\n')" \
    --command-line "bash -c 'echo \$RUN_B64 | base64 -d | bash'" --output none
  IP=$(az container show --subscription "$SUB" -g "$RG" -n "$NAME" --query ipAddress.ip -o tsv)
  echo "컨테이너 $NAME ($IP), Tor 준비 대기"
  for _ in $(seq 1 60); do
    az container logs --subscription "$SUB" -g "$RG" -n "$NAME" 2>/dev/null | grep -q "Bootstrapped 100" && break
    sleep 5
  done
  sleep 3
  echo "터널: 127.0.0.1:9050 → 컨테이너 Tor"
  exec ssh -i "$KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KEY.known_hosts" -o ServerAliveInterval=30 \
    -o ExitOnForwardFailure=yes -N -L 9050:127.0.0.1:9050 "root@$IP"
  ;;
down)
  az container delete --subscription "$SUB" -g "$RG" -n "$NAME" --yes --output none && echo "컨테이너 삭제: $NAME"
  ;;
*)
  echo "사용: $0 up|down"; exit 1;;
esac
