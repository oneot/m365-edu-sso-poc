"""PoC 테스트 데이터 생성: IdP 계정(users.json), 테넌트 계정 목록, ImmutableID 매핑 CSV.

SEN 아이디는 '아이디@joowon.me' 형식이고, 학교 테넌트 1곳의 Microsoft 365 계정(UPN)과 ImmutableID로 연결된다.

사용: python make_test_data.py --domains ../idp/data/domains.json --out-dir ../out --password-file <경로>
  - ../idp/data/users.json 을 만든다(비밀번호 해시 포함, 저장소에 올리지 않음). 기존 ImmutableID는 그대로 쓴다.
  - out/entra-users.json  : 테넌트에 만들 사용자와 라이선스 대상 여부
  - out/immutableid.csv   : Invoke-SenM365Federation.ps1 -Mode SetImmutableId 입력
  - 비밀번호는 --password-file 에만 평문으로 저장한다(이미 있으면 재사용).
  - IdP는 1차 인증만 한다. MFA는 Entra가 수행하므로 MFA 계정은 Entra 사용자별 MFA와 Entra 인증 수단 등록으로 만든다.
"""
import argparse
import csv
import json
import os
import secrets
import string
import uuid

from werkzeug.security import generate_password_hash

# (SEN 아이디, 이름, 역할, 학교 키, 플래그, 라이선스 부여 여부, 설명). 학교 계정은 학교 테넌트 1곳에만 만든다.
ACCOUNTS = [
    ("student01", "학생01", "학생", "A", {}, True, "기본 시나리오(학교 A)"),
    ("teacher01", "교사01", "교사", "A", {"routeIssuerFromRequest": True}, True,
     "기본 시나리오(학교 A). SEN 아이디로 들어오면 라우팅 도메인 Issuer로 응답(R11, 거부 확인)"),
    ("student02", "학생02", "학생", "B", {}, True, "기본 시나리오(학교 B)"),
    ("mfa01", "MFA학생01", "학생", "A", {}, True, "학교 A의 MFA 필수 계정(Entra 사용자별 MFA, Entra 인증 앱 등록)"),
    ("mfa02", "MFA학생02", "학생", "B", {}, True, "학교 B의 MFA 필수 계정(Entra 사용자별 MFA, Entra 인증 앱 등록)"),
    ("nomap01", "미매핑01", "학생", "A", {"skipImmutableId": True}, False, "Entra 쪽 ImmutableID 없음(C1)"),
    ("badissuer01", "잘못된발급자01", "학생", "A", {"badIssuer": True}, False, "등록 안 된 Issuer(B2a)"),
    ("badsig01", "서명변조01", "학생", "A", {"badSignature": True}, False, "서명 변조(B2b)"),
    # 보안 데모(학교 B, Microsoft 365 A5): 계정이 유출됐다고 가정하고 위험 기반 탐지·차단을 재현한다
    ("hack01", "보안데모01", "학생", "B", {}, True, "보안 데모 S1: 유출 계정으로 Tor 로그인 → 로그인 위험 정책(차단)"),
    ("hack02", "보안데모02", "학생", "B", {}, True,
     "보안 데모 S2: Tor 로그인 + 로그인 위험 정책(MFA 요구), Entra 인증 앱으로 MFA 완료"),
    ("hack03", "보안데모03", "학생", "B", {}, True, "보안 데모 S4: 관리자 침해 확인 → 사용자 위험 정책(차단)·CAE 세션 종료"),
    ("hack04", "보안데모04", "학생", "B", {}, True, "보안 데모 S3: Tor 로그인 + 로그인 위험 정책(MFA 요구), Entra 인증 수단 미등록"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--password-file", required=True)
    args = ap.parse_args()

    domains = json.load(open(args.domains, encoding="utf-8"))
    school_domains = [d for d, v in domains.items() if v.get("mode") == "school"]
    if len(school_domains) < 2:
        raise SystemExit("학교 도메인이 2개 이상 필요합니다")
    keymap = {"A": school_domains[0], "B": school_domains[1]}

    if os.path.exists(args.password_file):
        password = open(args.password_file, encoding="utf-8").read().strip()
    else:
        alphabet = string.ascii_letters + string.digits
        password = "PoC-" + "".join(secrets.choice(alphabet) for _ in range(8))
        os.makedirs(os.path.dirname(args.password_file), exist_ok=True)
        with open(args.password_file, "w", encoding="utf-8") as f:
            f.write(password + "\n")
        os.chmod(args.password_file, 0o600)

    users_path = os.path.join(os.path.dirname(os.path.abspath(args.domains)), "users.json")
    old = json.load(open(users_path, encoding="utf-8")) if os.path.exists(users_path) else {}
    users, entra, csv_rows = {}, [], []
    for uid, name, role, school, flags, licensed, note in ACCOUNTS:
        domain = keymap[school]
        upn = f"{uid}@{domain}"
        prev = old.get(uid, {}).get("accounts", [])
        immutable = prev[0]["immutableId"] if prev else uuid.uuid4().hex
        tenant = domains[domain]["tenantId"]
        entra.append({"tenantId": tenant, "upn": upn, "displayName": f"{name} (PoC {role})",
                      "mailNickname": uid, "licensed": licensed, "note": note})
        if not flags.get("skipImmutableId"):
            csv_rows.append({"TenantId": tenant, "UserPrincipalName": upn, "ImmutableId": immutable})
        users[uid] = {
            "name": name, "role": role, "note": note,
            "passwordHash": generate_password_hash(password, method="pbkdf2:sha256:600000"),
            "accounts": [{"domain": domain, "upn": upn, "immutableId": immutable}],
            "flags": {k: v for k, v in flags.items() if k != "skipImmutableId"},
        }

    with open(users_path, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "entra-users.json"), "w", encoding="utf-8") as f:
        json.dump(entra, f, ensure_ascii=False, indent=2)
    with open(os.path.join(args.out_dir, "immutableid.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["TenantId", "UserPrincipalName", "ImmutableId"])
        w.writeheader()
        w.writerows(csv_rows)
    print(f"IdP 계정 {len(users)}개, 테넌트 계정 {len(entra)}개, ImmutableID 매핑 {len(csv_rows)}행")


if __name__ == "__main__":
    main()
