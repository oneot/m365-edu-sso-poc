"""PoC 테스트 데이터 생성: IdP 계정(users.json), 테넌트 계정 목록, ImmutableID 매핑 CSV.

IdP 계정 아이디는 '아이디@joowon.me' 형식(IdP 안에서만 쓰는 ID)이고,
각 학교 테넌트의 실제 Microsoft 365 계정(UPN)과 ImmutableID로 연결된다.

사용: python make_test_data.py --domains ../idp/data/domains.json --out-dir ../out --password-file <경로>
  - ../idp/data/users.json 을 만든다(비밀번호 해시 포함, 저장소에 올리지 않음).
  - out/entra-users.json  : 테넌트에 만들 사용자와 라이선스 대상 여부
  - out/immutableid.csv   : Invoke-SenM365Federation.ps1 -Mode SetImmutableId 입력
  - 비밀번호는 --password-file 에만 평문으로 저장한다(이미 있으면 재사용).
"""
import argparse
import csv
import json
import os
import secrets
import string
import uuid

from werkzeug.security import generate_password_hash

# (IdP 아이디, 이름, 역할, 연결 학교 키 목록, 플래그, 라이선스 부여 여부, 설명)
ACCOUNTS = [
    ("student01", "학생01", "학생", ["A"], {}, True, "기본 시나리오(학교 A)"),
    ("teacher01", "교사01", "교사", ["A"], {}, True, "기본 시나리오(학교 A)"),
    ("student02", "학생02", "학생", ["B"], {}, True, "기본 시나리오(학교 B)"),
    ("multi01", "겸임교사01", "교사", ["A", "B"], {}, True, "두 학교 소속(B-4, 라우팅 학교 선택)"),
    ("mfa01", "MFA학생01", "학생", ["A"], {"mfa": True}, True, "IdP가 MFA 수행 표시(C-7)"),
    ("nomap01", "미매핑01", "학생", ["A"], {"skipImmutableId": True}, False, "Entra 쪽 ImmutableID 없음(C-1)"),
    ("badissuer01", "잘못된발급자01", "학생", ["A"], {"badIssuer": True}, False, "등록 안 된 Issuer(B-2)"),
    ("badsig01", "서명변조01", "학생", ["A"], {"badSignature": True}, False, "서명 변조(B-2)"),
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
    for uid, name, role, schools, flags, licensed, note in ACCOUNTS:
        prev = {a["domain"]: a["immutableId"] for a in old.get(uid, {}).get("accounts", [])}
        immutable = next(iter(prev.values()), None) or uuid.uuid4().hex
        accounts = []
        for key in schools:
            domain = keymap[key]
            upn = f"{uid}@{domain}"
            accounts.append({"domain": domain, "upn": upn, "immutableId": immutable})
            entra.append({"tenantId": domains[domain]["tenantId"], "upn": upn, "displayName": f"{name} (PoC {role})",
                          "mailNickname": uid, "licensed": licensed, "note": note})
            if not flags.get("skipImmutableId"):
                csv_rows.append({"TenantId": domains[domain]["tenantId"], "UserPrincipalName": upn, "ImmutableId": immutable})
        users[uid] = {
            "name": name, "role": role, "note": note,
            "passwordHash": generate_password_hash(password, method="pbkdf2:sha256:600000"),
            "accounts": accounts,
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
