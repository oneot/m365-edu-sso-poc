"""학교 테넌트에 PoC 테스트 계정을 만들고 라이선스를 준다(멱등).

ImmutableID는 넣지 않는다. 페더레이션 전에 graph/Invoke-SenM365Federation.ps1 -Mode SetImmutableId 로 설정한다.
테넌트 쪽 비밀번호는 --password-file 값(없으면 무작위)으로 정한다. 페더레이션 후에는 IdP로만 로그인하므로
도메인이 관리형일 때만 의미가 있다(원복 대비).
--rename 옛도메인=새도메인: 새 UPN 계정이 없고 옛 UPN 계정이 있으면 새로 만들지 않고 UPN만 바꾼다
(메일함·Teams·ImmutableID 유지).

사용: python provision_users.py --users ../out/entra-users.json \
        --skus <tenantId>=<skuPartNumber>[,<skuPartNumber>] [--skus ...] [--usage-location KR] \
        [--password-file <파일>] [--rename old.example.edu=new.example.edu]
"""
import argparse
import json
import secrets
import string

from graph_token import Graph


def random_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(24))
        if any(c.isdigit() for c in pw) and any(c.isupper() for c in pw) and any(c.islower() for c in pw):
            return pw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--users", required=True)
    ap.add_argument("--skus", action="append", default=[], help="tenantId=SKU1,SKU2")
    ap.add_argument("--usage-location", default="KR")
    ap.add_argument("--password-file")
    ap.add_argument("--rename", action="append", default=[], help="옛도메인=새도메인")
    args = ap.parse_args()
    password = open(args.password_file, encoding="utf-8").read().strip() if args.password_file else None
    renames = dict(x.split("=", 1) for x in args.rename)

    sku_map = {}
    for item in args.skus:
        tenant, names = item.split("=", 1)
        sku_map[tenant] = [n for n in names.split(",") if n]

    rows = json.load(open(args.users, encoding="utf-8"))
    for tenant in sorted({r["tenantId"] for r in rows}):
        g = Graph(tenant)
        skus = {s["skuPartNumber"]: s["skuId"] for s in g.get_all("/subscribedSkus?$select=skuPartNumber,skuId")}
        wanted = []
        for name in sku_map.get(tenant, []):
            if name not in skus:
                raise SystemExit(f"{tenant}: 라이선스 {name} 없음")
            wanted.append(skus[name])
        for r in [x for x in rows if x["tenantId"] == tenant]:
            upn = r["upn"]
            sel = "$select=id,userPrincipalName,assignedLicenses"
            found = g.get_all(f"/users?$filter=userPrincipalName eq '{upn}'&{sel}")
            action = "있음"
            if not found:
                local, domain = upn.split("@")
                for old_domain in [o for o, n in renames.items() if n == domain]:
                    old = g.get_all(f"/users?$filter=userPrincipalName eq '{local}@{old_domain}'&{sel}")
                    if old:
                        g.call("PATCH", f"/users/{old[0]['id']}", {"userPrincipalName": upn})
                        found, action = old, f"이름 변경({local}@{old_domain})"
                        break
            if found:
                user = found[0]
                if password:
                    try:
                        g.call("PATCH", f"/users/{user['id']}",
                               {"passwordProfile": {"password": password, "forceChangePasswordNextSignIn": False}})
                        action += ", 비밀번호 설정"
                    except RuntimeError as e:  # 기존 계정 비밀번호 재설정은 User-PasswordProfile 권한이 필요할 수 있음
                        action += f", 비밀번호 재설정 건너뜀({str(e).split(':')[0].split('-> ')[-1]})"
            else:
                user = g.call("POST", "/users", {
                    "accountEnabled": True,
                    "displayName": r["displayName"],
                    "mailNickname": r["mailNickname"],
                    "userPrincipalName": upn,
                    "usageLocation": args.usage_location,
                    "passwordProfile": {"password": password or random_password(), "forceChangePasswordNextSignIn": False},
                })
                user["assignedLicenses"] = []
                action = "생성"
            lic = ""
            if r.get("licensed") and wanted:
                have = {l["skuId"] for l in user.get("assignedLicenses", [])}
                add = [{"skuId": s, "disabledPlans": []} for s in wanted if s not in have]
                if add:
                    g.call("PATCH", f"/users/{user['id']}", {"usageLocation": args.usage_location})
                    g.call("POST", f"/users/{user['id']}/assignLicense", {"addLicenses": add, "removeLicenses": []})
                    lic = f", 라이선스 {len(add)}개 부여"
                else:
                    lic = ", 라이선스 있음"
            print(f"[{tenant[:8]}] {upn}: {action}{lic}")


if __name__ == "__main__":
    main()
