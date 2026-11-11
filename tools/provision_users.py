"""학교 테넌트에 PoC 테스트 계정을 만들고 라이선스를 준다(멱등).

ImmutableID는 넣지 않는다. 페더레이션 전에 graph/Invoke-SenM365Federation.ps1 -Mode SetImmutableId 로 설정한다.
테넌트 쪽 비밀번호는 무작위로 정하고 저장하지 않는다(페더레이션 후에는 IdP로만 로그인).

사용: python provision_users.py --users ../out/entra-users.json \
        --skus <tenantId>=<skuPartNumber>[,<skuPartNumber>] [--skus ...] [--usage-location KR]
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
    args = ap.parse_args()

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
            found = g.get_all(f"/users?$filter=userPrincipalName eq '{upn}'&$select=id,userPrincipalName,assignedLicenses")
            if found:
                user = found[0]
                action = "있음"
            else:
                user = g.call("POST", "/users", {
                    "accountEnabled": True,
                    "displayName": r["displayName"],
                    "mailNickname": r["mailNickname"],
                    "userPrincipalName": upn,
                    "usageLocation": args.usage_location,
                    "passwordProfile": {"password": random_password(), "forceChangePasswordNextSignIn": False},
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
