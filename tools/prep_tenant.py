"""학교 테넌트 사전 준비(PoC): 하위 도메인 추가, 인증용 TXT 값, 라이선스·보안 기본값·전역 관리자 확인.

사용: python prep_tenant.py <tenantId> <subdomain> [subdomain ...]
"""
import json
import sys

from graph_token import Graph

GA_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"


def main(tenant, domains):
    g = Graph(tenant)
    org = g.call("GET", "/organization?$select=displayName,verifiedDomains")["value"][0]
    print(f"[테넌트] {org['displayName']} ({tenant})")
    existing = {d["id"].lower(): d for d in g.get_all("/domains")}
    for d in existing.values():
        print(f"  도메인 {d['id']}: verified={d['isVerified']} default={d['isDefault']} auth={d['authenticationType']}")

    records = []
    for name in domains:
        name = name.lower()
        if name not in existing:
            g.call("POST", "/domains", {"id": name})
            print(f"  + 추가: {name}")
        dom = g.call("GET", f"/domains/{name}")
        if dom["isVerified"]:
            print(f"  = 이미 인증됨: {name}")
            continue
        for rec in g.get_all(f"/domains/{name}/verificationDnsRecords"):
            if rec.get("recordType") == "Txt":
                records.append({"domain": name, "type": "TXT", "text": rec["text"], "ttl": rec.get("ttl")})

    skus = g.get_all("/subscribedSkus?$select=skuPartNumber,consumedUnits,prepaidUnits,capabilityStatus")
    print("  [라이선스] 남은 수량")
    for s in skus:
        if s.get("capabilityStatus") != "Enabled":
            continue
        free = s["prepaidUnits"]["enabled"] - s["consumedUnits"]
        print(f"    {s['skuPartNumber']}: {free} 남음 / 전체 {s['prepaidUnits']['enabled']}")

    sd = g.call("GET", "/policies/identitySecurityDefaultsEnforcementPolicy")
    print(f"  [보안 기본값] isEnabled={sd.get('isEnabled')}")
    gas = g.get_all(f"/directoryRoles(roleTemplateId='{GA_TEMPLATE}')/members?$select=userPrincipalName,accountEnabled")
    print("  [전역 관리자] " + ", ".join(f"{m.get('userPrincipalName')}({'on' if m.get('accountEnabled') else 'off'})" for m in gas))
    print("DNS_RECORDS=" + json.dumps(records, ensure_ascii=False))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
