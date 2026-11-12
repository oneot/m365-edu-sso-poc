"""④ 라우팅 도메인 브라우저 시연: 실제 Microsoft 웹앱에 통합 아이디로 로그인하고 단계별 화면을 저장한다.

헤드리스 Chrome(Playwright, 임시 프로필)이 사람이 하는 순서를 그대로 따른다.
  1) 앱 접속 → Microsoft 로그인 화면에 통합 아이디 입력
  2) IdP 로그인 화면(GitHub Pages)에 비밀번호 입력(아이디는 IdP가 미리 채움)
  3) 학교 선택(여러 학교 소속) / 2단계 인증(TOTP)
  4) Microsoft 확인 화면(도메인 확인, 로그인 상태 유지)
  5) 앱 화면

사용: python browser_route_demo.py --password-file <파일> --totp-file <JSON> --out-dir <폴더> [--flow outlook teams]
"""
import argparse
import json
import os
import re
import time
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

from e2e_signin import totp_now

ROUTE = "id.joowon.me"
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/157.0.0.0 Safari/537.36")
FLOWS = {
    # 이름: (앱 주소, 통합 아이디, IdP 아이디, 고를 학교 도메인, 앱 주소 판별)
    "outlook": ("https://outlook.office.com/mail/", f"student02@{ROUTE}", "student02", None, "outlook."),
    "teams": ("https://teams.microsoft.com/v2/", f"multi01@{ROUTE}", "multi01", "school1.joowon.me",
              "teams."),
    # 포털 링크(login_hint=통합 아이디): 아이디 입력 없이 진행되어 도메인 확인 대화상자가 뜨는 경로
    "m365": (f"https://www.office.com/?auth=2&login_hint=student02%40{ROUTE}", f"student02@{ROUTE}", "student02", None,
             "m365.cloud"),
}
# 앱 오른쪽 위 계정 버튼(로그인한 계정·조직 확인용)
ACCOUNT_BUTTONS = ["#O365_MainLink_Me", "#idna-me-control-avatar-trigger", "[data-tid='me-control-avatar-trigger']",
                   "button[aria-label*='계정 관리자']", "button[aria-label*='프로필']", "button[aria-label*='Account manager']"]


def click_first(page, selectors):
    for sel in selectors:
        loc = page.locator(sel)
        if loc.count() and loc.first.is_visible():
            loc.first.click()
            return sel
    return None


def run_flow(pw, name, args, password, totp):
    url, routing_id, idp_user, choose, app_host = FLOWS[name]
    out_dir = os.path.join(args.out_dir, name)
    os.makedirs(out_dir, exist_ok=True)
    browser = pw.chromium.launch(channel="chrome", headless=not args.headed)
    ctx = browser.new_context(locale="ko-KR", user_agent=UA, viewport={"width": 1280, "height": 800})
    page = ctx.new_page()
    log, shots, done = [], [], set()
    mfa_tries = 0

    def shot(label):
        path = os.path.join(out_dir, f"{len(shots) + 1:02d}-{label}.png")
        page.screenshot(path=path)
        shots.append(path)
        log.append(f"{label}: {urlparse(page.url).netloc}{urlparse(page.url).path}")

    page.goto(url)
    deadline = time.time() + args.timeout
    result = {"flow": name, "routingId": routing_id}
    while time.time() < deadline:
        page.wait_for_timeout(1200)
        try:
            page.wait_for_load_state("domcontentloaded", timeout=10000)
            url_now = page.url
            body = page.locator("body").inner_text(timeout=5000) if page.locator("body").count() else ""
        except Exception:  # noqa: BLE001  화면 전환 중
            continue
        if page.url != url_now:
            continue  # 읽는 사이 다음 화면으로 넘어감
        host, path = urlparse(url_now).netloc, urlparse(url_now).path
        if host.endswith("login.microsoftonline.com") or host.endswith("login.microsoft.com"):
            if re.search(r"AADSTS\d+", body):
                shot("ms-error")
                result.update(result="error", error=re.search(r"AADSTS\d+[^\n]*", body).group(0)[:200])
                break
            email = page.locator("input[name=loginfmt]")
            if "username" not in done and email.count() and email.first.is_visible():
                email.first.fill(routing_id)
                shot("ms-signin-routing-id")
                click_first(page, ["#idSIButton9", "input[type=submit]", "button[type=submit]"])
                done.add("username")
                continue
            if "kmsi" not in done and ("로그인 상태를 유지" in body or "Stay signed in" in body):
                shot("ms-kmsi")
                click_first(page, ["#idSIButton9", "button:has-text('예')", "input[value='예']", "button:has-text('Yes')"])
                done.add("kmsi")
                continue
            if "confirm" not in done and path.endswith(("/login.srf", "/appverify")):
                # 도메인 확인 대화상자(사용자 이름 입력 없이 조용히 로그인될 때)
                shot("ms-domain-confirm")
                if click_first(page, ["#idSIButton9", "button:has-text('계속')", "button:has-text('확인')",
                                      "input[type=submit]", "button[type=submit]"]):
                    done.add("confirm")
                    continue
        elif host == "login.joowon.me" and "idp-login" not in done and page.locator("#password").count():
            prefilled = page.locator("#username").input_value()
            result["prefilled"] = prefilled
            shot("sen-login")
            if not prefilled:
                page.locator("#username").fill(idp_user)
            page.locator("#password").fill(password)
            page.locator("button[type=submit]").click()
            done.add("idp-login")
        elif host == "auth.joowon.me":
            if "choose" not in done and page.locator("button[name=domain]").count():
                shot("sen-choose-school")
                page.locator(f"button[name=domain][value='{choose}']").click()
                done.add("choose")
            elif page.locator("input[name=code]").count() and mfa_tries < 3 and (
                    mfa_tries == 0 or page.locator(".alert").count()):
                # 다른 시험이 같은 30초 코드를 이미 썼으면 IdP가 재사용으로 거부 → 다음 코드로 재시도
                shot("sen-mfa" if mfa_tries == 0 else f"sen-mfa-retry{mfa_tries}")
                page.locator("input[name=code]").fill(totp_now(idp_user, totp[idp_user]))
                page.locator("button[type=submit]").click()
                mfa_tries += 1
        elif app_host in host and "idp-login" in done:
            page.wait_for_timeout(args.settle * 1000)
            result.update(result="app", title=page.title(), url=f"{host}{urlparse(page.url).path}")
            shot("app")
            clicked = click_first(page, ACCOUNT_BUTTONS)
            if not clicked:
                page.mouse.click(1251, 23)  # 오른쪽 위 계정 아이콘 위치
            page.wait_for_timeout(4000)
            shot("app-account")
            result["accountButton"] = clicked or "coordinate"
            break
    else:
        shot("timeout")
        result["result"] = "timeout"
    result.update(steps=log, screenshots=shots)
    ctx.close()
    browser.close()
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--password-file", required=True)
    ap.add_argument("--totp-file", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--flow", nargs="*", default=list(FLOWS))
    ap.add_argument("--timeout", type=int, default=150)
    ap.add_argument("--settle", type=int, default=25, help="앱 화면이 다 그려질 때까지 기다리는 초")
    ap.add_argument("--headed", action="store_true")
    args = ap.parse_args()
    password = open(args.password_file, encoding="utf-8").read().strip()
    totp = {u: parse_qs(urlparse(x).query)["secret"][0]
            for u, x in json.load(open(args.totp_file, encoding="utf-8")).items()}
    results = []
    with sync_playwright() as pw:
        for name in args.flow:
            r = run_flow(pw, name, args, password, totp)
            results.append(r)
            print(json.dumps({k: v for k, v in r.items() if k != "screenshots"}, ensure_ascii=False))
    with open(os.path.join(args.out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
