/* SEN IdP 화면 동작: 유리 카드의 빛과 로그인 칸 도우미. 폼은 그대로 서버(/login)로 보냅니다. */
(() => {
  "use strict";
  const root = document.documentElement;
  const motion = matchMedia("(prefers-reduced-motion: reduce)");
  const play = (el, frames, options) => (motion.matches || !el.animate ? null : el.animate(frames, options));
  requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove("init")));

  // 유리 위의 빛이 포인터를 따라갑니다.
  for (const glass of document.querySelectorAll(".glass")) {
    glass.addEventListener("pointermove", event => {
      const r = glass.getBoundingClientRect();
      glass.style.setProperty("--x", event.clientX - r.left + "px");
      glass.style.setProperty("--y", event.clientY - r.top + "px");
    });
  }

  const form = document.getElementById("loginForm");
  if (!form) return;
  const $ = id => document.getElementById(id);
  const box = $("box"), id = $("username"), pw = $("password"), suffix = $("suffix");
  const eye = $("eye"), send = $("send"), msg = $("msg");
  const SUFFIX = "@" + form.dataset.idDomain;
  const HANGUL = /[ㄱ-ㅎㅏ-ㅣ가-힣]/;
  let busy = false;
  let shown = msg.textContent.trim() ? "error" : "";

  const shake = () => play(box, [
    { transform: "translateX(0)" }, { transform: "translateX(-10px)" }, { transform: "translateX(8px)" },
    { transform: "translateX(-5px)" }, { transform: "translateX(3px)" }, { transform: "translateX(0)" },
  ], { duration: 480, easing: "ease-out", composite: "add" });
  const jelly = () => play(box, [
    { transform: "scale(1)" }, { transform: "scale(1.012, .985)" }, { transform: "scale(.997, 1.006)" }, { transform: "scale(1)" },
  ], { duration: 600, easing: "ease-out", composite: "add" });

  function say(kind, text) {
    shown = text ? kind : "";
    msg.textContent = text || "";
    msg.classList.toggle("info", kind !== "error");
  }
  const clear = kind => { if (shown === kind) say("", ""); };
  const normalize = value => {
    const v = value.trim();
    return v.toLowerCase().endsWith(SUFFIX) ? v.slice(0, -SUFFIX.length) : v;
  };
  const sync = () => {
    suffix.hidden = id.value.includes("@");
    send.disabled = busy || !id.value.trim() || !pw.value;
  };

  // JS가 있으면 검사·안내를 여기서 하고, 없으면 브라우저 기본 검사로 동작합니다.
  form.noValidate = true;
  eye.hidden = false;

  form.addEventListener("submit", event => {
    const v = normalize(id.value);
    let problem = busy;
    if (!busy && !v) { problem = true; shake(); id.focus(); }
    else if (!busy && HANGUL.test(v)) { problem = true; say("error", "아이디는 영문과 숫자로 입력해 주세요."); shake(); id.focus(); }
    else if (!busy && !pw.value) { problem = true; pw.focus(); }
    if (problem) { event.preventDefault(); return; }
    id.value = v;
    busy = true;
    box.classList.add("busy");
    id.readOnly = pw.readOnly = true;
    sync();
    jelly();
  });
  // 비밀번호가 비어 있으면 Enter로 다음 칸으로 넘어갑니다.
  id.addEventListener("keydown", event => {
    if (event.key !== "Enter" || event.isComposing || event.keyCode === 229 || pw.value) return;
    event.preventDefault();
    if (normalize(id.value)) pw.focus();
    else shake();
  });

  id.addEventListener("input", () => {
    clear("error");
    if (HANGUL.test(id.value)) say("hangul", "한글로 입력되고 있습니다. 한/영 키를 눌러 주세요.");
    else clear("hangul");
    sync();
  });
  pw.addEventListener("input", () => { clear("error"); sync(); });
  const caps = event => {
    if (!event.getModifierState) return;
    if (event.getModifierState("CapsLock")) { if (shown !== "error") say("caps", "Caps Lock이 켜져 있습니다."); }
    else clear("caps");
  };
  pw.addEventListener("keydown", caps);
  pw.addEventListener("keyup", caps);
  pw.addEventListener("blur", () => clear("caps"));

  eye.addEventListener("click", () => {
    const show = pw.type === "password";
    pw.type = show ? "text" : "password";
    eye.classList.toggle("on", show);
    eye.setAttribute("aria-pressed", String(show));
    eye.setAttribute("aria-label", show ? "비밀번호 숨기기" : "비밀번호 보기");
    pw.focus();
  });

  // 뒤로 가기로 돌아오면(bfcache) 보내는 중 상태를 풉니다.
  window.addEventListener("pageshow", event => {
    if (!event.persisted) return;
    busy = false;
    box.classList.remove("busy");
    id.readOnly = pw.readOnly = false;
    pw.value = "";
    sync();
  });

  sync();
  if (shown === "error") setTimeout(shake, 200);
  if (matchMedia("(pointer: fine)").matches) (id.value ? pw : id).focus({ preventScroll: true });
})();
