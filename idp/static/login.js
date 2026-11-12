(function () {
  "use strict";

  var SUFFIX = "@joowon.me";
  var ALLOWED_API = ["https://auth.joowon.me", "https://sen-sso-idp-878679.azurewebsites.net"];
  if (location.hostname === "localhost" || location.hostname === "127.0.0.1") {
    ALLOWED_API.push("http://127.0.0.1:5000", "http://localhost:5000");
  }
  var ERRORS = {
    "1": "아이디 또는 비밀번호가 맞지 않습니다.",
    locked: "로그인 시도가 너무 많습니다. 잠시 후 다시 시도해 주세요.",
    expired: "로그인 요청이 만료됐습니다. 앱이나 사이트에서 다시 시작해 주세요.",
    switch: "이 브라우저에 다른 사용자가 로그인되어 있습니다. 입력한 아이디로 다시 로그인해 주세요."
  };

  var form = document.getElementById("loginForm");
  var params = new URLSearchParams(location.search);

  // GitHub Pages 화면: 로그인 처리 서버 주소를 허용 목록에서만 고른다.
  if (document.body.dataset.mode === "pages") {
    var api = params.get("api");
    form.action = (ALLOWED_API.indexOf(api) >= 0 ? api : ALLOWED_API[0]) + "/login";
    document.getElementById("k").value = params.get("k") || "";
    var user = params.get("user");
    if (user) document.getElementById("username").value = user.replace(SUFFIX, "");
    var school = params.get("school");
    if (school) {
      var ctx = document.getElementById("context");
      ctx.textContent = school + " Microsoft 365에 로그인합니다.";
      ctx.hidden = false;
    }
    var err = params.get("err");
    if (err && ERRORS[err]) {
      var alertBox = document.getElementById("alert");
      alertBox.textContent = ERRORS[err];
      alertBox.hidden = false;
    }
  }

  var pw = document.getElementById("password");
  var toggle = document.getElementById("togglePw");
  if (toggle && pw) {
    toggle.addEventListener("click", function () {
      var show = pw.type === "password";
      pw.type = show ? "text" : "password";
      toggle.setAttribute("aria-label", show ? "비밀번호 숨기기" : "비밀번호 보기");
      toggle.classList.toggle("on", show);
    });
  }

  form.addEventListener("submit", function () {
    var u = document.getElementById("username");
    u.value = u.value.trim().replace(new RegExp(SUFFIX.replace(/[.]/g, "\\.") + "$", "i"), "");
    form.querySelector("button[type=submit]").disabled = true;
  });
})();
