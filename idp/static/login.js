(function () {
  "use strict";

  var SUFFIX = "@joowon.me";
  var form = document.getElementById("loginForm");

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
