// Applies the saved theme before first paint. Storage can be unavailable
// (private mode, blocked site data); the OS preference is the fallback.
(function () {
  try {
    var t = window.localStorage.getItem("buffmon.theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage unavailable: follow the OS */ }
})();
