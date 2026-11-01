(function () {
  "use strict";
  if (new URLSearchParams(window.location.search).get("error")) {
    document.getElementById("err").hidden = false;
  }
})();
