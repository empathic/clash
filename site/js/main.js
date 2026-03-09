// Version selector toggle
document.addEventListener("DOMContentLoaded", function () {
  var selector = document.querySelector(".version-selector");
  if (selector) {
    var btn = selector.querySelector(".version-btn");
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      var isOpen = selector.classList.toggle("open");
      btn.setAttribute("aria-expanded", isOpen);
    });
    document.addEventListener("click", function () {
      selector.classList.remove("open");
      btn.setAttribute("aria-expanded", "false");
    });
  }
});

// Copy-to-clipboard for code blocks
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("pre").forEach(function (pre) {
    var btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.addEventListener("click", function () {
      var code = pre.querySelector("code");
      var text = (code || pre).textContent;
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = "Copied";
        btn.classList.add("copied");
        setTimeout(function () {
          btn.textContent = "Copy";
          btn.classList.remove("copied");
        }, 1500);
      });
    });
    pre.appendChild(btn);
  });
});
