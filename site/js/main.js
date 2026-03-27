// Theme toggle: system → light → dark → system
document.addEventListener("DOMContentLoaded", function () {
  var btn = document.querySelector(".theme-toggle");
  if (!btn) return;
  var states = [null, "light", "dark"];
  var svgs = [
    '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zM2 8a6 6 0 016-6v12a6 6 0 01-6-6z"/></svg>',
    '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><circle cx="8" cy="8" r="3.5"/><path d="M8 0v2M8 14v2M0 8h2M14 8h2M2.3 2.3l1.4 1.4M12.3 12.3l1.4 1.4M13.7 2.3l-1.4 1.4M3.7 12.3l-1.4 1.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
    '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M6 1a7 7 0 009 6.7A7 7 0 116 1z"/></svg>'
  ];

  function preference() {
    var t = localStorage.getItem("theme");
    return states.indexOf(t) !== -1 ? t : null;
  }

  function apply(pref) {
    if (pref) {
      localStorage.setItem("theme", pref);
      document.documentElement.setAttribute("data-theme", pref);
    } else {
      localStorage.removeItem("theme");
      document.documentElement.removeAttribute("data-theme");
    }
    btn.innerHTML = svgs[states.indexOf(pref)];
  }

  // Set icon to match stored preference (CSS @media handles system default)
  btn.innerHTML = svgs[states.indexOf(preference())];

  btn.addEventListener("click", function () {
    var idx = states.indexOf(preference());
    apply(states[(idx + 1) % states.length]);
  });
});

// Mobile hamburger menu (toggles .nav-overflow dropdown)
document.addEventListener("DOMContentLoaded", function () {
  var nav = document.querySelector(".nav");
  var hamburger = document.querySelector(".nav-hamburger");
  if (hamburger) {
    hamburger.addEventListener("click", function (e) {
      e.stopPropagation();
      var isOpen = nav.classList.toggle("open");
      hamburger.setAttribute("aria-expanded", isOpen);
    });
    document.addEventListener("click", function (e) {
      if (!nav.contains(e.target)) {
        nav.classList.remove("open");
        hamburger.setAttribute("aria-expanded", "false");
      }
    });
  }
});

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
