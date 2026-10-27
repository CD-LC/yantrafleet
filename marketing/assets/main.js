// Yantrika marketing site — shared, tiny, no dependencies.
// 1) mobile nav toggle, 2) the product-shot switcher on the landing page,
// 3) copy buttons on snippet blocks. Everything else on these pages is
// static HTML; with this file blocked every page still reads fine.
(function () {
  var btn = document.querySelector(".navtoggle");
  var nav = document.querySelector("nav.top");
  if (btn && nav) {
    btn.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // -- product shots (index.html) --------------------------------------
  var show = document.getElementById("showcase");
  var img = document.getElementById("shot-img");
  if (show && img) {
    var ALT = {
      overview: "Yantrika console — Overview: fleet health, throughput chart with the incident dip, top issues, live alerts and the fleet table",
      liveops: "Yantrika console — Live Ops: robots on the warehouse map, AMR-07 in fault with its telemetry drawer open",
      incident: "Yantrika console — Incidents: INC-1042 with recorded-telemetry replay, root cause and fix",
      maint: "Yantrika console — Maintenance: predicted failures with RUL and confidence next to the robot health table",
      analytics: "Yantrika console — Analytics: tasks, utilization, SLA and reliability tiles, time lost by cause",
      copilot: "Yantrika console — the Sarathi copilot answering why throughput dropped, with evidence chips",
      connect: "Yantrika console — Workspace & Connect: ready-to-paste REST snippet for publishing robot state with an ingest key"
    };
    var tabs = show.querySelectorAll(".tabs button");
    // Preload the other shots once the page is idle so switching is instant.
    var preload = function () {
      Object.keys(ALT).forEach(function (k) {
        var i = new Image(); i.src = "assets/screens/console-" + k + ".webp";
      });
    };
    if (window.requestIdleCallback) { requestIdleCallback(preload); } else { setTimeout(preload, 1500); }
    Array.prototype.forEach.call(tabs, function (t) {
      t.addEventListener("click", function () {
        var k = t.getAttribute("data-shot");
        Array.prototype.forEach.call(tabs, function (x) { x.classList.toggle("on", x === t); x.setAttribute("aria-selected", x === t ? "true" : "false"); });
        img.src = "assets/screens/console-" + k + ".webp";
        img.alt = ALT[k] || img.alt;
      });
    });
  }

  // -- copy buttons on .snip blocks (integrations.html) ------------------
  var snips = document.querySelectorAll(".snip");
  if (snips.length && navigator.clipboard) {
    Array.prototype.forEach.call(snips, function (s) {
      var b = document.createElement("button");
      b.className = "copybtn"; b.type = "button"; b.textContent = "Copy";
      b.addEventListener("click", function () {
        var code = s.querySelector("code") || s.querySelector("pre");
        navigator.clipboard.writeText(code ? code.innerText : s.innerText).then(function () {
          b.textContent = "Copied ✓"; setTimeout(function () { b.textContent = "Copy"; }, 1500);
        });
      });
      s.appendChild(b);
    });
  }
})();
