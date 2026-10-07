/*
 * Renders the shared app shell: a fixed dark navigation rail on desktop, a
 * drawer + compact pill nav on mobile, and a sticky topbar. Mounts into
 * #app-shell and re-parents the page's <main> underneath the topbar so the
 * rail and the content column can be laid out independently.
 *
 * Self-contained (no dependency on config/core/services) so it can run before
 * the rest of the app scripts and the nav appears immediately.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.ui = window.LogAnalyzer.ui || {};

  var TABS = [
    { key: "overview", label: "Overview", short: "Overview", href: "index.html", icon: "space_dashboard" },
    { key: "threats", label: "Threats", short: "Threats", href: "threats.html", icon: "gpp_maybe" },
    { key: "log-events", label: "Log events", short: "Events", href: "log-events.html", icon: "receipt_long" },
    { key: "upload", label: "Upload logs", short: "Upload", href: "upload.html", icon: "upload_file" }
  ];

  var ACTIVE_TAB_BY_PAGE = {
    overview: "overview",
    upload: "upload",
    threats: "threats",
    "threat-detail": "threats",
    "log-events": "log-events"
  };

  // Title shown in the topbar per page. Keeps each page's <h1> in the content
  // area, so the topbar uses a plain div rather than a second h1.
  var PAGE_META = {
    overview: { title: "Overview", sub: "Posture across ingested logs" },
    threats: { title: "Threats", sub: "Detected events and risk scoring" },
    "threat-detail": { title: "Threat detail", sub: "Single finding breakdown" },
    "log-events": { title: "Log events", sub: "Raw parsed records" },
    upload: { title: "Upload logs", sub: "Ingest a new log file" }
  };

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function railLinkHtml(tab, activeKey) {
    var isActive = tab.key === activeKey;
    return (
      '<a class="rail-link"' +
      (isActive ? ' aria-current="page"' : "") +
      ' href="' + tab.href + '">' +
      '<span class="material-symbols-outlined" data-icon="' + tab.icon + '">' + tab.icon + '</span>' +
      "<span>" + esc(tab.label) + "</span>" +
      "</a>"
    );
  }

  function pillHtml(tab, activeKey) {
    var isActive = tab.key === activeKey;
    return (
      '<a class="topbar-pill"' +
      (isActive ? ' aria-current="page"' : "") +
      ' href="' + tab.href + '">' +
      '<span class="material-symbols-outlined" data-icon="' + tab.icon + '">' + tab.icon + '</span>' +
      "<span>" + esc(tab.short) + "</span>" +
      "</a>"
    );
  }

  var BRAND_HTML =
    '<div class="rail-brand">' +
    '<div class="rail-mark"><span class="material-symbols-outlined" data-icon="shield" ' +
    'style="font-variation-settings:\'FILL\' 1;">shield</span></div>' +
    '<div class="min-w-0">' +
    '<div class="rail-title truncate">THREAT-NEXUS</div>' +
    '<div class="rail-sub truncate">Security Ops</div>' +
    "</div>" +
    "</div>";

  var RAIL_HTML =
    '<aside class="app-rail" id="app-rail" aria-label="Primary">' +
    BRAND_HTML +
    '<div class="rail-label">Monitor</div>' +
    '<nav class="rail-nav" id="app-rail-nav"></nav>' +
    '<div class="rail-foot">' +
    '<div class="rail-status" id="app-status">' +
    '<span class="rail-dot" id="app-status-dot"></span>' +
    '<span id="app-status-text">Connecting</span>' +
    "</div>" +
    "</div>" +
    "</aside>";

  var TOPBAR_HTML =
    '<header class="app-topbar">' +
    '<button class="btn btn-icon lg:hidden" id="app-rail-toggle" type="button" ' +
    'aria-label="Open navigation" aria-expanded="false" aria-controls="app-rail">' +
    '<span class="material-symbols-outlined" data-icon="menu">menu</span>' +
    "</button>" +
    '<div class="min-w-0 lg:hidden"><div class="text-[13px] font-semibold text-on-surface leading-tight" ' +
    'id="app-topbar-title">THREAT-NEXUS</div></div>' +
    '<div class="topbar-tabs" id="app-topbar-tabs"></div>' +
    '<div class="ml-auto flex items-center gap-2 shrink-0">' +
    '<button class="btn btn-primary btn-sm hidden sm:inline-flex" id="app-upload-button" type="button">' +
    '<span class="material-symbols-outlined" data-icon="add">add</span>' +
    "<span>Upload log</span>" +
    "</button>" +
    '<div class="w-7 h-7 rounded-lg bg-rail text-white flex items-center justify-center ' +
    'text-[10px] font-semibold select-none" title="Operator profile">OP</div>' +
    "</div>" +
    "</header>";

  function render() {
    var placeholder = document.getElementById("app-shell");
    if (!placeholder) {
      return;
    }

    var dataPage = document.body.getAttribute("data-page") || "overview";
    var activeKey = ACTIVE_TAB_BY_PAGE[dataPage] || "overview";
    var meta = PAGE_META[dataPage] || PAGE_META.overview;

    placeholder.innerHTML =
      RAIL_HTML + TOPBAR_HTML + '<div class="rail-scrim" id="app-rail-scrim" hidden></div>';

    document.getElementById("app-rail-nav").innerHTML = TABS.map(function (tab) {
      return railLinkHtml(tab, activeKey);
    }).join("");

    document.getElementById("app-topbar-tabs").innerHTML = TABS.map(function (tab) {
      return pillHtml(tab, activeKey);
    }).join("");

    var titleEl = document.getElementById("app-topbar-title");
    if (titleEl) {
      titleEl.textContent = meta.title;
    }

    /*
     * The page's <main> is parsed *after* this script runs, and the rail and
     * topbar are both position:fixed, so there is nothing to re-parent: the
     * layout is pure CSS (see .app-rail / .app-topbar / .app-content in
     * css/style.css) and <main> simply needs to clear the fixed topbar.
     * Doing it this way avoids a visible reflow on load.
     */
    wireDrawer();
    wireUploadButton(dataPage);
    updateStatus();
  }

  function wireDrawer() {
    var rail = document.getElementById("app-rail");
    var toggle = document.getElementById("app-rail-toggle");
    var scrim = document.getElementById("app-rail-scrim");
    if (!rail || !toggle || !scrim) {
      return;
    }

    function setOpen(open) {
      rail.classList.toggle("is-open", open);
      scrim.classList.toggle("is-open", open);
      scrim.hidden = !open;
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
      var icon = toggle.querySelector(".material-symbols-outlined");
      if (icon) {
        icon.textContent = open ? "close" : "menu";
      }
    }

    toggle.addEventListener("click", function () {
      setOpen(!rail.classList.contains("is-open"));
    });
    scrim.addEventListener("click", function () {
      setOpen(false);
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && rail.classList.contains("is-open")) {
        setOpen(false);
        toggle.focus();
      }
    });
  }

  function wireUploadButton(dataPage) {
    var button = document.getElementById("app-upload-button");
    if (!button || dataPage === "upload") {
      return;
    }
    button.addEventListener("click", function () {
      window.location.href = "upload.html";
    });
  }

  /*
   * The rail's status pill reports where the data on screen comes from.
   * config.js loads after this file, so the first render falls back to
   * "Connecting" and DOMContentLoaded corrects it.
   *
   * When mock mode is off we actually probe the API rather than just
   * echoing the config, because "configured for live" and "backend
   * reachable" are different things - a deployed dashboard pointing at a
   * dead API should say so instead of looking healthy next to empty tables.
   */
  function setStatus(text, tone) {
    var textEl = document.getElementById("app-status-text");
    var dotEl = document.getElementById("app-status-dot");
    if (!textEl || !dotEl) {
      return;
    }
    textEl.textContent = text;
    dotEl.classList.toggle("is-offline", tone === "offline");
    dotEl.classList.toggle("is-mock", tone === "mock");
    dotEl.classList.toggle("is-checking", tone === "checking");
  }

  function probeHealth(baseUrl) {
    var controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    var timer = setTimeout(function () {
      if (controller) {
        controller.abort();
      }
    }, 5000);

    return fetch(baseUrl + "/health", { signal: controller ? controller.signal : undefined })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("HTTP " + response.status);
        }
        setStatus("Live backend", "live");
      })
      .catch(function () {
        setStatus("Backend offline", "offline");
      })
      .then(function () {
        clearTimeout(timer);
      });
  }

  function updateStatus() {
    if (!document.getElementById("app-status-text")) {
      return;
    }
    var config = window.LogAnalyzer && window.LogAnalyzer.config;
    if (!config) {
      setStatus("Connecting", "checking");
      return;
    }
    if (config.USE_MOCK) {
      setStatus("Demo data", "mock");
      return;
    }
    setStatus("Checking API", "checking");
    probeHealth(config.BASE_URL);
  }

  document.addEventListener("DOMContentLoaded", updateStatus);

  window.LogAnalyzer.ui.layout = {
    render: render,
    updateStatus: updateStatus
  };

  render();
})();