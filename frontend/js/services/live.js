/*
 * Live threat alerts over Socket.IO.
 *
 * Connects to the API origin, shows a Live / Disconnected badge under the page
 * title and re-broadcasts every server "threat_alert" as a DOM event named
 * "threat-alert", so any page can react without touching the socket itself.
 *
 * Skipped in mock mode (?mock=...) and when the Socket.IO client script failed
 * to load, so the dashboard keeps working either way.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  var config = window.LogAnalyzer.config;

  if (!config || config.USE_MOCK || typeof window.io !== "function") {
    return;
  }

  // BASE_URL is ".../api/v1" or a relative "/api/v1"; Socket.IO lives on the
  // origin root, so only the origin is needed.
  function apiOrigin() {
    try {
      return new URL(config.BASE_URL, window.location.href).origin;
    } catch (error) {
      return undefined;
    }
  }

  var badge = null;
  var dot = null;
  var label = null;

  function buildBadge() {
    var host = document.querySelector(".page-sub");
    if (!host) {
      return;
    }
    badge = document.createElement("span");
    badge.id = "live-status";
    badge.className = "inline-flex items-center gap-1.5 ml-3 text-[12px]";
    badge.setAttribute("role", "status");

    dot = document.createElement("span");
    dot.style.cssText = "width:8px;height:8px;border-radius:9999px;display:inline-block;";

    label = document.createElement("span");

    badge.appendChild(dot);
    badge.appendChild(label);
    host.appendChild(badge);
  }

  function setStatus(connected) {
    if (!badge) {
      return;
    }
    dot.style.background = connected ? "#16a34a" : "#9ca3af";
    label.textContent = connected ? "Live" : "Disconnected";
  }

  buildBadge();
  setStatus(false);

  var socket = window.io(apiOrigin());

  socket.on("connect", function () {
    setStatus(true);
  });

  socket.on("disconnect", function () {
    setStatus(false);
  });

  socket.on("connect_error", function () {
    setStatus(false);
  });

  socket.on("threat_alert", function (alert) {
    window.dispatchEvent(new CustomEvent("threat-alert", { detail: alert }));
  });

  window.LogAnalyzer.live = { socket: socket };
})();