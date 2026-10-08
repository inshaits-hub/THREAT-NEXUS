/*
 * Builds the JSON/HTML report bodies used by the mock exportReport().
 * The real backend (GET /export/report) builds its own report server-side -
 * this is only reached when LogAnalyzer.config.USE_MOCK is true.
 */
(function () {
  window.LogAnalyzer = window.LogAnalyzer || {};
  window.LogAnalyzer.services = window.LogAnalyzer.services || {};

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function buildJsonReport(generatedAt, summaryData, statsData, threatsList) {
    var typeCounts = {};
    threatsList.forEach(function (item) {
      typeCounts[item.type] = (typeCounts[item.type] || 0) + 1;
    });
    var payload = {
      report: {
        title: "THREAT-NEXUS Report",
        format: "json",
        generated_at: generatedAt
      },
      summary: {
        total_events: summaryData.total_events,
        total_threats: summaryData.total_threats,
        critical_threats: summaryData.critical_threats,
        unique_ips: summaryData.unique_ips
      },
      statistics: {
        severity_distribution: statsData.severity_counts,
        threat_types: typeCounts,
        top_risk_ips: statsData.top_risk_ips
      },
      threats: threatsList
    };
    return JSON.stringify(payload, null, 2);
  }

  function buildHtmlReport(generatedAt, summaryData, threatsList) {
    var bodyHtml;
    if (threatsList.length === 0) {
      bodyHtml = "<p>No threats detected in the analyzed logs.</p>";
    } else {
      var rows = threatsList
        .map(function (item) {
          return (
            "<tr><td>" + escapeHtml(item.timestamp) + "</td>" +
            "<td>" + escapeHtml(item.ip) + "</td>" +
            "<td>" + escapeHtml(item.title) + "</td>" +
            "<td>" + escapeHtml(item.severity) + "</td>" +
            "<td>" + escapeHtml(item.risk_score) + "</td>" +
            "<td>" + escapeHtml(item.details) + "</td></tr>"
          );
        })
        .join("");
      bodyHtml =
        "<table><thead><tr><th>Timestamp</th><th>IP</th><th>Threat</th>" +
        "<th>Severity</th><th>Risk</th><th>Details</th></tr></thead><tbody>" +
        rows +
        "</tbody></table>";
    }

    return (
      "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
      "<title>THREAT-NEXUS Report</title>" +
      "<style>body{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#161616;}" +
      "h1{margin-bottom:4px;}.meta{color:#525252;font-size:13px;margin-bottom:20px;}" +
      ".cards{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap;}" +
      ".card{border:1px solid #d0d0d0;padding:12px 16px;}" +
      ".card .label{font-size:11px;text-transform:uppercase;color:#525252;}" +
      ".card .value{font-size:24px;font-weight:700;}" +
      "table{width:100%;border-collapse:collapse;font-size:13px;}" +
      "th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e0e0e0;}" +
      "th{text-transform:uppercase;font-size:11px;color:#525252;}</style>" +
      "</head><body>" +
      "<h1>THREAT-NEXUS Report</h1>" +
      "<div class=\"meta\">Generated: " + escapeHtml(generatedAt) + "</div>" +
      "<div class=\"cards\">" +
      "<div class=\"card\"><div class=\"label\">Total events</div><div class=\"value\">" + escapeHtml(summaryData.total_events) + "</div></div>" +
      "<div class=\"card\"><div class=\"label\">Total threats</div><div class=\"value\">" + escapeHtml(summaryData.total_threats) + "</div></div>" +
      "<div class=\"card\"><div class=\"label\">Critical threats</div><div class=\"value\">" + escapeHtml(summaryData.critical_threats) + "</div></div>" +
      "<div class=\"card\"><div class=\"label\">Unique IPs</div><div class=\"value\">" + escapeHtml(summaryData.unique_ips) + "</div></div>" +
      "</div>" +
      bodyHtml +
      "</body></html>"
    );
  }

  window.LogAnalyzer.services.reportBuilder = {
    escapeHtml: escapeHtml,
    buildJsonReport: buildJsonReport,
    buildHtmlReport: buildHtmlReport
  };
})();