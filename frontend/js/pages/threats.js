(function () {
  var api = window.LogAnalyzer.Api;
  var format = window.LogAnalyzer.core.format;
  var dom = window.LogAnalyzer.core.dom;
  var pagination = window.LogAnalyzer.core.pagination;
  var severity = window.LogAnalyzer.ui.severity;

  var DISABLED_BUTTON_CLASS = "btn btn-icon opacity-40 pointer-events-none";
  var ENABLED_BUTTON_CLASS = "btn btn-icon";

  var countEl = document.getElementById("threats-count");
  var searchInput = document.getElementById("threats-search");
  var severitySelect = document.getElementById("threats-filter-severity");
  var typeSelect = document.getElementById("threats-filter-type");
  var timeSelect = document.getElementById("threats-filter-time");
  var clearFiltersButton = document.getElementById("threats-clear-filters");
  var sortHeader = document.getElementById("threats-sort-last-seen");
  var sortIcon = document.getElementById("threats-sort-icon");
  var tbody = document.getElementById("threats-tbody");
  var rangeEl = document.getElementById("threats-range");
  var pageSizeSelect = document.getElementById("threats-page-size");
  var prevButton = document.getElementById("threats-prev-button");
  var nextButton = document.getElementById("threats-next-button");

  var exportButton = document.getElementById("threats-export-button");
  var exportDialogOverlay = document.getElementById("export-dialog-overlay");
  var exportDialogCloseButton = document.getElementById("export-dialog-close-button");
  var exportDialogCancelButton = document.getElementById("export-dialog-cancel-button");
  var exportDialogExportButton = document.getElementById("export-dialog-export-button");
  var exportDialogHelperText = document.getElementById("export-dialog-helper-text");
  var exportDialogError = document.getElementById("export-dialog-error");
  var exportFormatHtmlRadio = document.getElementById("export-format-html");
  var exportFormatJsonRadio = document.getElementById("export-format-json");

  var allThreats = [];
  var threatsLoadFailed = false;
  var state = {
    search: "",
    severity: "",
    type: "",
    timeWindowHours: 24,
    sortDirection: "desc",
    page: 1,
    pageSize: 25
  };

  function getReferenceTime() {
    if (allThreats.length === 0) {
      return Date.now();
    }
    return Math.max.apply(
      null,
      allThreats.map(function (item) {
        return format.parseTimestamp(item.timestamp).getTime();
      })
    );
  }

  function applyFilters() {
    var searchTerm = state.search.trim().toLowerCase();
    var referenceTime = getReferenceTime();
    var windowMs = state.timeWindowHours * 60 * 60 * 1000;

    var filtered = allThreats.filter(function (item) {
      if (searchTerm) {
        var haystack = (item.ip + " " + item.type + " " + item.title + " " + item.details).toLowerCase();
        if (haystack.indexOf(searchTerm) === -1) {
          return false;
        }
      }
      if (state.severity && item.severity !== state.severity) {
        return false;
      }
      if (state.type && item.type !== state.type) {
        return false;
      }
      var itemTime = format.parseTimestamp(item.timestamp).getTime();
      if (referenceTime - itemTime > windowMs) {
        return false;
      }
      return true;
    });

    filtered.sort(function (a, b) {
      var diff = format.parseTimestamp(a.timestamp).getTime() - format.parseTimestamp(b.timestamp).getTime();
      return state.sortDirection === "asc" ? diff : -diff;
    });

    return filtered;
  }

  function buildRow(item) {
    var tr = document.createElement("tr");
    tr.className = "row-link";
    tr.addEventListener("click", function () {
      window.location.href = "threat-detail.html?id=" + item.id;
    });

    var severityTd = document.createElement("td");
    severityTd.appendChild(severity.buildPill(item.severity));
    tr.appendChild(severityTd);

    var typeTd = document.createElement("td");
    typeTd.className = "font-medium";
    typeTd.textContent = item.title;
    tr.appendChild(typeTd);

    var ipTd = document.createElement("td");
    ipTd.className = "mono text-secondary";
    ipTd.textContent = item.ip;
    tr.appendChild(ipTd);

    var detailsTd = document.createElement("td");
    detailsTd.className = "mono text-secondary max-w-[22rem] truncate";
    detailsTd.setAttribute("title", item.details);
    detailsTd.textContent = item.details;
    tr.appendChild(detailsTd);

    var riskTd = document.createElement("td");
    riskTd.className = "num";
    riskTd.textContent = format.formatNumber(item.risk_score);
    tr.appendChild(riskTd);

    var timestampTd = document.createElement("td");
    timestampTd.className = "num mono text-secondary";
    timestampTd.textContent = format.isoDateTime(item.timestamp);
    tr.appendChild(timestampTd);

    return tr;
  }

  function setButtonDisabled(button, disabled) {
    dom.setDisabled(button, disabled);
    button.className = disabled ? DISABLED_BUTTON_CLASS : ENABLED_BUTTON_CLASS;
  }

  function updateSortIcon() {
    if (state.sortDirection === "desc") {
      sortIcon.textContent = "arrow_downward";
      sortIcon.setAttribute("data-icon", "arrow_downward");
    } else {
      sortIcon.textContent = "arrow_upward";
      sortIcon.setAttribute("data-icon", "arrow_upward");
    }
  }

  function render() {
    dom.clear(tbody);

    var filtered = applyFilters();
    var result = pagination.paginate(filtered, state.page, state.pageSize);
    state.page = result.page;

    if (result.total === 0) {
      dom.appendMessageRow(tbody, { colspan: 6, message: "No threats match the current filters." });
    } else {
      result.pageItems.forEach(function (item) {
        tbody.appendChild(buildRow(item));
      });
    }

    rangeEl.textContent = result.rangeText;

    setButtonDisabled(prevButton, result.page <= 1 || result.total === 0);
    setButtonDisabled(nextButton, result.page >= result.totalPages || result.total === 0);
  }

  function renderLoadFailure() {
    dom.clear(tbody);
    dom.appendMessageRow(tbody, { colspan: 6, message: "Couldn't load threats. Check that the backend is running." });
    rangeEl.textContent = "0 of 0";
    setButtonDisabled(prevButton, true);
    setButtonDisabled(nextButton, true);
  }

  searchInput.addEventListener("input", function () {
    state.search = searchInput.value;
    state.page = 1;
    render();
  });

  severitySelect.addEventListener("change", function () {
    state.severity = severitySelect.value;
    state.page = 1;
    render();
  });

  typeSelect.addEventListener("change", function () {
    state.type = typeSelect.value;
    state.page = 1;
    render();
  });

  timeSelect.addEventListener("change", function () {
    state.timeWindowHours = Number(timeSelect.value);
    state.page = 1;
    render();
  });

  clearFiltersButton.addEventListener("click", function () {
    state.search = "";
    state.severity = "";
    state.type = "";
    state.timeWindowHours = 24;
    state.page = 1;
    searchInput.value = "";
    severitySelect.value = "";
    typeSelect.value = "";
    timeSelect.value = "24";
    render();
  });

  sortHeader.addEventListener("click", function () {
    state.sortDirection = state.sortDirection === "desc" ? "asc" : "desc";
    updateSortIcon();
    render();
  });

  pageSizeSelect.addEventListener("change", function () {
    state.pageSize = Number(pageSizeSelect.value);
    state.page = 1;
    render();
  });

  prevButton.addEventListener("click", function () {
    if (state.page > 1) {
      state.page -= 1;
      render();
    }
  });

  nextButton.addEventListener("click", function () {
    var totalPages = Math.max(1, Math.ceil(applyFilters().length / state.pageSize));
    if (state.page < totalPages) {
      state.page += 1;
      render();
    }
  });

  function openExportDialog() {
    exportDialogOverlay.classList.remove("hidden");
    exportFormatHtmlRadio.checked = true;
    exportFormatJsonRadio.checked = false;
    exportDialogError.classList.add("hidden");
    exportDialogError.textContent = "";
    exportDialogHelperText.textContent = threatsLoadFailed
      ? "The report includes all stored threats. Filters on this page are not applied."
      : "The report includes all " + format.formatNumber(allThreats.length) + " stored threats. Filters on this page are not applied.";
    exportFormatHtmlRadio.focus();
  }

  function closeExportDialog() {
    exportDialogOverlay.classList.add("hidden");
    exportButton.focus();
  }

  exportButton.addEventListener("click", openExportDialog);

  exportDialogCloseButton.addEventListener("click", closeExportDialog);

  exportDialogCancelButton.addEventListener("click", closeExportDialog);

  exportDialogOverlay.addEventListener("click", function (event) {
    if (event.target === exportDialogOverlay) {
      closeExportDialog();
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && !exportDialogOverlay.classList.contains("hidden")) {
      closeExportDialog();
    }
  });

  exportDialogExportButton.addEventListener("click", function () {
    var exportFormat = exportFormatJsonRadio.checked ? "json" : "html";
    exportDialogExportButton.setAttribute("disabled", "");
    exportDialogExportButton.textContent = "Exporting...";
    api.exportReport(exportFormat)
      .then(function () {
        exportDialogExportButton.removeAttribute("disabled");
        exportDialogExportButton.textContent = "Export";
        closeExportDialog();
      })
      .catch(function (error) {
        console.error(error);
        exportDialogExportButton.removeAttribute("disabled");
        exportDialogExportButton.textContent = "Export";
        exportDialogError.textContent = "Couldn't export the report. Check that the backend is running.";
        exportDialogError.classList.remove("hidden");
      });
  });

    var refreshTimer = null;

  // silent = live refresh: on failure keep showing the table we already have.
  function loadThreats(silent) {
    return api.getThreats()
      .then(function (data) {
        allThreats = data;
        threatsLoadFailed = false;
        countEl.textContent = format.formatNumber(allThreats.length);
        render();
      })
      .catch(function (error) {
        console.error(error);
        if (silent) {
          return;
        }
        threatsLoadFailed = true;
        countEl.textContent = "-";
        renderLoadFailure();
      });
  }

  // A whole upload can emit dozens of alerts within milliseconds; wait for the
  // burst to settle and reload the list once.
  window.addEventListener("threat-alert", function () {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(function () {
      loadThreats(true);
    }, 300);
  });

  updateSortIcon();
  loadThreats(false);
})();
