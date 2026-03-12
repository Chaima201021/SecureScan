(function () {
  "use strict";

  const scanForm = document.getElementById("scan-form");
  if (!scanForm) {
    return;
  }

  const scanButton = document.getElementById("scan-button");
  const scanMeta = document.getElementById("scan-meta");
  const scanAllCheckbox = document.getElementById("scan-all");
  const apiBase = window.SECURESCAN_API_BASE
    || (window.location.protocol === "file:" ? "http://localhost:3000" : (window.location.port === "3000" ? "" : "http://localhost:3000"));

  const toggleConfig = [
    { checkboxId: "all-ports", inputId: "ports" },
    { checkboxId: "all-vulnerabilities", inputId: "vulnerabilities" },
    { checkboxId: "all-security-headers", inputId: "security-headers" },
    { checkboxId: "all-https-analysis", inputId: "https-analysis" },
  ];

  function applyFieldDisabledState(input, checkbox) {
    if (!input || !checkbox) {
      return;
    }

    const shouldDisable = checkbox.checked;
    input.disabled = shouldDisable;

    if (shouldDisable) {
      input.value = "";
    }
  }

  function syncScanAllState() {
    if (!scanAllCheckbox) {
      return;
    }

    const allChecked = toggleConfig
      .map((config) => document.getElementById(config.checkboxId))
      .filter(Boolean)
      .every((checkbox) => checkbox.checked);

    scanAllCheckbox.checked = allChecked;
  }

  function initializeFieldToggles() {
    toggleConfig.forEach((config) => {
      const checkbox = document.getElementById(config.checkboxId);
      const input = document.getElementById(config.inputId);

      if (!checkbox || !input) {
        return;
      }

      applyFieldDisabledState(input, checkbox);

      checkbox.addEventListener("change", () => {
        applyFieldDisabledState(input, checkbox);
        syncScanAllState();
      });
    });

    if (scanAllCheckbox) {
      scanAllCheckbox.addEventListener("change", () => {
        toggleConfig.forEach((config) => {
          const checkbox = document.getElementById(config.checkboxId);
          const input = document.getElementById(config.inputId);

          if (!checkbox || !input) {
            return;
          }

          checkbox.checked = scanAllCheckbox.checked;
          applyFieldDisabledState(input, checkbox);
        });
      });
    }

    syncScanAllState();
  }

  function setLoadingState(isLoading) {
    scanButton.disabled = isLoading;
    scanButton.innerHTML = isLoading
      ? '<i class="bi bi-hourglass-split me-2"></i>Analyse en cours...'
      : '<i class="bi bi-play-circle me-2"></i>Analyser le site';
  }

  function parsePorts(rawPorts) {
    return rawPorts
      .split(",")
      .map((port) => Number(port.trim()))
      .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
  }

  function parseCsv(rawValue) {
    if (!rawValue) {
      return [];
    }

    return String(rawValue)
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  async function requestScan(payload) {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 180000);
    const token = window.securescanAuth ? window.securescanAuth.getToken() : null;

    try {
      const response = await fetch(`${apiBase}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        let backendError = "API de scan indisponible";

        try {
          const data = await response.json();
          backendError = data?.details || data?.error || `Erreur HTTP ${response.status}`;
        } catch (parseError) {
          backendError = `Erreur HTTP ${response.status}`;
        }

        throw new Error(backendError);
      }

      return await response.json();
    } catch (error) {
      if (error.name === "AbortError") {
        throw new Error("Timeout: le scan a pris trop de temps.");
      }
      if (error instanceof TypeError) {
        throw new Error("Impossible de joindre le backend (http://localhost:3000). Vérifiez que le serveur est démarré.");
      }
      throw error;
    } finally {
      window.clearTimeout(timeoutId);
    }
  }

  window.toggleInput = function (inputId, checkbox) {
    const input = document.getElementById(inputId);
    applyFieldDisabledState(input, checkbox);
    syncScanAllState();
  };

  initializeFieldToggles();

  scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!window.securescanAuth || !window.securescanAuth.getToken()) {
      window.location.href = "login.html";
      return;
    }

    const formData = new FormData(scanForm);
    const targetUrl = String(formData.get("targetUrl") || "").trim();
    const ports = parsePorts(String(formData.get("ports") || ""));
    const testForm = Boolean(formData.get("testForm"));
    const vulnerabilities = parseCsv(formData.get("vulnerabilities"));
    const securityHeaders = parseCsv(formData.get("securityHeaders"));
    const httpsAnalysis = parseCsv(formData.get("httpsAnalysis"));
    const allPorts = Boolean(formData.get("allPorts"));
    const allVulnerabilities = Boolean(formData.get("allVulnerabilities"));
    const allSecurityHeaders = Boolean(formData.get("allSecurityHeaders"));
    const allHttpsAnalysis = Boolean(formData.get("allHttpsAnalysis"));

    if (!targetUrl) {
      scanMeta.textContent = "Veuillez saisir une URL valide.";
      return;
    }

    const payload = {
      targetUrl,
      ports,
      vulnerabilities,
      securityHeaders,
      httpsAnalysis,
      allPorts,
      allVulnerabilities,
      allSecurityHeaders,
      allHttpsAnalysis,
      testForm,
    };

    setLoadingState(true);
    scanMeta.textContent = "Analyse en cours...";

    try {
      const apiResult = await requestScan(payload);
      const resultToStore = { ...apiResult, target: apiResult.target || targetUrl };
      sessionStorage.setItem("securescan_result", JSON.stringify(resultToStore));
      window.location.href = "result.html";
    } catch (error) {
      scanMeta.textContent = error instanceof Error
        ? `Erreur: ${error.message}`
        : "Erreur: scan indisponible.";
    } finally {
      setLoadingState(false);
    }
  });

  async function loadHistory() {
    const historyList = document.getElementById("history-list");
    const historyEmpty = document.getElementById("history-empty");

    if (!historyList || !historyEmpty) {
      return;
    }

    if (!window.securescanAuth || !window.securescanAuth.getToken()) {
      historyEmpty.textContent = "Connectez-vous pour voir votre historique.";
      return;
    }

    historyList.innerHTML = "";
    historyEmpty.textContent = "Chargement de l'historique...";

    try {
      const response = await fetch(`${apiBase}/api/scans?limit=10`, {
        headers: {
          Authorization: `Bearer ${window.securescanAuth.getToken()}`,
        },
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.error || "Impossible de charger l'historique");
      }

      const scans = Array.isArray(data.scans) ? data.scans : [];
      if (!scans.length) {
        historyEmpty.textContent = "Aucun scan enregistré pour le moment.";
        return;
      }

      historyEmpty.textContent = "";
      scans.forEach((scan) => {
        const item = document.createElement("li");
        item.className = "history-item";

        const portsOpen = Array.isArray(scan.portsOpen) && scan.portsOpen.length
          ? scan.portsOpen.join(", ")
          : "Aucun port ouvert";

        item.innerHTML = `
          <div class="d-flex justify-content-between flex-wrap gap-2 align-items-center">
            <strong>${scan.target}</strong>
            <div class="d-flex align-items-center gap-2">
              <small>${new Date(scan.createdAt).toLocaleString("fr-FR")}</small>
              <button type="button" class="btn btn-sm btn-outline-info download-report-btn" data-scan-id="${scan.id}" title="Télécharger le rapport PDF">
                <i class="bi bi-file-earmark-pdf"></i>
              </button>
            </div>
          </div>
          <div class="d-flex justify-content-between flex-wrap gap-2 mt-1">
            <small>Moteur: ${scan.portsEngine}</small>
            <small>Ports: ${portsOpen}</small>
          </div>
        `;
        historyList.appendChild(item);
      });

      historyList.querySelectorAll(".download-report-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const scanId = btn.getAttribute("data-scan-id");
          btn.disabled = true;
          btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
          try {
            const response = await fetch(`${apiBase}/api/scans/${scanId}/report`, {
              headers: { Authorization: `Bearer ${window.securescanAuth.getToken()}` },
            });
            if (!response.ok) throw new Error("Erreur téléchargement");
            const blob = await response.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `rapport-scan-${scanId}.pdf`;
            a.click();
            URL.revokeObjectURL(url);
          } catch (e) {
            alert("Impossible de télécharger le rapport.");
          } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-file-earmark-pdf"></i>';
          }
        });
      });
    } catch (error) {
      historyEmpty.textContent = error instanceof Error
        ? error.message
        : "Impossible de charger l'historique";
    }
  }

  loadHistory();
})();