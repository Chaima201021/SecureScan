(function () {
  "use strict";
  const apiBase = window.SECURESCAN_API_BASE
    || (window.location.protocol === "file:" ? "http://localhost:3000" : (window.location.port === "3000" ? "" : "http://localhost:3000"));

  const raw = sessionStorage.getItem("securescan_result");
  const meta = document.getElementById("result-meta");
  const httpsSummary = document.getElementById("https-summary");
  const headersList = document.getElementById("headers-list");
  const portsList = document.getElementById("ports-list");
  const vulnerabilitiesList = document.getElementById("vulnerabilities-list");
  const formList = document.getElementById("form-list");
  const downloadButton = document.getElementById("download-report");
  const portsEngineBadge = document.getElementById("ports-engine-badge");
  const portsEngineNote = document.getElementById("ports-engine-note");

  function setFallbackState(message) {
    meta.textContent = message;
    httpsSummary.textContent = "Aucune donnée disponible.";
  }

  function fillList(target, items, fallbackLabel) {
    target.innerHTML = "";

    const safeItems = Array.isArray(items) ? items : [];
    if (!safeItems.length) {
      const line = document.createElement("li");
      line.textContent = fallbackLabel;
      target.appendChild(line);
      return;
    }

    safeItems.forEach((item) => {
      const line = document.createElement("li");
      line.textContent = item;
      target.appendChild(line);
    });
  }

  if (!raw) {
    setFallbackState("Résultat introuvable. Lancez un nouveau scan.");
    if (downloadButton) {
      downloadButton.disabled = true;
    }
    return;
  }

  if (!window.securescanAuth || !window.securescanAuth.getToken()) {
    window.location.href = "login.html";
    return;
  }

  const result = JSON.parse(raw);

  meta.textContent = `Cible: ${result.target || "N/A"} • ${new Date(result.timestamp || Date.now()).toLocaleString("fr-FR")}`;
  httpsSummary.textContent = result.https?.details || "Information HTTPS indisponible.";

  fillList(
    headersList,
    [
      ...(result.headers?.present || []).map((item) => `✅ Présent: ${item}`),
      ...(result.headers?.missing || []).map((item) => `⚠️ Manquant: ${item}`),
    ],
    "Aucun header analysé"
  );

  fillList(
    portsList,
    (result.ports?.open || []).map((port) => `Port ${port} ouvert`),
    "Aucun port ouvert détecté"
  );

  if (portsEngineBadge) {
    const engine = String(result.ports?.engine || "tcp-socket-fallback").toLowerCase();
    const isNmap = engine === "nmap";

    portsEngineBadge.textContent = isNmap ? "Nmap" : "Fallback";
    portsEngineBadge.classList.remove("engine-nmap", "engine-fallback");
    portsEngineBadge.classList.add(isNmap ? "engine-nmap" : "engine-fallback");
  }

  if (portsEngineNote) {
    portsEngineNote.textContent = result.ports?.note || "Moteur de scan non spécifié.";
  }

  fillList(
    vulnerabilitiesList,
    result.vulnerabilities?.findings || [],
    "Aucune vulnérabilité détectée"
  );

  fillList(
    formList,
    result.form?.findings || [],
    "Aucune anomalie formulaire"
  );


  downloadButton.addEventListener("click", async () => {
    downloadButton.disabled = true;
    downloadButton.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>Génération...';

    try {
      const response = await fetch(`${apiBase}/api/report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${window.securescanAuth.getToken()}`,
        },
        body: JSON.stringify({ result }),
      });

      if (!response.ok) {
        throw new Error("Impossible de générer le PDF");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `securescan-report-${Date.now()}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      alert(error instanceof Error ? error.message : "Erreur lors du téléchargement du rapport PDF.");
    } finally {
      downloadButton.disabled = false;
      downloadButton.innerHTML = '<i class="bi bi-file-earmark-pdf me-1"></i>Télécharger le rapport PDF';
    }
  });

})();
