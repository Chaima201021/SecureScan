import PDFDocument from "pdfkit";

function addSectionTitle(doc, title) {
  doc.moveDown(0.7);
  doc.fontSize(14).fillColor("#1a2e5a").text(title, { underline: true });
  doc.moveDown(0.4);
}

function addList(doc, items) {
  if (!items || !items.length) {
    doc.fontSize(11).fillColor("#333333").text("- Aucun élément");
    return;
  }

  items.forEach((item) => {
    doc.fontSize(11).fillColor("#333333").text(`- ${item}`);
  });
}

export function generateReportPdf(result) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 40 });
    const chunks = [];

    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    doc.fontSize(20).fillColor("#10213f").text("SecureScan - Rapport de Sécurité", { align: "center" });
    doc.moveDown(1);
    doc.fontSize(11).fillColor("#333333").text(`Cible: ${result.target || "N/A"}`);
    doc.text(`Date: ${new Date(result.timestamp || Date.now()).toLocaleString("fr-FR")}`);

    addSectionTitle(doc, "HTTPS");
    doc.text(`Statut: ${result.https?.used ? "Actif" : "Absent"}`);
    doc.text(`Détail: ${result.https?.details || "N/A"}`);

    addSectionTitle(doc, "Headers de sécurité");
    doc.text("Headers présents:");
    addList(doc, result.headers?.present || []);
    doc.moveDown(0.4);
    doc.text("Headers manquants:");
    addList(doc, result.headers?.missing || []);

    addSectionTitle(doc, "Ports ouverts");
    addList(doc, (result.ports?.open || []).map((port) => `Port ${port}`));

    addSectionTitle(doc, "Vulnérabilités");
    addList(doc, result.vulnerabilities?.findings || []);

    addSectionTitle(doc, "Formulaire");
    addList(doc, result.form?.findings || []);

    doc.end();
  });
}
