import express from "express";
import cors from "cors";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runScan } from "./scanner.js";
import { generateReportPdf } from "./pdf.js";
import { initDb } from "./db.js";
import { comparePassword, hashPassword, signToken, verifyToken } from "./auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const workspaceRoot = path.resolve(__dirname, "..", "..");

const app = express();
const port = process.env.PORT || 3000;
let db;

app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.use("/assets", express.static(path.join(workspaceRoot, "assets")));
app.use(express.static(path.join(workspaceRoot, "frontend")));

app.get("/", (req, res) => {
  res.sendFile(path.join(workspaceRoot, "frontend", "index.html"));
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Non autorisé" });
  }

  try {
    const payload = verifyToken(token);
    req.user = payload;
    return next();
  } catch (error) {
    return res.status(401).json({ error: "Token invalide" });
  }
}

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const user = await db.get("SELECT id, email, created_at FROM users WHERE id = ?", req.user.id);
  if (!user) {
    return res.status(404).json({ error: "Utilisateur introuvable" });
  }

  return res.json({ user });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: "Email ou mot de passe invalide" });
    }

    const existing = await db.get("SELECT id FROM users WHERE email = ?", email);
    if (existing) {
      return res.status(409).json({ error: "Email déjà utilisé" });
    }

    const passwordHash = await hashPassword(password);
    const createdAt = new Date().toISOString();
    const result = await db.run(
      "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
      email,
      passwordHash,
      createdAt
    );

    const token = signToken({ id: result.lastID, email });
    return res.json({ token, user: { id: result.lastID, email, created_at: createdAt } });
  } catch (error) {
    return res.status(500).json({ error: "Inscription échouée" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    const user = await db.get("SELECT id, email, password_hash, created_at FROM users WHERE email = ?", email);
    if (!user) {
      return res.status(401).json({ error: "Identifiants invalides" });
    }

    const match = await comparePassword(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Identifiants invalides" });
    }

    const token = signToken({ id: user.id, email: user.email });
    return res.json({ token, user: { id: user.id, email: user.email, created_at: user.created_at } });
  } catch (error) {
    return res.status(500).json({ error: "Connexion échouée" });
  }
});

app.post("/api/scan", authMiddleware, async (req, res) => {
  try {
    const result = await runScan(req.body || {});
    const createdAt = new Date().toISOString();
    const portsOpen = Array.isArray(result.ports?.open) ? result.ports.open : [];
    const portsEngine = String(result.ports?.engine || "tcp-socket-fallback");
    const portsNote = result.ports?.note || null;

    await db.run(
      `
        INSERT INTO scans (user_id, target, created_at, ports_open, ports_engine, ports_note, result_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      req.user.id,
      result.target || "",
      createdAt,
      JSON.stringify(portsOpen),
      portsEngine,
      portsNote,
      JSON.stringify(result)
    );

    res.json(result);
  } catch (error) {
    res.status(400).json({
      error: "Scan échoué",
      details: error instanceof Error ? error.message : "Erreur inconnue",
    });
  }
});

app.get("/api/scans", authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 10, 50);
    const rows = await db.all(
      `
        SELECT id, target, created_at, ports_open, ports_engine, ports_note
        FROM scans
        WHERE user_id = ?
        ORDER BY datetime(created_at) DESC
        LIMIT ?
      `,
      req.user.id,
      limit
    );

    const scans = rows.map((row) => ({
      id: row.id,
      target: row.target,
      createdAt: row.created_at,
      portsOpen: JSON.parse(row.ports_open || "[]"),
      portsEngine: row.ports_engine,
      portsNote: row.ports_note,
    }));

    return res.json({ scans });
  } catch (error) {
    return res.status(500).json({ error: "Lecture historique échouée" });
  }
});

app.get("/api/scans/:id/report", authMiddleware, async (req, res) => {
  try {
    const scanId = Number(req.params.id);
    const row = await db.get(
      "SELECT result_json, target FROM scans WHERE id = ? AND user_id = ?",
      scanId,
      req.user.id
    );

    if (!row) {
      return res.status(404).json({ error: "Scan introuvable" });
    }

    const result = JSON.parse(row.result_json);
    const pdfBuffer = await generateReportPdf(result);

    const filename = `rapport-${row.target.replace(/[^a-z0-9]/gi, "_")}-${Date.now()}.pdf`;
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(pdfBuffer);
  } catch (error) {
    res.status(500).json({ error: "Génération du rapport échouée" });
  }
});

app.post("/api/report", authMiddleware, async (req, res) => {
  try {
    const result = req.body?.result;

    if (!result) {
      return res.status(400).json({ error: "Données de résultat manquantes" });
    }

    const pdfBuffer = await generateReportPdf(result);
    const filename = `securescan-report-${Date.now()}.pdf`;

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=\"${filename}\"`);
    res.send(pdfBuffer);
  } catch (error) {
    res.status(500).json({
      error: "Génération PDF échouée",
      details: error instanceof Error ? error.message : "Erreur inconnue",
    });
  }
});

initDb()
  .then((database) => {
    db = database;
    app.listen(port, () => {
      console.log(`SecureScan backend running on http://localhost:${port}`);
    });
  })
  .catch((error) => {
    console.error("Database init failed", error);
    process.exit(1);
  });
