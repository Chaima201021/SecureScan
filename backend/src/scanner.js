import dns from "node:dns/promises";
import net from "node:net";
import https from "node:https";
import http from "node:http";
import { execFile } from "node:child_process";
import fetch from "node-fetch";

// Agent HTTPS qui accepte les certificats auto-signés
const httpsAgent = new https.Agent({
  rejectUnauthorized: false,
});

const httpAgent = new http.Agent();

const DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443];
const DEFAULT_SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
];

const DEFAULT_VULNERABILITY_CHECKS = [
  "Missing CSP",
  "Missing HSTS",
  "Missing X-Frame-Options",
  "Exposed Server Header",
  "Insecure Form Action",
  "Directory Listing Exposure",
];

function parseCsvToArray(value) {
  if (!value || typeof value !== "string") {
    return [];
  }

  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeTarget(targetUrl) {
  if (!targetUrl) {
    throw new Error("URL cible obligatoire.");
  }

  let normalized = String(targetUrl).trim();
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = `https://${normalized}`;
  }

  const parsed = new URL(normalized);
  return parsed;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const isHttps = url.toString().startsWith("https:");

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      agent: isHttps ? httpsAgent : httpAgent,
      headers: {
        "User-Agent": "SecureScan/1.0 (Security Scanner)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ...options.headers,
      },
    });
    return response;
  } finally {
    clearTimeout(timeout);
  }
}

function checkSinglePort(host, port, timeoutMs = 1200) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const finalize = (isOpen) => {
      if (resolved) {
        return;
      }
      resolved = true;
      socket.destroy();
      resolve(isOpen);
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finalize(true));
    socket.once("timeout", () => finalize(false));
    socket.once("error", () => finalize(false));

    socket.connect(port, host);
  });
}

function runNmapCommand(args, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    execFile("nmap", args, { timeout: timeoutMs, windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        const details = stderr || stdout || error.message;
        const wrappedError = new Error(details || "Échec exécution nmap");
        wrappedError.code = error.code;
        wrappedError.original = error;
        reject(wrappedError);
        return;
      }

      resolve(stdout);
    });
  });
}

function parseNmapGrepableOutput(output) {
  const lines = String(output || "").split(/\r?\n/);
  const hostLine = lines.find((line) => line.startsWith("Host:") && line.includes("Ports:"));

  if (!hostLine) {
    return [];
  }

  const portsPartMatch = hostLine.match(/Ports:\s*(.*)$/);
  if (!portsPartMatch || !portsPartMatch[1]) {
    return [];
  }

  const portsPart = portsPartMatch[1].split("\t")[0].trim();
  if (!portsPart) {
    return [];
  }

  return portsPart
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [portRaw, stateRaw, protocolRaw] = entry.split("/");
      return {
        port: Number(portRaw),
        state: String(stateRaw || "").toLowerCase(),
        protocol: String(protocolRaw || "tcp").toLowerCase(),
      };
    })
    .filter((entry) => Number.isInteger(entry.port) && entry.port > 0);
}

async function scanPortsWithSockets(host, portsToTest) {
  const checks = await Promise.all(
    portsToTest.map(async (port) => {
      const isOpen = await checkSinglePort(host, port);
      return { port, isOpen };
    })
  );

  return {
    engine: "tcp-socket-fallback",
    tested: portsToTest,
    open: checks.filter((entry) => entry.isOpen).map((entry) => entry.port),
    note: "Nmap indisponible, résultat obtenu avec un scan TCP basique.",
  };
}

async function scanPortsWithNmap(host, requestedPorts, scanAllPorts) {
  const validatedRequestedPorts = requestedPorts.filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);

  const args = ["-Pn", "-n", "--max-retries", "2", "--host-timeout", "90s", "-T4", "-oG", "-"];
  if (scanAllPorts || !validatedRequestedPorts.length) {
    args.push("--top-ports", "1000");
  } else {
    args.push("-p", validatedRequestedPorts.join(","));
  }
  args.push(host);

  const stdout = await runNmapCommand(args);
  const parsed = parseNmapGrepableOutput(stdout);
  const open = parsed.filter((entry) => entry.state === "open").map((entry) => entry.port);
  const tested = parsed.map((entry) => entry.port);

  return {
    engine: "nmap",
    tested: tested.length ? tested : validatedRequestedPorts,
    open,
    note: scanAllPorts || !validatedRequestedPorts.length
      ? "Scan Nmap exécuté avec --top-ports 1000."
      : "Scan Nmap exécuté sur les ports demandés.",
  };
}

async function scanPorts(host, requestedPorts, scanAllPorts) {
  const validatedPorts = requestedPorts.filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
  const fallbackPorts = scanAllPorts || !validatedPorts.length ? DEFAULT_PORTS : validatedPorts;

  try {
    return await scanPortsWithNmap(host, validatedPorts, scanAllPorts);
  } catch (error) {
    return await scanPortsWithSockets(host, fallbackPorts);
  }
}

function scanHeaders(responseHeaders, requestedHeaders, scanAllHeaders) {
  const headersToTest = scanAllHeaders || !requestedHeaders.length
    ? DEFAULT_SECURITY_HEADERS
    : requestedHeaders.map((header) => header.toLowerCase());

  const present = [];
  const missing = [];

  headersToTest.forEach((headerName) => {
    if (responseHeaders.get(headerName)) {
      present.push(headerName);
    } else {
      missing.push(headerName);
    }
  });

  return {
    tested: headersToTest,
    present,
    missing,
  };
}

function scanHttps(inputUrl, finalUrl) {
  const usesHttps = finalUrl.protocol === "https:";
  const redirectedToHttps = inputUrl.protocol !== "https:" && usesHttps;

  return {
    used: usesHttps,
    redirected: redirectedToHttps,
    details: usesHttps
      ? redirectedToHttps
        ? "Le site redirige HTTP vers HTTPS."
        : "Connexion HTTPS détectée."
      : "Le site cible ne force pas HTTPS.",
  };
}

function scanVulnerabilities(vulnerabilityChecks, scanAllVulnerabilities, headersResult, serverHeader, html) {
  const checksToRun = scanAllVulnerabilities || !vulnerabilityChecks.length
    ? DEFAULT_VULNERABILITY_CHECKS
    : vulnerabilityChecks;

  const findings = [];

  checksToRun.forEach((check) => {
    const key = check.toLowerCase();

    if (key.includes("csp") && headersResult.missing.includes("content-security-policy")) {
      findings.push("Missing CSP: Content-Security-Policy absent.");
    }

    if ((key.includes("hsts") || key.includes("https")) && headersResult.missing.includes("strict-transport-security")) {
      findings.push("Missing HSTS: Strict-Transport-Security absent.");
    }

    if ((key.includes("frame") || key.includes("clickjacking")) && headersResult.missing.includes("x-frame-options")) {
      findings.push("Missing X-Frame-Options: risque de clickjacking.");
    }

    if (key.includes("server") && serverHeader) {
      findings.push(`Exposed Server Header: ${serverHeader}`);
    }

    if ((key.includes("form") || key.includes("insecure")) && /<form[^>]+action=["']http:\/\//i.test(html)) {
      findings.push("Insecure Form Action: formulaire envoyé via HTTP.");
    }

    if (key.includes("directory") && /<title>\s*index of\s*\//i.test(html)) {
      findings.push("Directory Listing Exposure: index de dossier potentiellement exposé.");
    }
  });

  return {
    tested: checksToRun,
    findings: [...new Set(findings)],
  };
}

export async function runScan(payload) {
  const target = normalizeTarget(payload.targetUrl);

  const requestedPorts = Array.isArray(payload.ports)
    ? payload.ports.map((port) => Number(port)).filter((port) => Number.isInteger(port))
    : parseCsvToArray(payload.ports).map((port) => Number(port)).filter((port) => Number.isInteger(port));

  const requestedHeaders = Array.isArray(payload.securityHeaders)
    ? payload.securityHeaders
    : parseCsvToArray(payload.securityHeaders);

  const requestedVulnerabilities = Array.isArray(payload.vulnerabilities)
    ? payload.vulnerabilities
    : parseCsvToArray(payload.vulnerabilities);

  const scanAllPorts = Boolean(payload.allPorts);
  const scanAllHeaders = Boolean(payload.allSecurityHeaders);
  const scanAllVulnerabilities = Boolean(payload.allVulnerabilities);
  const testForm = payload.testForm !== false;

  // Vérifier la résolution DNS
  try {
    await dns.lookup(target.hostname);
  } catch (dnsError) {
    throw new Error(`Impossible de résoudre le domaine "${target.hostname}". Vérifiez l'URL.`);
  }

  // Récupérer la page
  let response;
  let pageHtml;
  try {
    response = await fetchWithTimeout(target.toString(), { redirect: "follow" }, 20000);
    pageHtml = await response.text();
  } catch (fetchError) {
    if (fetchError.name === "AbortError") {
      throw new Error(`Le site "${target.hostname}" ne répond pas (timeout). Vérifiez que le site est accessible.`);
    }
    if (fetchError.code === "ECONNREFUSED") {
      throw new Error(`Connexion refusée par "${target.hostname}".`);
    }
    if (fetchError.code === "ENOTFOUND") {
      throw new Error(`Site introuvable: "${target.hostname}".`);
    }
    throw new Error(`Impossible d'accéder à "${target.hostname}": ${fetchError.message}`);
  }

  const finalUrl = new URL(response.url || target.toString());

  const headersResult = scanHeaders(response.headers, requestedHeaders, scanAllHeaders);
  const httpsResult = scanHttps(target, finalUrl);
  const portsResult = await scanPorts(finalUrl.hostname, requestedPorts, scanAllPorts);
  const vulnerabilitiesResult = scanVulnerabilities(
    requestedVulnerabilities,
    scanAllVulnerabilities,
    headersResult,
    response.headers.get("server"),
    pageHtml
  );

  const formFindings = testForm
    ? vulnerabilitiesResult.findings.filter((item) => item.toLowerCase().includes("form"))
    : ["Test formulaire non exécuté."];

  return {
    mode: "api",
    target: finalUrl.toString(),
    timestamp: new Date().toISOString(),
    https: httpsResult,
    headers: headersResult,
    ports: portsResult,
    vulnerabilities: vulnerabilitiesResult,
    form: {
      tested: testForm,
      vulnerable: testForm ? formFindings.length > 0 : false,
      findings: formFindings.length ? formFindings : ["Aucune vulnérabilité évidente détectée sur le formulaire."],
    },
  };
}
