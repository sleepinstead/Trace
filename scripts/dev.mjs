#!/usr/bin/env node
// One command for the whole app: installs whatever is missing, then runs the API and the web app together.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BACKEND = path.join(ROOT, "backend");
const FRONTEND = path.join(ROOT, "frontend");
const VENV = path.join(BACKEND, ".venv");
const VENV_PYTHON = path.join(VENV, ...(process.platform === "win32" ? ["Scripts", "python.exe"] : ["bin", "python"]));
const MIN_PYTHON = [3, 12];

const log = (message) => console.log(`\x1b[1mtrace\x1b[0m  ${message}`);

function fail(message) {
  console.error(`\n\x1b[1mtrace\x1b[0m  ${message}\n`);
  process.exit(1);
}

const quiet = (cmd, args) => spawnSync(cmd, args, { encoding: "utf8", cwd: BACKEND });

function run(cmd, args, cwd, failure) {
  const { status, error } = spawnSync(cmd, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });
  if (status !== 0) fail(`${failure}${error ? ` (${error.message})` : ""}`);
}

const hashOf = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
const stale = (stamp, hash) => !existsSync(stamp) || readFileSync(stamp, "utf8") !== hash;

function findPython() {
  const candidates = [process.env.TRACE_PYTHON, "python3.14", "python3.13", "python3.12", "python3.15", "python3", "python"].filter(Boolean);
  for (const candidate of candidates) {
    const { status, stdout } = quiet(candidate, ["-c", "import sys; print(*sys.version_info[:2])"]);
    if (status !== 0) continue;
    const [major, minor] = stdout.trim().split(" ").map(Number);
    if (major > MIN_PYTHON[0] || (major === MIN_PYTHON[0] && minor >= MIN_PYTHON[1])) return candidate;
  }
  fail(`Python ${MIN_PYTHON.join(".")} or newer is required. Install it (macOS: brew install python), then run npm run dev again.`);
}

function setupBackend() {
  // A virtual environment stops working if the project folder is moved or renamed, so test it rather than trust it.
  const healthy = existsSync(VENV_PYTHON) && quiet(VENV_PYTHON, ["-c", "import pip"]).status === 0;
  if (!healthy) {
    log("Creating the Python environment");
    rmSync(VENV, { recursive: true, force: true });
    run(findPython(), ["-m", "venv", VENV], BACKEND, "Could not create the Python environment.");
  }

  const requirements = path.join(BACKEND, "requirements.txt");
  const stamp = path.join(VENV, ".requirements-hash");
  const hash = hashOf(requirements);
  if (stale(stamp, hash)) {
    log("Installing Python packages (the first run takes a minute or two)");
    run(VENV_PYTHON, ["-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", requirements], BACKEND, "Installing the Python packages failed. See the error above.");
    writeFileSync(stamp, hash);
  }

  const xgboost = quiet(VENV_PYTHON, ["-c", "import xgboost"]);
  if (xgboost.status !== 0) {
    if (/libomp|OpenMP/.test(xgboost.stderr)) fail("XGBoost needs the OpenMP runtime. Run: brew install libomp\nThen run npm run dev again.");
    fail(`XGBoost could not be loaded:\n${xgboost.stderr}`);
  }
}

function setupFrontend() {
  const stamp = path.join(FRONTEND, "node_modules", ".trace-lock-hash");
  const hash = hashOf(path.join(FRONTEND, "package-lock.json"));
  if (stale(stamp, hash)) {
    log("Installing web packages");
    run("npm", ["install", "--no-fund", "--no-audit"], FRONTEND, "Installing the web packages failed. See the error above.");
    writeFileSync(stamp, hash);
  }
}

function portIsFree(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.once("listening", () => probe.close(() => resolve(true)));
    probe.listen(port, "127.0.0.1");
  });
}

async function freePort(start) {
  for (let port = start; port < start + 20; port++) if (await portIsFree(port)) return port;
  fail(`No free port found between ${start} and ${start + 19}.`);
}

async function announceWhenReady(port) {
  for (let attempt = 0; attempt < 240; attempt++) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/health`);
      if (response.ok) return log(`Scanner ready on port ${port}. Open the Local address shown above. Press Ctrl+C to stop.`);
    } catch {
      /* not listening yet: the first start also trains the URL model */
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  log("The scanner has not answered after two minutes. Check the output above for errors.");
}

async function dev() {
  const apiPort = await freePort(Number(process.env.TRACE_API_PORT) || 8000);
  log(`Starting the scanner on port ${apiPort}. The first start also trains the URL model (about 15 seconds).`);

  const children = [
    spawn(VENV_PYTHON, ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(apiPort), "--reload", "--reload-dir", "app", "--no-access-log"], { cwd: BACKEND, stdio: "inherit" }),
    spawn(process.execPath, [path.join(FRONTEND, "node_modules", "vite", "bin", "vite.js")], { cwd: FRONTEND, stdio: "inherit", env: { ...process.env, TRACE_API: `http://127.0.0.1:${apiPort}` } }),
  ];

  let stopping = false;
  const stop = (code) => {
    if (stopping) return;
    stopping = true;
    children.forEach((child) => child.kill("SIGTERM"));
    setTimeout(() => process.exit(code), 500);
  };
  children.forEach((child) => {
    child.on("error", (error) => {
      console.error(error.message);
      stop(1);
    });
    child.on("exit", (code) => stop(code ?? 0));
  });
  process.on("SIGINT", () => stop(0));
  process.on("SIGTERM", () => stop(0));

  await announceWhenReady(apiPort);
}

setupBackend();
setupFrontend();

if (process.argv.includes("--test")) run(VENV_PYTHON, ["-m", "pytest", "-q"], BACKEND, "Tests failed.");
else if (process.argv.includes("--setup-only")) log("Setup complete. Run npm run dev to start Trace.");
else await dev();
