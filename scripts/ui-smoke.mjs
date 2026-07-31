#!/usr/bin/env node

import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const baseUrl = process.env.JFR_BASE_URL ?? "http://127.0.0.1:18080";
const apiKey = process.env.JFR_BOOTSTRAP_API_KEY;
const chromeBinary = process.env.JFR_CHROME_BIN ?? "google-chrome";
const desktopScreenshot =
  process.env.JFR_DESKTOP_SCREENSHOT ?? "/tmp/jfr-ui-desktop.png";
const mobileScreenshot =
  process.env.JFR_MOBILE_SCREENSHOT ?? "/tmp/jfr-ui-mobile.png";
const assuranceScreenshot =
  process.env.JFR_ASSURANCE_SCREENSHOT ?? "/tmp/jfr-ui-assurance.png";
const debuggingPort = 19223;

if (!apiKey) {
  throw new Error("JFR_BOOTSTRAP_API_KEY is required");
}

const profile = await mkdtemp(join(tmpdir(), "jfr-ui-smoke-"));
const chrome = spawn(
  chromeBinary,
  [
    "--headless=new",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--no-first-run",
    "--no-sandbox",
    `--remote-debugging-port=${debuggingPort}`,
    `--user-data-dir=${profile}`,
    "--window-size=1440,1100",
    "about:blank",
  ],
  { stdio: ["ignore", "ignore", "pipe"] },
);

let chromeErrors = "";
chrome.stderr.on("data", (chunk) => {
  chromeErrors += chunk.toString();
});

try {
  const version = await poll(async () => {
    const response = await fetch(
      `http://127.0.0.1:${debuggingPort}/json/version`,
    ).catch(() => null);
    return response?.ok ? response.json() : null;
  });
  const socket = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });

  let requestId = 0;
  const pending = new Map();
  const browserErrors = [];
  socket.addEventListener("message", (message) => {
    const payload = JSON.parse(message.data);
    if (payload.id && pending.has(payload.id)) {
      const request = pending.get(payload.id);
      pending.delete(payload.id);
      if (payload.error) {
        request.reject(new Error(payload.error.message));
      } else {
        request.resolve(payload.result);
      }
      return;
    }
    if (
      payload.method === "Runtime.exceptionThrown" ||
      (payload.method === "Log.entryAdded" &&
        payload.params.entry.level === "error")
    ) {
      browserErrors.push(payload);
    }
  });

  function send(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = ++requestId;
      pending.set(id, { resolve, reject });
      socket.send(
        JSON.stringify({
          id,
          method,
          params,
          ...(sessionId ? { sessionId } : {}),
        }),
      );
    });
  }

  const { targetId } = await send("Target.createTarget", { url: baseUrl });
  const { sessionId } = await send("Target.attachToTarget", {
    targetId,
    flatten: true,
  });
  await send("Runtime.enable", {}, sessionId);
  await send("Log.enable", {}, sessionId);
  await send("Page.enable", {}, sessionId);

  async function evaluate(expression) {
    const result = await send(
      "Runtime.evaluate",
      { expression, awaitPromise: true, returnByValue: true },
      sessionId,
    );
    if (result.exceptionDetails) {
      throw new Error(
        result.exceptionDetails.exception?.description ??
          result.exceptionDetails.text,
      );
    }
    return result.result.value;
  }

  await poll(async () => {
    const page = JSON.parse(
      await evaluate(
        `JSON.stringify({ready: document.readyState, href: location.href})`,
      ),
    );
    return page.ready === "complete" && page.href.startsWith(baseUrl);
  });
  await evaluate(
    `sessionStorage.setItem("jfr_api_key", ${JSON.stringify(apiKey)})`,
  );
  await send("Page.reload", {}, sessionId);
  await poll(async () => {
    const ready = await evaluate(`JSON.stringify({
      loaded: document.readyState === "complete",
      appVisible: !document.querySelector("#app-shell")?.hidden,
      cases: document.querySelectorAll(".case-item").length
    })`);
    const state = JSON.parse(ready);
    return state.loaded && state.appVisible && state.cases > 0;
  });
  await evaluate(`document.querySelector(".case-item").click()`);
  await poll(async () => {
    const name = await evaluate(
      `document.querySelector("#case-name")?.textContent ?? ""`,
    );
    return name && name !== "No fiber loaded";
  });
  await evaluate(`document.querySelector("#audit-button").click()`);
  await poll(async () => {
    const semantic = await evaluate(
      `document.querySelector("#semantic-status")?.textContent ?? ""`,
    );
    return semantic.startsWith("Complete");
  });

  const desktop = JSON.parse(
    await evaluate(`JSON.stringify({
      title: document.title,
      authHidden: document.querySelector("#auth-gate").hidden,
      appHidden: document.querySelector("#app-shell").hidden,
      cases: document.querySelectorAll(".case-item").length,
      branches: document.querySelectorAll("#branch-table tr").length,
      certifyEnabled: !document.querySelector("#materialize-fiber-button").disabled,
      advanceEnabled: !document.querySelector("#advance-fiber-button").disabled,
      likelihoodEnabled: !document.querySelector("#likelihood-button").disabled,
      assumptions: document.querySelectorAll("#assumption-list .assurance-card").length,
      guarantees: document.querySelectorAll("#guarantee-list .assurance-card").length,
      authorizations: document.querySelectorAll("#authorization-list .assurance-card").length,
      audit: document.querySelector("#audit-status").textContent,
      semantic: document.querySelector("#semantic-status").textContent,
      guaranteeSemantic: document.querySelector("#guarantee-semantic-status").textContent,
      escape: document.querySelector("#escape-score").textContent,
      bodyWidth: document.body.scrollWidth,
      viewportWidth: innerWidth
    })`),
  );
  assert(desktop.authHidden, "authentication gate remained visible");
  assert(!desktop.appHidden, "operator console remained hidden");
  assert(desktop.cases > 0, "no cases rendered");
  assert(desktop.branches > 0, "no branches rendered");
  assert(desktop.certifyEnabled, "certified fiber action is unavailable");
  assert(desktop.advanceEnabled, "continuation action is unavailable");
  assert(desktop.likelihoodEnabled, "Bayesian evidence action is unavailable");
  assert(desktop.assumptions > 0, "assumption fiber did not render");
  assert(desktop.guarantees > 0, "guarantee gates did not render");
  assert(desktop.authorizations > 0, "authorization history did not render");
  assert(desktop.semantic.startsWith("Complete"), "semantic fiber audit failed");
  assert(desktop.guaranteeSemantic.startsWith("Exact"), "semantic guarantee audit failed");
  assert(
    desktop.bodyWidth <= desktop.viewportWidth,
    "desktop layout has horizontal overflow",
  );
  const desktopCapture = await send(
    "Page.captureScreenshot",
    { format: "png", captureBeyondViewport: false },
    sessionId,
  );
  await writeFile(desktopScreenshot, Buffer.from(desktopCapture.data, "base64"));
  await evaluate(`document.querySelector(".assurance-workspace").scrollIntoView({block:"start"})`);
  await new Promise((resolve) => setTimeout(resolve, 150));
  const assuranceCapture = await send(
    "Page.captureScreenshot",
    { format: "png", captureBeyondViewport: false },
    sessionId,
  );
  await writeFile(
    assuranceScreenshot,
    Buffer.from(assuranceCapture.data, "base64"),
  );

  await send(
    "Emulation.setDeviceMetricsOverride",
    {
      width: 390,
      height: 844,
      deviceScaleFactor: 1,
      mobile: true,
    },
    sessionId,
  );
  await send("Page.reload", {}, sessionId);
  await poll(async () => {
    const ready = await evaluate(`JSON.stringify({
      loaded: document.readyState === "complete",
      appVisible: !document.querySelector("#app-shell")?.hidden,
      cases: document.querySelectorAll(".case-item").length
    })`);
    const state = JSON.parse(ready);
    return state.loaded && state.appVisible && state.cases > 0;
  });
  await evaluate(`document.querySelector(".case-item").click()`);
  await poll(async () => {
    const name = await evaluate(
      `document.querySelector("#case-name")?.textContent ?? ""`,
    );
    return name && name !== "No fiber loaded";
  });
  const mobile = JSON.parse(
    await evaluate(`JSON.stringify({
      bodyWidth: document.body.scrollWidth,
      viewportWidth: innerWidth,
      branches: document.querySelectorAll("#branch-table tr").length
    })`),
  );
  assert(mobile.branches > 0, "mobile branch list did not render");
  assert(
    mobile.bodyWidth <= mobile.viewportWidth,
    "mobile layout has horizontal overflow",
  );
  const mobileCapture = await send(
    "Page.captureScreenshot",
    { format: "png", captureBeyondViewport: false },
    sessionId,
  );
  await writeFile(mobileScreenshot, Buffer.from(mobileCapture.data, "base64"));

  assert(
    browserErrors.length === 0,
    `browser console contains errors: ${JSON.stringify(browserErrors)}`,
  );
  await send("Target.closeTarget", { targetId });
  socket.close();
  process.stdout.write(
    `${JSON.stringify(
      {
        desktop,
        mobile,
        browserErrors: browserErrors.length,
        screenshots: [desktopScreenshot, assuranceScreenshot, mobileScreenshot],
      },
      null,
      2,
    )}\n`,
  );
} finally {
  chrome.kill("SIGTERM");
  if (chrome.exitCode === null) {
    await Promise.race([
      new Promise((resolve) => chrome.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 2_000)),
    ]);
  }
  await rm(profile, {
    recursive: true,
    force: true,
    maxRetries: 5,
    retryDelay: 100,
  });
  if (chrome.exitCode && chrome.exitCode !== 0) {
    process.stderr.write(chromeErrors);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function poll(operation, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await operation();
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`condition was not met within ${timeoutMs} ms`);
}
