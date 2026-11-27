"""Self-contained interactive HTML dashboard served at / for Stackgini live demos."""

from __future__ import annotations

_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Stackgini Vendor Verifier</title>
  <style>
    :root {
      --bg: #f6f7f9;
      --surface: #ffffff;
      --ink: #111827;
      --muted: #4b5563;
      --border: #e5e7eb;
      --accent: #0f172a;
      --green-bg: #ecfdf5;
      --green-fg: #065f46;
      --yellow-bg: #fffbeb;
      --yellow-fg: #92400e;
      --red-bg: #fef2f2;
      --red-fg: #991b1b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--ink);
      line-height: 1.5;
    }
    .wrap { max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 24px;
    }
    h1 { margin: 0; font-size: 26px; letter-spacing: -0.02em; }
    .sub { color: var(--muted); font-size: 14px; margin: 4px 0 0; }
    .navlinks a { color: var(--muted); font-size: 13px; text-decoration: none; border-bottom: 1px solid var(--border); }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 18px;
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
    label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
      margin-bottom: 6px;
    }
    input {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #d1d5db;
      border-radius: 7px;
      font-size: 14px;
    }
    .actions { display: flex; gap: 10px; align-items: center; margin-top: 14px; flex-wrap: wrap; }
    button {
      background: var(--accent);
      color: #fff;
      border: 0;
      border-radius: 7px;
      padding: 10px 18px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
    }
    button.secondary {
      background: #fff;
      color: var(--ink);
      border: 1px solid #d1d5db;
      font-weight: 500;
      padding: 7px 12px;
      font-size: 13px;
    }
    button:disabled { opacity: 0.6; cursor: wait; }
    .badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 13px;
    }
    .badge.Green { background: var(--green-bg); color: var(--green-fg); }
    .badge.Yellow { background: var(--yellow-bg); color: var(--yellow-fg); }
    .badge.Red { background: var(--red-bg); color: var(--red-fg); }
    .error-box {
      background: var(--red-bg);
      color: var(--red-fg);
      padding: 12px 14px;
      border-radius: 8px;
      display: none;
      margin-bottom: 16px;
    }
    .findings-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .findings-table th, .findings-table td {
      text-align: left;
      padding: 8px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    ul { margin: 6px 0 0; padding-left: 18px; font-size: 14px; }
    .meta { color: var(--muted); font-size: 13px; }
    #result { display: none; }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div>
        <h1>Stackgini Vendor Verifier</h1>
        <p class="sub">
          Five deterministic registry probes, headless DOM claim cross-checks, and cited off-site verification.
        </p>
      </div>
      <div class="navlinks"><a href="/api/docs">OpenAPI Docs</a></div>
    </header>

    <section class="card">
      <form id="assess-form">
        <div class="grid">
          <div>
            <label for="vendor-url">Product URL or Domain</label>
            <input id="vendor-url" name="url" placeholder="https://linear.app" required />
          </div>
          <div>
            <label for="vendor-product">Product Name</label>
            <input id="vendor-product" name="product" placeholder="Linear" required />
          </div>
          <div>
            <label for="vendor-company">Vendor Legal Entity</label>
            <input id="vendor-company" name="vendor" placeholder="Linear Orbit, Inc." required />
          </div>
        </div>
        <div class="actions">
          <button id="submit-btn" type="submit">Run Full Verification</button>
          <button
            type="button"
            class="secondary preset-btn"
            data-url="https://linear.app"
            data-product="Linear"
            data-vendor="Linear Orbit, Inc."
          >Sample: Linear</button>
          <button
            type="button"
            class="secondary preset-btn"
            data-url="https://www.postfix.org/"
            data-product="Postfix"
            data-vendor="Wietse Venema"
          >Sample: Postfix</button>
          <span id="status-note" class="meta"></span>
        </div>
      </form>
    </section>

    <div id="error-box" class="error-box" role="alert"></div>

    <section id="result" class="card" aria-live="polite">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
        <div>
          <span id="res-verdict" class="badge">Green</span>
          <strong id="res-title" style="margin-left:8px;font-size:18px;"></strong>
        </div>
        <div class="meta" id="res-score"></div>
      </div>
      <p id="res-reasoning" style="margin-top:12px;"></p>
      <p class="meta" id="res-dom"></p>

      <div class="grid" style="margin-top:14px;">
        <div><strong>Green Flags</strong><ul id="res-green"></ul></div>
        <div><strong>Yellow Flags</strong><ul id="res-yellow"></ul></div>
        <div><strong>Red Flags</strong><ul id="res-red"></ul></div>
      </div>

      <h3 style="margin:20px 0 8px;font-size:15px;">Deterministic Infrastructure Probes</h3>
      <table class="findings-table">
        <thead><tr><th>Rule</th><th>Claim</th><th>Observed</th><th>Impact</th><th>Source</th></tr></thead>
        <tbody id="res-findings"></tbody>
      </table>

      <h3 style="margin:20px 0 8px;font-size:15px;">Verified Source Citations</h3>
      <ul id="res-sources"></ul>
    </section>
  </div>

  <script>
    const form = document.getElementById("assess-form");
    const submitBtn = document.getElementById("submit-btn");
    const statusNote = document.getElementById("status-note");
    const errorBox = document.getElementById("error-box");
    const resultCard = document.getElementById("result");

    for (const btn of document.querySelectorAll(".preset-btn")) {
      btn.addEventListener("click", () => {
        document.getElementById("vendor-url").value = btn.dataset.url || "";
        document.getElementById("vendor-product").value = btn.dataset.product || "";
        document.getElementById("vendor-company").value = btn.dataset.vendor || "";
      });
    }

    function fillList(id, items, emptyText) {
      const el = document.getElementById(id);
      el.innerHTML = "";
      const entries = items && items.length ? items : [emptyText];
      for (const txt of entries) {
        const li = document.createElement("li");
        li.textContent = txt;
        el.appendChild(li);
      }
    }

    function fillFindings(findings) {
      const tbody = document.getElementById("res-findings");
      tbody.innerHTML = "";
      for (const f of (findings || [])) {
        const tr = document.createElement("tr");
        const cells = [f.rule_id, f.claim, f.observed_fact, String(f.impact)];
        for (const text of cells) {
          const td = document.createElement("td");
          td.textContent = text;
          tr.appendChild(td);
        }
        const srcTd = document.createElement("td");
        const link = document.createElement("a");
        link.href = f.source_url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = "link";
        srcTd.appendChild(link);
        tr.appendChild(srcTd);
        tbody.appendChild(tr);
      }
    }

    function fillSources(urls) {
      const el = document.getElementById("res-sources");
      el.innerHTML = "";
      for (const u of (urls || [])) {
        const li = document.createElement("li");
        const a = document.createElement("a");
        a.href = u;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = u;
        li.appendChild(a);
        el.appendChild(li);
      }
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      errorBox.style.display = "none";
      submitBtn.disabled = true;
      statusNote.textContent = "Running probes, headless DOM, and research...";
      try {
        const payload = {
          row_id: "ui-1",
          url: document.getElementById("vendor-url").value.trim(),
          product: document.getElementById("vendor-product").value.trim(),
          vendor: document.getElementById("vendor-company").value.trim(),
        };
        const resp = await fetch("/api/v1/assess", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) {
          throw new Error(data.detail || ("HTTP " + resp.status));
        }
        const badge = document.getElementById("res-verdict");
        badge.textContent = data.overall;
        badge.className = "badge " + data.overall;
        document.getElementById("res-title").textContent = data.product + " (" + data.vendor + ")";
        document.getElementById("res-score").textContent =
          "Infra Trust: " + data.trust_score + "/100 (" + data.infra_verdict + ")";
        document.getElementById("res-reasoning").textContent = data.reasoning;
        document.getElementById("res-dom").textContent = data.dom_summary ? ("DOM: " + data.dom_summary) : "";
        fillList("res-green", data.green_flags, "None identified.");
        fillList("res-yellow", data.yellow_flags, "None identified.");
        fillList("res-red", data.red_flags, "None identified.");
        fillFindings(data.findings);
        fillSources(data.source_urls);
        resultCard.style.display = "block";
        statusNote.textContent = "Completed.";
      } catch (err) {
        errorBox.textContent = String(err.message || err);
        errorBox.style.display = "block";
        statusNote.textContent = "";
      } finally {
        submitBtn.disabled = false;
      }
    });
  </script>
</body>
</html>
"""


def render_dashboard_html() -> str:
    """Return the static HTML+JS dashboard page for Stackgini live demos."""
    return _DASHBOARD_HTML
