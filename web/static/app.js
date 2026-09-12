/* SOCrates analyst console: drives the agent service and follows the trace over SSE. */
(() => {
  const $ = (id) => document.getElementById(id);
  const api = async (path, opts = {}) => {
    const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || body.detail || r.statusText);
    return body;
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  let incidentId = null;
  let source = null;
  let seen = new Set();          // trace seqs already rendered
  let evidenceCount = 0;
  let alertsDone = new Set();

  // ---------------------------------------------------------------- boot
  function applyMeta(meta) {
    $("planner").textContent = meta.planner === "gemini" ? `gemini · ${meta.model} (${meta.key_hint})` : "scripted (offline)";
    $("key-model").placeholder = meta.gemini_model || "gemini-2.5-flash";
    $("key-btn").textContent = meta.has_key ? "Key ✓" : "Key";
  }

  async function boot() {
    const meta = await api("/api/meta");
    applyMeta(meta);
    $("st-budget").textContent = meta.budget;
    const scenarios = await api("/api/scenarios");
    const sel = $("scenario");
    sel.innerHTML = scenarios.map((s) => `<option value="${s.id}">${s.id} — ${esc(s.name)}</option>`).join("");
    const env = await api("/api/env");
    sel.value = env.scenario.id;
    renderAlerts(env.alerts);
    renderEnv(env.truth);
    const existing = await api("/api/incidents");
    if (existing.length) attach(existing[existing.length - 1].id);
  }

  $("load").addEventListener("click", async () => {
    try {
      await api("/api/scenario/load", { method: "POST", body: JSON.stringify({ scenario: $("scenario").value }) });
      detach();
      alertsDone = new Set();
      const env = await api("/api/env");
      renderAlerts(env.alerts);
      renderEnv(env.truth);
      resetHero("no incident", "Pick an alert", "Scenario loaded. Choose an alert from the queue to start the investigation.");
    } catch (e) { toast(e.message); }
  });

  // ---------------------------------------------------------------- alerts
  function renderAlerts(alerts) {
    $("alert-count").textContent = alerts.length;
    $("alerts").innerHTML = alerts.map((a) => `
      <div class="alert ${alertsDone.has(a.alert_id) ? "done" : ""}" data-id="${a.alert_id}">
        <div>
          <div class="sig"><span class="sev s${a.alert.severity}"></span> ${esc(a.alert.signature)}</div>
          <div class="meta"><b>${a.alert_id}</b><span>sid ${a.alert.signature_id}</span><span>${esc(a.src_ip)} → ${esc(a.dest_ip)}:${a.dest_port}</span></div>
        </div>
        <button class="btn investigate" data-id="${a.alert_id}">Run</button>
      </div>`).join("") || `<div class="empty">No alerts in this scenario.</div>`;
    document.querySelectorAll(".investigate").forEach((b) => b.addEventListener("click", () => investigate(b.dataset.id)));
  }

  async function investigate(alertId) {
    try {
      const { incident_id } = await api("/api/investigate", { method: "POST", body: JSON.stringify({ alert_id: alertId }) });
      alertsDone.add(alertId);
      document.querySelector(`.alert[data-id="${alertId}"]`)?.classList.add("done");
      attach(incident_id);
    } catch (e) { toast(e.message); }
  }

  // ---------------------------------------------------------------- incident stream
  function detach() {
    if (source) source.close();
    source = null; incidentId = null; seen = new Set(); evidenceCount = 0;
    $("trace").innerHTML = ""; $("evidence").innerHTML = ""; $("chat-log").innerHTML = "";
    $("incident-id").textContent = "none"; setStatus("idle"); setStats({ steps: 0, budget: null, evidence: [], actions: [], verdict: null });
    $("approval").hidden = true; $("chat-input").disabled = true; $("chat-send").disabled = true;
  }

  function attach(id) {
    detach();
    incidentId = id;
    $("incident-id").textContent = id;
    $("chat-input").disabled = false; $("chat-send").disabled = false;
    api(`/api/incidents/${id}`).then((inc) => { (inc.chat || []).forEach((m) => addMsg(m.who, m.text)); });
    source = new EventSource(`/api/incidents/${id}/events`);
    source.addEventListener("snapshot", (e) => {
      const d = JSON.parse(e.data);
      d.trace.forEach(addRow);
      applySummary(d.incident);
    });
    source.addEventListener("trace", (e) => {
      const d = JSON.parse(e.data);
      addRow(d.event);
      applySummary(d.incident);
      if (["action", "verification", "escalation", "final", "human"].includes(d.event.kind)) refreshEnv();
    });
    source.addEventListener("done", (e) => { applySummary(JSON.parse(e.data).incident); refreshEnv(); });
  }

  async function refreshEnv() {
    try { const env = await api("/api/env"); renderEnv(env.truth); renderAlerts(env.alerts); } catch (_) {}
  }

  // ---------------------------------------------------------------- rendering
  const KIND_LABEL = { goal: "goal", decision: "decision", action: "action", result: "result", guardrail: "guardrail",
    verification: "verify", adaptation: "adapt", escalation: "escalate", final: "final", error: "error", human: "human" };

  function addRow(ev) {
    if (seen.has(ev.seq)) return;
    seen.add(ev.seq);
    const li = document.createElement("li");
    const cls = [ev.kind];
    if (ev.kind === "guardrail" && ev.detail.blocked) cls.push("blocked");
    if (ev.kind === "verification" && ev.detail.ok === false) cls.push("bad");
    li.className = "row " + cls.join(" ");
    let title = esc(ev.title);
    if (ev.kind === "decision" && ev.detail.tool) title = `<code>${esc(ev.title)}</code>`;
    const refs = (ev.detail.evidence || []).map((id) => `<span class="ev-ref">${id}</span>`).join("");
    let sub = "";
    if (ev.detail.rationale) sub += `<div class="sub">${esc(ev.detail.rationale)}</div>`;
    if (ev.detail.notes && ev.detail.notes.length) sub += `<div class="sub notes">${ev.detail.notes.map((n) => "· " + esc(n)).join("\n")}</div>`;
    if (ev.detail.missing_evidence && ev.detail.missing_evidence.length) sub += `<div class="sub notes">missing: ${ev.detail.missing_evidence.map(esc).join("; ")}</div>`;
    li.innerHTML = `<span class="step">${String(ev.step).padStart(2, "0")}</span><span class="kind">${KIND_LABEL[ev.kind] || ev.kind}</span><div class="title">${title}${refs}${sub}</div>`;
    const list = $("trace");
    list.querySelector(".empty")?.remove();
    list.querySelectorAll(".row.latest").forEach((r) => r.classList.remove("latest"));
    li.classList.add("latest");
    list.appendChild(li);
    li.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function applySummary(inc) {
    setStatus(inc.running ? (inc.status === "awaiting_approval" ? "awaiting_approval" : "open") : inc.status);
    setStats(inc);
    $("hero-right").textContent = inc.scenario ? `scenario ${inc.scenario} · ${inc.status.replace("_", " ")}` : "";
    // hero
    const v = inc.verdict;
    if (v && v.verdict) {
      $("hero-kicker").textContent = `${inc.id} · alert ${inc.current_alert_id}`;
      const hv = $("hero-verdict");
      hv.textContent = v.verdict.replace("_", " ");
      hv.className = "hero-verdict " + v.verdict;
      $("hero-summary").textContent = v.summary || "";
    } else {
      $("hero-kicker").textContent = `${inc.id} · alert ${inc.current_alert_id} · step ${inc.steps}`;
      const hv = $("hero-verdict");
      hv.textContent = inc.running ? "Investigating" : (inc.status === "awaiting_approval" ? "Waiting for you" : "Paused");
      hv.className = "hero-verdict working";
      $("hero-summary").textContent = "Collecting evidence: flow, asset, advisories, host logs. The verdict appears when the ledger supports one.";
    }
    const chips = [];
    inc.blocked_ips.forEach((ip) => chips.push(`<span class="chip crit">blocked ${ip}</span>`));
    inc.actions.filter((a) => a.type === "isolate_host").forEach((a) => chips.push(`<span class="chip crit">isolated ${a.target}</span>`));
    inc.actions.filter((a) => a.type === "unblock_ip").forEach((a) => chips.push(`<span class="chip human">unblocked ${a.target}</span>`));
    inc.actions.filter((a) => a.type === "watchlist").forEach((a) => chips.push(`<span class="chip ok">watch-list ${a.target}</span>`));
    inc.escalations.forEach((t) => chips.push(`<span class="chip accent">${t.ticket_id}</span>`));
    inc.followup_alerts.forEach((a) => chips.push(`<span class="chip adapt">pivot → ${a}</span>`));
    if (inc.logs_degraded) chips.push(`<span class="chip adapt">logs degraded · confidence capped</span>`);
    $("hero-chips").innerHTML = chips.join("");
    // approval
    const pend = inc.pending_approval;
    if (inc.status === "awaiting_approval" && pend) {
      $("approval").hidden = false;
      $("approval-text").textContent = `${pend.decision.action.replace("_", " ")} ${pend.decision.target || ""} — ${pend.decision.reason}`;
    } else {
      $("approval").hidden = true;
    }
    // evidence
    if (inc.evidence.length !== evidenceCount) {
      evidenceCount = inc.evidence.length;
      $("evidence-count").textContent = evidenceCount;
      $("evidence").innerHTML = inc.evidence.map((e) => `
        <li class="ev"><span class="id">${e.id}</span>
          <div><div class="ex">${esc(e.excerpt)}</div>${e.meaning ? `<div class="mean">${esc(e.meaning)} · ${esc(e.source)}</div>` : ""}</div>
          <span class="cat ${e.category}">${e.category.replace("_", " ")}</span></li>`).join("");
      $("evidence").lastElementChild?.scrollIntoView({ block: "nearest" });
    }
  }

  function renderEnv(t) {
    const chips = (arr, cls) => arr.length ? arr.map((x) => `<span class="chip ${cls}">${esc(x)}</span>`).join("") : "none";
    $("env-rules").innerHTML = chips(t.blocked_ips, "crit");
    $("env-isolated").innerHTML = chips(t.isolated_hosts, "crit");
    $("env-allow").innerHTML = chips(t.allowlist, "human");
    $("env-watch").innerHTML = chips(t.watchlist, "ok");
    $("env-tickets").innerHTML = t.tickets.length ? t.tickets.map((k) => `<div>${k.ticket_id}: ${esc(k.reason)}</div>`).join("") : "none";
    $("env-assess").innerHTML = t.assessments.length ? t.assessments.map((a) => `<span class="chip">${a.assessment_id} ${a.verdict}</span>`).join(" ") : "none";
  }

  function setStatus(s) { const p = $("status-pill"); p.textContent = s.replace("_", " "); p.className = "pill " + s; }
  function setStats(inc) {
    if (inc.budget) $("st-budget").textContent = inc.budget;
    $("st-steps").textContent = inc.steps ?? 0;
    $("st-evidence").textContent = (inc.evidence || []).length;
    $("st-actions").textContent = (inc.actions || []).filter((a) => a.type !== "watchlist").length;
    $("st-conf").textContent = inc.verdict && inc.verdict.confidence != null ? Number(inc.verdict.confidence).toFixed(2) : "—";
  }
  function resetHero(k, v, s) { $("hero-kicker").textContent = k; $("hero-right").textContent = ""; $("hero-verdict").textContent = v; $("hero-verdict").className = "hero-verdict"; $("hero-summary").textContent = s; $("hero-chips").innerHTML = ""; }

  // ---------------------------------------------------------------- gemini key
  $("key-btn").addEventListener("click", () => {
    const p = $("key-pop");
    p.hidden = !p.hidden;
    if (!p.hidden) { p.style.top = `${document.querySelector(".bar").getBoundingClientRect().bottom + 10}px`; $("key-input").focus(); }
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("key-pop").hidden = true; });
  $("key-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const st = $("key-status");
    st.className = "key-status mono"; st.textContent = "validating…";
    try {
      const meta = await api("/api/settings/key", { method: "POST", body: JSON.stringify({ api_key: $("key-input").value, model: $("key-model").value || null }) });
      applyMeta(meta);
      $("key-input").value = "";
      st.className = "key-status mono ok"; st.textContent = `ok · planner is now gemini · ${meta.model}. Applies to the next investigation.`;
    } catch (err) { st.className = "key-status mono bad"; st.textContent = err.message; }
  });
  $("key-clear").addEventListener("click", async () => {
    try { applyMeta(await api("/api/settings/key", { method: "DELETE" })); $("key-status").className = "key-status mono"; $("key-status").textContent = "using the scripted planner"; }
    catch (err) { toast(err.message); }
  });

  // ---------------------------------------------------------------- approval + chaos + chat
  $("approve").addEventListener("click", () => approve(true));
  $("deny").addEventListener("click", () => approve(false));
  async function approve(ok) {
    if (!incidentId) return;
    try { await api(`/api/incidents/${incidentId}/approve`, { method: "POST", body: JSON.stringify({ approved: ok }) }); $("approval").hidden = true; }
    catch (e) { toast(e.message); }
  }

  document.querySelectorAll(".chaos-btn").forEach((b) => b.addEventListener("click", async () => {
    try {
      const res = await api(`/api/chaos/${b.dataset.kind}`, { method: "POST", body: JSON.stringify({ incident_id: incidentId, payload: {} }) });
      toast(`${b.dataset.kind}: ${JSON.stringify(res)}`);
      refreshEnv();
    } catch (e) { toast(e.message); }
  }));

  $("chat-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("chat-input");
    const text = input.value.trim();
    if (!text || !incidentId) return;
    input.value = "";
    addMsg("analyst", text);
    try {
      const { reply } = await api(`/api/incidents/${incidentId}/chat`, { method: "POST", body: JSON.stringify({ message: text }) });
      addMsg("agent", reply);
    } catch (err) { addMsg("agent", `error: ${err.message}`); }
  });

  function addMsg(who, text) {
    const d = document.createElement("div");
    d.className = "msg " + who;
    d.innerHTML = `<span class="who">${who}</span>${esc(text)}`;
    $("chat-log").appendChild(d);
    d.scrollIntoView({ block: "nearest" });
  }

  function toast(text) {
    let t = document.querySelector(".toast");
    if (!t) { t = document.createElement("div"); t.className = "toast"; document.body.appendChild(t); }
    t.textContent = text; t.style.opacity = "1";
    clearTimeout(t._h); t._h = setTimeout(() => (t.style.opacity = "0"), 3200);
  }

  boot().catch((e) => toast(e.message));
})();
