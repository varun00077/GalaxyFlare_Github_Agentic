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

  // ---------------------------------------------------------------- serverless (Vercel) mode
  // No server-side session: the browser holds {incident, world, usage} and sends it with every request.
  const SL = { on: false, state: null, busy: false, continues: 0 };
  const store = { get: (k) => { try { return sessionStorage.getItem(k) || localStorage.getItem(k); } catch (_) { return null; } },
                  set: (k, v, persist) => { try { (persist ? localStorage : sessionStorage).setItem(k, v); if (!persist) localStorage.removeItem(k); } catch (_) {} },
                  del: (k) => { try { sessionStorage.removeItem(k); localStorage.removeItem(k); } catch (_) {} } };
  function slHeaders() {
    const h = { "Content-Type": "application/json" };
    const k = store.get("planner_key"), p = store.get("planner_provider"), m = store.get("planner_model");
    if (k) h["X-Planner-Key"] = k;
    if (p) h["X-Planner-Provider"] = p;
    if (m) h["X-Planner-Model"] = m;
    return h;
  }
  function slHandle(ev, d) {
    if (ev === "trace") { addRow(d.event); applySummary(d.incident); }
    else if (ev === "state") {
      SL.state = d.state;
      if (d.incident) applySummary(d.incident);
      if (d.env) { renderEnv(d.env.truth); renderAlerts(d.env.alerts, d.env.handled); }
      const inc = d.incident;
      if (inc && inc.status === "open" && !inc.pending_approval && SL.continues < 8) {
        SL.continues += 1;
        toast("request time budget reached — continuing in a new request");
        slStream("/api/resume", { state: SL.state }).catch((e) => toast(e.message));
      } else { SL.continues = 0; }
    }
  }
  async function slStream(path, body) {
    if (SL.busy) { toast("the agent is still working — wait for it to pause or finish"); return; }
    SL.busy = true; setStatus("open");
    try {
      const r = await fetch(path, { method: "POST", headers: slHeaders(), body: JSON.stringify(body) });
      if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || j.detail || r.statusText); }
      if ((r.headers.get("content-type") || "").includes("application/json")) {
        const d = await r.json();
        if (d.state) SL.state = d.state;
        if (d.env) { renderEnv(d.env.truth); renderAlerts(d.env.alerts, d.env.handled); }
        return d;
      }
      const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
          let ev = null, data = null;
          for (const line of block.split("\n")) { if (line.startsWith("event: ")) ev = line.slice(7); else if (line.startsWith("data: ")) data = line.slice(6); }
          if (ev && data != null) { try { slHandle(ev, JSON.parse(data)); } catch (e) { console.error(e); } }
        }
      }
    } finally { SL.busy = false; }
  }

  // ---------------------------------------------------------------- boot
  let META = null;
  function applyMeta(meta) {
    META = meta;
    SL.on = meta.mode === "serverless";
    $("environment").hidden = SL.on;
    const p = meta.planner;
    const bk = SL.on ? store.get("planner_key") : null;
    if (bk) $("planner").textContent = `${store.get("planner_provider") || "groq"} · browser key (...${bk.slice(-4)})`;
    else $("planner").textContent = p === "mock" ? "scripted (offline)" : `${p}${meta.model ? " · " + meta.model : ""} (${meta.providers[p].key_hint})`;
    const anyKey = Object.values(meta.providers).some((x) => x.has_key);
    $("key-btn").textContent = anyKey ? "Key ✓" : "Key";
    refreshKeyPanel();
    const live = meta.environment === "live";
    $("environment").value = meta.environment;
    $("env-tag").textContent = live ? "LIVE HOST MODE" : "AUTONOMOUS SOC INVESTIGATION";
    document.querySelectorAll(".chaos").forEach((el) => { el.hidden = el.classList.contains("live-only") ? !live : live; });
  }
  function refreshKeyPanel() {
    if (!META) return;
    const prov = $("key-provider").value;
    const info = META.providers[prov];
    $("key-loaded").textContent = info.has_key ? `loaded (${info.key_hint}) · model ${info.model}${META.planner === prov ? " · active" : ""}` : "no key loaded";
    $("key-model").placeholder = prov === "groq" ? "auto (best available)" : "gemini-3.6-flash";
    $("model-list").innerHTML = "";
    if (SL.on) { const bk = store.get("planner_key"); $("key-loaded").textContent = bk && (store.get("planner_provider") || "groq") === prov ? `browser key (...${bk.slice(-4)}) · sent with each request, never stored on the server` : (info.has_key ? `deployment key loaded (${info.key_hint})` : "no key — paste one; it stays in this browser"); return; }
    if (info.has_key) api(`/api/settings/models?provider=${prov}`).then((m) => { $("model-list").innerHTML = m.models.map((x) => `<option value="${x}">`).join(""); }).catch(() => {});
  }
  $("key-provider").addEventListener("change", refreshKeyPanel);

  async function boot() {
    const meta = await api("/api/meta");
    applyMeta(meta);
    $("st-budget").textContent = meta.budget;
    const scenarios = await api("/api/scenarios");
    const sel = $("scenario");
    sel.innerHTML = scenarios.map((s) => `<option value="${s.id}">${s.id} — ${esc(s.name)}</option>`).join("");
    const env = await api("/api/env");
    sel.value = env.scenario.id;
    renderAlerts(env.alerts, env.handled);
    renderEnv(env.truth);
    if (SL.on) { $("chat-input").disabled = true; $("chat-send").disabled = true; return; }
    const existing = await api("/api/incidents");
    if (existing.length) attach(existing[existing.length - 1].id);
  }

  $("environment").addEventListener("change", async () => {
    try {
      const meta = await api("/api/settings/environment", { method: "POST", body: JSON.stringify({ environment: $("environment").value }) });
      applyMeta(meta);
      detach(); alertsDone = new Set();
      const scenarios = await api("/api/scenarios");
      $("scenario").innerHTML = scenarios.map((s) => `<option value="${s.id}">${s.id} — ${esc(s.name)}</option>`).join("");
      const env = await api("/api/env");
      $("scenario").value = env.scenario.id;
      renderAlerts(env.alerts); renderEnv(env.truth);
      resetHero("no incident", meta.environment === "live" ? "This machine" : "Pick an alert",
        meta.environment === "live" ? `${env.scenario.name}. ${env.scenario.description}` : "Scenario loaded. Choose an alert from the queue to start the investigation.");
    } catch (e) { toast(e.message); $("environment").value = META ? META.environment : "sandbox"; }
  });

  $("load").addEventListener("click", async () => {
    try {
      if (SL.on) { SL.state = null; } else { await api("/api/scenario/load", { method: "POST", body: JSON.stringify({ scenario: $("scenario").value }) }); }
      detach();
      alertsDone = new Set();
      const env = await api(SL.on ? `/api/env?scenario=${encodeURIComponent($("scenario").value)}` : "/api/env");
      handledAlerts = {};
      renderAlerts(env.alerts, env.handled);
      renderEnv(env.truth);
      resetHero("no incident", "Pick an alert", "Scenario loaded. Choose an alert from the queue to start the investigation.");
    } catch (e) { toast(e.message); }
  });

  // ---------------------------------------------------------------- alerts
  let handledAlerts = {};
  function renderAlerts(alerts, handled) {
    if (handled) handledAlerts = handled;
    $("alert-count").textContent = alerts.length;
    $("alerts").innerHTML = alerts.map((a) => {
      const h = handledAlerts[a.alert_id];
      const done = !!h || alertsDone.has(a.alert_id);
      const tag = h ? `<span class="handled">${h.role === "follow-up" ? "pivot · handled in" : "handled in"} ${h.incident}${h.verdict ? " · " + h.verdict : ""}</span>` : "";
      return `
      <div class="alert ${done ? "done" : ""}" data-id="${a.alert_id}">
        <div>
          <div class="sig"><span class="sev s${a.alert.severity}"></span> ${esc(a.alert.signature)}</div>
          <div class="meta"><b>${a.alert_id}</b><span>sid ${a.alert.signature_id}</span><span>${esc(a.src_ip)} → ${esc(a.dest_ip)}:${a.dest_port}</span>${tag}</div>
        </div>
        <button class="btn investigate" data-id="${a.alert_id}">${done ? "Re-run" : "Run"}</button>
      </div>`; }).join("") || `<div class="empty">No alerts in this scenario.</div>`;
    document.querySelectorAll(".investigate").forEach((b) => b.addEventListener("click", () => investigate(b.dataset.id)));
  }

  async function investigate(alertId) {
    if (SL.on) {
      const carry = SL.state && !SL.state.incident ? SL.state : null;   // sandbox changed by chaos before the run
      detach(); SL.continues = 0;
      alertsDone.add(alertId);
      incidentId = "serverless"; $("chat-input").disabled = false; $("chat-send").disabled = false; $("incident-id").textContent = "…";
      addMsg("agent", `Investigating ${alertId}. Ask why, or use /override, /reopen, /help.`);
      slStream("/api/run", { scenario: $("scenario").value, alert_id: alertId, state: carry }).catch((e) => { toast(e.message); setStatus("idle"); });
      return;
    }
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
    $("incident-id").textContent = "none"; setStatus("idle"); setStats({ steps: 0, budget: null, evidence: [], actions: [], verdict: null, llm_usage: {} });
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
    try { const env = await api("/api/env"); renderEnv(env.truth); renderAlerts(env.alerts, env.handled); } catch (_) {}
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
    if (SL.on && inc.id) { incidentId = inc.id; $("incident-id").textContent = inc.id; }
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
    const u = inc.llm_usage || {};
    $("st-calls").textContent = u.calls ?? 0;
    const tok = (u.prompt || 0) + (u.output || 0);
    $("st-tokens").textContent = tok ? `${tok >= 1000 ? (tok / 1000).toFixed(1) + "k" : tok} tokens${u.model_switches ? ` · ${u.model_switches} switches` : ""}` : "0 tokens";
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
    if (SL.on) {
      try {
        const prov = $("key-provider").value, key = $("key-input").value.trim(), model = $("key-model").value.trim();
        const r = await fetch("/api/settings/validate", { method: "POST", headers: { "Content-Type": "application/json", "X-Planner-Provider": prov, "X-Planner-Key": key, "X-Planner-Model": model }, body: "{}" });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || d.detail || r.statusText);
        const persist = $("key-remember").checked;
        store.set("planner_key", key, persist); store.set("planner_provider", prov, persist); if (model) store.set("planner_model", model, persist); else store.del("planner_model");
        $("key-input").value = "";
        applyMeta(META);
        st.className = "key-status mono ok"; st.textContent = `ok · ${prov} · ${d.model} · key kept in this browser${persist ? " (remembered)" : " (this tab)"}`;
      } catch (err) { st.className = "key-status mono bad"; st.textContent = err.message; }
      return;
    }
    try {
      const meta = await api("/api/settings/key", { method: "POST", body: JSON.stringify({ api_key: $("key-input").value, model: $("key-model").value || null, remember: $("key-remember").checked, provider: $("key-provider").value }) });
      applyMeta(meta);
      $("key-input").value = "";
      st.className = "key-status mono ok"; st.textContent = `ok · planner is now ${meta.planner} · ${meta.model}${meta.remembered ? " · saved to .env" : ""}. Applies to the next investigation.`;
    } catch (err) { st.className = "key-status mono bad"; st.textContent = err.message; }
  });
  $("key-use").addEventListener("click", async () => {
    const st = $("key-status");
    if (SL.on) { st.className = "key-status mono"; st.textContent = "in this deployment the planner is chosen by the key you paste (or the env vars)"; return; }
    try { applyMeta(await api("/api/settings/provider", { method: "POST", body: JSON.stringify({ provider: $("key-provider").value }) })); st.className = "key-status mono ok"; st.textContent = `planner is now ${META.planner} · ${META.model}`; }
    catch (err) { st.className = "key-status mono bad"; st.textContent = err.message; }
  });
  $("key-clear").addEventListener("click", async () => {
    if (SL.on) { store.del("planner_key"); store.del("planner_provider"); store.del("planner_model"); applyMeta(META); $("key-status").className = "key-status mono"; $("key-status").textContent = "using the deployment's planner (scripted unless env keys are set)"; return; }
    try { applyMeta(await api("/api/settings/key", { method: "DELETE" })); $("key-status").className = "key-status mono"; $("key-status").textContent = "using the scripted planner"; }
    catch (err) { toast(err.message); }
  });

  // ---------------------------------------------------------------- approval + chaos + chat
  $("approve").addEventListener("click", () => approve(true));
  $("deny").addEventListener("click", () => approve(false));
  async function approve(ok) {
    if (!incidentId) return;
    if (SL.on) { $("approval").hidden = true; slStream("/api/resume", { state: SL.state, approved: ok }).catch((e) => toast(e.message)); return; }
    try { await api(`/api/incidents/${incidentId}/approve`, { method: "POST", body: JSON.stringify({ approved: ok }) }); $("approval").hidden = true; }
    catch (e) { toast(e.message); }
  }

  document.querySelectorAll(".chaos-btn").forEach((b) => b.addEventListener("click", async () => {
    if (SL.on) {
      toast(`${b.dataset.kind} injected`);
      slStream(`/api/chaos/${b.dataset.kind}`, { state: SL.state, scenario: $("scenario").value, payload: {} }).catch((e) => toast(e.message));
      return;
    }
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
    if (SL.on) {
      try {
        const r = await fetch("/api/chat", { method: "POST", headers: slHeaders(), body: JSON.stringify({ state: SL.state, message: text }) });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || d.detail || r.statusText);
        addMsg("agent", d.reply);
        if (d.state) SL.state = d.state;
        if (d.needs_run) slStream("/api/resume", { state: SL.state }).catch((e) => toast(e.message));
      } catch (err) { addMsg("agent", `error: ${err.message}`); }
      return;
    }
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
