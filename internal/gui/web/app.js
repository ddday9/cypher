"use strict";

const token = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
let info = null;
let state = null;
let settingsDirty = false;
let prevTraffic = null;
let logNext = 0;

// --- API ---------------------------------------------------------------------

async function api(path, body) {
  const opts = { method: body === undefined ? "GET" : "POST", headers: { "X-Cypher-Token": token } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch("/api/" + path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const e = new Error(data.error || r.statusText);
    e.code = data.code;
    throw e;
  }
  return data;
}

// --- helpers -------------------------------------------------------------------

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) if (c != null) n.append(c);
  return n;
}

function bytes(n) {
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)) + " " + u[i];
}

function duration(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = String(Math.floor(s / 3600)).padStart(2, "0");
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  return `${h}:${m}:${String(s % 60).padStart(2, "0")}`;
}

function ago(iso) {
  const t = Date.parse(iso);
  if (!t || t < 0) return "никогда";
  const m = Math.round((Date.now() - t) / 60000);
  if (m < 1) return "только что";
  if (m < 60) return m + " мин назад";
  const h = Math.round(m / 60);
  if (h < 48) return h + " ч назад";
  return Math.round(h / 24) + " дн назад";
}

let toastTimer;
function toast(msg, isErr) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), isErr ? 6000 : 2500);
}

function pingBadge(ms) {
  if (ms === undefined) return el("span", { class: "ping" }, "—");
  if (ms < 0) return el("span", { class: "ping bad" }, "нет связи");
  const cls = ms < 120 ? "good" : ms < 300 ? "mid" : "bad";
  return el("span", { class: "ping " + cls }, ms < 1 ? "<1 мс" : ms + " мс");
}

async function busy(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { handleError(e); } finally { btn.disabled = false; }
}

function handleError(e) {
  if (e.code === "need_elevation") {
    showBanner("Для режима «Весь трафик» нужны права администратора. Перезапустить cypher с правами?", true);
    return;
  }
  toast(e.message, true);
}

function showBanner(text, elevate) {
  const b = $("banner");
  b.replaceChildren(text);
  b.className = "banner" + (elevate ? " info" : "");
  if (elevate) {
    b.append(el("div", {}, el("button", { class: "btn primary small", onclick: () => api("elevate", {}).catch(handleError) }, "Перезапустить с правами")));
  }
}

// --- navigation ------------------------------------------------------------------

function show(view) {
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + view));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === view));
  if (view === "settings" && !settingsDirty) fillSettings();
  if (view === "logs") pollLogs(true);
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => show(t.dataset.view)));
$("serverCard").addEventListener("click", () => show("servers"));
$("routingCard").addEventListener("click", () => show("settings"));

// --- home ----------------------------------------------------------------------------

$("power").addEventListener("click", async () => {
  if (!state) return;
  const btn = $("power");
  if (state.status === "connected") {
    await busy(btn, () => api("disconnect", {}));
  } else if (state.status === "stopped") {
    $("banner").classList.add("hidden");
    renderPower("connecting");
    await busy(btn, () => api("connect", {}));
  }
  refresh();
});

document.querySelectorAll(".seg").forEach((b) => b.addEventListener("click", async () => {
  const s = { ...state.data.settings, mode: b.dataset.mode };
  try { await api("settings", s); } catch (e) { handleError(e); }
  refresh();
}));

function renderPower(status) {
  const p = $("power");
  p.className = "power " + (status === "connected" ? "on" : status === "connecting" ? "connecting" : "off");
  p.setAttribute("aria-label", status === "connected" ? "Отключить" : "Подключить");
  const st = $("statusText");
  st.className = "status-text" + (status === "connected" ? " on" : "");
  st.textContent = status === "connected" ? "Подключено" : status === "connecting" ? (state && state.busy) || "Подключение…" : "Не подключено";
}

function renderHome() {
  const s = state;
  renderPower(s.status);
  $("timer").textContent = s.status === "connected" ? duration(Date.now() - Date.parse(s.since)) : " ";

  const now = Date.now();
  if (s.status === "connected" && prevTraffic) {
    const dt = Math.max(0.2, (now - prevTraffic.t) / 1000);
    $("upRate").textContent = bytes(Math.max(0, (s.up - prevTraffic.up) / dt)) + "/с";
    $("downRate").textContent = bytes(Math.max(0, (s.down - prevTraffic.down) / dt)) + "/с";
  } else {
    $("upRate").textContent = "0 Б/с";
    $("downRate").textContent = "0 Б/с";
  }
  prevTraffic = s.status === "connected" ? { up: s.up, down: s.down, t: now } : null;
  $("upTotal").textContent = bytes(s.up || 0);
  $("downTotal").textContent = bytes(s.down || 0);

  const set = s.data.settings;
  document.querySelectorAll(".seg").forEach((b) => b.classList.toggle("active", b.dataset.mode === set.mode));
  const chip = $("modeChip");
  chip.textContent = s.status === "connected" ? (s.mode === "tun" ? "TUN" : "Прокси") : "выключено";
  chip.classList.toggle("on", s.status === "connected");

  const profiles = s.data.profiles || [];
  const sel = profiles.find((p) => p.id === s.data.selected) || profiles[0];
  $("serverName").textContent = sel ? sel.name : "Добавьте сервер";
  $("serverHost").textContent = sel ? sel.server : "Вставьте ссылку cypher:// или подписку";
  $("serverPing").replaceChildren(...(sel ? [pingBadge(s.pings[sel.id])] : []));
  $("serverPing").classList.toggle("hidden", !sel);

  const preset = info.presets.find((p) => p.id === set.routing) || info.presets[0];
  $("routingName").textContent = preset.name;

  if (s.error && s.status === "stopped" && $("banner").classList.contains("hidden")) {
    showBanner(s.error);
  }
  if (s.status === "connected") $("banner").classList.add("hidden");
}

// --- servers ---------------------------------------------------------------------------

$("importBtn").addEventListener("click", (e) => busy(e.target, async () => {
  const text = $("importText").value.trim();
  if (!text) return;
  const r = await api("import", { text });
  $("importText").value = "";
  toast("Добавлено серверов: " + r.added);
  await refresh();
}));

$("pasteBtn").addEventListener("click", async () => {
  try {
    $("importText").value = await navigator.clipboard.readText();
  } catch {
    $("importText").focus();
    toast("Вставьте ссылку в поле (Ctrl+V)");
  }
});

$("pingBtn").addEventListener("click", (e) => busy(e.target, async () => {
  await api("ping", {});
  await refresh();
}));

$("refreshSubsBtn").addEventListener("click", (e) => busy(e.target, async () => {
  const r = await api("subscription/refresh", { id: "" });
  toast("Серверов в подписках: " + r.profiles);
  await refresh();
}));

function serverRow(p) {
  const selected = p.id === state.data.selected;
  const row = el("div", { class: "srv" + (selected ? " selected" : ""), role: "button", tabindex: "0" },
    el("span", { class: "radio" }),
    el("div", { class: "server-main" },
      el("div", { class: "server-name" }, p.name),
      el("div", { class: "server-host" }, p.server)),
    pingBadge(state.pings[p.id]),
    el("button", { class: "icon-btn", title: "Скопировать ссылку", onclick: async (e) => {
      e.stopPropagation();
      try {
        const r = await api("profile/share", { id: p.id });
        await navigator.clipboard.writeText(r.link);
        toast("Ссылка скопирована");
      } catch (err) { handleError(err); }
    } }, "⧉"),
    p.subId ? null : el("button", { class: "icon-btn", title: "Удалить", onclick: async (e) => {
      e.stopPropagation();
      if (!confirm(`Удалить сервер «${p.name}»?`)) return;
      await api("profile/delete", { id: p.id }).catch(handleError);
      refresh();
    } }, "✕"));
  row.addEventListener("click", async () => {
    try { await api("select", { id: p.id }); } catch (e) { handleError(e); }
    refresh();
  });
  return row;
}

function renderServers() {
  const list = $("serverList");
  const profiles = state.data.profiles || [];
  const subs = state.data.subscriptions || [];
  const nodes = [];
  const own = profiles.filter((p) => !p.subId);
  if (own.length) {
    nodes.push(el("div", { class: "group-head" }, el("span", { class: "title" }, "Мои серверы")));
    own.forEach((p) => nodes.push(serverRow(p)));
  }
  for (const sub of subs) {
    const meta = sub.error ? el("span", { class: "meta err" }, "ошибка: " + sub.error) : el("span", { class: "meta" }, "обновлено " + ago(sub.updated));
    nodes.push(el("div", { class: "group-head" },
      el("div", {}, el("div", { class: "title" }, sub.name || "Подписка"), meta),
      el("div", { class: "group-actions" },
        el("button", { class: "icon-btn", title: "Обновить", onclick: (e) => busy(e.target, async () => { await api("subscription/refresh", { id: sub.id }); await refresh(); }) }, "⟳"),
        el("button", { class: "icon-btn", title: "Удалить подписку", onclick: async () => {
          if (!confirm(`Удалить подписку «${sub.name}» и её серверы?`)) return;
          await api("subscription/delete", { id: sub.id }).catch(handleError);
          refresh();
        } }, "✕"))));
    profiles.filter((p) => p.subId === sub.id).forEach((p) => nodes.push(serverRow(p)));
  }
  if (!nodes.length) nodes.push(el("div", { class: "empty" }, "Серверов пока нет. Вставьте ссылку cypher:// или адрес подписки выше."));
  list.replaceChildren(...nodes);
}

// --- settings ----------------------------------------------------------------------------

let draft = null;

function fillSettings() {
  draft = structuredClone(state.data.settings);
  renderPresets();
  $("customRules").value = JSON.stringify(draft.customRules || [], null, 2);
  $("sysProxy").checked = draft.systemProxy;
  $("fingerprint").value = draft.fingerprint || "";
  $("socksPort").value = draft.socksPort;
  $("httpPort").value = draft.httpPort;
  $("geoAuto").checked = draft.geoAuto;
  $("geositeUrl").value = draft.geositeUrl;
  $("geoipUrl").value = draft.geoipUrl;
  $("autostart").checked = draft.autostart;
  $("autoConnect").checked = draft.autoConnect;
  $("logLevel").value = draft.logLevel || "info";
  $("geoUpdated").textContent = state.haveGeo ? "Обновлено " + ago(draft.geoUpdated) : "Ещё не загружены";
  $("about").textContent = `cypher ${info.version} · данные: ${info.dataDir}`;
  settingsDirty = false;
}

function renderPresets() {
  $("presetList").replaceChildren(...info.presets.map((p) => {
    const n = el("div", { class: "preset" + (p.id === draft.routing ? " selected" : ""), role: "radio" },
      el("span", { class: "radio" }),
      el("div", {}, el("b", {}, p.name), el("small", {}, p.description)));
    n.addEventListener("click", () => { draft.routing = p.id; settingsDirty = true; renderPresets(); });
    return n;
  }));
  $("customBox").classList.toggle("hidden", draft.routing !== "custom");
}

document.querySelectorAll("#view-settings input, #view-settings select, #view-settings textarea")
  .forEach((i) => i.addEventListener("input", () => { settingsDirty = true; }));

$("saveBtn").addEventListener("click", (e) => busy(e.target, async () => {
  const s = draft;
  if (s.routing === "custom") {
    try { s.customRules = JSON.parse($("customRules").value || "[]"); }
    catch (err) { throw new Error("Ошибка в JSON правил: " + err.message); }
  }
  s.systemProxy = $("sysProxy").checked;
  s.fingerprint = $("fingerprint").value;
  s.socksPort = Number($("socksPort").value);
  s.httpPort = Number($("httpPort").value);
  s.geoAuto = $("geoAuto").checked;
  s.geositeUrl = $("geositeUrl").value.trim();
  s.geoipUrl = $("geoipUrl").value.trim();
  s.autostart = $("autostart").checked;
  s.autoConnect = $("autoConnect").checked;
  s.logLevel = $("logLevel").value;
  s.mode = state.data.settings.mode;
  await api("settings", s);
  settingsDirty = false;
  toast(state.status === "connected" ? "Сохранено, переподключаюсь" : "Сохранено");
  await refresh();
  fillSettings();
}));

$("geoBtn").addEventListener("click", (e) => busy(e.target, async () => {
  toast("Загружаю базы…");
  await api("geo/update", {});
  toast("Базы обновлены");
  await refresh();
  if (!settingsDirty) fillSettings();
}));

// --- logs -----------------------------------------------------------------------------------

async function pollLogs(force) {
  if (!force && !$("view-logs").classList.contains("active")) return;
  const r = await api("logs?from=" + logNext).catch(() => null);
  if (!r || !r.lines || !r.lines.length) return;
  logNext = r.next;
  const box = $("logBox");
  const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
  for (const line of r.lines) {
    const m = line.match(/level=(\w+)/);
    box.append(el("div", { class: m ? "lv-" + m[1] : "" }, line.replace(/^time=\S+ /, "")));
  }
  while (box.childNodes.length > 1500) box.firstChild.remove();
  if (atBottom) box.scrollTop = box.scrollHeight;
}

$("copyLogs").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("logBox").innerText).catch(() => {});
  toast("Логи скопированы");
});

// --- loop -------------------------------------------------------------------------------------

async function refresh() {
  try {
    state = await api("state");
  } catch (e) {
    return;
  }
  renderHome();
  renderServers();
}

async function main() {
  info = await api("info");
  await refresh();
  setInterval(refresh, 1000);
  setInterval(pollLogs, 1000);
}
main().catch((e) => toast(e.message, true));
