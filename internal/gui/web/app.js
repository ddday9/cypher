"use strict";

const token = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
let info = null;
let state = null;
let settingsDirty = false;
let prevTraffic = null;
let logNext = 0;

// --- API ---------------------------------------------------------------------

// Android: the page talks to nevio through a JavaScript bridge, in process
// (there is no local HTTP server another app could find).
const bridge = window.NevioAndroid;
let bridgeSeq = 0;
const bridgePending = {};
window.__nevioReply = (id, json) => {
  const done = bridgePending[id];
  delete bridgePending[id];
  if (done) done(json);
};
function bridgeCall(method, path, body) {
  return new Promise((resolve) => {
    const id = ++bridgeSeq;
    bridgePending[id] = resolve;
    bridge.call(id, method, path, body);
  });
}

async function copyText(text) {
  if (bridge) { bridge.copy(text); return; }
  await navigator.clipboard.writeText(text);
}
async function pasteText() {
  if (bridge) return bridge.paste();
  return navigator.clipboard.readText();
}

async function api(path, body) {
  if (bridge) {
    const env = JSON.parse(await bridgeCall(body === undefined ? "GET" : "POST", "/api/" + path, body === undefined ? "" : JSON.stringify(body)));
    if (env.status >= 400) {
      const e = new Error((env.body && env.body.error) || "ошибка " + env.status);
      e.code = env.body && env.body.code;
      throw e;
    }
    return env.body;
  }
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
    showBanner("Для режима «Весь трафик» нужны права администратора. Перезапустить nevio с правами?", true);
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
  $("afBadge").classList.toggle("hidden", !(s.status === "connected" && s.antiFreeze));
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
  chip.textContent = s.status === "connected" ? (s.mode === "tun" ? (info.mobile ? "VPN" : "TUN") : "Прокси") : "выключено";
  if (info.mobile) renderProxyCard(set);
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

// --- Android ---------------------------------------------------------------------------

function proxyLink(set) {
  const q = new URLSearchParams({ server: "127.0.0.1", port: String(set.proxyPort), user: set.proxyUser, pass: set.proxyPass });
  return "tg://socks?" + q.toString();
}

function renderProxyCard(set) {
  const show = set.mode !== "tun";
  $("proxyCard").classList.toggle("hidden", !show);
  if (!show) return;
  $("proxyAddr").textContent = `127.0.0.1:${set.proxyPort} · логин ${set.proxyUser} · пароль ${set.proxyPass}`;
  $("proxyTg").href = proxyLink(set);
}

$("proxyCopy").addEventListener("click", async () => {
  const set = state.data.settings;
  await copyText(`socks5://${set.proxyUser}:${set.proxyPass}@127.0.0.1:${set.proxyPort}`).catch(() => {});
  toast("Адрес прокси скопирован");
});

$("ruAppsShow").addEventListener("click", (e) => {
  e.preventDefault();
  const box = $("ruAppsList");
  box.textContent = info.russianApps.join(", ");
  box.classList.toggle("hidden");
});

let appLabels = {};
async function loadAppLabels() {
  const apps = await api("processes").catch(() => []);
  appLabels = Object.fromEntries(apps.map((a) => [a.name, a.label || a.name]));
  return apps;
}

function setupMobile() {
  document.body.classList.add("mobile");
  for (const id of ["sysProxy", "socksPort", "httpPort", "autostart"]) {
    const item = $(id).closest(".item");
    if (item) item.classList.add("hidden");
  }
  $("stealthBox").classList.remove("hidden");
  document.querySelector('.seg[data-mode="proxy"]').textContent = "Прокси (без VPN)";
  document.querySelector('.seg[data-mode="tun"]').textContent = "VPN";
  $("appsHint").textContent = "«Мимо VPN» — приложение не видит VPN и ходит в интернет напрямую. Добавьте сюда банки и госприложения, которых нет в списке выше.";
  $("pickerSearch").placeholder = "Поиск по названию или имени пакета";
  if (bridge) {
    $("disguise").value = bridge.icon();
    $("disguise").addEventListener("change", () => {
      bridge.setIcon($("disguise").value);
      toast("Значок изменён");
    });
  }
  loadAppLabels();
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
    $("importText").value = await pasteText();
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
      el("div", { class: "server-host" }, p.server + (p.exitKey && p.exitPublicKey ? " · через ретранслятор, сквозное шифрование" : ""))),
    pingBadge(state.pings[p.id]),
    el("button", { class: "icon-btn", title: "Скопировать ссылку", onclick: async (e) => {
      e.stopPropagation();
      try {
        const r = await api("profile/share", { id: p.id });
        await copyText(r.link);
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

const RULE_TYPES = [
  ["domain", "Домен", "example.com (и поддомены)"],
  ["geosite", "geosite", "google, youtube, category-ru"],
  ["ip", "IP / сеть", "1.2.3.4, 10.0.0.0/8"],
  ["geoip", "geoip", "ru, private, telegram"],
  ["port", "Порт", "443, 27015-27030"],
  ["keyword", "Слово в домене", "torrent"],
  ["full", "Точный домен", "www.example.com"],
];
const ACTIONS = [["proxy", "Через VPN"], ["direct", "Напрямую"], ["block", "Блокировать"]];
const ACTIONS_SHORT = [["proxy", "VPN"], ["direct", "Напрямую"], ["block", "Блок"]];

function select(options, value, onchange) {
  const sel = el("select", {});
  for (const [v, label] of options) {
    const o = el("option", { value: v }, label);
    if (v === value) o.selected = true;
    sel.append(o);
  }
  sel.addEventListener("change", () => { onchange(sel.value); settingsDirty = true; });
  return sel;
}

function fillSettings() {
  draft = structuredClone(state.data.settings);
  draft.userRules = draft.userRules || [];
  renderPresets();
  renderApps();
  renderRules();
  $("customRules").value = (draft.customRules && draft.customRules.length) ? JSON.stringify(draft.customRules, null, 2) : "";
  $("defaultAction").value = draft.defaultAction || "proxy";
  $("sysProxy").checked = draft.systemProxy;
  $("fingerprint").value = draft.fingerprint === "firefox" ? "" : (draft.fingerprint || "");
  $("antiFreeze").value = draft.antiFreeze || "";
  $("connMode").value = draft.single ? "single" : "";
  $("antiFreezeRate").value = String([20, 1000].includes(draft.antiFreezeRate) ? draft.antiFreezeRate : 0);
  $("socksPort").value = draft.socksPort;
  $("httpPort").value = draft.httpPort;
  renderGeo();
  $("autostart").checked = draft.autostart;
  $("autoConnect").checked = draft.autoConnect;
  $("logLevel").value = draft.logLevel || "info";
  if (info.mobile) {
    $("hideRuApps").checked = !!draft.hideRuApps;
    $("appScope").value = draft.appScope || "";
    $("proxyPort").value = draft.proxyPort;
  }
  $("about").textContent = `nevio ${info.version} · протокол cypher · данные: ${info.dataDir}`;
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
  $("defaultBox").classList.toggle("hidden", draft.routing !== "custom");
}

const APP_ACTIONS_MOBILE = [["direct", "Мимо VPN"], ["proxy", "Через VPN"]];

function renderApps() {
  const apps = draft.userRules.map((r, i) => [r, i]).filter(([r]) => r.type === "process");
  if (!apps.length) {
    $("appList").replaceChildren(el("div", { class: "empty-row" }, info.mobile
      ? "Например, банк — «Мимо VPN»: он не увидит VPN."
      : "Например, dota2.exe — напрямую, чтобы игра шла без VPN."));
    return;
  }
  $("appList").replaceChildren(...apps.map(([r, i]) => el("div", { class: "app" },
    el("span", { class: "app-icon" }, ((appLabels[r.value] || r.value)[0] || "?")),
    el("span", { class: "app-name", title: r.value }, appLabels[r.value] || r.value),
    select(info.mobile ? APP_ACTIONS_MOBILE : ACTIONS, r.action, (v) => { r.action = v; }),
    el("button", { class: "icon-btn", title: "Убрать", onclick: () => { draft.userRules.splice(i, 1); settingsDirty = true; renderApps(); } }, "✕"))));
}

function renderRules() {
  const rules = draft.userRules.map((r, i) => [r, i]).filter(([r]) => r.type !== "process");
  if (!rules.length) {
    $("ruleList").replaceChildren(el("div", { class: "empty-row" }, "Правил пока нет."));
    return;
  }
  $("ruleList").replaceChildren(...rules.map(([r, i]) => {
    const type = RULE_TYPES.find((t) => t[0] === r.type) || RULE_TYPES[0];
    const input = el("input", { type: "text", value: r.value, placeholder: type[2], spellcheck: "false" });
    input.addEventListener("input", () => { r.value = input.value; settingsDirty = true; });
    return el("div", { class: "rule" },
      select(RULE_TYPES.map((t) => [t[0], t[1]]), r.type, (v) => { r.type = v; renderRules(); }),
      input,
      select(ACTIONS_SHORT, r.action, (v) => { r.action = v; }),
      el("button", { class: "icon-btn", title: "Удалить", onclick: () => { draft.userRules.splice(i, 1); settingsDirty = true; renderRules(); } }, "✕"));
  }));
}

$("addRuleBtn").addEventListener("click", () => {
  draft.userRules.push({ type: "domain", value: "", action: "direct" });
  settingsDirty = true;
  renderRules();
  const inputs = $("ruleList").querySelectorAll("input");
  if (inputs.length) inputs[inputs.length - 1].focus();
});

// Application picker.
let processes = [];
function addApp(name) {
  name = name.trim();
  if (!name) return;
  if (!draft.userRules.some((r) => r.type === "process" && r.value.toLowerCase() === name.toLowerCase())) {
    draft.userRules.push({ type: "process", value: name, action: "direct" });
    settingsDirty = true;
  }
  renderApps();
  $("picker").classList.add("hidden");
}
function renderPicker() {
  const q = $("pickerSearch").value.trim().toLowerCase();
  const list = processes.filter((p) => !q || p.name.toLowerCase().includes(q) || (p.label || "").toLowerCase().includes(q)).slice(0, 300);
  $("pickerList").replaceChildren(...(list.length ? list.map((p) => el("div", { class: "pick", onclick: () => addApp(p.name) },
    el("span", { class: "app-icon" }, (p.label || p.name)[0] || "?"),
    el("span", {}, p.label || p.name, p.label ? el("small", {}, " " + p.name) : "")))
    : [el("div", { class: "empty-row" }, info.mobile ? "Не найдено — добавьте по имени пакета." : "Не найдено среди запущенных — добавьте по имени файла.")]));
}
$("addAppBtn").addEventListener("click", async () => {
  $("pickerSearch").value = "";
  $("picker").classList.remove("hidden");
  $("pickerSearch").focus();
  processes = info.mobile ? await loadAppLabels() : await api("processes").catch(() => []);
  renderPicker();
});
$("pickerSearch").addEventListener("input", renderPicker);
$("pickerSearch").addEventListener("keydown", (e) => { if (e.key === "Enter") addApp($("pickerSearch").value); });
$("pickerManual").addEventListener("click", () => addApp($("pickerSearch").value));
$("pickerClose").addEventListener("click", () => $("picker").classList.add("hidden"));
$("picker").addEventListener("click", (e) => { if (e.target.id === "picker") $("picker").classList.add("hidden"); });

function renderGeo() {
  const sel = $("geoSource");
  sel.replaceChildren(...info.geoSources.map((g) => el("option", { value: g.id }, g.name)), el("option", { value: "custom" }, "Свои ссылки"));
  sel.value = draft.geoSource || "custom";
  const showCustom = () => {
    const g = info.geoSources.find((x) => x.id === sel.value);
    $("geoNote").textContent = g ? g.note : "любые файлы в формате Xray";
    $("geoCustom").classList.toggle("hidden", !!g);
  };
  sel.onchange = () => { draft.geoSource = sel.value; settingsDirty = true; showCustom(); };
  showCustom();
  $("geositeUrl").value = draft.geositeUrl;
  $("geoipUrl").value = draft.geoipUrl;
  $("geoInterval").value = String(draft.geoAuto ? (draft.geoIntervalHours || 24) : 0);
  $("geoUpdated").textContent = state.haveGeo ? "обновлено " + ago(draft.geoUpdated) : "ещё не загружены";
}

document.querySelectorAll("#view-settings input, #view-settings select, #view-settings textarea")
  .forEach((i) => i.addEventListener("input", () => { settingsDirty = true; }));

$("saveBtn").addEventListener("click", (e) => busy(e.target, async () => {
  const s = draft;
  const json = $("customRules").value.trim();
  try { s.customRules = json ? JSON.parse(json) : []; }
  catch (err) { throw new Error("Ошибка в JSON расширенных правил: " + err.message); }
  s.userRules = s.userRules.filter((r) => r.value.trim() !== "");
  s.defaultAction = $("defaultAction").value;
  s.systemProxy = $("sysProxy").checked;
  s.fingerprint = $("fingerprint").value;
  s.antiFreeze = $("antiFreeze").value;
  s.single = $("connMode").value === "single";
  s.antiFreezeRate = Number($("antiFreezeRate").value);
  s.socksPort = Number($("socksPort").value);
  s.httpPort = Number($("httpPort").value);
  s.geoSource = $("geoSource").value;
  s.geositeUrl = $("geositeUrl").value.trim();
  s.geoipUrl = $("geoipUrl").value.trim();
  const hours = Number($("geoInterval").value);
  s.geoAuto = hours > 0;
  if (hours > 0) s.geoIntervalHours = hours;
  s.autostart = $("autostart").checked;
  s.autoConnect = $("autoConnect").checked;
  s.logLevel = $("logLevel").value;
  s.mode = state.data.settings.mode;
  if (info.mobile) {
    s.hideRuApps = $("hideRuApps").checked;
    s.appScope = $("appScope").value;
    s.proxyPort = Number($("proxyPort").value);
  }
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
  await copyText($("logBox").innerText).catch(() => {});
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
  if (info.mobile) setupMobile();
  await refresh();
  setInterval(refresh, 1000);
  setInterval(pollLogs, 1000);
}
main().catch((e) => toast(e.message, true));
