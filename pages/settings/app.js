"use strict";

const $ = (id) => document.getElementById(id);
const all = (selector) => [...document.querySelectorAll(selector)];
const bridge = window.AstrBotPluginPage;
const labels = {
  sentry: "静默加固", aegis: "复核确认", scorch: "内容替换", intercept: "立即阻断",
  active: "主动复核", standby: "按风险复核", disabled: "关闭",
  graded: "分级处理", strict: "严格阻断",
  allow: "放行", harden: "加固", replace: "替换", block: "阻断",
  ban: "新增封禁", review_failure: "复核失败",
  blacklist: "黑名单", whitelist: "白名单",
  not_requested: "未请求", skipped: "跳过", safe: "判定安全", confirmed: "确认注入",
  failed: "失败", unavailable: "不可用",
  prompt: "本轮输入", extra_text: "本轮额外文本", extra_user_content_parts: "本轮额外文本",
  manual: "手动", automatic: "自动", legacy: "旧版迁移",
  response: "模型响应", requested: "请求中指定", provider_default: "Provider 配置",
  no_evidence: "未发现可疑证据", rule_evidence: "规则命中",
  review_confirmed: "复核确认注入", review_safe: "复核判定安全",
  inspection_incomplete: "检查未完成",
  replacement_unavailable: "无法完整隔离风险输入", review_pending: "需要模型复核", exempt: "名单豁免",
};
const reviewKeys = new Set([
  "llm_analysis_mode", "review_provider", "review_model", "llm_analysis_private_chat_enabled",
  "review_failure_policy", "review_timeout_seconds", "review_max_concurrency", "review_max_chars",
]);
const advancedKeys = new Set([
  "scan_extra_text", "detect_encoded", "anti_harassment_enabled", "incident_history_size", "persona_sensitivity",
  "review_timeout_seconds", "review_max_concurrency", "review_max_chars",
]);
const fieldHelp = {
  defense_mode: {
    sentry: "检测到风险时加固，继续对话；不发起复核。",
    aegis: "可疑内容需复核。判定安全时放行，确认注入后加固。",
    scorch: "替换风险输入；无法完整隔离时阻断本轮。",
    intercept: "阻断本轮主请求。",
  },
  auto_blacklist: "仅对已确认且实际替换或阻断的技术注入生效。",
  blacklist_duration: "0 表示永久。",
  gentle_refusal: "仅在因注入风险阻断时生成一句拒绝，可能产生模型费用。不会发送被拦截的消息。",
  review_failure_policy: {
    graded: "可疑证据需要完成复核，失败则阻断；主动复核故障可放行普通请求。",
    strict: "凡是需要复核，失败即阻断；故障不处罚。",
  },
};
let snapshot = null;
let draft = {};
let tab = "overview";
let saving = false;
let configLoading = false;
let conflicted = false;
let overview = null;
let entries = null;
let records = null;
let adopt = null;
let visibleRecords = [];
let recordLimit = 50;
let providerChoices = null;
let modelChoices = new Map();
const pickerKeys = new Set(["review_provider", "review_model", "refusal_provider", "refusal_model"]);
const versions = {};
const get = (path) => bridge.apiGet(path);
const post = (path, body) => bridge.apiPost(path, body);
const label = (value) => Object.hasOwn(labels, value) ? labels[value] : value;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}

function message(id, text, error = false) {
  const target = $(id);
  target.textContent = text;
  target.dataset.error = String(error);
  target.hidden = !text;
}

function button(text, action, className) {
  const element = node("button", text, className);
  element.type = "button";
  element.addEventListener("click", action);
  return element;
}

function confirmAction(text) {
  const dialog = $("confirm-dialog");
  if (dialog.open) return Promise.resolve(false);
  const focus = document.activeElement;
  $("confirm-message").textContent = text;
  dialog.returnValue = "cancel";
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      if (focus?.isConnected) focus.focus();
      resolve(dialog.returnValue === "accept");
    }, { once: true });
    dialog.showModal();
  });
}

function changes() {
  return snapshot ? Object.fromEntries(
    Object.entries(draft).filter(([key, value]) => value !== snapshot.config[key]),
  ) : {};
}

function isDirty() {
  return Object.keys(changes()).length > 0;
}

function saveState(text, error = false) {
  message("save-state", text, error);
  $("save").disabled = saving || configLoading || conflicted || !isDirty();
  $("reload-config").hidden = !conflicted || configLoading;
}

function baseStatus() {
  if (snapshot?.apply_status === "reload_required") return "配置已保存，重载插件后应用。";
  if (snapshot?.apply_status === "apply_failed") return "配置已保存，但未应用；请检查插件状态。";
  return "当前设置已生效";
}

function formatTime(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) return "—";
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.valueOf()) ? "—" : date.toLocaleString("zh-CN", { hour12: false });
}

function displayPairs(target, pairs) {
  target.replaceChildren(...pairs.map(([title, value]) => {
    const item = node("div");
    item.append(node("dt", title), node("dd", value ?? "—"));
    return item;
  }));
}

function renderOverview() {
  const effective = overview.effective;
  const until = overview.observation_until;
  const observing = typeof until === "number" && until * 1000 > Date.now();
  displayPairs($("effective"), [
    ["防护", effective.enabled ? "已启用" : "已关闭"],
    ["生效模式", label(effective.defense_mode)],
    ["复核触发", !effective.enabled || effective.defense_mode === "sentry" ? "不调用" : label(effective.llm_analysis_mode)],
    ["私聊复核", effective.llm_analysis_private_chat_enabled ? "允许" : "关闭"],
    ["复核 Provider", effective.review_provider || "跟随会话"],
    ["复核模型", effective.review_model || "使用 Provider 配置"],
    ["临时观察", observing ? `至 ${formatTime(until)}` : "未开启"],
  ]);
  displayPairs($("statistics"), ["allow", "harden", "replace", "block", "ban", "review_failure"].map(
    (key) => [label(key), overview.stats[key]],
  ));
  $("observation-status").textContent = observing ? `观察至 ${formatTime(until)}` : "未开启";
  $("observation-stop").disabled = !observing;
  $("sample-provider").textContent = effective.review_provider
    ? `当前复核 Provider：${effective.review_provider}`
    : "未配置复核 Provider，暂不可试算。";
}

function optionsFor(control, items, current, missing) {
  control.replaceChildren(...items.map(([value, text]) => new Option(text, value)));
  if (current && !items.some(([value]) => value === current)) {
    control.add(new Option(`${current}（${missing}）`, current));
  }
  control.value = current;
}

function updatePickers() {
  for (const prefix of ["review", "refusal"]) {
    const p = $(`field-${prefix}_provider`), m = $(`field-${prefix}_model`);
    if (!p || !m) continue;
    const id = draft[`${prefix}_provider`], current = draft[`${prefix}_model`];
    const off = prefix === "refusal" && !draft.gentle_refusal;
    const providers = providerChoices || [];
    const found = providers.find((entry) => entry.id === id);
    optionsFor(p, [["", "跟随会话"], ...providers.map((entry) => [entry.id, entry.id])], id,
      providerChoices ? "当前不可用" : "已保存");
    p.disabled = saving || configLoading || off;
    const state = modelChoices.get(id);
    const names = [...new Set([found?.model, ...(state?.names || [])].filter(Boolean))];
    const defaultText = id ? (found?.model ? `提供商默认（${found.model}）` : "提供商默认")
      : prefix === "refusal" ? "跟随会话模型" : "会话提供商的默认模型";
    optionsFor(m, [["", defaultText], ...names.map((name) => [name, name])], current,
      state?.status === "ready" ? "未列出" : "已保存");
    // Keep a legacy session-wide override clearable, even without an explicit provider.
    m.disabled = saving || configLoading || off || (!id && !current);
    $(`help-${prefix}_provider`).textContent = providerChoices === null ? "提供商列表未载入，可刷新重试。"
      : !providers.length ? "尚无可用的对话提供商。" : "";
    $(`help-${prefix}_model`).textContent = !id ? "指定提供商后可选其他模型。"
      : state?.status === "loading" ? "正在获取模型…"
      : state?.status === "error" ? "模型列表未能载入，可使用默认模型或刷新重试。" : "";
  }
}

async function loadVisibleModels() {
  for (const prefix of ["review", "refusal"]) {
    if (tab !== (prefix === "review" ? "review" : "defense") || (prefix === "refusal" && !draft.gentle_refusal)) continue;
    const id = draft[`${prefix}_provider`];
    const cache = modelChoices;
    if (!id || !providerChoices?.some((item) => item.id === id) || cache.has(id)) continue;
    cache.set(id, {status: "loading"});
    updatePickers();
    try {
      const names = await post("models", {provider: id});
      if (!Array.isArray(names)) throw new Error("Invalid list");
      cache.set(id, {status: "ready", names});
    } catch {
      cache.set(id, {status: "error"});
    }
    if (cache === modelChoices) updatePickers();
  }
}

function renderSettings() {
  for (const id of ["defense-fields", "defense-advanced", "review-fields", "review-advanced"]) $(id).replaceChildren();
  for (const [key, spec] of Object.entries(snapshot.fields)) {
    let control;
    if (pickerKeys.has(key)) {
      control = node("select");
    } else if (Array.isArray(spec.options)) {
      control = node("select");
      for (const option of spec.options) {
        const item = node("option", label(option));
        item.value = option;
        control.add(item);
      }
    } else {
      control = node("input");
      control.type = { bool: "checkbox", int: "number", float: "number", string: "text" }[spec.type];
      if (spec.bounds) [control.min, control.max] = spec.bounds;
      if (spec.type === "float") control.step = "any";
      if (spec.type === "string") control.maxLength = 256;
    }
    control.id = `field-${key}`;
    if (spec.type === "bool") control.checked = draft[key] === true;
    else control.value = draft[key];
    const row = node("label", null, "field");
    const title = node("span", spec.description);
    const help = node("small");
    help.id = `help-${key}`;
    function updateHelp() {
      const text = fieldHelp[key];
      help.textContent = (typeof text === "object" ? text[draft[key]] : text) || "";
    }
    updateHelp();
    if (fieldHelp[key] || pickerKeys.has(key)) title.append(help);
    row.append(title, control);
    const section = reviewKeys.has(key) ? "review" : "defense";
    $(`${section}-${advancedKeys.has(key) ? "advanced" : "fields"}`).append(row);
    control.addEventListener("input", () => {
      draft[key] = spec.type === "bool" ? control.checked
        : ["int", "float"].includes(spec.type) ? (Number.isFinite(control.valueAsNumber) ? control.valueAsNumber : null)
          : control.value;
      if (key === "review_provider" || key === "refusal_provider") {
        draft[key.replace("_provider", "_model")] = "";
      }
      updateHelp();
      if (pickerKeys.has(key) || key === "gentle_refusal") {
        updatePickers();
        void loadVisibleModels();
      }
      if (!saving && !conflicted) saveState(isDirty() ? "有未保存的更改" : baseStatus());
    });
  }
  updatePickers();
}

async function loadSettings(discard = false) {
  if (saving || configLoading) return;
  if (discard && isDirty() && !await confirmAction("放弃未保存的更改并载入最新设置？")) return;
  configLoading = true;
  for (const input of all("[id^=field-]")) input.disabled = true;
  saveState("正在载入设置…");
  try {
    const [latest, choices] = await Promise.all([get("settings"), get("providers").catch(() => null)]);
    if (!latest?.revision || !latest.config || !latest.fields) throw new Error("设置响应不完整");
    snapshot = latest;
    providerChoices = Array.isArray(choices) ? choices : null;
    modelChoices = new Map();
    draft = { ...snapshot.config };
    conflicted = false;
    renderSettings();
    $("workspace").hidden = false;
    message("connection", "");
  } catch {
    if (!snapshot) message("connection", "无法载入设置。请检查 Dashboard 登录状态后刷新。", true);
    else {
      configLoading = false;
      saveState("载入失败，未更改当前草稿。", true);
    }
    return;
  } finally {
    configLoading = false;
    for (const input of all("[id^=field-]")) input.disabled = false;
    updatePickers();
    void loadVisibleModels();
  }
  saveState(baseStatus(), snapshot.apply_status === "apply_failed");
}

async function save() {
  if (!snapshot || saving || configLoading || conflicted || !isDirty()) return;
  const patch = changes();
  for (const key of Object.keys(patch)) {
    const input = $(`field-${key}`);
    if (!input.validity.valid || patch[key] === null) {
      showTab(reviewKeys.has(key) ? "review" : "defense");
      const details = input.closest("details");
      if (details) details.open = true;
      input.focus();
      saveState(`请检查：${snapshot.fields[key].description}`, true);
      return;
    }
  }
  saving = true;
  for (const field of all("[id^=field-]")) field.disabled = true;
  saveState("正在保存并应用…");
  let status = "保存未确认。请先载入最新设置，再决定是否重试。";
  let error = true;
  try {
    const result = await post("settings/save", { revision: snapshot.revision, patch });
    if (result.status === "conflict") {
      conflicted = true;
      status = "配置已在别处更新；草稿保留，未覆盖现有设置。";
    } else if (result.status === "applied" || result.status === "reload_required") {
      snapshot = result;
      draft = { ...snapshot.config };
      renderSettings();
      status = result.status === "applied" ? "已保存并生效" : "已保存，重载插件后生效。";
      error = false;
      void fetchData("overview");
    } else if (result.status === "save_failed") {
      status = "保存失败，已保留草稿。";
    } else if (result.status === "apply_failed") {
      conflicted = true;
      status = "配置已保存，但应用失败。请检查插件状态并载入最新设置。";
    } else {
      conflicted = true;
    }
  } catch {
    conflicted = true;
  } finally {
    for (const field of all("[id^=field-]")) field.disabled = false;
    saving = false;
    updatePickers();
    void loadVisibleModels();
    saveState(status, error);
  }
}

function showTab(next) {
  tab = next;
  void loadVisibleModels();
  all("[data-panel]").forEach((panel) => { panel.hidden = panel.dataset.panel !== tab; });
  all("[data-tab]").forEach((item) => {
    if (item.dataset.tab === tab) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  if (["overview", "defense", "entries", "records"].includes(tab)) {
    void fetchData(tab === "defense" ? "overview" : tab);
  }
}

function searchSettings() {
  const term = $("settings-search").value.trim().toLowerCase();
  const results = $("search-results");
  results.replaceChildren();
  results.hidden = !term;
  if (!term || !snapshot) return;
  for (const [key, field] of Object.entries(snapshot.fields)) {
    const words = [key, field.description, ...(field.options || []).map(label)].join(" ").toLowerCase();
    if (!words.includes(term)) continue;
    results.append(button(field.description, () => {
      showTab(reviewKeys.has(key) ? "review" : "defense");
      const input = $(`field-${key}`);
      const details = input.closest("details");
      if (details) details.open = true;
      $("settings-search").value = "";
      results.hidden = true;
      input.focus();
    }));
  }
  if (!results.children.length) results.append(node("small", "没有匹配的设置"));
}

function formFields(form) {
  return Object.fromEntries(new FormData(form).entries());
}

async function operation(scope, trigger, work) {
  if (trigger.disabled || pendingOperations.has(scope)) return;
  pendingOperations.add(scope);
  trigger.disabled = true;
  message(`${scope}-message`, "正在处理…");
  try {
    await work();
  } catch {
    message(`${scope}-message`, "操作未完成或结果未确认。请刷新核对后再重试。", true);
  } finally {
    pendingOperations.delete(scope);
    trigger.disabled = false;
  }
}
const pendingOperations = new Set();

async function setObservation(trigger, minutes) {
  await operation("observation", trigger, async () => {
    await post("observation", { minutes });
    const refreshed = await fetchData("overview");
    message("observation-message", refreshed
      ? (minutes ? "已开启临时观察。" : "已结束观察。")
      : "观察状态已更新，但未能刷新显示。", !refreshed);
  });
  if (overview) renderOverview();
}

function expiry(entry) {
  if (entry.expires_at == null) return "永久";
  const seconds = Math.ceil(entry.expires_at - Date.now() / 1000);
  if (!Number.isFinite(seconds)) return "—";
  return seconds <= 0 ? "已到期" : `${Math.ceil(seconds / 60)} 分钟 · 至 ${formatTime(entry.expires_at)}`;
}

function fillTable(id, headers, rows, empty) {
  const target = $(id);
  target.replaceChildren();
  if (!rows.length) {
    target.append(node("p", empty, "muted"));
    return;
  }
  const table = node("table");
  const header = table.createTHead().insertRow();
  for (const title of headers) {
    const th = node("th", title);
    th.scope = "col";
    header.append(th);
  }
  const body = table.createTBody();
  for (const row of rows) {
    const tr = body.insertRow();
    for (const cell of row) {
      const td = tr.insertCell();
      if (cell instanceof Node) td.append(cell);
      else td.textContent = cell ?? "—";
    }
  }
  target.append(table);
}

function entryIdentity(row) {
  return { kind: row.kind, user: row.user, platform: row.platform, instance: row.instance, session: row.session };
}

async function changeEntry(trigger, action, entry, onSuccess) {
  await operation("entry", trigger, async () => {
    const result = await post("entries/update", { action, entry });
    if (result.updated !== true) throw new Error("No list update");
    if (onSuccess) onSuccess();
    const refreshed = await fetchData("entries");
    message("entry-message", refreshed ? "名单已更新。" : "名单已更新，但未能刷新显示。", !refreshed);
  });
}

function renderEntries() {
  const kind = $("entry-filter").value;
  const term = $("entry-search").value.trim().toLowerCase();
  const filter = (entry) => (!kind || entry.kind === kind) && (!term || [
    entry.platform, entry.instance, entry.user, entry.session, entry.reason,
  ].some((value) => String(value ?? "").toLowerCase().includes(term)));
  fillTable("entry-list", ["名单 / 用户", "平台 / 实例", "会话", "有效期", "原因 / 来源", "操作"],
    entries.entries.map((row) => ({ ...row, ...row.identity })).filter(filter).map((row) => [
      `${label(row.kind)} · ${row.user}`, `${row.platform} / ${row.instance}`, row.session || "实例内全部会话",
      expiry(row), row.reason || label(row.origin),
      button("移除", async (event) => {
        const trigger = event.currentTarget;
        if (await confirmAction(`移除 ${row.user} 的${label(row.kind)}条目？`)) {
          void changeEntry(trigger, "remove", entryIdentity(row));
        }
      }),
    ]), kind || term ? "没有匹配条目。" : "暂无已生效名单条目。");
  $("pending-count").textContent = `（${entries.pending.length}）`;
  fillTable("pending-list", ["名单", "旧用户 ID", "有效期", "操作"], entries.pending.filter(filter).map((row) => {
    const controls = node("div", null, "controls");
    const identity = { kind: row.kind, user: row.user };
    controls.append(
      button("认领", () => {
        adopt = identity;
        $("adopt-user").textContent = `${label(row.kind)} · ${row.user}`;
        $("adopt-form").reset();
        $("adopt-form").hidden = false;
        $("adopt-form").elements.platform.focus();
      }),
      button("移除", async (event) => {
        const trigger = event.currentTarget;
        if (await confirmAction(`永久移除 ${row.user} 的旧${label(row.kind)}条目？`)) {
          void changeEntry(trigger, "remove_pending", identity, () => {
            if (adopt?.user === row.user && adopt?.kind === row.kind) closeAdopt();
          });
        }
      }),
    );
    return [label(row.kind), row.user, expiry(row), controls];
  }), "没有待认领条目。");
}

function closeAdopt() {
  adopt = null;
  $("adopt-form").hidden = true;
}

function decision(row, sample = false) {
  const item = node("details", null, "decision");
  item.open = sample;
  item.append(node("summary", [
    label(row.action) || "决策", row.banned && "封禁", row.observed && "观察",
    !sample && formatTime(row.time), row.source && label(row.source),
  ].filter(Boolean).join(" · ")));
  const list = node("dl");
  const pairs = [
    ["请求 ID", row.request_id], ["拟执行", label(row.intended_action)], ["复核", label(row.review_status)],
    ["实际 Provider", row.provider], ["实际模型", row.model],
    ["模型标识来源", label(row.model_source)], ["决策原因", label(row.decision_reason)],
    ["复核理由", row.review_reason],
    ["耗时", Number.isFinite(row.elapsed_ms) ? `${row.elapsed_ms.toFixed(2)} ms` : null],
    ["故障类别", row.fault], ["检查未完成", row.incomplete ? "是" : null],
    ["摘录", row.excerpt],
    ["规则证据", row.rules?.map((rule) => rule.evidence ? `${rule.id}：${rule.evidence}` : rule.id).join("\n")],
  ];
  for (const [title, value] of pairs) {
    if (value != null && value !== "") list.append(node("dt", title), node("dd", value));
  }
  item.append(list);
  return item;
}

function renderRecords() {
  const action = $("action-filter").value;
  const review = $("review-filter").value;
  const disposition = $("ban-filter").value;
  const term = $("record-search").value.trim().toLowerCase();
  const start = $("date-start").value ? new Date(`${$("date-start").value}T00:00`).getTime() / 1000 : -Infinity;
  const endDate = $("date-end").value ? new Date(`${$("date-end").value}T00:00`) : null;
  if (endDate) endDate.setDate(endDate.getDate() + 1);
  const end = endDate ? endDate.getTime() / 1000 : Infinity;
  visibleRecords = records.filter((row) =>
    row.time >= start && row.time < end &&
    (!action || row.action === action) &&
    (!review || row.review_failed || ["failed", "unavailable"].includes(row.review_status)) &&
    (!disposition || row[disposition] === true) &&
    (!term || [row.request_id, row.source, label(row.source), row.provider, row.model,
      row.decision_reason, row.review_reason, row.excerpt,
      ...(row.rules || []).flatMap((rule) => [rule.id, rule.evidence])].some(
      (value) => String(value ?? "").toLowerCase().includes(term),
    )),
  );
  const target = $("record-list");
  target.replaceChildren();
  if (!visibleRecords.length) target.append(node("p", records.length ? "没有匹配记录。" : "暂无诊断记录。", "muted"));
  else {
    target.append(node("p", `显示 ${Math.min(recordLimit, visibleRecords.length)} / ${visibleRecords.length} 条`, "muted"));
    for (const row of visibleRecords.slice(0, recordLimit)) target.append(decision(row));
    if (recordLimit < visibleRecords.length) target.append(button("显示更多", () => { recordLimit += 50; renderRecords(); }));
  }
  $("export").disabled = visibleRecords.length === 0;
  $("clear").disabled = records.length === 0;
}

async function fetchData(scope) {
  const version = versions[scope] = (versions[scope] || 0) + 1;
  const id = { overview: "connection", entries: "entry-message", records: "record-message" }[scope];
  try {
    const result = await get(scope);
    if (versions[scope] !== version) return;
    if (scope === "overview" && result?.effective && result.stats) {
      overview = result;
      renderOverview();
    } else if (scope === "entries" && Array.isArray(result?.entries) && Array.isArray(result.pending)) {
      entries = result;
      renderEntries();
    } else if (scope === "records" && Array.isArray(result)) {
      records = result;
      renderRecords();
    } else throw new Error("Incomplete data response");
    if ($(id).dataset.error === "true") message(id, "");
    return true;
  } catch {
    if (versions[scope] === version) message(id, "无法刷新数据。已显示的信息可能不是最新状态。", true);
    return false;
  }
}

function downloadRecords() {
  if (!visibleRecords.length) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(visibleRecords, null, 2)], { type: "application/json" }));
  const anchor = node("a");
  anchor.href = url;
  anchor.download = `antipromptinjector-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

let runningSample = false;
async function runSample(paid) {
  const form = $("sample-form");
  if (runningSample || !form.reportValidity()) return;
  const { text } = formFields(form);
  if (!text.trim()) {
    message("sample-message", "请输入样例文本。", true);
    return;
  }
  const provider = overview?.effective.review_provider;
  if (paid && !provider?.trim()) {
    message("sample-message", "请先配置并应用复核 Provider ID。", true);
    return;
  }
  if (paid && !await confirmAction(`将使用 ${provider} 复核样例，可能计费。确认调用？`)) return;
  runningSample = true;
  const buttons = [...form.querySelectorAll("button")];
  buttons.forEach((item) => { item.disabled = true; });
  $("sample-result").replaceChildren();
  message("sample-message", paid ? "正在复核…" : "正在试算…");
  try {
    const result = await post(paid ? "preview/review" : "preview/rules",
      paid ? { text, confirm: true, expected_provider_id: provider } : { text });
    if (!result?.action) throw new Error("Invalid decision");
    $("sample-result").append(decision(result, true));
    const failed = ["failed", "unavailable"].includes(result.review_status);
    message("sample-message", failed ? "试算完成，模型复核失败。" : "试算完成。", failed);
  } catch {
    message("sample-message", paid ? "模型试算未确认。请勿直接重复调用。" : "规则试算失败，请检查样例后重试。", true);
  } finally {
    buttons.forEach((item) => { item.disabled = false; });
    runningSample = false;
  }
}

all("[data-tab]").forEach((item) => item.addEventListener("click", () => showTab(item.dataset.tab)));
$("settings-search").addEventListener("input", searchSettings);
$("save").addEventListener("click", save);
$("reload-config").addEventListener("click", () => loadSettings(true));
$("refresh").addEventListener("click", async () => {
  if (!snapshot) {
    await start();
    return;
  }
  message("connection", "");
  if (!isDirty() && !conflicted) await loadSettings();
  showTab(tab);
});
$("observation-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void setObservation(event.submitter, Number(event.currentTarget.elements.minutes.value));
});
$("observation-stop").addEventListener("click", (event) => setObservation(event.currentTarget, 0));
$("entry-filter").addEventListener("change", () => { if (entries) renderEntries(); });
$("entry-search").addEventListener("input", () => { if (entries) renderEntries(); });
$("entry-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const entry = formFields(form);
  entry.duration_minutes = Number(entry.duration_minutes);
  void changeEntry(event.submitter, "add", entry, () => form.reset());
});
$("adopt-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (adopt) void changeEntry(event.submitter, "adopt", { ...adopt, ...formFields(event.currentTarget) }, closeAdopt);
});
$("adopt-cancel").addEventListener("click", closeAdopt);
for (const id of ["action-filter", "review-filter", "ban-filter", "record-search", "date-start", "date-end"]) {
  $(id).addEventListener("input", () => {
    recordLimit = 50;
    if (records) renderRecords();
  });
}
$("export").addEventListener("click", downloadRecords);
$("clear").addEventListener("click", async (event) => {
  const trigger = event.currentTarget;
  if (!await confirmAction("清除所有诊断记录？名单和防护设置不会更改。")) return;
  void operation("record", trigger, async () => {
    await post("records/clear", { confirm: true });
    records = [];
    renderRecords();
    const [refreshed] = await Promise.all([fetchData("records"), fetchData("overview")]);
    message("record-message", refreshed ? "已清除诊断记录。" : "已清除记录，但未能刷新显示。", !refreshed);
  }).finally(() => { if (records) renderRecords(); });
});
$("sample-form").addEventListener("submit", (event) => { event.preventDefault(); void runSample(false); });
$("paid").addEventListener("click", () => runSample(true));
window.addEventListener("beforeunload", (event) => {
  if (isDirty()) {
    event.preventDefault();
    event.returnValue = "";
  }
});

let starting = false;
async function start() {
  if (starting) return;
  starting = true;
  let timer;
  try {
    if (!bridge?.ready) throw new Error("Missing AstrBot bridge");
    message("connection", "正在连接 AstrBot Dashboard…");
    await Promise.race([
      bridge.ready(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Bridge timeout")), 8000); }),
    ]);
    await loadSettings();
    if (snapshot) showTab(tab);
  } catch {
    message("connection", "未连接 AstrBot Dashboard。请从 AstrBot 插件页打开。", true);
  } finally {
    clearTimeout(timer);
    starting = false;
  }
}
void start();
