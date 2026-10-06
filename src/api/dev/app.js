// The dev page. Every string from the plane reaches the document as text:
// elements are made with createElement and filled through textContent, and
// nothing the plane returns becomes markup, an attribute, a link or a handler.

const POLL_MS = 1500;
const TASK_DECIDED = 'agentplane.task.decided';
// The task states a person can still decide.
const DECIDABLE = ['open', 'claimed', 'escalated'];

// The session token travels in the URL fragment, which the browser never
// sends. It moves into this module's memory and out of the address bar before
// anything else runs, and leaves only as an Authorization header.
const fragment = new URLSearchParams(location.hash.slice(1));
const token = fragment.get('t') || '';
const linkedRun = fragment.get('run');
history.replaceState(null, '', location.pathname);

// Every content-security-policy violation is counted where a reader, or the
// browser smoke, can see it. Trusted Types are required with no policy, so a
// sink that would parse HTML throws and lands here.
let violations = 0;
document.addEventListener('securitypolicyviolation', () => {
  violations += 1;
  byId('violations').textContent = String(violations);
});

const state = {
  run: null,
  next: 1,
  records: [],
  // run id → the operator API's view of it, or null until read.
  runs: new Map(),
  order: [],
  waiting: new Map(),
  declaration: null,
  fingerprint: null,
  tasks: [],
  stopped: false,
  // run id → what its model is writing now, until the journal has the answer.
  live: new Map(),
  // Whether this tab is starting a run, so its first delta selects it.
  starting: false,
  // The run a start in this tab selected by its first delta, if any.
  autoSelected: null,
  // The export link's blob, released when the next export replaces it.
  exportUrl: null,
};

// ── Small helpers ──────────────────────────────────────────────────────────

function byId(id) {
  return document.getElementById(id);
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function button(text, className, onClick) {
  const node = el('button', text, className);
  node.type = 'button';
  node.addEventListener('click', onClick);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function say(node, text, className) {
  node.textContent = text;
  node.className = 'result' + (className ? ' ' + className : '');
}

let toastTimer = null;
function toast(text) {
  const node = byId('toast');
  node.textContent = text;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.hidden = true;
  }, 1800);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied');
  } catch (_) {
    toast('Copy is not available here');
  }
}

function pre(value) {
  return el('pre', typeof value === 'string' ? value : JSON.stringify(value, null, 2));
}

function pairs(entries, className) {
  const list = el('dl', null, className);
  for (const [term, value] of entries) {
    if (value === undefined || value === null || value === '') continue;
    list.append(el('dt', term), el('dd', value));
  }
  return list;
}

function short(text, n = 96) {
  const s = typeof text === 'string' ? text : JSON.stringify(text);
  if (s === undefined) return '';
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function duration(ms) {
  if (ms === undefined || ms === null) return '';
  if (ms < 1000) return ms + ' ms';
  if (ms < 60000) return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + ' s';
  return Math.floor(ms / 60000) + 'm ' + Math.round((ms % 60000) / 1000) + 's';
}

function shortRun(run) {
  return run.length > 16 ? run.slice(0, 14) + '…' : run;
}

async function call(method, path, body) {
  const headers = { Authorization: 'Bearer ' + token };
  const init = { method, headers, cache: 'no-store', credentials: 'omit' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }
  if (response.status === 401) {
    state.stopped = true;
    say(byId('session'), 'This tab’s token is not this session’s — open the URL `agentplane dev` printed.', 'error');
  }
  return { status: response.status, ok: response.ok, data };
}

function refusal(answer) {
  if (answer.data && typeof answer.data.error === 'string') return answer.data.error;
  return 'refused with ' + answer.status;
}

// A status's tone: what colour a person should read it in.
function tone(status) {
  switch (status) {
    case 'succeeded':
      return 'good';
    case 'running':
    case 'replanning':
      return 'run';
    case 'suspended':
    case 'withheld':
    case 'exhausted':
      return 'wait';
    case 'failed':
    case 'quarantined':
    case 'cancelled':
    case 'abandoned':
      return 'bad';
    default:
      return '';
  }
}

// ── Tabs ───────────────────────────────────────────────────────────────────

function showTab(name) {
  for (const tab of document.querySelectorAll('.tab')) {
    tab.ariaSelected = String(tab.dataset.tab === name);
  }
  for (const panel of document.querySelectorAll('[role="tabpanel"]')) {
    panel.hidden = panel.id !== 'tab-' + name;
  }
}

// ── Declaration ────────────────────────────────────────────────────────────

function capabilities() {
  const d = state.declaration;
  if (!d) return [];
  return d.agents.flatMap((agent) => agent.provides || []);
}

// A starting input for a schema: every declared property, at an empty value of
// its type, or the default or first example it declares.
function skeleton(schema, depth = 0) {
  if (!schema || typeof schema !== 'object' || depth > 4) return null;
  if ('default' in schema) return schema.default;
  if (Array.isArray(schema.examples) && schema.examples.length) return schema.examples[0];
  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
  switch (type) {
    case 'object': {
      const out = {};
      for (const [key, inner] of Object.entries(schema.properties || {})) out[key] = skeleton(inner, depth + 1);
      return out;
    }
    case 'array':
      return [];
    case 'string':
      return Array.isArray(schema.enum) && schema.enum.length ? schema.enum[0] : '';
    case 'integer':
    case 'number':
      return 0;
    case 'boolean':
      return false;
    default:
      return null;
  }
}

function schemaFor(capability) {
  const d = state.declaration;
  if (!d) return null;
  const agent = d.agents.find((a) => (a.provides || []).includes(capability));
  return agent ? agent.input_schema : null;
}

function updateSchemaHint() {
  const schema = schemaFor(byId('capability').value);
  const hint = byId('schema-hint');
  if (!schema) {
    hint.hidden = true;
    return;
  }
  const required = Array.isArray(schema.required) ? schema.required : [];
  hint.textContent = 'Declared input' + (required.length ? ' — required: ' + required.join(', ') : '');
  hint.hidden = false;
  const input = byId('input');
  if (input.value.trim() === '{}' || input.value.trim() === '') {
    input.value = JSON.stringify(skeleton(schema) ?? {}, null, 2);
    validateInput();
  }
}

function renderDeclaration(d) {
  byId('file').textContent = d.file;
  const chips = byId('agents');
  clear(chips);
  for (const agent of d.agents) {
    const chip = el('span', null, 'chip');
    chip.append(el('strong', agent.name), el('span', agent.version, 'muted'), el('code', agent.digest.slice(0, 12), 'muted'));
    chips.append(chip);
  }
  const refused = byId('refused');
  if (d.refused) {
    refused.textContent = 'The file as saved does not load; the plane runs the last one that did: ' + d.refused;
    refused.hidden = false;
  } else {
    refused.hidden = true;
  }
  const live = byId('live');
  if (d.live.length) {
    live.textContent = 'Live transports — approving a task here performs a real effect through: ' + d.live.join(', ');
    live.hidden = false;
  } else {
    live.hidden = true;
  }

  const body = byId('declaration-body');
  clear(body);
  for (const agent of d.agents) {
    const card = el('div', null, 'card');
    card.append(el('h2', agent.name + ' ' + agent.version));
    const digest = el('div', null, 'run-title');
    digest.append(el('code', agent.digest, 'mono'), button('Copy', 'icon', () => copy(agent.digest)));
    card.append(digest);
    card.append(pairs([['provides', (agent.provides || []).join(', ')]]));
    if (agent.bound.length) {
      card.append(el('h3', 'What a run can cost'));
      card.append(pre(agent.bound.join('\n')));
    }
    if (agent.input_schema) {
      card.append(el('h3', 'Input schema'));
      card.append(pre(agent.input_schema));
    }
    body.append(card);
  }
  if (d.refused) body.append(el('h3', 'Why the saved file does not load'), pre(d.refused));

  const select = byId('capability');
  const chosen = select.value;
  clear(select);
  for (const capability of capabilities()) {
    const option = el('option', capability);
    option.value = capability;
    select.append(option);
  }
  if (capabilities().includes(chosen)) select.value = chosen;
  updateSchemaHint();
}

async function loadDeclaration() {
  const answer = await call('GET', '/dev/manifest');
  if (!answer.ok) {
    const refused = byId('refused');
    refused.textContent = refusal(answer);
    refused.hidden = false;
    return;
  }
  const fingerprint = JSON.stringify(answer.data);
  if (fingerprint === state.fingerprint) return;
  const first = state.fingerprint === null;
  state.fingerprint = fingerprint;
  state.declaration = answer.data;
  renderDeclaration(answer.data);
  if (!first) toast('The declaration changed — the plane was rebuilt');
}

// ── The run list ───────────────────────────────────────────────────────────

function knowRun(run, first = false) {
  if (state.runs.has(run)) return;
  state.runs.set(run, null);
  if (first) state.order.unshift(run);
  else state.order.push(run);
}

async function refreshRun(run) {
  const known = state.runs.get(run);
  if (known && known.sealed) return;
  const answer = await call('GET', '/dev/runs/' + encodeURIComponent(run));
  if (answer.ok) {
    state.runs.set(run, answer.data);
    // A sealed run streams nothing more; its journal has every answer.
    if (answer.data.sealed) state.live.delete(run);
  }
}

async function loadRuns() {
  const [listed, waiting] = await Promise.all([call('GET', '/dev/runs'), call('GET', '/api/runs/waiting')]);
  if (listed.ok) for (const run of listed.data.runs) knowRun(run);
  state.waiting.clear();
  if (waiting.ok) {
    for (const w of waiting.data.runs) {
      knowRun(w.run);
      state.waiting.set(w.run, w.waiting_for);
    }
  }
  // A few at a time, so a store with many runs is not asked about all of
  // them at once; a sealed run is never asked about again.
  const pending = state.order.filter((run) => {
    const view = state.runs.get(run);
    return !view || !view.sealed;
  });
  for (let i = 0; i < pending.length; i += 8) {
    await Promise.all(pending.slice(i, i + 8).map(refreshRun));
  }
  renderRuns();
}

function renderRuns() {
  const list = byId('runs-list');
  const filter = byId('run-filter').value.trim().toLowerCase();
  clear(list);
  let shown = 0;
  for (const run of state.order) {
    const view = state.runs.get(run);
    const status = view ? view.status : '…';
    if (filter && !run.toLowerCase().includes(filter) && !status.includes(filter)) continue;
    const item = el('li');
    const pick = el('button');
    pick.type = 'button';
    pick.dataset.run = run;
    pick.ariaCurrent = String(run === state.run);
    pick.title = run;
    pick.append(el('span', null, 'dot ' + tone(status)), el('span', shortRun(run), 'id'), el('span', status, 'sub'));
    pick.addEventListener('click', () => selectRun(run));
    item.append(pick);
    list.append(item);
    shown += 1;
  }
  byId('runs-empty').hidden = shown > 0 || state.order.length > 0;
}

function selectRun(run) {
  showTab('run');
  if (state.run !== run) {
    state.run = run;
    state.next = 1;
    state.records = [];
    clear(byId('timeline'));
    clear(byId('conversation'));
    byId('timeline-escaped').hidden = true;
    byId('event-form').hidden = true;
    say(byId('run-result'), '');
  }
  renderLive();
  byId('composer').open = false;
  byId('run-view').hidden = false;
  renderRuns();
  renderRunHead();
  pollTimeline();
}

// ── Starting a run ─────────────────────────────────────────────────────────

function validateInput() {
  const input = byId('input');
  const note = byId('input-state');
  try {
    JSON.parse(input.value || '{}');
    input.classList.remove('invalid');
    note.textContent = '';
    return true;
  } catch (e) {
    input.classList.add('invalid');
    note.textContent = '— ' + e.message;
    return false;
  }
}

function correlationKeys() {
  return byId('correlate')
    .value.split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

async function startRun() {
  if (state.starting) return;
  const result = byId('start-result');
  if (!validateInput()) {
    say(result, 'The input is not JSON.', 'error');
    return;
  }
  const request = { input: JSON.parse(byId('input').value || '{}'), correlate: correlationKeys() };
  const capability = byId('capability').value;
  if (capability) request.capability = capability;
  const start = byId('start-run');
  start.disabled = true;
  state.starting = true;
  state.autoSelected = null;
  say(result, 'running…');
  try {
    const answer = await call('POST', '/dev/runs', request);
    if (!answer.ok) {
      say(result, refusal(answer), 'error');
      return;
    }
    say(result, answer.data.run + ' — ' + answer.data.status, tone(answer.data.status) === 'bad' ? 'error' : 'good');
    knowRun(answer.data.run, true);
    await refreshRun(answer.data.run);
    // Not if the person has since opened another run.
    if (state.run === null || state.run === state.autoSelected) selectRun(answer.data.run);
    await loadTasks();
  } finally {
    start.disabled = false;
    state.starting = false;
  }
}

// ── The run inspector ──────────────────────────────────────────────────────

function spendOf(records) {
  const total = { effects: 0, models: 0, tokens: 0, minor: 0, refusals: 0, failures: 0, ms: 0, slowest: 0 };
  for (const view of records) {
    const r = view.record || {};
    switch (view.kind) {
      case 'EffectStarted':
        total.effects += 1;
        if (r.descriptor && /model|completion|chat/i.test(r.descriptor.kind || '')) total.models += 1;
        break;
      case 'EffectDone':
        total.ms += r.elapsed_ms || 0;
        total.slowest = Math.max(total.slowest, r.elapsed_ms || 0);
        if (r.spend) {
          total.tokens += r.spend.tokens || 0;
          total.minor += r.spend.minor_units || 0;
        }
        break;
      case 'EffectFailed':
        total.failures += 1;
        total.ms += r.elapsed_ms || 0;
        total.slowest = Math.max(total.slowest, r.elapsed_ms || 0);
        if (r.spend) {
          total.tokens += r.spend.tokens || 0;
          total.minor += r.spend.minor_units || 0;
        }
        break;
      case 'PolicyDenied':
      case 'BudgetRefused':
      case 'AuthorityWithheld':
        total.refusals += 1;
        break;
      default:
        break;
    }
  }
  return total;
}

function stat(value, label) {
  const node = el('span', null, 'stat');
  node.append(el('b', value), el('span', value === 1 ? label.replace(/s$/, '').replace(/ies$/, 'y') : label, 'muted'));
  return node;
}

function renderRunHead() {
  const run = state.run;
  if (!run) return;
  const view = state.runs.get(run);
  const status = view ? view.status : '…';
  const badge = byId('run-status');
  badge.textContent = status;
  badge.className = 'badge ' + tone(status);
  byId('run-id').textContent = run;

  const waiting = state.waiting.get(run);
  const facts = byId('run-facts');
  clear(facts);
  const entries = [];
  if (view) {
    if (view.reason) entries.push(['reason', view.reason]);
    if (view.waiting_for) entries.push(['waiting for', view.waiting_for]);
    if (view.case) entries.push(['case', view.case]);
    if (view.undecided && view.undecided.length) entries.push(['undecided', view.undecided.join(', ')]);
    if (view.exhaustion) entries.push(['budget', JSON.stringify(view.exhaustion)]);
    if (view.decided_by) entries.push(['decided by', JSON.stringify(view.decided_by)]);
    entries.push(['records', String(view.records)], ['sealed', view.sealed ? 'yes' : 'no']);
  }
  for (const [term, value] of entries) facts.append(el('dt', term), el('dd', value));

  const total = spendOf(state.records);
  const stats = byId('run-stats');
  clear(stats);
  stats.append(stat(total.effects, 'effects'), stat(total.models, 'model calls'), stat(total.tokens, 'tokens'));
  if (waiting && waiting.reason === 'awaiting_event' && waiting.kind === TASK_DECIDED) {
    stats.append(button('Waiting on a person — open the worklist', 'small', () => showTab('worklist')));
  }
  if (total.ms) stats.append(stat(duration(total.ms), 'in calls'));
  if (total.minor) stats.append(stat(total.minor, 'minor units'));
  if (total.failures) stats.append(stat(total.failures, 'failed attempts'));
  if (total.refusals) stats.append(stat(total.refusals, 'refusals'));

  const open = view && !view.sealed && ['running', 'suspended', 'withheld', 'exhausted', 'replanning'].includes(status);
  byId('cancel-run').hidden = !open;

  const form = byId('event-form');
  const awaits = waiting && waiting.reason === 'awaiting_event' && waiting.kind !== TASK_DECIDED;
  if (awaits && form.hidden) {
    byId('event-kind').value = waiting.kind;
    byId('event-correlation').value = (waiting.correlation || []).map((k) => k.namespace + '=' + k.value).join('\n');
  }
  form.hidden = !awaits;
}

// The composer, filled with the input and capability this run was admitted
// with, as the timeline shows them.
function runAgain() {
  const admitted = state.records.find((view) => view.kind === 'RunAdmitted');
  if (!admitted) {
    toast('This run’s admission has not been read yet');
    return;
  }
  const r = admitted.record;
  const select = byId('capability');
  if (r.capability && capabilities().includes(r.capability)) select.value = r.capability;
  byId('input').value = JSON.stringify(r.input === undefined ? {} : r.input, null, 2);
  validateInput();
  byId('composer').open = true;
  byId('input').focus();
  const escaped = !byId('timeline-escaped').hidden;
  toast(escaped ? 'Copied — hidden characters arrive as the \\u{…} text the page shows' : 'Input copied from ' + shortRun(state.run));
}

async function cancelRun() {
  const result = byId('run-result');
  const run = state.run;
  clear(result);
  result.className = 'result';
  const reason = el('input');
  reason.type = 'text';
  reason.placeholder = 'why — recorded on the run';
  const confirm = button('Cancel this run', 'danger small', async () => {
    if (!reason.value.trim()) {
      reason.focus();
      return;
    }
    const answer = await call('POST', '/api/runs/' + encodeURIComponent(run) + '/cancel', { reason: reason.value.trim() });
    const text = answer.ok ? 'cancellation recorded — the run stops at its next step boundary' : refusal(answer);
    if (state.run !== run) {
      toast(shortRun(run) + ': ' + text);
      return;
    }
    say(result, text, answer.ok ? 'good' : 'error');
    if (!answer.ok) return;
    await refreshRun(run);
    renderRunHead();
  });
  result.append(reason, confirm);
  reason.focus();
}

async function sendEvent(event) {
  event.preventDefault();
  const result = byId('event-result');
  let payload;
  try {
    payload = JSON.parse(byId('event-payload').value || 'null');
  } catch (e) {
    say(result, 'The payload is not JSON: ' + e.message, 'error');
    return;
  }
  const correlation = byId('event-correlation')
    .value.split('\n')
    .map((pair) => pair.trim())
    .filter((pair) => pair.includes('='))
    .map((pair) => ({ namespace: pair.slice(0, pair.indexOf('=')), value: pair.slice(pair.indexOf('=') + 1) }));
  const answer = await call('POST', '/api/events', {
    id: crypto.randomUUID(),
    kind: byId('event-kind').value.trim(),
    payload,
    correlation,
  });
  if (!answer.ok) {
    say(result, refusal(answer), 'error');
    return;
  }
  say(result, answer.data.delivery + (answer.data.run ? ' → ' + answer.data.run : ''), 'good');
  await loadRuns();
  renderRunHead();
  await pollTimeline();
}

// ── Live model output ──────────────────────────────────────────────────────

function renderLive() {
  const panel = byId('live-output');
  const live = state.run ? state.live.get(state.run) : null;
  if (!live || (!live.text && !live.usage)) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  byId('live-text').textContent = live.text;
  const usage = live.usage;
  byId('live-usage').textContent =
    (usage ? usage.input_tokens + ' in · ' + usage.output_tokens + ' out' : '') + (live.lagged ? ' · some output was missed' : '');
}

// The most a live panel holds; older text is in the journal once the call ends.
const LIVE_LIMIT = 100000;

function onStreamEvent(event) {
  if (!event) return;
  if (event.type === 'lagged') {
    // Not one run's: the page fell behind the whole stream.
    for (const live of state.live.values()) live.lagged = true;
    renderLive();
    return;
  }
  if (typeof event.run !== 'string') return;
  const run = event.run;
  if (!state.live.has(run)) state.live.set(run, { text: '', usage: null, lagged: false, ended: false });
  const live = state.live.get(run);
  if (event.type === 'text_delta') {
    // Usage closes a call; text after it is the next call's.
    if (live.ended) {
      live.text = '';
      live.usage = null;
      live.ended = false;
    }
    live.text = (live.text + event.value).slice(-LIVE_LIMIT);
  } else if (event.type === 'usage') {
    live.usage = event.value;
    live.ended = true;
  }
  const isNew = !state.runs.has(run);
  if (isNew) {
    knowRun(run, true);
    renderRuns();
  }
  // A run this tab is starting announces itself by its first delta; only a
  // run the page had not seen can be it.
  if (state.starting && isNew && state.autoSelected === null) {
    state.autoSelected = run;
    selectRun(run);
  }
  if (run === state.run) renderLive();
}

// One stream for the session, re-opened if it ends: the plane forwards every
// run's model output on it as the calls happen.
async function follow() {
  while (!state.stopped) {
    try {
      const response = await fetch('/dev/stream', {
        headers: { Authorization: 'Bearer ' + token },
        cache: 'no-store',
        credentials: 'omit',
      });
      if (response.status === 401) {
        state.stopped = true;
        return;
      }
      if (response.ok && response.body) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let pending = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          pending += decoder.decode(value, { stream: true });
          let newline;
          while ((newline = pending.indexOf('\n')) >= 0) {
            const line = pending.slice(0, newline);
            pending = pending.slice(newline + 1);
            if (line.trim()) {
              try {
                onStreamEvent(JSON.parse(line));
              } catch (_) {
                // A line that is not JSON is skipped, never shown.
              }
            }
          }
        }
      }
    } catch (_) {
      // Reconnected below.
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

// ── The timeline ───────────────────────────────────────────────────────────

// What a record says in one line, and the tone it is read in.
function describe(view) {
  const r = view.record || {};
  switch (view.kind) {
    case 'EffectStarted': {
      const kind = r.descriptor ? r.descriptor.kind : '';
      return [kind + (r.attempt > 1 ? ' · attempt ' + r.attempt : '') + (r.mutates ? ' · mutates' : ''), 'effect'];
    }
    case 'EffectDone': {
      const spend = r.spend ? [r.spend.tokens ? r.spend.tokens + ' tokens' : '', r.spend.minor_units ? r.spend.minor_units + ' minor' : ''].filter(Boolean).join(', ') : '';
      const took = r.elapsed_ms !== undefined ? duration(r.elapsed_ms) + ' · ' : '';
      return [took + (spend ? spend + ' · ' : '') + short(r.output, 120), 'good'];
    }
    case 'EffectFailed':
      return [(r.elapsed_ms !== undefined ? duration(r.elapsed_ms) + ' · ' : '') + (r.disposition || '') + ' · ' + short(r.error, 120), 'bad'];
    case 'EffectReconciled':
      return [r.disposition || '', r.disposition === 'landed' ? 'good' : 'wait'];
    case 'PolicyDenied':
      return [(r.action || '') + ' · ' + short(r.reason, 120), 'bad'];
    case 'BudgetRefused':
      return [(r.limit || '') + ' · ' + (r.used || ''), 'bad'];
    case 'AuthorityWithheld':
      return [(r.subject || '') + ' · ' + short(r.reason, 100), 'bad'];
    case 'RunSuspended': {
      const reason = r.reason || {};
      return [(reason.reason || '') + (reason.kind ? ' · ' + reason.kind : ''), 'wait'];
    }
    case 'StepStarted':
      return [r.skill || '', ''];
    case 'StepFinished':
      return [r.outcome || '', r.outcome === 'succeeded' ? 'good' : tone(r.outcome)];
    case 'RunConcluded':
      return [(r.outcome || '') + (r.reason ? ' · ' + short(r.reason, 100) : ''), tone(r.outcome)];
    case 'Note':
      return [short(r.text, 120), ''];
    case 'IdentityBound':
      return [(r.chain || []).map((p) => p.id).join(' → '), ''];
    case 'Released':
      return ['label lowered', 'wait'];
    default:
      return ['', ''];
  }
}

function recordItem(view, previous) {
  const [summary, mood] = describe(view);
  const item = el('li');
  item.className = (mood ? 'tone-' + mood : '') + (view.step && (!previous || previous.step !== view.step) ? ' step-start' : '');
  item.dataset.kind = view.kind;
  item.dataset.search = (view.kind + ' ' + (view.step || '') + ' ' + summary).toLowerCase();
  const details = el('details');
  const head = el('summary');
  head.append(el('span', view.seq, 'seq'), el('span', view.kind, 'kind'));
  const took = view.record && view.record.elapsed_ms;
  if (typeof took === 'number') {
    const bar = el('span', null, 'took');
    const fill = el('span', null, 'fill');
    bar.append(fill);
    bar.dataset.ms = String(took);
    bar.title = duration(took);
    head.append(bar);
  }
  if (view.step) head.append(el('span', 'step ' + view.step, 'tag'));
  if (view.phase && view.phase !== 'forward') head.append(el('span', view.phase, 'tag'));
  if (summary) head.append(el('span', summary, 'summary'));
  details.append(head);
  const output = view.record && view.record.output;
  if (view.kind === 'EffectDone' && output && typeof output.run === 'string' && 'answer' in output) {
    const sub = output.run;
    head.append(el('span', '→ ' + shortRun(sub), 'tag'));
    details.append(button('Open the sub-run that answered', 'small secondary', () => {
      knowRun(sub);
      selectRun(sub);
    }));
  }
  details.append(pre(view.record));
  if (view.effect_key) details.append(el('p', 'effect ' + view.effect_key, 'muted small-text'));
  item.append(details);
  return item;
}

// ── The conversation ───────────────────────────────────────────────────────

const MODEL_KIND = 'model.complete';

function bubble(role, title, body, extra) {
  const node = el('div', null, 'bubble ' + role + (extra ? ' ' + extra : ''));
  node.append(el('div', title, 'who'));
  if (typeof body === 'string') node.append(el('div', body, 'text'));
  else if (body !== undefined) node.append(pre(body));
  return node;
}

// Every model call of the run, paired with what it answered, in order.
function modelCalls(records) {
  const calls = [];
  const byKey = new Map();
  for (const view of records) {
    const r = view.record || {};
    if (view.kind === 'EffectStarted' && r.descriptor && r.descriptor.kind === MODEL_KIND) {
      const call = { seq: view.seq, step: view.step, attempt: r.attempt, args: r.descriptor.args, done: null, failed: null };
      calls.push(call);
      byKey.set(view.effect_key, call);
    } else if (view.kind === 'EffectDone' && byKey.has(view.effect_key)) {
      byKey.get(view.effect_key).done = r;
    } else if (view.kind === 'EffectFailed' && byKey.has(view.effect_key)) {
      byKey.get(view.effect_key).failed = r;
    }
  }
  return calls;
}

function renderConversation() {
  const box = byId('conversation');
  if (box.hidden) return;
  clear(box);
  const calls = modelCalls(state.records);
  if (!calls.length) {
    box.append(el('p', 'This run has made no model call yet.', 'muted'));
    return;
  }
  let shownSystem = null;
  let shownPrompt = null;
  let exchangesSeen = 0;
  calls.forEach((call, index) => {
    const args = call.args || {};
    const turn = el('div', null, 'turn');
    const head = el('div', null, 'turn-head');
    head.append(el('strong', 'Model call ' + (index + 1)), el('span', 'seq ' + call.seq, 'muted'));
    if (args.provider || args.model) head.append(el('span', (args.provider || '') + '/' + (args.model || ''), 'tag'));
    if (call.step) head.append(el('span', 'step ' + call.step, 'tag'));
    if (call.attempt > 1) head.append(el('span', 'attempt ' + call.attempt, 'tag'));
    const out = call.done ? call.done.output || {} : null;
    if (out && out.usage) head.append(el('span', out.usage.input_tokens + ' in · ' + out.usage.output_tokens + ' out', 'muted'));
    if (out && out.stop_reason) head.append(el('span', out.stop_reason, 'muted'));
    const took = call.done ? call.done.elapsed_ms : call.failed ? call.failed.elapsed_ms : undefined;
    if (took !== undefined) head.append(el('span', duration(took), 'tag'));
    turn.append(head);
    const body = el('div', null, 'turn-body');
    if (typeof args.model !== 'string') {
      body.append(el('p', 'The call’s arguments are sealed in this journal.', 'muted'));
    } else {
      const prompt = args.prompt;
      const system = prompt && typeof prompt === 'object' && typeof prompt.system === 'string' ? prompt.system : null;
      if (system !== null && system !== shownSystem) {
        body.append(bubble('system', 'System', system));
        shownSystem = system;
      }
      let asked = prompt;
      if (system !== null) {
        asked = Object.assign({}, prompt);
        delete asked.system;
        if (Object.keys(asked).length === 1 && 'input' in asked) asked = asked.input;
      }
      const askedText = JSON.stringify(asked);
      if (askedText !== shownPrompt) {
        body.append(bubble('user', 'Input', typeof asked === 'string' ? asked : asked));
        shownPrompt = askedText;
      }
      const exchanges = Array.isArray(args.exchanges) ? args.exchanges : [];
      if (exchanges.length < exchangesSeen) exchangesSeen = 0;
      for (const exchange of exchanges.slice(exchangesSeen)) {
        const callOf = exchange.call || {};
        body.append(bubble('tool', 'Tool result · ' + callOf.name + (exchange.failed ? ' · failed' : ''), exchange.output, exchange.failed ? 'failed' : ''));
      }
      exchangesSeen = exchanges.length;
    }
    if (call.failed) {
      body.append(bubble('assistant', 'Failed · ' + (call.failed.disposition || ''), call.failed.error || '', 'failed'));
    } else if (out) {
      if (out.text) body.append(bubble('assistant', 'Model', out.structured ? out.structured : out.text));
      for (const asked of out.tool_calls || []) body.append(bubble('assistant', 'Calls tool · ' + asked.name, asked.arguments));
      if (!out.text && !(out.tool_calls || []).length) body.append(bubble('assistant', 'Model', '(no text)'));
    } else {
      body.append(el('p', 'No answer recorded yet.', 'muted'));
    }
    turn.append(body);
    box.append(turn);
  });
}

function showView(name) {
  for (const seg of document.querySelectorAll('.seg')) seg.ariaSelected = String(seg.dataset.view === name);
  byId('timeline').hidden = name !== 'timeline';
  byId('conversation').hidden = name !== 'conversation';
  for (const id of ['timeline-filter', 'effects-only', 'expand-all', 'collapse-all']) byId(id).disabled = name !== 'timeline';
  renderConversation();
}

// Each duration bar against the run's slowest call.
function scaleDurations() {
  const slowest = spendOf(state.records).slowest || 1;
  for (const bar of byId('timeline').querySelectorAll('.took')) {
    const share = Number(bar.dataset.ms) / slowest;
    bar.firstChild.style.width = Math.max(share * 100, share > 0 ? 3 : 0) + '%';
  }
}

function applyTimelineFilter() {
  const text = byId('timeline-filter').value.trim().toLowerCase();
  const effectsOnly = byId('effects-only').checked;
  for (const item of byId('timeline').children) {
    const isEffect = /^(Effect|Policy|Budget|Authority)/.test(item.dataset.kind);
    const hide = (effectsOnly && !isEffect) || (text && !item.dataset.search.includes(text));
    item.classList.toggle('hidden-by-filter', Boolean(hide));
  }
}

function expandAll(open) {
  for (const details of byId('timeline').querySelectorAll('details')) details.open = open;
}

// One poll at a time: a second caller while one is in flight asks for one
// more pass and awaits the same promise, so no page is read twice and no
// record is appended twice.
let polling = null;
let pollAgain = false;

function pollTimeline() {
  if (polling) {
    pollAgain = true;
    return polling;
  }
  polling = (async () => {
    try {
      do {
        pollAgain = false;
        await readTimeline();
      } while (pollAgain);
    } finally {
      polling = null;
    }
  })();
  return polling;
}

// Pages of the chosen run from the cursor on. An answer for a run or cursor
// that is no longer the chosen one is dropped, and the next pass reads what is.
async function readTimeline() {
  for (;;) {
    const run = state.run;
    const from = state.next;
    if (!run) return;
    const answer = await call('GET', '/dev/runs/' + encodeURIComponent(run) + '/history?from=' + from);
    if (state.run !== run || state.next !== from) {
      pollAgain = true;
      return;
    }
    if (!answer.ok) return;
    const timeline = byId('timeline');
    for (const view of answer.data.records) {
      timeline.append(recordItem(view, state.records[state.records.length - 1]));
      state.records.push(view);
      state.next = view.seq + 1;
    }
    if (answer.data.records.some((view) => view.kind === 'RunConcluded' || view.kind === 'RunSuspended')) {
      // The run stopped writing; every answer the panel showed is in the journal.
      state.live.delete(run);
      renderLive();
    }
    if (answer.data.records.length) {
      applyTimelineFilter();
      scaleDurations();
      renderRunHead();
      renderConversation();
    }
    if (answer.data.escaped) byId('timeline-escaped').hidden = false;
    if (!answer.data.next_from) return;
  }
}

// ── The worklist ───────────────────────────────────────────────────────────

function reachSection(reach) {
  const box = el('div', null, 'reach');
  box.append(el('h3', 'The agent this consultation hands work to — ' + reach.capability));
  const d = reach.declaration;
  if (!d) {
    box.append(el('p', 'No declaration governs it: nothing about what it may do can be stated.', 'error'));
    return box;
  }
  box.append(pairs([
    ['agent', d.agent + ' ' + d.version],
    ['digest', d.digest],
    ['delegation ceiling', d.max_delegation_depth],
    ['budgets', d.budgets ? JSON.stringify(d.budgets) : 'none declared'],
  ]));
  const table = el('table');
  const head = el('tr');
  for (const name of ['grant', 'mutates', 'asks a person', 'consults']) head.append(el('th', name));
  table.append(head);
  for (const grant of d.grants) {
    const row = el('tr');
    row.append(
      el('td', grant.reference),
      el('td', grant.mutates ? 'yes' : 'no', grant.mutates && !grant.requires_approval ? 'yes-bad' : ''),
      el('td', grant.requires_approval ? 'yes' : 'no'),
      el('td', grant.consults ? 'yes' : ''),
    );
    table.append(row);
  }
  box.append(table);
  return box;
}

function taskItem(task) {
  const item = el('li');
  const shown = task.rendering;
  const title = el('div', null, 'run-title');
  title.append(el('span', task.state, 'badge ' + (DECIDABLE.includes(task.state) ? 'wait' : '')), el('strong', shown.summary));
  item.append(title);
  item.append(pairs([
    ['task', task.id],
    ['run', task.run],
    ['kind', task.kind],
    ['cost', shown.cost],
  ]));
  if (shown.withheld) item.append(el('p', 'The proposal is withheld: ' + JSON.stringify(shown.withheld), 'error'));
  item.append(el('h3', 'Proposed action'), pre(shown.proposed_action));
  if (shown.reach) item.append(reachSection(shown.reach));
  for (const line of shown.evidence || []) item.append(el('h3', 'Evidence'), pre(line));
  if (shown.escaped) item.append(el('p', 'Hidden characters are shown as \\u{…}.', 'flag'));
  for (const mixed of shown.mixed_script || []) {
    item.append(el('p', 'Mixed scripts at ' + mixed.at + ': ' + mixed.word + ' (' + mixed.scripts.join(', ') + ')', 'flag'));
  }
  if (DECIDABLE.includes(task.state) && task.decidable_by_you !== false) {
    const reason = el('input');
    reason.type = 'text';
    reason.placeholder = 'reason — recorded with the decision';
    const amendment = el('textarea', '', 'mono');
    amendment.rows = 3;
    amendment.placeholder = 'optional: the arguments to dispatch instead, as JSON';
    const result = el('p', '', 'result');
    const actions = el('div', null, 'actions');
    actions.append(
      button('Approve', '', () => decide(task, true, reason.value, amendment.value, result)),
      button('Reject', 'danger', () => decide(task, false, reason.value, '', result)),
      button('Open run', 'secondary', () => selectRun(task.run)),
    );
    item.append(el('label', 'Reason'), reason);
    // Only a call's approval can substitute what is dispatched.
    if (task.kind === 'agent.approve_call') item.append(el('label', 'Amend the arguments'), amendment);
    item.append(actions, result);
  }
  return item;
}

async function decide(task, approved, reason, amendmentText, result) {
  const body = { approved, reason, digest: task.digest };
  if (amendmentText.trim()) {
    try {
      body.amendment = JSON.parse(amendmentText);
    } catch (e) {
      say(result, 'The amendment is not JSON: ' + e.message, 'error');
      return;
    }
  }
  const answer = await call('POST', '/api/tasks/' + encodeURIComponent(task.id) + '/decide', body);
  if (answer.status === 412) {
    // The row is replaced by its new version; the note has to outlive it.
    toast('The task changed — re-read it before deciding.');
    await loadTasks();
    return;
  }
  if (!answer.ok) {
    say(result, refusal(answer), 'error');
    return;
  }
  toast(approved ? 'Approved' : 'Rejected');
  knowRun(task.run);
  await loadTasks();
  await loadRuns();
  if (state.run === task.run) await pollTimeline();
}

async function loadTasks() {
  const answer = await call('GET', '/api/tasks');
  if (!answer.ok) return;
  const fingerprint = JSON.stringify(answer.data.tasks.map((t) => [t.id, t.state, t.digest]));
  const count = byId('task-count');
  const open = answer.data.tasks.filter((t) => DECIDABLE.includes(t.state)).length;
  count.textContent = String(open);
  count.hidden = open === 0;
  if (fingerprint === state.tasks) return;
  state.tasks = fingerprint;
  const list = byId('tasks');
  // Keyed by task, and a row kept while its task is unchanged, so a reason or
  // an amendment half typed into one row survives another task changing.
  const kept = new Map();
  for (const node of [...list.children]) {
    if (node.dataset.key) kept.set(node.dataset.key, node);
  }
  clear(list);
  if (!answer.data.tasks.length) list.append(el('li', 'Nothing waits on a person.', 'muted empty'));
  for (const task of answer.data.tasks) {
    const key = JSON.stringify([task.id, task.state, task.digest]);
    let node = kept.get(key);
    if (!node) {
      node = taskItem(task);
      node.dataset.key = key;
    }
    list.append(node);
  }
}

// ── Strict replay and export ───────────────────────────────────────────────

async function replay(all) {
  const list = all ? byId('verdicts') : null;
  const result = byId('run-result');
  if (list) clear(list);
  if (!all && !state.run) return;
  const run = state.run;
  if (!all) say(result, 'replaying…');
  const answer = await call('POST', '/dev/replay', all ? {} : { run });
  if (!all && state.run !== run) {
    toast(shortRun(run) + ': ' + (answer.ok ? answer.data[0].verdict : refusal(answer)));
    return;
  }
  if (!answer.ok) {
    if (list) list.append(el('li', refusal(answer), 'error'));
    else say(result, refusal(answer), 'error');
    return;
  }
  if (!all) {
    const verdict = answer.data[0];
    clear(result);
    result.className = 'result';
    result.append(el('strong', verdict.verdict, verdict.verdict === 'reproduced' ? 'good' : 'error'), pre(verdict.detail));
    return;
  }
  if (!answer.data.length) list.append(el('li', 'No runs to replay.', 'muted empty'));
  for (const verdict of answer.data) {
    const item = el('li');
    const head = el('div', null, 'run-title');
    head.append(
      el('span', verdict.verdict, 'badge ' + (verdict.verdict === 'reproduced' ? 'good' : 'bad')),
      button(verdict.run, 'icon', () => selectRun(verdict.run)),
    );
    item.append(head, pre(verdict.detail));
    list.append(item);
  }
}

async function exportStore() {
  const body = byId('export-body');
  clear(body);
  const answer = await call('GET', '/dev/export');
  if (!answer.ok) {
    body.append(el('p', refusal(answer), 'error'));
    return;
  }
  const report = answer.data.report;
  const sound = report.findings.length === 0 && report.complete && !report.unverifiable;
  body.append(el('p', sound ? 'The export verifies.' : 'The export does not verify.', sound ? 'good' : 'error'));
  if (answer.data.partial) body.append(el('p', 'Partial: the store held more runs than one export reads.', 'error'));
  body.append(pre(report));
  const blob = new Blob([answer.data.export], { type: 'application/jsonl' });
  const link = el('a', 'Save export.jsonl — the bytes verified above');
  link.download = 'export.jsonl';
  if (state.exportUrl) URL.revokeObjectURL(state.exportUrl);
  link.href = URL.createObjectURL(blob);
  state.exportUrl = link.href;
  body.append(link);
  body.append(el('p', 'Verify it yourself:', 'muted'));
  for (const command of answer.data.verify) {
    const row = el('div', null, 'run-title');
    row.append(el('code', command, 'mono'), button('Copy', 'icon', () => copy(command)));
    body.append(row);
  }
}

// ── Wiring ─────────────────────────────────────────────────────────────────

// The next tick is scheduled when this one finishes, so a slow plane is never
// asked twice at once.
async function tick() {
  if (state.stopped) return;
  try {
    await loadDeclaration();
    await loadRuns();
    if (state.run) renderRunHead();
    await pollTimeline();
    await loadTasks();
  } finally {
    if (!state.stopped) setTimeout(tick, POLL_MS);
  }
}

function typing(event) {
  const t = event.target;
  return t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT');
}

function wire() {
  for (const tab of document.querySelectorAll('.tab')) tab.addEventListener('click', () => showTab(tab.dataset.tab));
  for (const seg of document.querySelectorAll('.seg')) seg.addEventListener('click', () => showView(seg.dataset.view));
  byId('new-run').addEventListener('click', () => {
    showTab('run');
    byId('composer').open = true;
    byId('input').focus();
  });
  byId('start-run').addEventListener('click', startRun);
  byId('format-input').addEventListener('click', () => {
    if (validateInput()) byId('input').value = JSON.stringify(JSON.parse(byId('input').value || '{}'), null, 2);
  });
  byId('input').addEventListener('input', validateInput);
  byId('input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) startRun();
  });
  byId('capability').addEventListener('change', updateSchemaHint);
  byId('run-filter').addEventListener('input', renderRuns);
  byId('timeline-filter').addEventListener('input', applyTimelineFilter);
  byId('effects-only').addEventListener('change', applyTimelineFilter);
  byId('expand-all').addEventListener('click', () => expandAll(true));
  byId('collapse-all').addEventListener('click', () => expandAll(false));
  byId('copy-run').addEventListener('click', () => state.run && copy(state.run));
  byId('replay-one').addEventListener('click', () => replay(false));
  byId('run-again').addEventListener('click', runAgain);
  byId('replay-all').addEventListener('click', () => replay(true));
  byId('cancel-run').addEventListener('click', cancelRun);
  byId('event-form').addEventListener('submit', sendEvent);
  byId('export-run').addEventListener('click', exportStore);
  document.addEventListener('keydown', (event) => {
    if (typing(event) || event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === 'n') {
      event.preventDefault();
      byId('new-run').click();
    } else if (event.key === '/') {
      event.preventDefault();
      byId('timeline-filter').focus();
    }
  });
  if (!token) {
    say(byId('session'), 'No session token — open the URL `agentplane dev` printed.', 'error');
    return;
  }
  say(byId('session'), 'loopback session — the token lives in this tab only', 'muted');
  if (linkedRun) {
    knowRun(linkedRun, true);
    selectRun(linkedRun);
  }
  tick();
  follow();
}

wire();
