/* pkrtrckr — client app.
 * Everything a user enters is encrypted here (AES-256-GCM) before it is sent.
 * Key derivation: PBKDF2-SHA256(passphrase, salt, iter) -> HKDF -> { auth key (sent), enc key (never leaves) }.
 */
'use strict';
(() => {

const API = 'api/index.php';
const IDLE_MS = 15 * 60 * 1000;
const PAGE = 20;
const DEFAULT_ITER = 600000;
const LISTS = { locations: 'Locations', games: 'Games', stakes: 'Cash stakes', buyins: 'Tournament buy-ins' };

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const te = new TextEncoder(), td = new TextDecoder();

const S = {
  name: '', key: null, auth: '', salt: '', iter: DEFAULT_ITER,
  entries: [],            // [{id, d:{t,at,loc,game,stakes,hu,min,res}}] sorted newest first
  prefs: null,
  view: 'add', page: 0, type: 'cash', sign: 1, editId: 0,
  bdDim: 'stakes',
};

/* ================= utils ================= */
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function b64(buf) { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000)); return btoa(s); }
function unb64(s) { const b = atob(s); const a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
function hex(buf) { return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join(''); }
function pad(n) { return String(n).padStart(2, '0'); }
function localISO(d) { return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; }
function parseAt(s) { const m = /^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d))?/.exec(s || ''); return m ? new Date(+m[1], m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0)) : new Date(NaN); }
function store(k, v) { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
function load(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 2200); }
function busy(msg) { $('#busyMsg').textContent = msg || ''; $('#busy').hidden = !msg; }

/* money / numbers */
function cur() { return (S.prefs && S.prefs.currency) || 'EUR'; }
const nfCache = {};
function nf(opts) { const k = cur() + JSON.stringify(opts); return nfCache[k] || (nfCache[k] = new Intl.NumberFormat(undefined, { style: 'currency', currency: cur(), ...opts })); }
function money(n, signed = true) {
  const frac = Math.abs(n) < 100 && Math.round(n) !== n ? 2 : 0;
  return nf({ minimumFractionDigits: frac, maximumFractionDigits: frac, signDisplay: signed ? 'exceptZero' : 'auto' }).format(n).replace('-', '−');
}
function moneyShort(n) { return nf({ notation: 'compact', maximumFractionDigits: 1, signDisplay: 'auto' }).format(n).replace('-', '−'); }
function curSymbol() { return (nf({}).formatToParts(0).find(p => p.type === 'currency') || {}).value || cur(); }
function cls(n) { return n > 0 ? 'pos' : n < 0 ? 'neg' : ''; }
function hrs(min) { return (min / 60).toLocaleString(undefined, { maximumFractionDigits: 1 }); }
function hm(min) { const h = Math.floor(min / 60), m = min % 60; return h ? (m ? `${h}h ${m}m` : `${h}h`) : `${m}m`; }
function dateLabel(d, withYear) {
  const now = new Date();
  return d.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', ...((withYear || d.getFullYear() !== now.getFullYear()) ? { year: 'numeric' } : {}) });
}
/* "1/2" -> 2, "€0.5/€1" -> 1, "2/5/10" -> 5, "NL200" -> 2 */
function bigBlind(st) {
  if (!st) return null;
  const s = String(st).replace(/[^\d./a-z]/gi, '');
  const parts = s.split('/').map(x => parseFloat(x.replace(/[a-z]/gi, ''))).filter(x => !isNaN(x));
  if (parts.length >= 2 && parts[1] > 0) return parts[1];
  const nl = /^(?:nl|pl|fl|plo)(\d+(?:\.\d+)?)$/i.exec(s);
  if (nl) return parseFloat(nl[1]) / 100;
  return null;
}
/* "100" -> 100, "50+5" -> 55, "€109" -> 109 */
function buyinAmount(st) {
  if (!st) return null;
  const parts = String(st).replace(/[^\d.+]/g, '').split('+').map(parseFloat).filter(x => !isNaN(x));
  return parts.length ? parts.reduce((a, b) => a + b, 0) : null;
}

/* ================= crypto ================= */
async function deriveKeys(pass, saltB64, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: iter }, base, 256);
  const hk = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const zero = new Uint8Array(32);
  const auth = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: zero, info: te.encode('pkrtrckr auth v1') }, hk, 256);
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: zero, info: te.encode('pkrtrckr enc v1') }, hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { auth: hex(auth), key };
}
async function seal(obj, kind) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode('pkrtrckr:' + kind) }, S.key, te.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function open(box, kind) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv), additionalData: te.encode('pkrtrckr:' + kind) }, S.key, unb64(box.ct));
  return JSON.parse(td.decode(pt));
}

/* ================= api ================= */
async function api(action, body = {}) {
  let r;
  try {
    r = await fetch(`${API}?a=${action}`, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Pkr': '1' },
      body: JSON.stringify(body),
    });
  } catch (e) { throw new Error('Can’t reach the server. Check your connection.'); }
  let data = {};
  try { data = await r.json(); } catch (e) { /* non-JSON */ }
  if (r.status === 401 && S.key && !['login', 'delete_account'].includes(action)) { lock('You were signed out. Sign in again.'); throw new Error('Signed out'); }
  if (!r.ok) throw new Error(data.error || `Server error (${r.status})`);
  return data;
}

/* ================= auth ================= */
let authMode = 'login';
function setAuthMode(m) {
  authMode = m;
  $$('#authTabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.mode === m)));
  $('#authPass2Wrap').hidden = $('#signupNote').hidden = m !== 'signup';
  $('#authPass').autocomplete = m === 'signup' ? 'new-password' : 'current-password';
  $('#authBtn').textContent = m === 'signup' ? 'Create account' : 'Sign in';
  $('#authErr').textContent = '';
}
async function onAuth(e) {
  e.preventDefault();
  const err = $('#authErr'); err.textContent = '';
  const name = $('#authName').value.trim().toLowerCase();
  const pass = $('#authPass').value;
  if (!/^[a-z0-9._-]{3,32}$/.test(name)) { err.textContent = 'Name must be 3–32 characters: letters, numbers, dot, dash or underscore.'; return; }
  if (!crypto || !crypto.subtle) { err.textContent = 'This browser can’t encrypt. Use an up-to-date browser over HTTPS.'; return; }
  if (authMode === 'signup') {
    if (pass.length < 10) { err.textContent = 'Use a passphrase of at least 10 characters.'; return; }
    if (pass !== $('#authPass2').value) { err.textContent = 'The passphrases don’t match.'; return; }
  } else if (!pass) { err.textContent = 'Enter your passphrase.'; return; }
  $('#authBtn').disabled = true;
  busy(authMode === 'signup' ? 'Creating your encryption key…' : 'Unlocking…');
  try {
    let salt, iter;
    if (authMode === 'signup') {
      salt = b64(crypto.getRandomValues(new Uint8Array(16))); iter = DEFAULT_ITER;
    } else {
      const p = await api('prelogin', { username: name }); salt = p.salt; iter = p.iter;
    }
    const k = await deriveKeys(pass, salt, iter);
    await api(authMode, { username: name, auth: k.auth, salt, iter });
    Object.assign(S, { name, key: k.key, auth: k.auth, salt, iter });
    store('pkr.name', name);
    $('#authPass').value = $('#authPass2').value = '';
    await loadData();
    enterApp();
    if (authMode === 'signup') toast('Account created');
  } catch (ex) {
    err.textContent = ex.message;
  } finally {
    busy(); $('#authBtn').disabled = false;
  }
}
function lock(msg) {
  S.key = null; S.auth = ''; S.entries = []; S.prefs = null; S.editId = 0;
  $('#app').hidden = true; $('#auth').hidden = false;
  if ($('#settings').open) $('#settings').close();
  setAuthMode('login');
  $('#authName').value = S.name || load('pkr.name') || '';
  $('#authErr').textContent = msg || '';
  ($('#authName').value ? $('#authPass') : $('#authName')).focus();
}
let idleT, lastPing = 0;
function activity() {
  if (!S.key) return;
  clearTimeout(idleT);
  idleT = setTimeout(() => { api('logout').catch(() => {}); lock('Signed out after 15 minutes of inactivity.'); }, IDLE_MS);
  // keep the server session alive while the user is active
  if (Date.now() - lastPing > 5 * 60 * 1000) { lastPing = Date.now(); api('ping').catch(() => {}); }
}

/* ================= data ================= */
function defaultPrefs() {
  return { v: 1, currency: 'EUR', lists: { locations: [], games: ["NL Hold'em", 'PLO'], stakes: [], buyins: [] }, type: 'cash' };
}
async function loadData() {
  const data = await api('data');
  S.prefs = data.prefs ? { ...defaultPrefs(), ...(await open(data.prefs, 'prefs')) } : defaultPrefs();
  for (const k of Object.keys(LISTS)) if (!Array.isArray(S.prefs.lists[k])) S.prefs.lists[k] = [];
  const out = [];
  let bad = 0;
  for (const e of data.entries) {
    try { out.push({ id: e.id, d: await open(e, 'entry') }); } catch (x) { bad++; }
  }
  if (bad) toast(`${bad} session(s) couldn’t be decrypted`);
  S.entries = out; sortEntries();
  if (!data.prefs) await savePrefs();
}
function sortEntries() { S.entries.sort((a, b) => (b.d.at || '').localeCompare(a.d.at || '') || b.id - a.id); }
let prefsT;
function savePrefs(later) {
  clearTimeout(prefsT);
  const go = async () => { const box = await seal(S.prefs, 'prefs'); await api('prefs', box); };
  if (later) { prefsT = setTimeout(() => go().catch(e => toast(e.message)), 600); return Promise.resolve(); }
  return go();
}
function listKey(kind) { return kind === 'stakes' && S.type === 'tourney' ? 'buyins' : kind; }
function bump(list, val) {
  if (!val) return false;
  const arr = S.prefs.lists[list]; const i = arr.indexOf(val);
  if (i === 0) return false;
  if (i > 0) arr.splice(i, 1);
  arr.unshift(val); return true;
}

/* ================= app shell ================= */
function enterApp() {
  $('#auth').hidden = true; $('#app').hidden = false;
  $('#curSym').textContent = curSymbol();
  S.type = S.prefs.type === 'tourney' ? 'tourney' : 'cash';
  resetForm();
  go('add');
  activity.at = Date.now();
  activity();
}
function go(view) {
  S.view = view;
  $$('.view').forEach(v => v.hidden = v.dataset.view !== view);
  $$('.tabs button').forEach(b => b.dataset.go === view ? b.setAttribute('aria-current', 'page') : b.removeAttribute('aria-current'));
  if (view === 'list') renderList();
  if (view === 'stats') renderStats();
  if (view === 'add') renderRecent();
  window.scrollTo(0, 0);
}

/* ================= entry form ================= */
function setType(t) {
  S.type = t;
  $$('#typeSeg button').forEach(b => b.setAttribute('aria-checked', String(b.dataset.type === t)));
  $('#stakesLabel').textContent = t === 'tourney' ? 'Buy-in' : 'Stakes';
  $('#stakesNew').placeholder = t === 'tourney' ? 'e.g. 100 or 50+5' : 'e.g. 1/2 or 2/5';
  $('#stakesCombo .add-btn').setAttribute('aria-label', t === 'tourney' ? 'Add buy-in' : 'Add stakes');
  toggleAdd($('#stakesCombo'), false);
  // Cash stakes and tournament buy-ins are separate lists: never carry the other format's value over.
  fillSelect('stakes', '');
}
function setSign(s) { S.sign = s; $$('#pmSeg button').forEach(b => b.setAttribute('aria-checked', String(+b.dataset.sign === s))); }
const SELECTS = { locations: '#fLocation', games: '#fGame', stakes: '#fStakes' };
function fillSelect(kind, keep) {
  const sel = $(SELECTS[kind]); const list = S.prefs.lists[listKey(kind)];
  const cur = keep !== undefined ? keep : sel.value;
  const vals = [...list];
  if (cur && !vals.includes(cur)) vals.unshift(cur); // editing an entry whose value was removed from the list
  const noun = { locations: 'a location', games: 'a game', stakes: S.type === 'tourney' ? 'a buy-in' : 'stakes' }[kind];
  sel.innerHTML = vals.length
    ? vals.map(v => `<option>${esc(v)}</option>`).join('')
    : `<option value="" disabled selected>Tap + to add ${noun}</option>`;
  if (cur && vals.includes(cur)) sel.value = cur;
  else if (vals.length) sel.value = vals[0];
}
function toggleAdd(combo, show) {
  const row = $('.add-row', combo), btn = $('.add-btn', combo);
  const on = show ?? row.hidden;
  row.hidden = !on; btn.setAttribute('aria-expanded', String(on));
  if (on) $('input', row).focus();
}
function addToList(combo) {
  const kind = combo.dataset.list; const inp = $('.add-row input', combo);
  const v = inp.value.trim().replace(/\s+/g, ' ');
  if (!v) { inp.focus(); return; }
  const lk = listKey(kind);
  const existing = S.prefs.lists[lk].find(x => x.toLowerCase() === v.toLowerCase());
  bump(lk, existing || v);
  savePrefs(true);
  fillSelect(kind, existing || v);
  inp.value = ''; toggleAdd(combo, false);
}
function minutesHint() { const m = parseInt($('#fMinutes').value, 10); $('#minHint').innerHTML = m > 0 ? `= ${hm(m)}` : '&nbsp;'; }
function whenSummary() {
  const v = $('#fWhen').value; const d = parseAt(v);
  const now = new Date();
  $('#whenSummary').textContent = isNaN(d) ? '' : (Math.abs(now - d) < 5 * 60000 ? 'Now' : `${dateLabel(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}`);
}
function resetForm() {
  S.editId = 0;
  $('#formTitle').textContent = 'New session';
  $('#saveBtn').textContent = 'Save session';
  $('#cancelEdit').hidden = $('#deleteEntry').hidden = true;
  setType(S.type);
  ['locations', 'games', 'stakes'].forEach(k => fillSelect(k, ''));
  $('#fHU').checked = false;
  $('#fMinutes').value = ''; $('#fAmount').value = ''; setSign(1);
  $('#fWhen').value = localISO(new Date());
  $('.more').open = false;
  $('#formErr').textContent = '';
  $$('.combo').forEach(c => toggleAdd(c, false));
  minutesHint(); whenSummary();
}
function editEntry(id) {
  const e = S.entries.find(x => x.id === id); if (!e) return;
  go('add');
  const d = e.d;
  S.editId = id;
  $('#formTitle').textContent = 'Edit session';
  $('#saveBtn').textContent = 'Save changes';
  $('#cancelEdit').hidden = $('#deleteEntry').hidden = false;
  setType(d.t === 'tourney' ? 'tourney' : 'cash');
  fillSelect('locations', d.loc); fillSelect('games', d.game); fillSelect('stakes', d.stakes);
  $('#fHU').checked = !!d.hu;
  $('#fMinutes').value = d.min; setSign(d.res < 0 ? -1 : 1); $('#fAmount').value = Math.abs(d.res);
  $('#fWhen').value = d.at; $('.more').open = true;
  minutesHint(); whenSummary();
  $('#recentBox').innerHTML = '';
}
async function onSave(e) {
  e.preventDefault();
  const err = $('#formErr'); err.textContent = '';
  const d = {
    t: S.type,
    at: $('#fWhen').value || localISO(new Date()),
    loc: $('#fLocation').value, game: $('#fGame').value, stakes: $('#fStakes').value,
    hu: $('#fHU').checked,
    min: parseInt($('#fMinutes').value, 10),
    res: Math.round(S.sign * parseFloat(String($('#fAmount').value).replace(',', '.')) * 100) / 100,
  };
  const label = S.type === 'tourney' ? 'buy-in' : 'stakes';
  if (!d.loc) return void (err.textContent = 'Add a location with +.');
  if (!d.game) return void (err.textContent = 'Add a game with +.');
  if (!d.stakes) return void (err.textContent = `Add ${label} with +.`);
  if (!(d.min > 0 && d.min <= 5000)) return void (err.textContent = 'Enter the duration in minutes.');
  if (isNaN(d.res)) return void (err.textContent = 'Enter the result (0 for break-even).');
  if (Object.is(d.res, -0)) d.res = 0;
  if (isNaN(parseAt(d.at))) return void (err.textContent = 'Check the date and time.');
  $('#saveBtn').disabled = true;
  try {
    const box = await seal(d, 'entry');
    const r = await api('save', { ...box, id: S.editId || undefined });
    const ex = S.entries.find(x => x.id === r.id);
    if (ex) ex.d = d; else S.entries.push({ id: r.id, d });
    sortEntries();
    let changed = false;
    changed = bump('locations', d.loc) || changed;
    changed = bump('games', d.game) || changed;
    changed = bump(d.t === 'tourney' ? 'buyins' : 'stakes', d.stakes) || changed;
    if (S.prefs.type !== d.t) { S.prefs.type = d.t; changed = true; }
    if (changed) savePrefs(true);
    toast(`${S.editId ? 'Updated' : 'Saved'} · ${money(d.res)}`);
    const wasEdit = !!S.editId;
    resetForm();
    if (wasEdit) go('list'); else renderRecent();
  } catch (ex) { err.textContent = ex.message; }
  finally { $('#saveBtn').disabled = false; }
}
async function onDelete() {
  if (!S.editId || !confirm('Delete this session?')) return;
  try {
    await api('delete', { id: S.editId });
    S.entries = S.entries.filter(x => x.id !== S.editId);
    resetForm(); toast('Session deleted'); go('list');
  } catch (ex) { $('#formErr').textContent = ex.message; }
}

/* ================= list ================= */
function sessItem(e) {
  const d = e.d; const at = parseAt(d.at);
  return `<li><button class="sess" data-id="${e.id}" type="button">
    <span class="l1">${esc(d.loc)}${d.hu ? '<span class="badge hu">HU</span>' : ''}${d.t === 'tourney' ? '<span class="badge">MTT</span>' : ''}</span>
    <span class="amt ${cls(d.res)}">${money(d.res)}<small>${hm(d.min)}</small></span>
    <span class="l2">${esc(dateLabel(at))} · ${esc(d.game)} · ${esc(d.stakes)}</span>
  </button></li>`;
}
function renderList() {
  const n = S.entries.length;
  const pages = Math.max(1, Math.ceil(n / PAGE));
  S.page = Math.min(Math.max(0, S.page), pages - 1);
  const slice = S.entries.slice(S.page * PAGE, S.page * PAGE + PAGE);
  $('#listCount').textContent = n ? `${n} total` : '';
  $('#sessionList').innerHTML = n ? slice.map(sessItem).join('') : '<li class="empty">No sessions yet. Add your first one from the Add tab.</li>';
  $('#pager').hidden = n <= PAGE;
  $('#pageInfo').textContent = `${S.page * PAGE + 1}–${Math.min(n, S.page * PAGE + PAGE)} of ${n}`;
  $('#prevPage').disabled = S.page === 0;
  $('#nextPage').disabled = S.page >= pages - 1;
}
function renderRecent() {
  if (S.editId) return;
  const r = S.entries.slice(0, 3);
  $('#recentBox').innerHTML = r.length ? `<h3>Recent</h3><ul class="sessions">${r.map(sessItem).join('')}</ul>` : '';
}

/* ================= stats ================= */
const FILTER_IDS = ['flPeriod', 'flType', 'flGame', 'flStakes', 'flLocation', 'flHU'];
function uniq(key) { return [...new Set(S.entries.map(e => e.d[key]).filter(Boolean))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })); }
function fillFilter(id, all, vals) {
  const sel = $('#' + id); const v = sel.value;
  sel.innerHTML = `<option value="">${all}</option>` + vals.map(x => `<option>${esc(x)}</option>`).join('');
  sel.value = vals.includes(v) ? v : '';
}
function getFiltered() {
  const f = Object.fromEntries(FILTER_IDS.map(id => [id, $('#' + id).value]));
  const now = new Date(); let from = null, to = null;
  const day = 864e5;
  switch (f.flPeriod) {
    case '30': case '90': case '365': from = new Date(now - (+f.flPeriod) * day); break;
    case 'ytd': from = new Date(now.getFullYear(), 0, 1); break;
    case 'lastyear': from = new Date(now.getFullYear() - 1, 0, 1); to = new Date(now.getFullYear(), 0, 1); break;
    case 'custom': {
      const a = $('#flFrom').value, b = $('#flTo').value;
      if (a) from = parseAt(a); if (b) { to = parseAt(b); to = new Date(to.getTime() + day); }
    }
  }
  return S.entries.filter(({ d }) => {
    if (f.flType && d.t !== f.flType) return false;
    if (f.flGame && d.game !== f.flGame) return false;
    if (f.flStakes && d.stakes !== f.flStakes) return false;
    if (f.flLocation && d.loc !== f.flLocation) return false;
    if (f.flHU === 'hu' && !d.hu) return false;
    if (f.flHU === 'ring' && d.hu) return false;
    if (from || to) { const t = parseAt(d.at); if (from && t < from) return false; if (to && t >= to) return false; }
    return true;
  }).map(e => e.d).sort((a, b) => a.at.localeCompare(b.at));
}
function agg(list) {
  const n = list.length, net = list.reduce((s, d) => s + d.res, 0), min = list.reduce((s, d) => s + d.min, 0);
  return { n, net, min, hourly: min ? net / (min / 60) : 0 };
}
function renderStats() {
  const t = $('#flType').value;
  fillFilter('flGame', 'All games', uniq('game'));
  fillFilter('flStakes', t === 'tourney' ? 'All buy-ins' : t === 'cash' ? 'All stakes' : 'All stakes / buy-ins',
    [...new Set(S.entries.filter(e => !t || e.d.t === t).map(e => e.d.stakes))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })));
  fillFilter('flLocation', 'All locations', uniq('loc'));
  $('#customRange').hidden = $('#flPeriod').value !== 'custom';
  FILTER_IDS.forEach(id => $('#' + id).classList.toggle('on', !!$('#' + id).value && $('#' + id).value !== 'all'));

  const L = getFiltered();
  const body = $('#statsBody');
  if (!S.entries.length) { body.innerHTML = '<div class="empty">Add a few sessions and your stats will appear here.</div>'; return; }
  if (!L.length) { body.innerHTML = '<div class="empty">No sessions match these filters.</div>'; return; }

  const A = agg(L);
  const wins = L.filter(d => d.res > 0).length;
  const best = L.reduce((m, d) => d.res > m.res ? d : m, L[0]);
  const worst = L.reduce((m, d) => d.res < m.res ? d : m, L[0]);
  // bb/hour over cash sessions whose stakes parse
  const cashBB = L.filter(d => d.t !== 'tourney').map(d => ({ d, bb: bigBlind(d.stakes) })).filter(x => x.bb);
  const bbMin = cashBB.reduce((s, x) => s + x.d.min, 0);
  const bbHr = bbMin ? cashBB.reduce((s, x) => s + x.d.res / x.bb, 0) / (bbMin / 60) : null;
  // ROI over tournaments whose buy-in parses (result is net, so ROI = net / buy-ins)
  const tour = L.filter(d => d.t === 'tourney').map(d => ({ d, bi: buyinAmount(d.stakes) })).filter(x => x.bi);
  const biSum = tour.reduce((s, x) => s + x.bi, 0);
  const roi = biSum ? tour.reduce((s, x) => s + x.d.res, 0) / biSum : null;

  const tile = (k, v, s, c = '') => `<div class="tile"><div class="k">${k}</div><div class="v ${c}">${v}</div>${s ? `<div class="s">${s}</div>` : ''}</div>`;
  const span = `${dateLabel(parseAt(L[0].at), true)} – ${dateLabel(parseAt(L[L.length - 1].at), true)}`;
  body.innerHTML = `
    <div class="hero"><div class="k">Net result</div><div class="v ${cls(A.net)}">${money(A.net)}</div>
      <div class="sub">${money(A.hourly)} per hour · ${hrs(A.min)} h · ${A.n} session${A.n === 1 ? '' : 's'}</div></div>
    <div class="tiles">
      ${tile('Hourly', money(A.hourly), 'net ÷ hours', cls(A.hourly))}
      ${tile('Hours played', hrs(A.min), `avg ${hm(Math.round(A.min / A.n))} / session`)}
      ${tile('Winning sessions', Math.round(wins / A.n * 100) + '%', `${wins} of ${A.n}`)}
      ${tile('Avg per session', money(A.net / A.n), '', cls(A.net))}
      ${bbHr !== null ? tile('Big blinds / hour', (bbHr > 0 ? '+' : '') + bbHr.toLocaleString(undefined, { maximumFractionDigits: 1 }).replace('-', '−') + ' bb', `${cashBB.length} cash session${cashBB.length === 1 ? '' : 's'}`, cls(bbHr)) : ''}
      ${roi !== null ? tile('Tournament ROI', (roi > 0 ? '+' : '') + (roi * 100).toFixed(0).replace('-', '−') + '%', `${tour.length} tournament${tour.length === 1 ? '' : 's'}`, cls(roi)) : ''}
      ${tile('Best session', money(best.res), esc(dateLabel(parseAt(best.at))), cls(best.res))}
      ${tile('Worst session', money(worst.res), esc(dateLabel(parseAt(worst.at))), cls(worst.res))}
    </div>
    <div class="card"><h3>Cumulative result</h3><p class="cap">${esc(span)}</p><div class="chart" id="chCum"></div></div>
    <div class="card"><h3 id="perTitle">Results by month</h3><p class="cap">Net per period. Tap a bar for details.</p><div class="chart" id="chPer"></div>
      <div class="legend"><span><i class="lg-pos"></i>Won</span><span><i class="lg-neg"></i>Lost</span></div></div>
    <div class="card"><h3>Breakdown</h3><p class="cap">Sorted by hours played.</p>
      <div class="bd-tabs" id="bdTabs">${Object.entries(BD).map(([k, v]) => `<button type="button" data-k="${k}" aria-pressed="${k === S.bdDim}">${v.label}</button>`).join('')}</div>
      <div id="bdTable"></div></div>`;
  drawCum(L); drawPeriods(L); drawBreakdown(L);
  $('#bdTabs').onclick = e => { const b = e.target.closest('button'); if (!b) return; S.bdDim = b.dataset.k; $$('#bdTabs button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); drawBreakdown(L); };
  renderStats.last = L;
}
const WD = [...Array(7)].map((_, i) => new Date(2024, 0, 1 + i).toLocaleDateString(undefined, { weekday: 'long' })); // Mon..Sun
const BD = {
  stakes: { label: 'Stakes', key: d => d.stakes },
  game: { label: 'Game', key: d => d.game },
  loc: { label: 'Location', key: d => d.loc },
  hu: { label: 'HU vs ring', key: d => d.hu ? 'Heads-up' : 'Ring / full table' },
  type: { label: 'Format', key: d => d.t === 'tourney' ? 'Tournament' : 'Cash game' },
  wd: { label: 'Weekday', key: d => WD[(parseAt(d.at).getDay() + 6) % 7], order: WD },
  len: { label: 'Length', key: d => d.min < 120 ? 'Under 2 h' : d.min < 240 ? '2–4 h' : d.min < 480 ? '4–8 h' : '8 h +', order: ['Under 2 h', '2–4 h', '4–8 h', '8 h +'] },
};
function drawBreakdown(L) {
  const dim = BD[S.bdDim]; const g = new Map();
  for (const d of L) { const k = dim.key(d); if (!g.has(k)) g.set(k, []); g.get(k).push(d); }
  let rows = [...g].map(([k, list]) => ({ k, ...agg(list) }));
  rows.sort(dim.order ? (a, b) => dim.order.indexOf(a.k) - dim.order.indexOf(b.k) : (a, b) => b.min - a.min);
  const maxAbs = Math.max(...rows.map(r => Math.abs(r.net)), 1);
  $('#bdTable').innerHTML = `<table class="bd"><thead><tr><th>${dim.label}</th><th>Sess.</th><th>Hours</th><th>Net</th><th>Per hour</th></tr></thead><tbody>${
    rows.map(r => `<tr><td>${esc(r.k)}</td><td>${r.n}</td><td>${hrs(r.min)}</td>
      <td class="barcell ${cls(r.net)}">${money(r.net)}<span class="mini ${r.net < 0 ? 'n' : 'p'}" data-w="${Math.max(2, Math.abs(r.net) / maxAbs * 100).toFixed(1)}"></span></td>
      <td class="${cls(r.hourly)}">${money(r.hourly)}</td></tr>`).join('')}</tbody></table>`;
  $$('#bdTable .mini').forEach(m => { m.style.width = m.dataset.w + '%'; }); // CSSOM, allowed by the CSP
}

/* ---------- SVG charts ---------- */
const NS = 'http://www.w3.org/2000/svg';
function niceTicks(min, max, count = 4) {
  if (min === max) { min -= 1; max += 1; }
  const span = max - min, step0 = span / count, mag = Math.pow(10, Math.floor(Math.log10(step0)));
  const step = [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => s >= step0) || 10 * mag;
  const lo = Math.floor(min / step) * step, hi = Math.ceil(max / step) * step;
  const t = []; for (let v = lo; v <= hi + step / 2; v += step) t.push(Math.round(v * 1e6) / 1e6);
  return t;
}
function svgEl(tag, attrs) { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; }
function frame(el, H) {
  el.innerHTML = '';
  const W = Math.max(260, el.clientWidth);
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img' });
  el.appendChild(svg);
  const tip = document.createElement('div'); tip.className = 'tip'; tip.hidden = true; el.appendChild(tip);
  return { svg, tip, W, H };
}
function yAxis(svg, ticks, y, x0, x1) {
  const g = svgEl('g', {});
  for (const v of ticks) {
    g.appendChild(svgEl('line', { x1: x0, x2: x1, y1: y(v), y2: y(v), class: v === 0 ? 'zero' : 'grid' }));
    const t = svgEl('text', { x: x0 - 6, y: y(v) + 4, 'text-anchor': 'end' }); t.textContent = moneyShort(v); g.appendChild(t);
  }
  svg.appendChild(g);
}
function placeTip(tip, el, x, y, html) {
  tip.innerHTML = html; tip.hidden = false;
  const w = tip.offsetWidth, W = el.clientWidth;
  tip.style.left = Math.min(Math.max(x, w / 2), W - w / 2) + 'px';
  tip.style.top = Math.max(y, tip.offsetHeight + 10) + 'px';
}
function drawCum(L) {
  const el = $('#chCum'); if (!el) return;
  const H = Math.round(Math.min(280, Math.max(190, el.clientWidth * 0.55)));
  const { svg, tip, W } = frame(el, H);
  let run = 0; const pts = [{ v: 0, d: null }].concat(L.map(d => ({ v: (run += d.res), d })));
  const vals = pts.map(p => p.v); const ticks = niceTicks(Math.min(0, ...vals), Math.max(0, ...vals));
  const padL = 46, padR = 10, padT = 10, padB = 24;
  const x = i => padL + (pts.length > 1 ? i / (pts.length - 1) : 0.5) * (W - padL - padR);
  const y = v => padT + (1 - (v - ticks[0]) / (ticks[ticks.length - 1] - ticks[0])) * (H - padT - padB);
  yAxis(svg, ticks, y, padL, W - padR);
  const line = pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.v).toFixed(1)}`).join('');
  svg.appendChild(svgEl('path', { d: `${line}L${x(pts.length - 1)},${y(0)}L${x(0)},${y(0)}Z`, class: 'area' }));
  svg.appendChild(svgEl('path', { d: line, class: 'line' }));
  // x labels: first and last date
  const xl = (i, anchor) => { const t = svgEl('text', { x: x(i), y: H - 6, 'text-anchor': anchor }); t.textContent = parseAt(pts[i].d.at).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: '2-digit' }); svg.appendChild(t); };
  xl(1, 'start'); if (pts.length > 2) xl(pts.length - 1, 'end');
  // last value label
  const last = pts[pts.length - 1];
  const xh = svgEl('line', { class: 'xh', y1: padT, y2: H - padB, visibility: 'hidden' });
  const dot = svgEl('circle', { r: 5, class: 'dot', visibility: 'hidden' });
  svg.append(xh, dot);
  svg.appendChild(svgEl('circle', { r: 4, class: 'dot', cx: x(pts.length - 1), cy: y(last.v) }));
  const show = ev => {
    const r = svg.getBoundingClientRect(); const px = (ev.clientX - r.left) * (W / r.width);
    let i = Math.round((px - padL) / ((W - padL - padR) / Math.max(1, pts.length - 1)));
    i = Math.min(pts.length - 1, Math.max(1, i));
    const p = pts[i];
    xh.setAttribute('x1', x(i)); xh.setAttribute('x2', x(i)); xh.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', x(i)); dot.setAttribute('cy', y(p.v)); dot.setAttribute('visibility', 'visible');
    placeTip(tip, el, x(i) * r.width / W, y(p.v) * r.height / H,
      `<b>${money(p.v)}</b>${esc(dateLabel(parseAt(p.d.at), true))}<br>Session ${i}: <span class="${cls(p.d.res)}">${money(p.d.res)}</span> · ${hm(p.d.min)}<br>${esc(p.d.stakes)} ${esc(p.d.game)}`);
  };
  const hide = () => { tip.hidden = true; xh.setAttribute('visibility', 'hidden'); dot.setAttribute('visibility', 'hidden'); };
  svg.addEventListener('pointermove', show); svg.addEventListener('pointerdown', show); svg.addEventListener('pointerleave', hide);
  svg.setAttribute('aria-label', `Cumulative result, ending at ${money(last.v)} after ${L.length} sessions`);
}
function drawPeriods(L) {
  const el = $('#chPer'); if (!el) return;
  const first = parseAt(L[0].at), lastD = parseAt(L[L.length - 1].at);
  const months = (lastD.getFullYear() - first.getFullYear()) * 12 + lastD.getMonth() - first.getMonth() + 1;
  const mode = months > 36 ? 'year' : months >= 2 ? 'month' : 'day';
  $('#perTitle').textContent = { year: 'Results by year', month: 'Results by month', day: 'Results by day' }[mode];
  const keyOf = d => { const t = parseAt(d.at); return mode === 'year' ? `${t.getFullYear()}` : mode === 'month' ? `${t.getFullYear()}-${pad(t.getMonth() + 1)}` : `${t.getFullYear()}-${pad(t.getMonth() + 1)}-${pad(t.getDate())}`; };
  // continuous buckets (show empty months/days as gaps)
  const keys = []; const c = new Date(first.getFullYear(), mode === 'year' ? 0 : first.getMonth(), mode === 'day' ? first.getDate() : 1);
  while (c <= lastD) { keys.push(keyOf({ at: localISO(c) })); if (mode === 'year') c.setFullYear(c.getFullYear() + 1); else if (mode === 'month') c.setMonth(c.getMonth() + 1); else c.setDate(c.getDate() + 1); }
  const g = new Map(keys.map(k => [k, []])); L.forEach(d => g.get(keyOf(d))?.push(d));
  const B = keys.map(k => ({ k, ...agg(g.get(k)) }));
  const H = Math.round(Math.min(240, Math.max(170, el.clientWidth * 0.48)));
  const { svg, tip, W } = frame(el, H);
  const ticks = niceTicks(Math.min(0, ...B.map(b => b.net)), Math.max(0, ...B.map(b => b.net)));
  const padL = 46, padR = 6, padT = 10, padB = 24;
  const y = v => padT + (1 - (v - ticks[0]) / (ticks[ticks.length - 1] - ticks[0])) * (H - padT - padB);
  yAxis(svg, ticks, y, padL, W - padR);
  const slot = (W - padL - padR) / B.length, gap = Math.min(2 + slot * 0.25, 10), bw = Math.max(1, slot - gap);
  const label = (k, short) => {
    if (mode === 'year') return k;
    const [yy, mm, dd] = k.split('-').map(Number);
    return mode === 'month'
      ? new Date(yy, mm - 1, 1).toLocaleDateString(undefined, short ? (months > 12 ? { month: 'short', year: '2-digit' } : { month: 'short' }) : { month: 'long', year: 'numeric' })
      : new Date(yy, mm - 1, dd).toLocaleDateString(undefined, short ? { day: 'numeric' } : { weekday: 'short', day: 'numeric', month: 'short' });
  };
  const every = Math.ceil(B.length / Math.max(1, Math.floor((W - padL) / (mode === 'month' && months > 12 ? 58 : 44))));
  B.forEach((b, i) => {
    const x0 = padL + i * slot + gap / 2;
    if (b.n) {
      const y0 = y(0), y1 = y(b.net), h = Math.abs(y1 - y0), r = Math.min(4, bw / 2, h);
      const top = Math.min(y0, y1);
      const d = b.net >= 0
        ? `M${x0},${y0}V${top + r}Q${x0},${top} ${x0 + r},${top}H${x0 + bw - r}Q${x0 + bw},${top} ${x0 + bw},${top + r}V${y0}Z`
        : `M${x0},${y0}V${y1 - r}Q${x0},${y1} ${x0 + r},${y1}H${x0 + bw - r}Q${x0 + bw},${y1} ${x0 + bw},${y1 - r}V${y0}Z`;
      const bar = svgEl('path', { d: h < 0.5 ? `M${x0},${y0 - 1}h${bw}v2h${-bw}Z` : d, class: b.net >= 0 ? 'bar-pos' : 'bar-neg' });
      svg.appendChild(bar);
      const hit = svgEl('rect', { x: padL + i * slot, y: padT, width: slot, height: H - padT - padB, class: 'hit' });
      const on = () => {
        $$('.bar-hover', svg).forEach(n => n.classList.remove('bar-hover')); bar.classList.add('bar-hover');
        const r = svg.getBoundingClientRect();
        placeTip(tip, el, (x0 + bw / 2) * r.width / W, Math.min(y0, y1) * r.height / H,
          `<b class="${cls(b.net)}">${money(b.net)}</b>${esc(label(b.k))}<br>${b.n} session${b.n === 1 ? '' : 's'} · ${hrs(b.min)} h · ${money(b.hourly)}/h`);
      };
      hit.addEventListener('pointerenter', on); hit.addEventListener('pointerdown', on);
      svg.appendChild(hit);
    }
    if (i % every === 0) { const t = svgEl('text', { x: x0 + bw / 2, y: H - 6, 'text-anchor': 'middle' }); t.textContent = label(b.k, true); svg.appendChild(t); }
  });
  svg.addEventListener('pointerleave', () => { tip.hidden = true; $$('.bar-hover', svg).forEach(n => n.classList.remove('bar-hover')); });
  svg.setAttribute('aria-label', `Results by ${mode}`);
}

/* ================= settings ================= */
function renderListsEditor() {
  $('#listsEditor').innerHTML = Object.entries(LISTS).map(([k, label]) => {
    const arr = S.prefs.lists[k];
    return `<div class="lst"><h4>${label}</h4><div class="chips">${arr.length ? arr.map((v, i) => `<span class="chip">${esc(v)}<button type="button" data-l="${k}" data-i="${i}" aria-label="Remove ${esc(v)}">✕</button></span>`).join('') : '<span class="muted small">Empty</span>'}</div></div>`;
  }).join('');
}
function openSettings() {
  $('#whoami').textContent = `Signed in as ${S.name} · ${S.entries.length} session${S.entries.length === 1 ? '' : 's'}`;
  $('#setCurrency').value = cur();
  $('#setErr').textContent = '';
  renderListsEditor();
  $('#settings').showModal();
}
function csvCell(v) {
  v = String(v ?? '');
  if (/^[=+\-@]/.test(v) && isNaN(+v)) v = "'" + v; // stop spreadsheet formula injection
  return /[",;\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}
function exportCsv() {
  const rows = [['date', 'type', 'location', 'game', 'stakes', 'hu', 'minutes', 'result']];
  [...S.entries].reverse().forEach(({ d }) => rows.push([d.at.replace('T', ' '), d.t === 'tourney' ? 'tournament' : 'cash', d.loc, d.game, d.stakes, d.hu ? 1 : 0, d.min, d.res]));
  const blob = new Blob(['﻿' + rows.map(r => r.map(csvCell).join(',')).join('\r\n')], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `pkrtrckr-${localISO(new Date()).slice(0, 10)}.csv`; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function parseCsv(text) {
  const rows = []; let row = [], f = '', q = false;
  text = text.replace(/^﻿/, '');
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) { if (ch === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += ch; }
    else if (ch === '"') q = true;
    else if (ch === ',' || ch === ';') { row.push(f); f = ''; }
    else if (ch === '\n' || ch === '\r') { if (ch === '\r' && text[i + 1] === '\n') i++; row.push(f); rows.push(row); row = []; f = ''; }
    else f += ch;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  return rows.filter(r => r.some(c => c.trim()));
}
async function importCsv(file) {
  const err = $('#setErr'); err.textContent = '';
  try {
    const rows = parseCsv(await file.text());
    if (rows.length < 2) throw new Error('The file has no rows.');
    const h = rows[0].map(x => x.trim().toLowerCase());
    const col = (...names) => h.findIndex(x => names.includes(x));
    const C = { at: col('date', 'datetime', 'start', 'end'), t: col('type', 'format'), loc: col('location', 'venue', 'place'), game: col('game'), stakes: col('stakes', 'limit', 'buyin', 'buy-in'), hu: col('hu', 'headsup', 'heads-up'), min: col('minutes', 'duration', 'mins'), res: col('result', 'profit', 'net', 'amount') };
    if (C.at < 0 || C.min < 0 || C.res < 0) throw new Error('Need at least these columns: date, minutes, result.');
    const items = [];
    for (const r of rows.slice(1)) {
      const g = k => (C[k] >= 0 ? (r[C[k]] || '').trim().replace(/^'/, '') : '');
      const at = parseAt(g('at'));
      const res = parseFloat(g('res').replace(/[^\d.,\-−]/g, '').replace('−', '-').replace(',', '.'));
      const min = parseInt(g('min'), 10);
      if (isNaN(at) || isNaN(res) || !(min > 0)) continue;
      const t = /tour|mtt|sng|sit/i.test(g('t')) ? 'tourney' : 'cash';
      items.push({ t, at: localISO(at), loc: g('loc') || 'Unknown', game: g('game') || 'Unknown', stakes: g('stakes') || '?', hu: /^(1|true|yes|y|hu|x)$/i.test(g('hu')), min, res: Math.round(res * 100) / 100 });
    }
    if (!items.length) throw new Error('No valid rows found.');
    if (!confirm(`Import ${items.length} session${items.length === 1 ? '' : 's'}?`)) return;
    busy(`Encrypting ${items.length} sessions…`);
    for (let i = 0; i < items.length; i += 1000) {
      const chunk = items.slice(i, i + 1000);
      const boxes = []; for (const d of chunk) boxes.push(await seal(d, 'entry'));
      const r = await api('import', { items: boxes });
      r.ids.forEach((id, j) => S.entries.push({ id, d: chunk[j] }));
    }
    sortEntries();
    for (const d of items) for (const [k, v] of [['locations', d.loc], ['games', d.game], [d.t === 'tourney' ? 'buyins' : 'stakes', d.stakes]]) if (!S.prefs.lists[k].includes(v)) S.prefs.lists[k].push(v);
    await savePrefs();
    renderListsEditor(); resetForm(); renderRecent();
    toast(`Imported ${items.length} sessions`);
  } catch (ex) { err.textContent = ex.message; }
  finally { busy(); $('#importCsv').value = ''; }
}
async function deleteAccount() {
  const err = $('#setErr'); err.textContent = '';
  if (!confirm(`Permanently delete the account "${S.name}" and all ${S.entries.length} sessions? This can’t be undone.`)) return;
  const pass = prompt('Type your passphrase to confirm');
  if (!pass) return;
  busy('Deleting…');
  try {
    const k = await deriveKeys(pass, S.salt, S.iter);
    await api('delete_account', { auth: k.auth });
    store('pkr.name', null); S.name = '';
    lock('Account deleted.');
  } catch (ex) { err.textContent = ex.message; }
  finally { busy(); }
}

/* ================= wire up ================= */
function init() {
  $('#authTabs').addEventListener('click', e => { const b = e.target.closest('button'); if (b) setAuthMode(b.dataset.mode); });
  $('#authForm').addEventListener('submit', onAuth);

  $$('.tabs button').forEach(b => b.addEventListener('click', () => { if (b.dataset.go === 'add' && S.editId) resetForm(); go(b.dataset.go); }));
  $('#typeSeg').addEventListener('click', e => { const b = e.target.closest('button'); if (b) setType(b.dataset.type); });
  $('#pmSeg').addEventListener('click', e => { const b = e.target.closest('button'); if (b) setSign(+b.dataset.sign); });
  $$('.combo').forEach(c => {
    $('.add-btn', c).addEventListener('click', () => toggleAdd(c));
    $('.add-row .btn', c).addEventListener('click', () => addToList(c));
    $('.add-row input', c).addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addToList(c); } if (e.key === 'Escape') toggleAdd(c, false); });
  });
  $('#fMinutes').addEventListener('input', minutesHint);
  $('#fWhen').addEventListener('input', whenSummary);
  $('#fAmount').addEventListener('input', e => { const v = e.target.value; if (v.startsWith('-')) { e.target.value = v.slice(1); setSign(-1); } });
  $('#entryForm').addEventListener('submit', onSave);
  $('#cancelEdit').addEventListener('click', () => { resetForm(); go('list'); });
  $('#deleteEntry').addEventListener('click', onDelete);

  const openFromList = e => { const b = e.target.closest('.sess'); if (b) editEntry(+b.dataset.id); };
  $('#sessionList').addEventListener('click', openFromList);
  $('#recentBox').addEventListener('click', openFromList);
  $('#prevPage').addEventListener('click', () => { S.page--; renderList(); window.scrollTo(0, 0); });
  $('#nextPage').addEventListener('click', () => { S.page++; renderList(); window.scrollTo(0, 0); });

  [...FILTER_IDS, 'flFrom', 'flTo'].forEach(id => $('#' + id).addEventListener('change', renderStats));
  $('#flReset').addEventListener('click', () => { FILTER_IDS.forEach(id => $('#' + id).value = id === 'flPeriod' ? 'all' : ''); $('#flFrom').value = $('#flTo').value = ''; renderStats(); });
  let rz; window.addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(() => { if (S.view === 'stats' && renderStats.last) { drawCum(renderStats.last); drawPeriods(renderStats.last); } }, 150); });

  $('#menuBtn').addEventListener('click', openSettings);
  $('#settings').addEventListener('click', e => { if (e.target === e.currentTarget) e.currentTarget.close(); });
  $('#setCurrency').addEventListener('change', e => { S.prefs.currency = e.target.value; savePrefs(true); $('#curSym').textContent = curSymbol(); renderRecent(); if (S.view === 'list') renderList(); });
  $('#listsEditor').addEventListener('click', e => {
    const b = e.target.closest('button[data-l]'); if (!b) return;
    S.prefs.lists[b.dataset.l].splice(+b.dataset.i, 1); savePrefs(true); renderListsEditor();
    ['locations', 'games', 'stakes'].forEach(k => fillSelect(k));
  });
  $('#exportCsv').addEventListener('click', exportCsv);
  $('#importCsv').addEventListener('change', e => { if (e.target.files[0]) importCsv(e.target.files[0]); });
  $('#logoutBtn').addEventListener('click', async () => { await api('logout').catch(() => {}); lock(''); });
  $('#deleteAccount').addEventListener('click', deleteAccount);

  ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach(ev => window.addEventListener(ev, activity, { passive: true }));
  document.addEventListener('visibilitychange', () => {
    // If the phone slept past the idle limit, lock as soon as it's visible again.
    if (document.visibilityState === 'visible' && S.key && Date.now() - (activity.at || Date.now()) > IDLE_MS) lock('Signed out after 15 minutes of inactivity.');
  });
  window.addEventListener('pointerdown', () => { activity.at = Date.now(); }, { passive: true });
  window.addEventListener('keydown', () => { activity.at = Date.now(); }, { passive: true });

  S.name = load('pkr.name') || '';
  if (!S.name) setAuthMode('signup');
  lock('');
  if (!S.name) setAuthMode('signup');
}
document.addEventListener('DOMContentLoaded', init);
})();
