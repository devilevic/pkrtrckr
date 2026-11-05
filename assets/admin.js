/* pkrtrckr admin dashboard. Shows only counts and dates the server already has;
 * poker sessions are end-to-end encrypted and never visible here. */
'use strict';
(() => {
const API = 'api/index.php';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const te = new TextEncoder();
let DATA = null, DAYS = 30;

function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function unb64(s) { const b = atob(s); const a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
function hex(buf) { return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join(''); }
function busy(msg) { $('#busyMsg').textContent = msg || ''; $('#busy').hidden = !msg; }
function num(n) { return Number(n).toLocaleString(); }
function pct(a, b) { return b ? Math.round(a / b * 100) + '%' : '—'; }
function date(ts) { return ts ? new Date(ts * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '—'; }
function ago(ts) {
  if (!ts) return 'never';
  const s = Date.now() / 1000 - ts;
  if (s < 90) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  if (s < 86400 * 30) return Math.round(s / 86400) + ' d ago';
  return date(ts);
}

async function api(action, body = {}) {
  let r;
  try {
    r = await fetch(`${API}?a=${action}`, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Pkr': '1' }, body: JSON.stringify(body) });
  } catch (e) { throw new Error('Can’t reach the server.'); }
  let data = {}; try { data = await r.json(); } catch (e) { /* non-JSON */ }
  if (!r.ok) { const err = new Error(data.error || `Server error (${r.status})`); err.status = r.status; throw err; }
  return data;
}
// Same derivation as the app; only the auth half is needed here.
async function authKey(pass, saltB64, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: iter }, base, 256);
  const hk = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode('pkrtrckr auth v1') }, hk, 256));
}

function showAuth(msg) {
  $('#dash').hidden = true; $('#auth').hidden = false;
  $('#authErr').textContent = msg || '';
  try { if (!$('#authName').value) $('#authName').value = localStorage.getItem('pkr.name') || ''; } catch (e) { /* private mode */ }
  ($('#authName').value ? $('#authPass') : $('#authName')).focus();
}
async function onAuth(e) {
  e.preventDefault();
  const name = $('#authName').value.trim().toLowerCase(), pass = $('#authPass').value;
  if (!name || !pass) { $('#authErr').textContent = 'Enter your name and passphrase.'; return; }
  $('#authBtn').disabled = true; busy('Signing in…');
  try {
    const p = await api('prelogin', { username: name });
    await api('login', { username: name, auth: await authKey(pass, p.salt, p.iter) });
    $('#authPass').value = '';
    await load();
  } catch (ex) { $('#authErr').textContent = ex.message; }
  finally { busy(); $('#authBtn').disabled = false; }
}

async function load() {
  try {
    DATA = await api('admin_stats');
  } catch (ex) {
    if (ex.status === 401) return showAuth('');
    if (ex.status === 404) return showAuth('This account doesn’t have dashboard access. Add its name to admin_users in api/config.php.');
    return showAuth(ex.message);
  }
  $('#auth').hidden = true; $('#dash').hidden = false;
  render();
}

function render() {
  const t = DATA.totals;
  $('#updated').textContent = `Updated ${new Date(DATA.generated * 1000).toLocaleString()} · days counted in ${DATA.tz}`;
  const tile = (k, v, s) => `<div class="tile"><div class="k">${k}</div><div class="v big">${v}</div>${s ? `<div class="s">${s}</div>` : ''}</div>`;
  $('#tiles').innerHTML = [
    tile('Users', num(t.users), `${num(t.users_with_entries)} logged a session (${pct(t.users_with_entries, t.users)})`),
    tile('New sign-ups', num(t.signups_7), `last 7 days · ${num(t.signups_1)} today · ${num(t.signups_30)} in 30 days`),
    tile('Active users', num(t.active_7), `last 7 days · ${num(t.active_1)} today · ${num(t.active_30)} in 30 days`),
    tile('Sessions logged', num(t.entries), `${num(t.entries_7)} in 7 days · ${num(t.entries_30)} in 30 days`),
  ].join('');
  const S = DATA.series.slice(-DAYS);
  bars($('#chActive'), S, 'active', n => `${n} active user${n === 1 ? '' : 's'}`);
  bars($('#chSignups'), S, 'signups', n => `${n} sign-up${n === 1 ? '' : 's'}`);
  bars($('#chEntries'), S, 'entries', n => `${n} session${n === 1 ? '' : 's'} logged`);
  renderUsers();
}

function renderUsers() {
  const q = $('#userSearch').value.trim().toLowerCase();
  const rows = DATA.users.filter(u => !q || u.username.includes(q));
  $('#usersTable').innerHTML = `<thead><tr><th>Name</th><th>Joined</th><th>Last active</th><th>Logins</th><th>Active days</th><th>Sessions</th></tr></thead><tbody>${
    rows.length ? rows.map(u => `<tr><td>${esc(u.username)}</td><td class="dim">${date(u.created_at)}</td><td>${ago(u.last_seen_at)}</td><td>${num(u.login_count)}</td><td>${num(u.active_days)}</td><td>${num(u.entries)}</td></tr>`).join('')
      : '<tr class="empty-row"><td colspan="6">No users found</td></tr>'}</tbody>`;
}

/* ---- simple single-series bar chart with hover ---- */
const NS = 'http://www.w3.org/2000/svg';
function el(tag, a) { const e = document.createElementNS(NS, tag); for (const k in a) e.setAttribute(k, a[k]); return e; }
function ticks(max) {
  if (max <= 4) return [...Array(Math.max(1, max) + 1).keys()];
  const step0 = max / 4, mag = Math.pow(10, Math.floor(Math.log10(step0)));
  const step = [1, 2, 5, 10].map(m => m * mag).find(s => s >= step0);
  const out = []; for (let v = 0; v < max + step; v += step) out.push(v); return out;
}
function bars(box, S, key, label) {
  box.innerHTML = '';
  const W = Math.max(260, box.clientWidth), H = Math.round(Math.min(220, Math.max(160, W * 0.32)));
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img' });
  box.appendChild(svg);
  const tip = document.createElement('div'); tip.className = 'tip'; tip.hidden = true; box.appendChild(tip);
  const vals = S.map(d => +d[key] || 0), T = ticks(Math.max(...vals, 0)), top = T[T.length - 1];
  const padL = 32, padR = 4, padT = 8, padB = 22;
  const y = v => padT + (1 - v / top) * (H - padT - padB);
  for (const v of T) {
    svg.appendChild(el('line', { x1: padL, x2: W - padR, y1: y(v), y2: y(v), class: v === 0 ? 'zero' : 'grid' }));
    const tx = el('text', { x: padL - 6, y: y(v) + 4, 'text-anchor': 'end' }); tx.textContent = num(v); svg.appendChild(tx);
  }
  const slot = (W - padL - padR) / S.length, gap = Math.min(2 + slot * 0.25, 8), bw = Math.max(1, slot - gap);
  const every = Math.ceil(S.length / Math.max(1, Math.floor((W - padL) / 56)));
  const fmtDay = (d, long) => new Date(d + 'T12:00:00').toLocaleDateString(undefined, long ? { weekday: 'short', day: 'numeric', month: 'short' } : { day: 'numeric', month: 'short' });
  S.forEach((d, i) => {
    const x0 = padL + i * slot + gap / 2, v = vals[i], y0 = y(0), y1 = y(v), r = Math.min(4, bw / 2, y0 - y1);
    let bar = null;
    if (v > 0) {
      bar = el('path', { class: 'bar', d: `M${x0},${y0}V${y1 + r}Q${x0},${y1} ${x0 + r},${y1}H${x0 + bw - r}Q${x0 + bw},${y1} ${x0 + bw},${y1 + r}V${y0}Z` });
      svg.appendChild(bar);
    }
    const hit = el('rect', { x: padL + i * slot, y: padT, width: slot, height: H - padT - padB, class: 'hit' });
    const on = () => {
      $$('.bar-hover', svg).forEach(n => n.classList.remove('bar-hover')); if (bar) bar.classList.add('bar-hover');
      const rc = svg.getBoundingClientRect();
      tip.innerHTML = `<b>${esc(label(v))}</b>${esc(fmtDay(d.d, true))}`; tip.hidden = false;
      const w = tip.offsetWidth, px = (x0 + bw / 2) * rc.width / W;
      tip.style.left = Math.min(Math.max(px, w / 2), box.clientWidth - w / 2) + 'px';
      tip.style.top = Math.max(y1 * rc.height / H, tip.offsetHeight + 10) + 'px';
    };
    hit.addEventListener('pointerenter', on); hit.addEventListener('pointerdown', on);
    svg.appendChild(hit);
    if (i % every === 0) { const tx = el('text', { x: x0 + bw / 2, y: H - 6, 'text-anchor': 'middle' }); tx.textContent = fmtDay(d.d); svg.appendChild(tx); }
  });
  svg.addEventListener('pointerleave', () => { tip.hidden = true; $$('.bar-hover', svg).forEach(n => n.classList.remove('bar-hover')); });
  svg.setAttribute('aria-label', `${key} per day, last ${S.length} days, total ${num(vals.reduce((a, b) => a + b, 0))}`);
}

document.addEventListener('DOMContentLoaded', () => {
  $('#authForm').addEventListener('submit', onAuth);
  $('#refreshBtn').addEventListener('click', async () => { busy('Refreshing…'); try { await load(); } finally { busy(); } });
  $('#rangeSeg').addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    DAYS = +b.dataset.days; $$('#rangeSeg button').forEach(x => x.setAttribute('aria-checked', String(x === b))); render();
  });
  $('#userSearch').addEventListener('input', renderUsers);
  let rz; window.addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(() => DATA && render(), 150); });
  load();
});
})();
