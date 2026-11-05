/* pkrtrckr service worker: lets the app open without a connection.
 * Pages: network first (so updates arrive right away), cached copy when offline.
 * Assets: cache first; their URLs carry ?v=N, so a new version is a new URL.
 * The API is never cached — data offline comes from the app's own encrypted copy. */
const CACHE = 'pkr-shell-v1';
const CORE = ['./', 'manifest.webmanifest', 'favicon.ico', 'assets/icon.svg', 'assets/icon-192.png', 'assets/icon-180.png'];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    await c.add('./');
    await Promise.all(CORE.slice(1).map(u => c.add(u).catch(() => {}))); // an icon missing shouldn't block offline mode
    // Also cache the exact CSS/JS versions the current page uses.
    const html = await (await c.match('./')).text();
    const assets = [...html.matchAll(/(?:href|src)="(assets\/[^"]+\.(?:css|js)\?v=[^"]+)"/g)].map(m => m[1]);
    await Promise.all(assets.map(u => c.add(u).catch(() => {})));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

async function timeout(ms) { await new Promise(r => setTimeout(r, ms)); throw new Error('timeout'); }

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin || url.pathname.includes('/api/')) return;

  if (req.mode === 'navigate') {
    e.respondWith((async () => {
      const c = await caches.open(CACHE);
      try {
        const res = await Promise.race([fetch(req), timeout(6000)]);
        if (res.ok && (url.pathname === '/' || url.pathname.endsWith('/index.html'))) c.put('./', res.clone());
        return res;
      } catch (err) {
        return (await c.match(req, { ignoreSearch: true })) || (await c.match('./')) || Response.error();
      }
    })());
    return;
  }

  e.respondWith((async () => {
    const c = await caches.open(CACHE);
    const hit = await c.match(req);
    if (hit) return hit;
    const res = await fetch(req);
    if (res.ok && res.type === 'basic') {
      // Keep only the newest version of each file.
      for (const k of await c.keys()) { const u = new URL(k.url); if (u.pathname === url.pathname && u.search !== url.search) c.delete(k); }
      c.put(req, res.clone());
    }
    return res;
  })());
});
