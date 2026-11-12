// Emberwall offline support. The app is a static bundle, so caching what was fetched is enough:
// pages come from the network when it is there (so updates arrive) and from the cache when it is not;
// hashed assets are served from the cache first.
// Both values are filled in at build time by the precache plugin in vite.config.ts.
const ASSETS = /*__PRECACHE__*/ ['./', './favicon.svg', './manifest.webmanifest'];
const CACHE = 'emberwall-' + /*__VERSION__*/ 'dev';

// Servers often send "Vary: Origin"; the precached copies were fetched without one, so ignore Vary.
const MATCH = { ignoreVary: true };

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  // Only same-origin GETs. Requests to other origins (the optional assistant's API calls) are never touched.
  const url = new URL(req.url);
  // Never cache or answer API calls: sessions and live server data must always come from the server.
  if (req.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  const put = (res) => {
    if (res.ok) caches.open(CACHE).then((c) => c.put(req, res.clone()));
    return res;
  };
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).then(put).catch(() => caches.match(req, MATCH).then((hit) => hit || caches.match('./', MATCH))));
    return;
  }
  event.respondWith(caches.match(req, MATCH).then((hit) => hit || fetch(req).then(put)));
});
