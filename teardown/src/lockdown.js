// Defense in depth for the workers. A <meta> Content-Security-Policy does NOT
// constrain a dedicated worker fetched over http(s); only a CSP *header* on the
// worker response does (see public/_headers). So the workers also remove the
// network APIs themselves before touching any file bytes. This is a speed bump
// against a parser bug, not a hard sandbox: the header is the real control.
for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'WebTransport', 'EventSource', 'importScripts', 'BroadcastChannel', 'indexedDB', 'caches']) {
  try {
    Object.defineProperty(self, name, { value: undefined, writable: false, configurable: false })
  } catch {
    try { self[name] = undefined } catch { /* already locked */ }
  }
}
