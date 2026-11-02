// Defense in depth for the workers. A <meta> Content-Security-Policy does NOT
// constrain a dedicated worker fetched over http(s); only a CSP *header* on the
// worker response does (see public/_headers). So the workers also remove the
// network APIs themselves before touching any file bytes. This is a speed bump
// against a parser bug, not a hard sandbox: the header is the real control.
// Worker/SharedWorker are included because a dedicated worker can spawn nested
// workers, and the nested worker would start with its network APIs intact.
for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'WebSocketStream', 'WebTransport', 'EventSource', 'importScripts', 'BroadcastChannel', 'indexedDB', 'caches', 'Worker', 'SharedWorker']) {
  try {
    Object.defineProperty(self, name, { value: undefined, writable: false, configurable: false })
  } catch {
    try { self[name] = undefined } catch { /* already locked */ }
  }
}
