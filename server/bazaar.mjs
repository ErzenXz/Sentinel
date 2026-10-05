import { trackedRefresh } from './refresh.mjs';
export async function syncBazaar(store, authKey, acceptTerms, fetcher = fetch) {
  if (!acceptTerms) throw new Error('Review MalwareBazaar usage/redistribution terms, then pass --accept-terms.');
  if (!authKey || /[\s\x00-\x1f]/.test(authKey)) throw new Error('Set MALWAREBAZAAR_AUTH_KEY to your operator Auth-Key.');
  return trackedRefresh(store, 'malwarebazaar', async () => {
  const response = await fetcher('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30_000),
    headers: { 'Auth-Key': authKey, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'query=get_recent&selector=100'
  });
  if (!response.ok) throw new Error(`MalwareBazaar returned HTTP ${response.status}. No changes made.`);
  const reader = response.body.getReader(); let bytes = 0; const chunks = [];
  while (true) { const { done, value } = await reader.read(); if (done) break; bytes += value.length; if (bytes > 8 * 1024 * 1024) { await reader.cancel(); throw new Error('Upstream response exceeds limit.'); } chunks.push(Buffer.from(value)); }
  let data;try{data=JSON.parse(Buffer.concat(chunks));}catch{throw new Error('Malformed MalwareBazaar response. No changes made.');}
  if (data.query_status === 'no_results') return { imported: 0, unchanged: true };
  if (data.query_status !== 'ok' || !Array.isArray(data.data) || data.data.length > 1000) throw new Error('MalwareBazaar response not accepted. Check account permissions. No changes made.');
  const indicators = data.data.map(row => ({ sha256: row.sha256_hash, label: String(row.signature || 'MalwareBazaar reported sample').slice(0,160), source: 'MalwareBazaar · operator-authorized import' }));
  return { ...store.import(indicators), imported: indicators.length };
  });
}
