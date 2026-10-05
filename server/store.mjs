import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const seedPath = fileURLToPath(new URL('./seeds/eset-sha256.json',import.meta.url));
const licensePath = fileURLToPath(new URL('./seeds/ESET-LICENSE.txt',import.meta.url));

export const MAX_INDICATORS = 100_000;
export const DEMO_TEXT = 'Sentinel harmless detection fixture v1\n';
export const DEMO_HASH = createHash('sha256').update(DEMO_TEXT).digest('hex');
export function normalizeIndicators(input, source = 'Operator curated') {
  if (!Array.isArray(input) || input.length > MAX_INDICATORS) throw new Error('Expected at most 100,000 hash indicators.');
  return input.map(row => {
    if (typeof row === 'string') row = { sha256: row };
    const sha256 = String(row?.sha256 ?? '').toLowerCase();
    const label = row?.label ?? 'Known threat hash';
    const origin = row?.source ?? source;
    if (!/^[a-f0-9]{64}$/.test(sha256) || ![label, origin].every(x => typeof x === 'string' && x.length > 0 && x.length <= 160 && !/[\x00-\x1f\x7f]/.test(x))) throw new Error('Invalid hash, label or source. Nothing was imported.');
    return { sha256, label, source: origin };
  });
}
export class ThreatStore {
  constructor(directory) { this.directory = resolve(directory); }
  path(name) { return join(this.directory, name); }
  atomic(name, content, mode = 0o600) {
    const path = this.path(name); writeFileSync(path + '.tmp', content, { mode }); renameSync(path + '.tmp', path);
  }
  init({ seed = true } = {}) {
    if (existsSync(this.path('state.json')) || existsSync(this.path('signing-private.pem'))) throw new Error('Server already initialized. Its keys will not be overwritten.');
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    this.atomic('signing-private.pem', privateKey);
    this.atomic('public.pem', publicKey, 0o644);
    this.atomic('admin-token.txt', randomBytes(32).toString('hex'));
    const initial = [{ sha256: DEMO_HASH, label: 'Harmless Sentinel demonstration fixture', source: 'Sentinel demo — not live malware intelligence' }];
    if (seed && existsSync(seedPath)) initial.push(...normalizeIndicators(JSON.parse(readFileSync(seedPath,'utf8'))));
    this.atomic('state.json', JSON.stringify({ schema: 1, sequence: 0, suppressed: [], hashes: initial }));
    return this.publish();
  }
  state() {
    const data = JSON.parse(readFileSync(this.path('state.json'), 'utf8'));
    if (data.schema !== 1 || !Number.isSafeInteger(data.sequence) || data.sequence < 0) throw new Error('Invalid server state.');
    if(data.suppressed && (!Array.isArray(data.suppressed)||data.suppressed.length>MAX_INDICATORS||data.suppressed.some(x=>typeof x!=='string'||!/^[a-f0-9]{64}$/.test(x))))throw new Error('Invalid suppression list.');
    return { ...data, hashes: normalizeIndicators(data.hashes) };
  }
  import(input, source) {
    const incoming = normalizeIndicators(input, source);
    const state = this.state(); const map = new Map(state.hashes.map(x => [x.sha256, x]));
    for (const indicator of incoming) if (!(state.suppressed ?? []).includes(indicator.sha256)) map.set(indicator.sha256, indicator);
    if (map.size > MAX_INDICATORS) throw new Error('Indicator capacity reached. Curate/prune the list before import.');
    state.hashes = [...map.values()].sort((a, b) => a.sha256.localeCompare(b.sha256));
    return this.publish(state);
  }
  replaceSource(prefix, input) {
    const incoming = normalizeIndicators(input); const state = this.state();
    const map = new Map(state.hashes.filter(x=>!x.source.startsWith(prefix)).map(x=>[x.sha256,x]));
    for(const row of incoming) if(!(state.suppressed??[]).includes(row.sha256) && !map.has(row.sha256)) map.set(row.sha256,row);
    if(map.size>MAX_INDICATORS)throw new Error('Indicator capacity reached.');
    state.hashes=[...map.values()].sort((a,b)=>a.sha256.localeCompare(b.sha256));return this.publish(state);
  }
  allow(hash) {
    if(!/^[a-fA-F0-9]{64}$/.test(hash))throw new Error('Invalid SHA-256.');
    const state=this.state();state.suppressed=(state.suppressed??[]).filter(x=>x!==hash.toLowerCase());return this.publish(state);
  }
  remove(hash) {
    if (!/^[a-fA-F0-9]{64}$/.test(hash)) throw new Error('Invalid SHA-256.');
    const state = this.state(); state.hashes = state.hashes.filter(x => x.sha256 !== hash.toLowerCase());
    state.suppressed=[...new Set([...(state.suppressed??[]),hash.toLowerCase()])];
    return this.publish(state);
  }
  publish(state = this.state(), now = new Date()) {
    state.sequence++;
    if (!Number.isSafeInteger(state.sequence)) throw new Error('Feed sequence exhausted.');
    const payload = Buffer.from(JSON.stringify({ schema: 1, sequence: state.sequence, issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 7 * 86_400_000).toISOString(), hashes: state.hashes, notices: state.hashes.some(x=>x.source.startsWith('ESET public IOC')) ? [{source:'ESET public IOC',license:readFileSync(licensePath,'utf8')}] : [] }));
    const signature = sign('RSA-SHA256', payload, { key: createPrivateKey(readFileSync(this.path('signing-private.pem'))), padding: 1 });
    const envelope = { schema: 1, algorithm: 'RSA-SHA256', payload: payload.toString('base64'), signature: signature.toString('base64') };
    const serialized=JSON.stringify(envelope);
    if(Buffer.byteLength(serialized)>24*1024*1024)throw new Error('Published feed exceeds the client size limit. Existing feed retained.');
    // State first prevents sequence reuse after a crash. Readers only see complete feed files.
    this.atomic('state.json', JSON.stringify(state)); this.atomic('feed.json', serialized, 0o644);
    return { sequence: state.sequence, indicators: state.hashes.length, expiresAt: new Date(now.getTime() + 7 * 86_400_000).toISOString() };
  }
  feed() { return readFileSync(this.path('feed.json')); }
  publicKey() { return readFileSync(this.path('public.pem'), 'utf8'); }
  fingerprint() { return createHash('sha256').update(createPublicKey(this.publicKey()).export({ type: 'spki', format: 'der' })).digest('hex').toUpperCase(); }
  token() { return readFileSync(this.path('admin-token.txt'), 'utf8').trim(); }
  recordRefresh(source, update) {
    if (!['eset', 'malwarebazaar'].includes(source)) throw new Error('Invalid refresh source.');
    const state = this.state();
    state.refreshes = { ...state.refreshes, [source]: { ...state.refreshes?.[source], ...update } };
    this.atomic('state.json', JSON.stringify(state));
  }
  health() {
    const signed = JSON.parse(this.feed()); const payload = JSON.parse(Buffer.from(signed.payload, 'base64'));
    if (!verify('RSA-SHA256', Buffer.from(signed.payload, 'base64'), { key: this.publicKey(), padding: 1 }, Buffer.from(signed.signature, 'base64'))) throw new Error('Stored feed signature failed verification.');
    const demoOnly = payload.hashes.every(x => x.source.startsWith('Sentinel demo'));
    const state = this.state();
    const sourceCounts = new Map();
    for (const row of payload.hashes) {
      const source = row.source.startsWith('ESET public IOC') ? 'ESET public IOC' : row.source.startsWith('MalwareBazaar') ? 'MalwareBazaar' : row.source.startsWith('Sentinel demo') ? 'Sentinel demo' : 'Operator curated';
      sourceCounts.set(source, (sourceCounts.get(source) ?? 0) + 1);
    }
    const refreshes = {};
    for (const source of ['eset','malwarebazaar']) {
      const row = state.refreshes?.[source];
      if (row) refreshes[source] = { status: ['running','ok','failed'].includes(row.status) ? row.status : 'unknown', attemptedAt: row.attemptedAt, succeededAt: row.succeededAt, imported: row.imported };
    }
    return { status: state.sequence !== payload.sequence ? 'inconsistent' : Date.parse(payload.expiresAt) > Date.now() ? 'ok' : 'expired',
      issuedAt: payload.issuedAt, ageSeconds: Math.max(0, Math.floor((Date.now() - Date.parse(payload.issuedAt)) / 1000)),
      sources: Object.fromEntries(sourceCounts), refreshes, corpusFreshnessGuaranteed: false, sequence: payload.sequence, indicators: payload.hashes.length, demoOnly, expiresAt: payload.expiresAt, fingerprint: this.fingerprint() };
  }
}
