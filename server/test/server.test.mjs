import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, verify } from 'node:crypto';
import { ThreatStore, DEMO_HASH } from '../store.mjs';
import { createThreatServer } from '../http.mjs';
import { syncBazaar } from '../bazaar.mjs';
import { syncEset } from '../eset.mjs';

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'sentinel-server-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const store = new ThreatStore(directory); store.init({seed:false}); return store;
}
test('Signed feed verifies and initially advertises demo-only intelligence', t => {
  const store = fixture(t); const signed = JSON.parse(store.feed());
  assert.equal(verify('RSA-SHA256', Buffer.from(signed.payload,'base64'), store.publicKey(), Buffer.from(signed.signature,'base64')), true);
  assert.equal(store.health().demoOnly, true);
  assert.equal(JSON.parse(Buffer.from(signed.payload,'base64')).hashes[0].sha256, DEMO_HASH);
  const modified = Buffer.from(signed.payload,'base64'); modified[modified.length-5] ^= 1;
  assert.equal(verify('RSA-SHA256', modified, store.publicKey(), Buffer.from(signed.signature,'base64')), false);
});
test('Invalid import is atomic and duplicates are deduplicated', t => {
  const store = fixture(t); const before = store.feed();
  assert.throws(() => store.import([{sha256:'x'}])); assert.deepEqual(store.feed(), before);
  const hash = createHash('sha256').update('test benign content').digest('hex');
  store.import([{ sha256:hash, label:'Test', source:'Operator fixture' }, { sha256:hash, label:'Test', source:'Operator fixture' }]);
  assert.equal(store.health().indicators, 2); assert.equal(store.health().sequence, 2);
  store.remove(hash); assert.equal(store.health().indicators, 1); assert.equal(store.health().sequence, 3);
});
test('Reinitialization cannot replace the signing identity', t => {
  const store = fixture(t); const key = store.publicKey(); assert.throws(() => store.init()); assert.equal(store.publicKey(), key);
});
test('Republishing advances sequence and signs new expiry', t => {
  const store = fixture(t); const old = store.health().sequence; store.publish(); assert.equal(store.health().sequence,old+1);
});
test('HTTP management requires a token; public routes disclose no private material', async t => {
  const store = fixture(t); const server = createThreatServer(store); await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(base+'/v1/admin/publish',{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).status,401);
  assert.equal((await fetch(base+'/v1/admin/publish',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer wrong-token'},body:'{}'})).status,401);
  assert.equal((await fetch(base+'/v1/admin/publish',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+store.token(),origin:'https://evil.example'},body:'{}'})).status,403);
  const published = await fetch(base+'/v1/admin/publish',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+store.token()},body:'{}'});
  assert.equal(published.status,200); assert.equal((await published.json()).sequence,2);
  const feed=await (await fetch(base+'/v1/feed')).text();assert.equal(feed.includes(store.token()),false);assert.equal(feed.includes('PRIVATE KEY'),false);
  assert.equal((await fetch(base+'/signing-private.pem')).status,404);
  assert.equal((await fetch(base+'/v1/upload',{method:'POST'})).status,404);
  assert.equal((await fetch(base+'/v1/public-key')).status,200);
});
test('MalwareBazaar importer requests metadata only and never downloads samples', async t => {
  const store=fixture(t); const hash=createHash('sha256').update('harmless upstream fixture').digest('hex'); let called=false;
  const fetcher=async (url,options) => {
    called=true;assert.equal(url,'https://mb-api.abuse.ch/api/v1/');assert.equal(options.body,'query=get_recent&selector=100');assert.equal(options.headers['Auth-Key'],'operator-secret');
    return new Response(JSON.stringify({query_status:'ok',data:[{sha256_hash:hash,signature:'Fixture label'}]}));
  };
  await assert.rejects(syncBazaar(store,'operator-secret',false,fetcher));assert.equal(called,false);
  const result=await syncBazaar(store,'operator-secret',true,fetcher);assert.equal(result.imported,1);assert.equal(store.health().indicators,2);
});
test('Failed upstream response retains the last good feed', async t => {
  const store=fixture(t);const before=store.feed();
  await assert.rejects(syncBazaar(store,'operator-secret',true,async()=>new Response('echoed secret',{status:401})),/HTTP 401/);
  assert.deepEqual(store.feed(),before);
});
test('Removed indicators remain suppressed through upstream refreshes', t => {
  const store=fixture(t);store.remove(DEMO_HASH);store.import([{sha256:DEMO_HASH,label:'Should stay suppressed',source:'Operator fixture'}]);
  assert.equal(store.health().indicators,0);store.allow(DEMO_HASH);store.import([{sha256:DEMO_HASH,label:'Allowed again',source:'Operator fixture'}]);assert.equal(store.health().indicators,1);
});
test('Source refresh replaces stale source rules and preserves curated rules', t => {
  const store=fixture(t);const hash=createHash('sha256').update('old source entry').digest('hex');
  store.import([{sha256:hash,label:'Old',source:'ESET public IOC · old'}]);store.replaceSource('ESET public IOC',[]);
  assert.equal(store.health().indicators,1);assert.equal(store.state().hashes[0].sha256,DEMO_HASH);
});
test('Source refresh health records failure without exposing secrets or resetting last success', async t => {
  const store = fixture(t); const hash = createHash('sha256').update('health fixture').digest('hex');
  await syncBazaar(store,'operator-secret',true,async()=>new Response(JSON.stringify({query_status:'ok',data:[{sha256_hash:hash}]})));
  const good = store.health(); assert.equal(good.refreshes.malwarebazaar.status,'ok'); assert.equal(good.sources.MalwareBazaar,1);
  const before = store.feed();
  await assert.rejects(syncBazaar(store,'operator-secret',true,async()=>{throw new Error('operator-secret echoed body');}));
  const health = store.health(); assert.equal(health.refreshes.malwarebazaar.status,'failed');
  assert.equal(health.refreshes.malwarebazaar.succeededAt,good.refreshes.malwarebazaar.succeededAt);
  assert.equal(JSON.stringify(health).includes('operator-secret'),false); assert.deepEqual(store.feed(),before);
  assert.equal(health.corpusFreshnessGuaranteed,false); assert.equal(typeof health.ageSeconds,'number');
});
test('Health distinguishes expired feeds and interrupted publications', t => {
  const store = fixture(t); store.publish(store.state(),new Date(Date.now()-8*86400000)); assert.equal(store.health().status,'expired');
  const state = store.state(); state.sequence++; store.atomic('state.json',JSON.stringify(state)); assert.equal(store.health().status,'inconsistent');
});

test('ESET refresh validates pinned metadata, deduplicates and reports source success', async t => {
  const store = fixture(t); const hash = createHash('sha256').update('ESET harmless mock').digest('hex');const commit='a'.repeat(40);const seen=[];
  const license=readFileSync(new URL('../seeds/ESET-LICENSE.txt',import.meta.url),'utf8');
  const fetcher=async url=>{seen.push(url);if(url.includes('api.github.com'))return new Response(JSON.stringify({sha:commit,truncated:false,tree:[{type:'blob',path:'fixture/samples.sha256'},{type:'blob',path:'fixture/malware.exe'}]}));if(url.endsWith('/LICENSE'))return new Response(license);return new Response(hash+'\n'+hash+'\n');};
  const result=await syncEset(store,fetcher);assert.equal(result.imported,1);assert.equal(result.commit,commit);
  assert.equal(store.health().refreshes.eset.status,'ok');assert.equal(store.health().sources['ESET public IOC'],1);
  assert.equal(seen.some(url=>url.endsWith('.exe')),false);assert.equal(seen.filter(url=>url.includes('raw.githubusercontent.com')).every(url=>url.includes(commit)),true);
});
test('ESET changed license is rejected and failed refresh preserves signed corpus', async t => {
  const store=fixture(t);const before=store.feed();
  await assert.rejects(syncEset(store,async url=>url.includes('api.github.com')?new Response(JSON.stringify({sha:'b'.repeat(40),truncated:false,tree:[{type:'blob',path:'test/samples.sha256'}]})):new Response('changed license')),/license changed/);
  assert.deepEqual(store.feed(),before);assert.equal(store.health().refreshes.eset.status,'failed');
});
