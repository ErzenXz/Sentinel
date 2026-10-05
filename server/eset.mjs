import { trackedRefresh } from './refresh.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const BASE = 'https://raw.githubusercontent.com/eset/malware-ioc/';
async function boundedText(url, fetcher, maxBytes = 2*1024*1024) {
  const response = await fetcher(url, { redirect: 'error', signal: AbortSignal.timeout(30_000), headers: { 'User-Agent': 'Sentinel-Threat-Intelligence/0.6' } });
  if (!response.ok) throw new Error(`ESET/GitHub source returned HTTP ${response.status}; existing feed retained.`);
  const chunks=[];let size=0;const reader=response.body.getReader();
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();throw new Error('Upstream IOC metadata exceeds limit.');}chunks.push(Buffer.from(value));}
  return Buffer.concat(chunks).toString('utf8');
}
export async function collectEset(fetcher = fetch) {
  const tree=JSON.parse(await boundedText('https://api.github.com/repos/eset/malware-ioc/git/trees/master?recursive=1',fetcher,8*1024*1024));
  if(tree.truncated || !/^[a-f0-9]{40}$/.test(tree.sha) || !Array.isArray(tree.tree)) throw new Error('Incomplete or malformed ESET repository tree.');
  const commit=tree.sha;
  const files=tree.tree.filter(x=>x.type==='blob' && /(^|\/)samples\.sha256$/i.test(x.path)).map(x=>x.path);
  if(files.length===0 || files.length>512 || files.some(x=>!/^[-A-Za-z0-9_./]+$/.test(x)||x.split('/').includes('..'))) throw new Error('Unexpected ESET IOC file list.');
  const license=await boundedText(BASE+commit+'/LICENSE',fetcher,16*1024);
  const acceptedLicense=readFileSync(fileURLToPath(new URL('./seeds/ESET-LICENSE.txt',import.meta.url)),'utf8');
  if(license.trim()!==acceptedLicense.trim()) throw new Error('Upstream license changed; operator review required.');
  const indicators=[];let cursor=0;
  // Four small text downloads at a time; never fetch binaries or malware samples.
  await Promise.all(Array.from({length:4},async()=>{
    while(cursor<files.length){const path=files[cursor++];const text=await boundedText(BASE+commit+'/'+path,fetcher);
      for(const line of text.split(/\r?\n/)){const value=line.trim();if(!value||value.startsWith('#'))continue;
        if(!/^[a-fA-F0-9]{64}$/.test(value))throw new Error('Malformed ESET SHA-256 list. Existing feed retained.');
        indicators.push({sha256:value.toLowerCase(),label:('ESET published IOC · '+path.split('/')[0]).slice(0,160),source:'ESET public IOC · snapshot '+commit.slice(0,12)});
        if(indicators.length>100_000)throw new Error('ESET indicator capacity exceeded.');
      }
    }
  }));
  const deduped=[...new Map(indicators.map(x=>[x.sha256,x])).values()].sort((a,b)=>a.sha256.localeCompare(b.sha256));
  return {indicators:deduped,license,provenance:{repository:'https://github.com/eset/malware-ioc',commit,files,downloadedAt:new Date().toISOString(),indicators:deduped.length}};
}
export async function syncEset(store, fetcher = fetch) {
  return trackedRefresh(store, 'eset', async () => {
  const collected=await collectEset(fetcher);
  // Persist source notice/provenance before publishing; no signing occurs until all source files validate.
  store.atomic('eset-license.txt',collected.license,0o644);
  store.atomic('eset-provenance.json',JSON.stringify(collected.provenance,null,2),0o644);
  return {...store.replaceSource('ESET public IOC',collected.indicators),imported:collected.indicators.length,commit:collected.provenance.commit};
  });
}
