import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ThreatStore, DEMO_TEXT } from './store.mjs';
import { createThreatServer } from './http.mjs';
import { syncBazaar } from './bazaar.mjs';
import { syncEset } from './eset.mjs';

const store = new ThreatStore(process.env.SENTINEL_DATA_DIR || resolve('data'));
const [command = 'serve', argument] = process.argv.slice(2);
try {
  switch (command) {
    case 'init': console.log(store.init()); console.log('Public key fingerprint:', store.fingerprint()); console.log('Pin data/public.pem in the Windows app. Keep signing-private.pem and admin-token.txt private.'); break;
    case 'import': {
      if (!argument) throw new Error('Usage: node cli.mjs import indicators.json OR hashes.txt');
      const text = readFileSync(argument, 'utf8');
      if (Buffer.byteLength(text) > 16 * 1024 * 1024) throw new Error('Import file too large.');
      const input = text.trim().startsWith('[') ? JSON.parse(text) : text.split(/\r?\n/).map(x => x.trim()).filter(x => x && !x.startsWith('#'));
      console.log(store.import(input)); break;
    }
    case 'sync-eset': console.log(await syncEset(store)); break;
    case 'allow': console.log(store.allow(argument ?? '')); break;
    case 'remove': console.log(store.remove(argument ?? '')); break;
    case 'publish': console.log(store.publish()); break;
    case 'sync-bazaar': console.log(await syncBazaar(store, process.env.MALWAREBAZAAR_AUTH_KEY, process.argv.includes('--accept-terms'))); break;
    case 'demo-text': process.stdout.write(DEMO_TEXT); break;
    case 'serve': {
      const host = process.env.SENTINEL_BIND || '127.0.0.1'; const port = Number(process.env.PORT || 8787);
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port.');
      let timer; let refreshing=false;
      if(process.env.SENTINEL_AUTO_SYNC==='eset'){
        const hours=Number(process.env.SENTINEL_REFRESH_HOURS || 24);
        if(!Number.isInteger(hours)||hours<6||hours>168)throw new Error('Refresh interval must be 6–168 hours.');
        const refresh=async()=>{if(refreshing)return;refreshing=true;try{const result=await syncEset(store);console.log(`ESET metadata refreshed: ${result.imported} hashes; sequence ${result.sequence}.`);}catch{console.error('ESET refresh failed. Existing signed feed retained.');}finally{refreshing=false;}};
        timer=setInterval(refresh,hours*3_600_000);void refresh();
      }
      const server = createThreatServer(store, { adminToken: process.env.SENTINEL_ADMIN_TOKEN || store.token() });
      server.listen(port, host, () => console.log(`Sentinel threat server listening on ${host}:${port}; ${store.health().indicators} indicators. No file-upload or per-device lookup endpoint.`));
      for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => { if(timer)clearInterval(timer); server.close(() => process.exit(0)); });
      break;
    }
    default: throw new Error('Commands: init, serve, import, remove, allow, publish, sync-eset, sync-bazaar, demo-text');
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
