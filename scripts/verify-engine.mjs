import { spawn } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { ThreatStore, DEMO_TEXT } from '../server/store.mjs';
import { createThreatServer } from '../server/http.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const temporary=join(root,'artifacts','engine-integration-'+Date.now());mkdirSync(temporary,{recursive:true});
const store=new ThreatStore(join(temporary,'server'));store.init({seed:false});
const server=createThreatServer(store);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const base=`http://127.0.0.1:${server.address().port}/`;
const requests=[];
const models=createServer((request,response)=>{
 const chunks=[]; request.on('data',x=>chunks.push(x)); request.on('end',()=>{
  requests.push({method:request.method,url:request.url,body:Buffer.concat(chunks).length,key:request.headers.authorization||request.headers['x-api-key']});
  response.setHeader('content-type','application/json');
  if (request.url==='/unavailable/v1/systemone') { response.statusCode=503;response.end('private upstream body');return; }
  if (request.url==='/v1/systemone') {
   const input=JSON.parse(Buffer.concat(chunks));assert.ok(!input.tools);assert.equal(input.questions.priority.type,'choice');
   assert.deepEqual(Object.keys(input.state),['schemaVersion','evidence']);
   assert.ok(!JSON.stringify(input.state).includes('private-example'));
   response.end(JSON.stringify({model:'jev-http-fixture',answers:{priority:{type:'choice',choice:'routine',confidence:.98,probabilities:{routine:.98,review:.01,urgent:.01}}}}));return;
  }
  response.end(JSON.stringify(request.url==='/api/tags'?{models:[{name:'fixture-local'}]}:{data:[{id:'fixture-local'}],has_more:false}));
 });
});
await new Promise(resolve=>models.listen(0,'127.0.0.1',resolve));
const modelBase=`http://127.0.0.1:${models.address().port}/`;
const dotnet=process.env.SENTINEL_DOTNET || 'dotnet';
const run=args=>new Promise((resolve,reject)=>{
 const child=spawn(dotnet,['run','--no-build','--project',join(root,'src','Sentinel.Cli'),'-c','Release','--',...args],{cwd:root,env:{...process.env,SENTINEL_AI_KEY:'',SENTINEL_JEV_KEY:'',DOTNET_CLI_TELEMETRY_OPTOUT:'1'},stdio:['ignore','pipe','pipe']});let out='',error='';
 child.stdout.on('data',x=>{out+=x;});child.stderr.on('data',x=>{error+=x;});child.on('error',reject);child.on('close',code=>resolve({code,out,error}));
});
function zipFixture(name, data) {
 const fileName=Buffer.from(name);let crc=0xffffffff;
 for(const value of data){crc^=value;for(let bit=0;bit<8;bit++)crc=(crc>>>1)^(0xedb88320&-(crc&1));}crc=(~crc)>>>0;
 const local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt16LE(20,4);local.writeUInt32LE(crc,14);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(fileName.length,26);
 const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);central.writeUInt32LE(crc,16);central.writeUInt32LE(data.length,20);central.writeUInt32LE(data.length,24);central.writeUInt16LE(fileName.length,28);
 const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+fileName.length,12);end.writeUInt32LE(local.length+fileName.length+data.length,16);
 return Buffer.concat([local,fileName,data,central,fileName,end]);
}
try {
 const state=join(temporary,'client');const key=store.path('public.pem');
 const update=await run(['update','--server',base,'--key',key,'--state',state]);assert.equal(update.code,0,update.error);
 console.log('PASS: real HTTP signed-feed download and Node → .NET RSA verification');
 store.publish();
 const renewed=await run(['update','--server',base,'--key',key,'--state',state]);assert.equal(renewed.code,0,renewed.error);assert.equal(JSON.parse(renewed.out).sequence,2);
 const retained=readFileSync(join(state,'feed.json'));
 store.publish(store.state(),new Date(Date.now()-8*86400000));
 const expired=await run(['update','--server',base,'--key',key,'--state',state]);assert.equal(expired.code,1);assert.deepEqual(readFileSync(join(state,'feed.json')),retained);
 console.log('PASS: renewal advances sequence; expired publication retains the verified cache');
 const file=join(temporary,'harmless-fixture.txt');writeFileSync(file,DEMO_TEXT);
 const scan=await run(['scan',file,'--feed',join(state,'feed.json'),'--key',key]);assert.equal(scan.code,2,scan.error);const report=JSON.parse(scan.out);assert.equal(report.detected,1);assert.equal(report.scanned,1);
 console.log('PASS: independent CLI detects exact harmless fixture from the self-hosted feed');
 const archive=join(temporary,'harmless-archive.zip');writeFileSync(archive,zipFixture('inside/fixture.txt',Buffer.from(DEMO_TEXT)));
 const reportPath=join(temporary,'exported-report.json');
 const archiveScan=await run(['scan',archive,'--feed',join(state,'feed.json'),'--key',key,'--report',reportPath]);
 assert.equal(archiveScan.code,2,archiveScan.error);const archiveReport=JSON.parse(readFileSync(reportPath));
 assert.equal(archiveReport.archiveEntries,1);assert.equal(archiveReport.findings[0].archiveEntry,'inside/fixture.txt');assert.equal(archiveReport.findings[0].path,archive);
 assert.deepEqual(JSON.parse(archiveScan.out),archiveReport);
 console.log('PASS: ZIP-contained feed detection and atomic report export through the actual CLI');
 const offlineProfile=join(temporary,'offline-profile');const ordinary=join(temporary,'ordinary.txt');writeFileSync(ordinary,'ordinary offline profile fixture');
 const offline=await run(['scan',ordinary,'--profile',offlineProfile,'--low-impact']);assert.equal(offline.code,0,offline.error);
 assert.equal(JSON.parse(offline.out).mode,'LowImpact');assert.equal(JSON.parse(offline.out).peakPendingDirectories,0);
 assert.equal(readdirSync(join(offlineProfile,'reports')).filter(x=>x.endsWith('.json')).length,1);
 console.log('PASS: low-impact offline profile uses bundled intelligence, streams JSON and saves report history');
 const envelope=JSON.parse(readFileSync(join(state,'feed.json')));const bytes=Buffer.from(envelope.payload,'base64');bytes[10]^=1;envelope.payload=bytes.toString('base64');writeFileSync(join(temporary,'tampered.json'),JSON.stringify(envelope));
 const bad=await run(['scan',file,'--feed',join(temporary,'tampered.json'),'--key',key]);assert.equal(bad.code,1);assert.match(bad.error,/signature is invalid/);
 console.log('PASS: altered server feed is rejected before scanning');
 for (const provider of ['Ollama','OpenAiCompatible','Anthropic']) {
  const discovery=await run(['models','--provider',provider,'--endpoint',provider==='OpenAiCompatible'?modelBase+'v1/':modelBase]);
  assert.equal(discovery.code,0,discovery.error);assert.deepEqual(JSON.parse(discovery.out).models,['fixture-local']);
 }
 assert.equal(requests.length,3); assert.deepEqual(requests.map(x=>x.url),['/api/tags','/v1/models','/v1/models?limit=1000']);
 assert.ok(requests.every(x=>x.method==='GET'&&x.body===0&&!x.key));
 console.log('PASS: actual CLI discovers three provider protocols with metadata-only GET requests');
 const network=join(temporary,'network.json');
 writeFileSync(network,JSON.stringify({capturedAt:new Date().toISOString(),profiles:['Domain','Private','Public'].map(name=>({name,enabled:name!=='Public',defaultInboundAction:'Block',defaultOutboundAction:'Allow'})),connections:[{localAddress:'0.0.0.0',localPort:9090,remoteAddress:'0.0.0.0',remotePort:0,state:'Listen',owningProcess:7}],processes:[{id:7,name:'private-example',path:'C:\\private-example\\app.exe',startedAt:new Date(Date.now()-100000).toISOString()}],truncated:false}));
 const localReview=await run(['network-review',network]);assert.equal(localReview.code,4,localReview.error);
 const app=JSON.parse(localReview.out).applications[0];assert.equal(app.priority,'Urgent');assert.equal(app.listeners,1);
 const evidence=join(temporary,'evidence.json');writeFileSync(evidence,JSON.stringify(app.evidence));
 for(const provider of ['TypeSafe','VercelGateway']) {
  const reviewed=await run(['jev-review',evidence,'--provider',provider,'--endpoint',modelBase,'--model','jev-fixture']);assert.equal(reviewed.code,4,reviewed.error);
  const decision=JSON.parse(reviewed.out);assert.equal(decision.modelDecision.choice,'routine');assert.equal(decision.priority,2);assert.equal(decision.cached,false);
 }
 const unavailable=await run(['jev-review',evidence,'--provider','TypeSafe','--endpoint',modelBase+'unavailable/','--model','jev-fixture']);assert.equal(unavailable.code,4,unavailable.error);
 assert.equal(JSON.parse(unavailable.out).modelDecision,null);assert.ok(!unavailable.out.includes('private upstream body'));
 assert.ok(requests.every(x=>!x.key));
 console.log('PASS: actual CLI local network review + both Jev protocols retain urgent policy warnings and fail to manual review without leaking upstream text');
 console.log('Integration completed without Defender, malware downloads, subscription credentials, or paid API calls.');
} finally { await Promise.all([new Promise(resolve=>server.close(resolve)),new Promise(resolve=>models.close(resolve))]);rmSync(temporary,{recursive:true,force:true}); }
