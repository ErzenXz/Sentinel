using System.Net;
using System.Text;
using System.Text.Json;
using Sentinel.Core;

internal static class NetworkTests
{
    private static void Check(bool ok, string why = "Network assertion failed") { if (!ok) throw new Exception(why); }
    private static async Task Fails<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    private static readonly FirewallProfile[] Profiles = [new("Domain",true,"Block","Allow"), new("Private",true,"Block","Allow"),new("Public",true,"Block","Allow")];
    private static readonly FirewallEvidence Routine = new(0,1,0,0,1,true,"Unknown",true,true,0,0,0,true);
    private static NetworkSnapshot Snapshot(params ConnectionRecord[] connections) => new(DateTimeOffset.UtcNow,Profiles,connections,[new(7,"fixture-app",@"C:\private\example.exe",DateTimeOffset.UtcNow.AddMinutes(-5).ToString("o"))],false);
    private static byte[] Answer(string choice = "routine", double confidence = .98, double routine = .98, double review = .01, double urgent = .01) => JsonSerializer.SerializeToUtf8Bytes(new {
        model="jev-fixture",answers=new { priority=new { type="choice",choice,confidence,probabilities=new { routine, review, urgent } } }
    });
    private static HttpResponseMessage Reply(byte[]? body = null) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body ?? Answer()) };
    private sealed class Clock : TimeProvider { public DateTimeOffset Now = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r,CancellationToken t)=>send(r,t); }
    public static void Register(Action<string,Func<Task>> test)
    {
        test("Network address categories handle IPv4, IPv6, mapped and invalid literals without DNS",()=>{
            foreach (var ip in new[]{"127.0.0.2","::1","::ffff:127.0.0.1"}) Check(NetworkReview.Scope(ip)==AddressScope.Loopback);
            foreach (var ip in new[]{"10.1.2.3","172.16.0.1","192.168.1.3","169.254.1.1","100.64.0.1","fd00::1","fe80::1%3","::ffff:192.168.1.5"}) Check(NetworkReview.Scope(ip)==AddressScope.LocalNetwork,ip);
            foreach (var ip in new[]{"8.8.8.8","2001:4860::8888","172.32.0.1"}) Check(NetworkReview.Scope(ip)==AddressScope.NonLocal);
            Check(NetworkReview.Scope("0.0.0.0")==AddressScope.Unspecified && NetworkReview.Scope("::")==AddressScope.Unspecified);
            foreach(var ip in new[]{"not-a-host","224.0.0.1","255.255.255.255","ff02::1"}) Check(NetworkReview.Scope(ip)==AddressScope.Unknown);
            return Task.CompletedTask;
        });
        test("Network review groups processes and distinguishes listeners from outbound metadata",()=>{
            var snapshot=Snapshot(new ConnectionRecord("127.0.0.1",9,"0.0.0.0",0,"Listen",7),new("0.0.0.0",10,"0.0.0.0",0,"Listen",7),new("10.1.0.1",5000,"8.8.8.8",443,"Established",7),new("10.1.0.1",5001,"10.1.0.2",443,"Established",7),new("::1",5002,"::1",8888,"Established",7),new("10.1.0.1",5003,"broken",4,"Established",99));
            var apps=NetworkReview.Assess(snapshot);Check(apps.Count==2);var app=apps.Single(x=>x.ProcessId==7);
            Check(app.Connections==5 && app.Evidence.EstablishedNonLocal==1 && app.Evidence.EstablishedLocal==2 && app.Evidence.NonLoopbackListeners==1 && app.Evidence.LoopbackListeners==1 && app.Decision.Priority==ReviewPriority.Review);
            Check(apps.Single(x=>x.ProcessId==99).Evidence.ProcessIdentified==false);Check(snapshot.Connections.Count==6);
            return Task.CompletedTask;
        });
        test("Disabled policy is urgent; missing/incomplete evidence cannot become routine",()=>{
            Check(NetworkReview.Decide(Routine).Priority==ReviewPriority.Routine);
            Check(NetworkReview.Decide(Routine with{DisabledProfiles=1}).Priority==ReviewPriority.Urgent);
            foreach(var evidence in new[]{Routine with{ProfilesKnown=false},Routine with{ConnectionsComplete=false},Routine with{ProcessIdentified=false},Routine with{ExecutableAvailable=false},Routine with{UnknownEndpoints=1},Routine with{AllowInboundProfiles=1},Routine with{UnknownInboundProfiles=1},Routine with{Signature="Invalid"}})
                Check(NetworkReview.Decide(evidence).Priority>=ReviewPriority.Review);
            Check(NetworkReview.Decide(Routine with{Signature="Unsigned"}).Priority==ReviewPriority.Routine);
            Check(NetworkReview.Decide(Routine with{Signature="Valid",NonLoopbackListeners=1}).Priority==ReviewPriority.Review);
            return Task.CompletedTask;
        });
        test("Duplicate/missing Windows profiles and absent process identities remain review",()=>{
            var snapshot=Snapshot(new ConnectionRecord("127.0.0.1",1,"127.0.0.1",2,"Established",7));
            foreach(var s in new[]{snapshot with{Profiles=Profiles[..2]},snapshot with{Profiles=[Profiles[0],Profiles[0],Profiles[2]]},snapshot with{ProfileError="Unavailable"},snapshot with{ProcessError="Partial"},snapshot with{Truncated=true}})
                Check(NetworkReview.Assess(s).Single().Decision.Priority==ReviewPriority.Review);
            return Task.CompletedTask;
        });
        test("Network snapshots and typed evidence reject unsafe or over-limit imports",async()=>{
            var snapshot=Snapshot(new ConnectionRecord("127.0.0.1",1,"127.0.0.1",2,"Established",7));
            foreach(var s in new[]{snapshot with{CapturedAt=default},snapshot with{Connections=Enumerable.Repeat(snapshot.Connections[0],1001).ToArray()},snapshot with{Processes=[snapshot.Processes[0],snapshot.Processes[0]]},snapshot with{Processes=[snapshot.Processes[0] with{Name="control\ntext"}]},snapshot with{Connections=[snapshot.Connections[0] with{RemotePort=65536}]},snapshot with{Processes=[snapshot.Processes[0] with{StartedAt="not-time"}]},snapshot with{Profiles=[null!]}})
                await Fails<InvalidDataException>(()=>Task.Run(()=>NetworkReview.Validate(s)));
            foreach(var e in new[]{Routine with{EstablishedLocal=-1},Routine with{Signature="ignore rules"},Routine with{DisabledProfiles=4},Routine with{NonLoopbackListeners=1000},Routine with{ExecutableAvailable=false,Signature="Valid"}})
                await Fails<InvalidDataException>(()=>Task.Run(()=>NetworkReview.Validate(e)));
        });
        test("Jev preview omits all private network and executable strings",()=>{
            var snapshot=Snapshot(new ConnectionRecord("10.0.1.5",1,"8.8.8.8",443,"Established",7));var evidence=NetworkReview.Assess(snapshot).Single().Evidence;
            var payload=JevClient.Preview(evidence);
            foreach(var hidden in new[]{"private","example.exe","fixture-app","8.8.8.8","10.0.1.5","\"processId\"","Publisher"}) Check(!payload.Contains(hidden,StringComparison.OrdinalIgnoreCase));
            Check(payload.Contains("schemaVersion") && payload.Contains("establishedNonLocal"));return Task.CompletedTask;
        });
        test("Network freshness rejects old/future snapshots and uses a two-minute window",()=>{
            var now=DateTimeOffset.UtcNow;var snapshot=Snapshot();Check(NetworkReview.IsFresh(snapshot with{CapturedAt=now.AddMinutes(-1)},now));
            Check(!NetworkReview.IsFresh(snapshot with{CapturedAt=now.AddMinutes(-3)},now) && !NetworkReview.IsFresh(snapshot with{CapturedAt=now.AddSeconds(10)},now));return Task.CompletedTask;
        });
        test("Global firewall warnings survive an empty connection table",()=>{
            Check(NetworkReview.GlobalDecision(Snapshot() with{Profiles=[]}).Priority==ReviewPriority.Review);
            Check(NetworkReview.GlobalDecision(Snapshot() with{Profiles=[Profiles[0],Profiles[1],Profiles[2] with{Enabled=false}]}).Priority==ReviewPriority.Urgent);
            Check(NetworkReview.GlobalDecision(Snapshot() with{ConnectionError="Unavailable"}).Priority==ReviewPriority.Review);
            return Task.CompletedTask;
        });
        test("Windows network capture uses one bounded fixed script and propagates cancellation",async()=>{
            var runner=new FakeRunner(script=>{Check(script.Contains("Select-Object -First 1001") && !script.Contains("Get-AuthenticodeSignature") && script.Contains("Get-NetFirewallProfile"));return JsonSerializer.Serialize(Snapshot(new ConnectionRecord("127.0.0.1",1,"127.0.0.1",2,"Established",7)));});
            var captured=await NetworkCapture.ReadAsync(runner);Check(runner.Calls==1 && captured.Connections.Count==1);
            await Fails<OperationCanceledException>(()=>NetworkCapture.ReadAsync(new FakeRunner(_=>throw new OperationCanceledException())));
            await Fails<InvalidDataException>(()=>NetworkCapture.ReadAsync(new FakeRunner(_=>"null")));
        });
        test("Selected publisher inspection validates process start/path through parameter data",async()=>{
            var app=NetworkReview.Assess(Snapshot(new ConnectionRecord("127.0.0.1",1,"127.0.0.1",2,"Established",7))).Single();
            var runner=new FakeRunner(script=>{Check(script.Contains("$proc.StartTime") && script.Contains("-LiteralPath $proc.Path") && !script.Contains(app.Path));return JsonSerializer.Serialize(new AppRecord(7,app.Name,app.Path,"Valid","Local publisher"));});
            var inspected=await NetworkCapture.InspectAsync(runner,app);Check(inspected.Signature=="Valid" && runner.Calls==1);
            await Fails<ArgumentException>(()=>NetworkCapture.InspectAsync(runner,app with{StartedAt=""}));
            await Fails<InvalidDataException>(()=>NetworkCapture.InspectAsync(new FakeRunner(_=>JsonSerializer.Serialize(inspected with{Id=8})),app));
        });
        foreach(var provider in Enum.GetValues<DecisionProvider>()) {
            var p=provider;test("Jev typed HTTP request uses verified route and no tools: "+p,async()=>{
                using var http=new HttpClient(new Handler(async(r,_token)=>{
                    var preset=DecisionSettings.Preset(p);Check(r.Method==HttpMethod.Post && r.RequestUri==new Uri(new Uri(preset.Endpoint),"v1/systemone") && r.Headers.Authorization?.Parameter=="fixture-key");
                    using var body=JsonDocument.Parse(await r.Content!.ReadAsStringAsync());Check(body.RootElement.GetProperty("model").GetString()==preset.Model);
                    Check(!body.RootElement.TryGetProperty("tools",out _) && body.RootElement.GetProperty("questions").GetProperty("priority").GetProperty("type").GetString()=="choice");
                    return Reply();
                }));
                var result=await new JevClient(http).EvaluateAsync(DecisionSettings.Preset(p),"fixture-key",Routine);Check(result.Choice=="routine" && result.Model=="jev-fixture");
            });
        }
        test("Jev rejects missing keys, unsafe endpoint/model/evidence before provider I/O",async()=>{
            var calls=0;using var http=new HttpClient(new Handler((_,_)=>{calls++;return Task.FromResult(Reply());}));var client=new JevClient(http);
            foreach(var s in new[]{new DecisionSettings(Endpoint:"http://remote.test/"),new DecisionSettings(Endpoint:"https://example.com/"+new string('x',2049)),new DecisionSettings(Model:""),new DecisionSettings(Provider:(DecisionProvider)99)})
                await Fails<ArgumentException>(()=>client.EvaluateAsync(s,"fixture",Routine));
            foreach(var key in new[]{"","line\nbreak",new string('a',8193)}) await Fails<ArgumentException>(()=>client.EvaluateAsync(new(),key,Routine));
            await Fails<InvalidDataException>(()=>client.EvaluateAsync(new(),"fixture",Routine with{Signature="Untrusted model input"}));Check(calls==0);
        });
        test("Jev parser rejects inconsistent, incomplete, duplicated and out-of-range probabilities",async()=>{
            var bad=new List<byte[]> { Encoding.UTF8.GetBytes("{}"),Encoding.UTF8.GetBytes("not JSON"),Answer("allow"),Answer(confidence:1.1),Answer(routine:.5),Answer("routine",.9,.1,.89,.01),Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Answer()).Replace("\"confidence\":0.98","\"confidence\":0.98,\"confidence\":0.2")),Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Answer()).Replace("\"urgent\":0.01","\"unknown\":0.01")) };
            foreach(var body in bad) await Fails<InvalidDataException>(()=>Task.Run(()=>JevClient.Parse(body,TimeSpan.Zero)));
            Check(JevClient.Parse(Answer("review",.1,.45,.45,.1),TimeSpan.Zero).Choice=="review");
        });
        test("Jev transport bounds responses and never displays provider errors or redirect bodies",async()=>{
            foreach(var response in new[]{new HttpResponseMessage(HttpStatusCode.Unauthorized){Content=new StringContent("private echoed key")},new HttpResponseMessage(HttpStatusCode.Redirect){Content=new StringContent("private redirect")},Reply(new byte[JevClient.MaxResponseBytes+1]),Reply(Encoding.UTF8.GetBytes("{\"private\":\"echoed key\"}"))})
            {
                using var http=new HttpClient(new Handler((_,_)=>Task.FromResult(response)));
                try{await new JevClient(http).EvaluateAsync(new(),"fixture",Routine);throw new Exception("Expected failure");}catch(Exception ex) when(ex is InvalidOperationException or InvalidDataException){Check(!ex.Message.Contains("private") && !ex.Message.Contains("echoed"));}
            }
        });
        test("Jev caller cancellation stops transport and does not become an uncertain result",async()=>{
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var http=new HttpClient(new Handler(async(_,token)=>{entered.TrySetResult();await Task.Delay(Timeout.Infinite,token);return Reply();}));
            var service=new DecisionReviewService(new JevClient(http));using var stop=new CancellationTokenSource();
            var review=service.ReviewAsync(new(),"fixture",Routine,stop.Token);await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));stop.Cancel();await Fails<OperationCanceledException>(()=>review);
        });
        test("Jev five-second deadline degrades to manual review without a retry",async()=>{
            var calls=0;using var http=new HttpClient(new Handler(async(_,token)=>{calls++;await Task.Delay(Timeout.Infinite,token);return Reply();}));
            var result=await new DecisionReviewService(new JevClient(http)).ReviewAsync(new(),"fixture",Routine);
            Check(calls==1 && result.Priority==ReviewPriority.Review && result.ModelDecision is null);
        });
        test("Jev results cannot lower local warnings and low confidence forces manual review",async()=>{
            using var http=new HttpClient(new Handler((_,_)=>Task.FromResult(Reply())));var service=new DecisionReviewService(new JevClient(http));
            Check((await service.ReviewAsync(new(),"fixture",Routine with{DisabledProfiles=1})).Priority==ReviewPriority.Urgent);
            Check((await service.ReviewAsync(new(),"fixture",Routine with{NonLoopbackListeners=1})).Priority==ReviewPriority.Review);
            using var uncertain=new HttpClient(new Handler((_,_)=>Task.FromResult(Reply(Answer("routine",.3,.6,.3,.1)))));
            Check((await new DecisionReviewService(new JevClient(uncertain)).ReviewAsync(new(),"fixture",Routine)).Priority==ReviewPriority.Review);
        });
        test("Jev failure retains local evidence and is never cached",async()=>{
            var calls=0;using var http=new HttpClient(new Handler((_,_)=>{calls++;return Task.FromResult(new HttpResponseMessage(HttpStatusCode.PaymentRequired){Content=new StringContent("private body")});}));
            var service=new DecisionReviewService(new JevClient(http));for(var i=0;i<2;i++){var result=await service.ReviewAsync(new(),"fixture",Routine);Check(result.Priority==ReviewPriority.Review && result.ModelDecision is null && !result.Cached);}
            Check(calls==2);
        });
        test("Jev single-flight cache deduplicates identical evidence but separates key/model and expiry",async()=>{
            var calls=0;var active=0;var peak=0;var clock=new Clock();
            using var http=new HttpClient(new Handler(async(_,token)=>{calls++;active++;peak=Math.Max(peak,active);await Task.Delay(10,token);active--;return Reply();}));var service=new DecisionReviewService(new JevClient(http),clock);
            var results=await Task.WhenAll(Enumerable.Range(0,8).Select(_=>service.ReviewAsync(new(),"fixture",Routine)));
            Check(calls==1 && peak==1 && results.Count(x=>x.Cached)==7);
            await service.ReviewAsync(new(),"other-key",Routine);await service.ReviewAsync(new(Model:"other-model"),"fixture",Routine);Check(calls==3);
            clock.Now=clock.Now.AddMinutes(3);Check(!(await service.ReviewAsync(new(),"fixture",Routine)).Cached && calls==4);
            using var canceled=new CancellationTokenSource();canceled.Cancel();await Fails<OperationCanceledException>(()=>service.ReviewAsync(new(),"fixture",Routine,canceled.Token));Check(calls==4);
        });
        test("Jev in-memory cache evicts old evidence at its 128-entry budget",async()=>{
            var calls=0;var clock=new Clock();using var http=new HttpClient(new Handler((_,_)=>{calls++;return Task.FromResult(Reply());}));var service=new DecisionReviewService(new JevClient(http),clock);
            for(var i=0;i<129;i++){clock.Now=clock.Now.AddMilliseconds(1);await service.ReviewAsync(new(),"fixture",Routine with{EstablishedLocal=i});}
            Check(!(await service.ReviewAsync(new(),"fixture",Routine with{EstablishedLocal=0})).Cached && calls==130);
        });
    }
}
