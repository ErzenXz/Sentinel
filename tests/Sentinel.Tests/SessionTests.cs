using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using Sentinel.Core;
using Sentinel.Core.Protection;

internal static class SessionTests
{
    private static void Check(bool ok) { if (!ok) throw new Exception("Session assertion failed"); }
    private static async Task Fails<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    private sealed class Temporary : IDisposable
    {
        public string Root { get; } = Path.Combine(AppContext.BaseDirectory,"session-test-"+Guid.NewGuid().ToString("N"));
        public Temporary() { Directory.CreateDirectory(Root); }
        public string File(string name) => Path.Combine(Root,name);
        public void Dispose() { Directory.Delete(Root,true); }
    }
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
    public static void Register(Action<string,Func<Task>> test)
    {
        test("Session preferences default off and retain only explicitly saved options", () => {
            using var tmp = new Temporary(); var path=tmp.File("nested/preferences.json");
            Check(ProtectionPreferencesStore.Load(path)==new ProtectionPreferences());
            var saved=new ProtectionPreferences(true,true,true,true,tmp.Root); ProtectionPreferencesStore.Save(path,saved);
            Check(ProtectionPreferencesStore.Load(path)==saved && !Directory.EnumerateFiles(Path.GetDirectoryName(path)!,"*.tmp").Any());
            return Task.CompletedTask;
        });
        test("Resume preferences reject missing, relative, oversized and malformed settings", async () => {
            using var tmp=new Temporary(); var path=tmp.File("preferences.json");
            await Fails<InvalidDataException>(()=>Task.Run(()=>ProtectionPreferencesStore.Save(path,new(RememberMonitor:true))));
            await Fails<ArgumentException>(()=>Task.Run(()=>ProtectionPreferencesStore.Save(path,new(RememberMonitor:true,MonitorFolder:"relative"))));
            await File.WriteAllTextAsync(path,new string('x',16*1024+1)); await Fails<InvalidDataException>(()=>Task.Run(()=>ProtectionPreferencesStore.Load(path)));
            await File.WriteAllTextAsync(path,"null"); await Fails<InvalidDataException>(()=>Task.Run(()=>ProtectionPreferencesStore.Load(path)));
        });
        test("Preferences cannot be written through a symbolic-link directory", async () => {
            if(OperatingSystem.IsWindows())return;
            using var tmp=new Temporary();Directory.CreateDirectory(tmp.File("target"));Directory.CreateSymbolicLink(tmp.File("link"),tmp.File("target"));
            await Fails<IOException>(()=>Task.Run(()=>ProtectionPreferencesStore.Save(tmp.File("link/preferences.json"),new())));
            Check(Directory.GetFiles(tmp.File("target")).Length==0);
        });
        test("Automatic checks preserve success state on failure and run sequentially", async () => {
            var clock=new Clock();var ticks=Channel.CreateUnbounded<bool>();var failed=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var succeeded=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var attempts=0;var active=0;var overlap=false;
            await using var loop=new FeedUpdateLoop(async token=>{
                if(Interlocked.Increment(ref active)>1)overlap=true;
                try { var attempt=Interlocked.Increment(ref attempts);await Task.Delay(10,token);if(attempt==2)throw new IOException("private error must not enter status"); }
                finally { Interlocked.Decrement(ref active); }
            },state=>{if(state.NextAttempt is not null){if(state.Failed)failed.TrySetResult();else succeeded.TrySetResult();}},TimeSpan.FromHours(6),async(_,token)=>{await ticks.Reader.ReadAsync(token);},clock);
            await succeeded.Task.WaitAsync(TimeSpan.FromSeconds(5));var firstSuccess=loop.Status.LastSuccess;Check(firstSuccess==clock.Now);
            clock.Now=clock.Now.AddHours(6);ticks.Writer.TryWrite(true);await failed.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Check(loop.Status.LastSuccess==firstSuccess && loop.Status.Failed && loop.Status.NextAttempt==clock.Now.AddHours(6) && attempts==2 && !overlap);
            await loop.DisposeAsync();await loop.DisposeAsync();Check(!loop.Status.Running && loop.Status.NextAttempt is null);
        });
        test("Automatic-check shutdown cancels an in-flight request and callback failures are isolated", async () => {
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var canceled=false;
            var loop=new FeedUpdateLoop(async token=>{entered.TrySetResult();try{await Task.Delay(Timeout.Infinite,token);}catch(OperationCanceledException){canceled=true;throw;}},_=>throw new Exception("observer"));
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));await loop.DisposeAsync();Check(canceled && !loop.Status.Running);
            await Fails<ArgumentOutOfRangeException>(()=>Task.Run(()=>new FeedUpdateLoop(_=>Task.CompletedTask,interval:TimeSpan.FromSeconds(1))));
        });
        test("Detection notifications contain counts only and throttle then flush bursts", () => {
            var clock=new Clock();var alerts=new DetectionAlerts(clock);
            Check(alerts.Record(5,false) is null);Check(alerts.Flush(true) is null);
            var first=alerts.Record(1,true);Check(first!.Contains("1 exact detection") && !first.Contains(".exe") && !first.Contains("SHA"));
            Check(alerts.Record(3,true) is null);Check(alerts.Record(2,true) is null);
            clock.Now=clock.Now.AddSeconds(31);Check(alerts.Flush(true)!.Contains("5 exact detections"));
            alerts.Record(2,true);alerts.Flush(false);clock.Now=clock.Now.AddSeconds(31);Check(alerts.Flush(true) is null);
            return Task.CompletedTask;
        });
        test("Finding filters preserve exact evidence and distinguish review from incomplete", () => {
            var exact=new FileFinding(Path.Combine(AppContext.BaseDirectory,"archive.zip"),FileVerdict.KnownThreat,"Known fixture",new string('a',64),ArchiveEntry:"nested/payload.bin",ContainerSha256:new string('b',64));
            Check(FindingSearch.Matches(exact,"PAYLOAD",FindingScope.Detections));Check(FindingSearch.Matches(exact,"AAAA",FindingScope.All));Check(!FindingSearch.Matches(exact,"",FindingScope.Review));
            Check(FindingSearch.Matches(exact with{Verdict=FileVerdict.Skipped},"",FindingScope.Incomplete));Check(!FindingSearch.Matches(exact,"missing",FindingScope.All));
            Check(exact.ArchiveEntry=="nested/payload.bin" && exact.Verdict==FileVerdict.KnownThreat);return Task.CompletedTask;
        });
        test("Trust reset waits for a signed update commit instead of racing it", async () => {
            using var tmp=new Temporary();using var key=RSA.Create(3072);var now=DateTimeOffset.UtcNow;
            var payload=JsonSerializer.SerializeToUtf8Bytes(new FeedPayload(1,1,now,now.AddDays(1),[]),FeedVerifier.Json);
            var envelope=JsonSerializer.SerializeToUtf8Bytes(new SignedFeed(1,"RSA-SHA256",Convert.ToBase64String(payload),Convert.ToBase64String(key.SignData(payload,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1))),FeedVerifier.Json);
            var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var http=new HttpClient(new FakeHttp(async _=>{entered.TrySetResult();await release.Task;return new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(envelope)};}));
            var repo=new FeedRepository(tmp.File("engine"));var update=repo.UpdateAsync(http,new("https://example.com",key.ExportSubjectPublicKeyInfoPem()));
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));var reset=repo.ResetTrustAsync();Check(!reset.IsCompleted);release.TrySetResult();await update;await reset;
            Check(repo.Current is null && !File.Exists(tmp.File("engine/feed.json")) && !File.Exists(tmp.File("engine/sequence.txt")) && !Directory.EnumerateFiles(tmp.File("engine"),"*.tmp").Any());
        });
        test("Oversized anti-rollback state is rejected before parsing", async () => {
            using var tmp=new Temporary();await File.WriteAllTextAsync(tmp.File("sequence.txt"),new string('9',129));
            using var key=RSA.Create(3072);using var http=new HttpClient(new FakeHttp(_=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("{}") } )));
            await Fails<InvalidDataException>(()=>new FeedRepository(tmp.Root).UpdateAsync(http,new("https://example.com",key.ExportSubjectPublicKeyInfoPem())));
        });
    }
}
