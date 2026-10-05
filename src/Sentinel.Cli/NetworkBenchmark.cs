using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Sentinel.Core;

internal static class NetworkBenchmark
{
    public static string Run(string? requested)
    {
        var iterations = requested is null ? 1000 : int.TryParse(requested, out var number) ? number : 0;
        if (iterations is < 1 or > 10000) throw new ArgumentException("Benchmark iterations must be 1..10000.");
        var now = DateTimeOffset.UtcNow;
        var snapshot = new NetworkSnapshot(now,[new("Domain",true,"Block","Allow"),new("Private",true,"Block","Allow"),new("Public",true,"Block","Allow")],
            Enumerable.Range(0,1000).Select(i => new ConnectionRecord(i%4==0?"0.0.0.0":"127.0.0.1",4000+i,i%4==0?"0.0.0.0":"192.168.1.2",i%4==0?0:443,i%4==0?"Listen":"Established",1+i%250)).ToArray(),
            Enumerable.Range(1,250).Select(i=>new NetworkProcess(i,"fixture-"+i,@"C:\fixtures\app-"+i+".exe",now.AddMinutes(-10).ToString("o"))).ToArray(),false);
        for (var i=0;i<20;i++) _ = NetworkReview.Assess(snapshot);
        var times = new double[iterations]; var before = GC.GetAllocatedBytesForCurrentThread(); var apps = 0;
        for (var i=0;i<iterations;i++) { var start = Stopwatch.GetTimestamp(); apps=NetworkReview.Assess(snapshot).Count; times[i]=Stopwatch.GetElapsedTime(start).TotalMilliseconds; }
        var allocated = GC.GetAllocatedBytesForCurrentThread()-before; Array.Sort(times);
        return JsonSerializer.Serialize(new { schemaVersion=1, description="Synthetic warmed local policy evaluation only; excludes Windows capture, UI, scanning, AI and startup.",
            os=RuntimeInformation.OSDescription, architecture=RuntimeInformation.ProcessArchitecture.ToString(), dotnet=Environment.Version.ToString(), iterations,
            connections=snapshot.Connections.Count, applications=apps, medianMilliseconds=times[iterations/2],p95Milliseconds=times[(int)Math.Ceiling(iterations*.95)-1],
            allocatedBytesPerEvaluation=allocated/iterations },NetworkReview.Json);
    }
}
