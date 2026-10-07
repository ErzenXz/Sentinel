using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sentinel.Core.Protection;

internal static class ProtectionTests
{
    private static readonly RSA Signer = RSA.Create(3072);
    private static string PublicKey => Signer.ExportSubjectPublicKeyInfoPem();
    private static void Check(bool ok) { if (!ok) throw new Exception("Protection assertion failed"); }
    private static async Task Fails<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    private static void Fails<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    private static byte[] Bundle(IEnumerable<HashIndicator>? hashes = null, long sequence = 1, DateTimeOffset? issued = null, DateTimeOffset? expires = null)
    {
        var now = DateTimeOffset.UtcNow;
        var data = JsonSerializer.SerializeToUtf8Bytes(new FeedPayload(1, sequence, issued ?? now, expires ?? now.AddDays(7), (hashes ?? []).ToList()), FeedVerifier.Json);
        return JsonSerializer.SerializeToUtf8Bytes(new SignedFeed(1, "RSA-SHA256", Convert.ToBase64String(data), Convert.ToBase64String(Signer.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))), FeedVerifier.Json);
    }
    private static VerifiedFeed FeedFor(byte[] file) => FeedVerifier.Verify(Bundle([new(Convert.ToHexString(SHA256.HashData(file)), "Harmless unit test indicator", "Local test")]), PublicKey, DateTimeOffset.UtcNow);
    private sealed class Temporary : IDisposable
    {
        public string Root { get; } = Path.Combine(AppContext.BaseDirectory, "protection-test-" + Guid.NewGuid().ToString("N"));
        public Temporary() { Directory.CreateDirectory(Root); }
        public string File(string name) => Path.Combine(Root, name);
        public void Dispose() { Directory.Delete(Root, recursive: true); }
    }
    private sealed class TestKeyProtector : IKeyProtector
    {
        public byte[] Protect(byte[] key) => key.ToArray();
        public byte[] Unprotect(byte[] wrapped) => wrapped.ToArray();
    }
    private sealed class BrokenProtector : IKeyProtector
    {
        public byte[] Protect(byte[] key) => throw new CryptographicException("Simulated DPAPI failure");
        public byte[] Unprotect(byte[] wrapped) => throw new CryptographicException();
    }
    public static void Register(Action<string, Func<Task>> test)
    {
        test("Windows scheduler arguments preserve spaces, quotes and trailing slashes", () => {
            Check(WindowsArgument.Quote("C:\\folder path\\") == "\"C:\\folder path\\\\\"");
            Check(WindowsArgument.Quote("a\"b") == "\"a\\\"b\"");
            return Task.CompletedTask;
        });
        test("Feed trust rejects private keys and weak public keys", () => {
            Fails<CryptographicException>(() => FeedVerifier.Fingerprint(Signer.ExportPkcs8PrivateKeyPem()));
            using var weak=RSA.Create(2048);Fails<CryptographicException>(()=>FeedVerifier.Fingerprint(weak.ExportSubjectPublicKeyInfoPem()));
            return Task.CompletedTask;
        });
        test("Bundled intelligence is available without a server connection", () => {
            Check(BuiltInCatalog.Current.Hashes.Count>6_000);
            Check(BuiltInCatalog.Current.Payload.Sequence==0);
            return Task.CompletedTask;
        });
        test("Independent feed accepts signed metadata and rejects wrong signer", () => {
            var bundle = Bundle(); Check(FeedVerifier.Verify(bundle, PublicKey, DateTimeOffset.UtcNow).Payload.Sequence == 1);
            using var wrong = RSA.Create(3072);
            Fails<CryptographicException>(() => FeedVerifier.Verify(bundle, wrong.ExportSubjectPublicKeyInfoPem(), DateTimeOffset.UtcNow));
            return Task.CompletedTask;
        });
        test("Feed rejects tampering before trusting indicators", () => {
            var signed = JsonSerializer.Deserialize<SignedFeed>(Bundle(), FeedVerifier.Json)!;
            var data = Convert.FromBase64String(signed.Payload); data[10] ^= 1;
            var tampered = JsonSerializer.SerializeToUtf8Bytes(signed with { Payload = Convert.ToBase64String(data) }, FeedVerifier.Json);
            Fails<CryptographicException>(() => FeedVerifier.Verify(tampered, PublicKey, DateTimeOffset.UtcNow)); return Task.CompletedTask;
        });
        test("Feed rollback, expiry and future timestamps are rejected", () => {
            var now = DateTimeOffset.UtcNow;
            Fails<InvalidDataException>(() => FeedVerifier.Verify(Bundle(sequence:1),PublicKey,now,minimumSequence:2));
            Fails<InvalidDataException>(() => FeedVerifier.Verify(Bundle(issued:now.AddDays(-8),expires:now.AddDays(-1)),PublicKey,now));
            Fails<InvalidDataException>(() => FeedVerifier.Verify(Bundle(issued:now.AddHours(1),expires:now.AddDays(1)),PublicKey,now));
            Check(FeedVerifier.Verify(Bundle(issued:now.AddDays(-8),expires:now.AddDays(-1)),PublicKey,now,allowExpired:true).IsExpired(now));
            return Task.CompletedTask;
        });
        test("Feed rejects malformed hashes and duplicate rules", () => {
            Fails<InvalidDataException>(() => FeedVerifier.Verify(Bundle([new("abc", "Test", "Source")]), PublicKey, DateTimeOffset.UtcNow));
            var indicator = new HashIndicator(new string('a',64), "Test", "Source");
            Fails<InvalidDataException>(() => FeedVerifier.Verify(Bundle([indicator,indicator]), PublicKey, DateTimeOffset.UtcNow));
            return Task.CompletedTask;
        });
        test("UTF-8 feed decoding accepts reordered escaped base64 and rejects missing or malformed encodings", () => {
            var signed = JsonSerializer.Deserialize<SignedFeed>(Bundle([new(new string('a', 64), "Transport fixture", "Local test")]), FeedVerifier.Json)!;
            var encodedPayload = "\"\\u" + ((int)signed.Payload[0]).ToString("X4") + signed.Payload[1..] + "\"";
            var reordered = Encoding.UTF8.GetBytes($"{{\"SIGNATURE\":{JsonSerializer.Serialize(signed.Signature)},\"PAYLOAD\":{encodedPayload},\"ALGORITHM\":\"RSA-SHA256\",\"SCHEMA\":1}}");
            Check(FeedVerifier.Verify(reordered, PublicKey, DateTimeOffset.UtcNow).Hashes.Count == 1);
            foreach (var invalid in new[] {
                "{\"schema\":1,\"algorithm\":\"RSA-SHA256\",\"payload\":null,\"signature\":\"AA==\"}",
                "{\"schema\":1,\"algorithm\":\"RSA-SHA256\",\"payload\":\"%%%\",\"signature\":\"AA==\"}",
                "{\"schema\":1,\"algorithm\":\"RSA-SHA256\",\"payload\":\"AA==\"}",
                "{\"schema\":1,\"algorithm\":\"RSA-SHA256\",\"payload\":12,\"signature\":\"AA==\"}" })
                Fails<InvalidDataException>(() => FeedVerifier.Verify(Encoding.UTF8.GetBytes(invalid), PublicKey, DateTimeOffset.UtcNow));
            return Task.CompletedTask;
        });
        test("Failed signed update retains the previous verified feed", async () => {
            using var tmp = new Temporary(); var repository = new FeedRepository(tmp.File("feed"));
            var good = Bundle(sequence:2); byte[] response = good;
            using var http = new HttpClient(new FakeHttp(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(response) })));
            var settings = new ProtectionSettings("https://example.com/",PublicKey);
            await repository.UpdateAsync(http,settings); response = Bundle(sequence:1);
            await Fails<InvalidDataException>(() => repository.UpdateAsync(http,settings));
            Check(repository.Current!.Payload.Sequence==2);Check(File.ReadAllBytes(tmp.File("feed/feed.json")).SequenceEqual(good));
            var loaded = new FeedRepository(tmp.File("feed")); loaded.Load(PublicKey);Check(loaded.Current!.Payload.Sequence==2);
        });
        test("Equal feed sequence cannot replace signed contents", async () => {
            using var tmp = new Temporary(); var repo = new FeedRepository(tmp.File("feed")); var first = Bundle(sequence:1); byte[] response=first;
            using var http = new HttpClient(new FakeHttp(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {Content=new ByteArrayContent(response)})));
            await repo.UpdateAsync(http,new("https://example.com/",PublicKey));
            response=Bundle([new(new string('f',64),"Different","Test")],sequence:1);
            await Fails<InvalidDataException>(()=>repo.UpdateAsync(http,new("https://example.com/",PublicKey)));
        });
        test("Multi-chunk feed refresh preserves every indicator and exact cache bytes", async () => {
            using var tmp = new Temporary(); var repo = new FeedRepository(tmp.File("feed"));
            var rules = Enumerable.Range(0, 1200).Select(i => new HashIndicator(i.ToString("X64"), "Harmless transport fixture", "Local test")).ToArray();
            var envelope = Bundle(rules); Check(envelope.Length > 128 * 1024);
            using var http = new HttpClient(new FakeHttp(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(envelope) })));
            var settings = new ProtectionSettings("https://example.com/", PublicKey);
            await repo.UpdateAsync(http, settings);
            var unchangedTime = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            File.SetLastWriteTimeUtc(tmp.File("feed/feed.json"), unchangedTime);
            File.SetLastWriteTimeUtc(tmp.File("feed/sequence.txt"), unchangedTime);
            var refreshed = await repo.UpdateAsync(http, settings);
            Check(refreshed.Hashes.Count == rules.Length && refreshed.Hashes.ContainsKey(rules[^1].Sha256));
            Check(File.ReadAllBytes(tmp.File("feed/feed.json")).SequenceEqual(envelope));
            Check(File.GetLastWriteTimeUtc(tmp.File("feed/feed.json")) == unchangedTime && File.GetLastWriteTimeUtc(tmp.File("feed/sequence.txt")) == unchangedTime);
            var cached = envelope.ToArray(); cached[^8] ^= 1; await File.WriteAllBytesAsync(tmp.File("feed/feed.json"), cached);
            await Fails<InvalidDataException>(() => repo.UpdateAsync(http, settings));
            Check(ReferenceEquals(repo.Current, refreshed) && File.ReadAllBytes(tmp.File("feed/feed.json")).SequenceEqual(cached));
        });
        test("Oversized declared feed and cache reject refresh while retaining trusted state", async () => {
            using var tmp = new Temporary(); var repo = new FeedRepository(tmp.File("feed")); var envelope = Bundle();
            var oversizedHeader = false;
            using var http = new HttpClient(new FakeHttp(_ => {
                var content = new ByteArrayContent(envelope);
                if (oversizedHeader) content.Headers.ContentLength = FeedVerifier.MaxEnvelopeBytes + 1L;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
            }));
            var settings = new ProtectionSettings("https://example.com/", PublicKey);
            var trusted = await repo.UpdateAsync(http, settings); oversizedHeader = true;
            await Fails<InvalidDataException>(() => repo.UpdateAsync(http, settings));
            Check(ReferenceEquals(repo.Current, trusted) && File.ReadAllBytes(tmp.File("feed/feed.json")).SequenceEqual(envelope));
            oversizedHeader = false;
            await using (var cache = new FileStream(tmp.File("feed/feed.json"), FileMode.Open, FileAccess.Write, FileShare.None)) cache.SetLength(FeedVerifier.MaxEnvelopeBytes + 1L);
            await Fails<InvalidDataException>(() => repo.UpdateAsync(http, settings));
            Check(ReferenceEquals(repo.Current, trusted) && new FileInfo(tmp.File("feed/feed.json")).Length == FeedVerifier.MaxEnvelopeBytes + 1L);
        });
        test("Canceled feed refresh retains committed cache and leaves no staging files", async () => {
            using var tmp = new Temporary(); var repo = new FeedRepository(tmp.File("feed")); var envelope = Bundle();
            using var cancel = new CancellationTokenSource(); var cancelRefresh = false;
            using var http = new HttpClient(new FakeHttp(_ => {
                if (cancelRefresh) cancel.Cancel();
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(envelope) });
            }));
            var settings = new ProtectionSettings("https://example.com/", PublicKey);
            var trusted = await repo.UpdateAsync(http, settings); cancelRefresh = true;
            await Fails<OperationCanceledException>(() => repo.UpdateAsync(http, settings, cancel.Token));
            Check(ReferenceEquals(repo.Current, trusted) && File.ReadAllBytes(tmp.File("feed/feed.json")).SequenceEqual(envelope));
            Check(!Directory.EnumerateFiles(tmp.File("feed"), "*.tmp").Any());
        });
        test("Independent scanner detects an exact hash without Defender", async () => {
            using var tmp = new Temporary(); var bytes=Encoding.UTF8.GetBytes("Harmless exact match fixture");await File.WriteAllBytesAsync(tmp.File("sample.bin"),bytes);
            var result=await new FileScanner(FeedFor(bytes)).ScanFileAsync(tmp.File("sample.bin"));Check(result.Verdict==FileVerdict.KnownThreat && result.Bytes==bytes.Length);
        });
        test("Unknown file remains no-known-match, never guaranteed safe", async () => {
            using var tmp=new Temporary();await File.WriteAllTextAsync(tmp.File("safe.txt"),"ordinary text");
            var result=await new FileScanner().ScanFileAsync(tmp.File("safe.txt"));Check(result.Verdict==FileVerdict.NoKnownMatch && result.Reason.Contains("does not establish"));
        });
        test("Standard harmless AV test marker is distinguished from malware", () => {
            var marker=Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
            Check(FileScanner.IsStandardTestFile(marker,marker.Length));
            Check(!FileScanner.IsStandardTestFile(marker,1000));
            return Task.CompletedTask;
        });
        test("Heuristics create review findings, never automatic removal", async () => {
            using var tmp=new Temporary();await File.WriteAllTextAsync(tmp.File("invoice.pdf.exe"),"benign double extension fixture");
            var finding=await new FileScanner().ScanFileAsync(tmp.File("invoice.pdf.exe"));Check(finding.Verdict==FileVerdict.NeedsReview);
            var vault=new QuarantineVault(tmp.File("vault"),new TestKeyProtector());await Fails<ArgumentException>(()=>vault.QuarantineAsync(finding));Check(File.Exists(finding.Path));
        });
        test("Size limits and cancellation are honored", async () => {
            using var tmp=new Temporary();await File.WriteAllTextAsync(tmp.File("large.bin"),new string('a',200));
            var scanner=new FileScanner(limits:new(MaxFileBytes:100));Check((await scanner.ScanFileAsync(tmp.File("large.bin"))).Verdict==FileVerdict.Skipped);
            using var cancel=new CancellationTokenSource();cancel.Cancel();await Fails<OperationCanceledException>(()=>scanner.ScanPathAsync(tmp.Root,token:cancel.Token));
        });
        test("Folder scan counts findings and bounds result collection", async () => {
            using var tmp=new Temporary();for(var i=0;i<6;i++)await File.WriteAllTextAsync(tmp.File($"file{i}.pdf.exe"),"test");
            var report=await new FileScanner(limits:new(MaxFindings:2)).ScanPathAsync(tmp.Root);Check(report.Scanned==6 && report.Review==6 && report.Findings.Count==2 && report.FindingsTruncated);
        });
        test("Symbolic-link scan cannot traverse a different file", async () => {
            if(OperatingSystem.IsWindows()) return; // CI can lack Windows symlink privileges; Windows acceptance covers junctions.
            using var tmp=new Temporary();await File.WriteAllTextAsync(tmp.File("target"),"test");File.CreateSymbolicLink(tmp.File("link"),tmp.File("target"));
            Check((await new FileScanner().ScanFileAsync(tmp.File("link"))).Verdict==FileVerdict.Error);
        });
        test("Quarantine encrypts, removes, and restores exact chunked content", async () => {
            using var tmp=new Temporary();var bytes=RandomNumberGenerator.GetBytes(200_000);var path=tmp.File("detected.bin");await File.WriteAllBytesAsync(path,bytes);
            var finding=await new FileScanner(FeedFor(bytes)).ScanFileAsync(path);var vault=new QuarantineVault(tmp.File("vault"),new TestKeyProtector());
            var entry=await vault.QuarantineAsync(finding);Check(entry.SourceRemoved && !File.Exists(path));Check(vault.List().Count==1);
            var raw=File.ReadAllBytes(tmp.File("vault/"+entry.Id+".vault"));Check(!raw.AsSpan().IndexOf(bytes.AsSpan(0,64)).Equals(0) && raw.AsSpan().IndexOf(bytes.AsSpan(0,64))<0);
            var restored=tmp.File("restored.bin");await vault.RestoreAsync(entry.Id,restored);Check(File.ReadAllBytes(restored).SequenceEqual(bytes));
            await Fails<IOException>(()=>vault.RestoreAsync(entry.Id,restored));vault.Delete(entry.Id);Check(vault.List().Count==0);
        });
        test("Quarantine refuses files changed after detection", async () => {
            using var tmp=new Temporary();var original=Encoding.UTF8.GetBytes("benign original");var path=tmp.File("file.bin");await File.WriteAllBytesAsync(path,original);
            var finding=await new FileScanner(FeedFor(original)).ScanFileAsync(path);await File.WriteAllTextAsync(path,"different file");
            var vault=new QuarantineVault(tmp.File("vault"),new TestKeyProtector());await Fails<IOException>(()=>vault.QuarantineAsync(finding));Check(File.Exists(path) && vault.List().Count==0);
        });
        test("Failed key protection retains the original file", async () => {
            using var tmp=new Temporary();var bytes=Encoding.UTF8.GetBytes("key failure fixture");var path=tmp.File("file.bin");await File.WriteAllBytesAsync(path,bytes);
            var finding=await new FileScanner(FeedFor(bytes)).ScanFileAsync(path);await Fails<CryptographicException>(()=>new QuarantineVault(tmp.File("vault"),new BrokenProtector()).QuarantineAsync(finding));Check(File.Exists(path));
        });
        test("Corrupted vault cannot produce a restored file", async () => {
            using var tmp=new Temporary();var bytes=Encoding.UTF8.GetBytes("tamper fixture");var path=tmp.File("file.bin");await File.WriteAllBytesAsync(path,bytes);
            var vault=new QuarantineVault(tmp.File("vault"),new TestKeyProtector());var entry=await vault.QuarantineAsync(await new FileScanner(FeedFor(bytes)).ScanFileAsync(path));
            var vaultPath=tmp.File("vault/"+entry.Id+".vault");var raw=File.ReadAllBytes(vaultPath);raw[40]^=1;await File.WriteAllBytesAsync(vaultPath,raw);
            await Fails<AuthenticationTagMismatchException>(()=>vault.RestoreAsync(entry.Id,tmp.File("restore.bin")));Check(!File.Exists(tmp.File("restore.bin")));
        });
        test("Folder monitor reports independent detection on new files", async () => {
            using var tmp=new Temporary();var bytes=Encoding.UTF8.GetBytes("watcher benign fixture");var feed=FeedFor(bytes);var detected=new TaskCompletionSource<FileFinding>(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var monitor=new FolderMonitor(tmp.Root,()=>new FileScanner(feed),finding=>{if(finding.Verdict==FileVerdict.KnownThreat)detected.TrySetResult(finding);},problem=>detected.TrySetException(new Exception(problem)));
            await File.WriteAllBytesAsync(tmp.File("download.bin"),bytes);var result=await detected.Task.WaitAsync(TimeSpan.FromSeconds(8));Check(result.Verdict==FileVerdict.KnownThreat);
        });
    }
}
