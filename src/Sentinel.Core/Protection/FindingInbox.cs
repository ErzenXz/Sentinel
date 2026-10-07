namespace Sentinel.Core.Protection;

// Bounded transport between a worker and a periodically drained UI. It retains exact
// detections ahead of review/error messages and never queues a UI closure per finding.
public sealed class FindingInbox
{
    private sealed class Identity : IEqualityComparer<FileFinding>
    {
        private static readonly StringComparer Paths = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        public bool Equals(FileFinding? x, FileFinding? y) => x is not null && y is not null && Paths.Equals(x.Path, y.Path)
            && x.ArchiveEntry == y.ArchiveEntry && StringComparer.OrdinalIgnoreCase.Equals(x.Sha256, y.Sha256) && x.Verdict == y.Verdict;
        public int GetHashCode(FileFinding value) => HashCode.Combine(Paths.GetHashCode(value.Path), value.ArchiveEntry,
            value.Sha256 is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(value.Sha256), value.Verdict);
    }
    private readonly object gate = new();
    private readonly LinkedList<FileFinding> findings = new();
    private readonly Dictionary<FileFinding, LinkedListNode<FileFinding>> identities = new(new Identity());
    private readonly int capacity;
    private long dropped;
    public FindingInbox(int capacity = 512)
    {
        if (capacity is < 1 or > 2_000) throw new ArgumentOutOfRangeException(nameof(capacity));
        this.capacity = capacity;
    }
    public int Count { get { lock (gate) return findings.Count; } }
    public long Dropped { get { lock (gate) return dropped; } }
    private static bool IsDetection(FileFinding value) => value.Verdict is FileVerdict.KnownThreat or FileVerdict.TestFile;
    public void Add(FileFinding value)
    {
        if (value.Verdict == FileVerdict.NoKnownMatch) return;
        lock (gate)
        {
            if (identities.ContainsKey(value)) return;
            if (findings.Count == capacity)
            {
                dropped++;
                if (!IsDetection(value)) return;
                var expendable = findings.First;
                while (expendable is not null && IsDetection(expendable.Value)) expendable = expendable.Next;
                if (expendable is null) return;
                identities.Remove(expendable.Value); findings.Remove(expendable);
            }
            identities.Add(value, findings.AddLast(value));
        }
    }
    public FileFinding[] Drain(int maximum = 128)
    {
        if (maximum is < 1 or > 2_000) throw new ArgumentOutOfRangeException(nameof(maximum));
        lock (gate)
        {
            if (findings.Count == 0) return [];
            var result = new FileFinding[Math.Min(maximum, findings.Count)];
            for (var i = 0; i < result.Length; i++)
            {
                var first = findings.First!; result[i] = first.Value; identities.Remove(first.Value); findings.RemoveFirst();
            }
            return result;
        }
    }
}
