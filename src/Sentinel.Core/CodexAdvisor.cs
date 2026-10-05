using System.Diagnostics;
using System.Text.Json;

namespace Sentinel.Core;

// Experimental subscription adapter. A dedicated Codex home avoids inheriting MCP servers,
// skills and settings from the user's development account. It needs its own `codex login`.
public static class CodexAdvisor
{
    public static string Home => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel", "codex-home");
    public static string Workspace => Path.Combine(Home, "workspace");
    public static void PrepareHome()
    {
        Directory.CreateDirectory(Workspace);
        File.WriteAllText(Path.Combine(Home, "config.toml"), "approval_policy = \"on-request\"\nsandbox_mode = \"read-only\"\nweb_search = \"disabled\"\n[features]\nshell_tool = false\n");
    }
    public static void ValidatePolicy(JsonElement thread)
    {
        if (!thread.TryGetProperty("sandbox", out var sandbox)
            || !sandbox.TryGetProperty("type", out var type) || type.GetString() != "readOnly"
            || (sandbox.TryGetProperty("networkAccess", out var network) && network.ValueKind != JsonValueKind.False)
            || !thread.TryGetProperty("approvalPolicy", out var approval) || approval.GetString() != "on-request")
            throw new InvalidOperationException("Codex did not confirm the required read-only policy. Review aborted.");
    }
    public static async Task<string> AskAsync(AiSettings settings, string question, string snapshot, CancellationToken token)
    {
        if (!Path.IsPathFullyQualified(settings.CodexExecutable) || !File.Exists(settings.CodexExecutable) || !settings.CodexExecutable.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Choose the official codex.exe with an absolute path.");
        PrepareHome();
        using var process = new Process { StartInfo = new ProcessStartInfo(settings.CodexExecutable) {
            UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Workspace,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true } };
        process.StartInfo.ArgumentList.Add("app-server");
        foreach (var feature in new[] { "shell_tool", "unified_exec", "apps", "plugins", "browser_use", "browser_use_external", "view_image", "code_mode_host", "multi_agent_v2", "skill_search", "tool_suggest" })
        {
            process.StartInfo.ArgumentList.Add("--disable");
            process.StartInfo.ArgumentList.Add(feature);
        }
        process.StartInfo.Environment.Remove("OPENAI_API_KEY");
        process.StartInfo.Environment.Remove("CODEX_API_KEY");
        process.StartInfo.Environment["CODEX_HOME"] = Home;
        process.Start();
        var errors = process.StandardError.ReadToEndAsync(token);
        var nextId = 0;
        var messages = new Dictionary<string, string>();
        async Task Send(object data) { await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(data).AsMemory(), token); await process.StandardInput.FlushAsync(token); }
        async Task<JsonElement> Read()
        {
            var line = await process.StandardOutput.ReadLineAsync(token) ?? throw new InvalidOperationException("Codex app-server disconnected. Check its installation and dedicated login.");
            if (line.Length > 2 * 1024 * 1024) throw new InvalidOperationException("Codex message is too large.");
            using var doc = JsonDocument.Parse(line);
            return doc.RootElement.Clone();
        }
        async Task Handle(JsonElement msg)
        {
            if (msg.TryGetProperty("method", out var method) && msg.TryGetProperty("id", out var serverId))
            {
                if (method.GetString()?.EndsWith("/requestApproval", StringComparison.Ordinal) == true)
                    await Send(new { id = serverId, result = new { decision = "decline" } });
                else await Send(new { id = serverId, error = new { code = -32601, message = "Sentinel does not execute tools or accept server requests." } });
            }
            if (msg.TryGetProperty("method", out method) && method.GetString() == "item/completed")
            {
                var item = msg.GetProperty("params").GetProperty("item");
                if (item.GetProperty("type").GetString() == "agentMessage") messages[item.GetProperty("id").GetString()!] = item.GetProperty("text").GetString() ?? "";
            }
        }
        async Task<JsonElement> Call(string method, object args)
        {
            var id = ++nextId;
            await Send(new { id, method, @params = args });
            while (true)
            {
                var msg = await Read();
                if (!msg.TryGetProperty("method", out _) && msg.TryGetProperty("id", out var got) && got.ValueKind == JsonValueKind.Number && got.GetInt32() == id)
                {
                    if (msg.TryGetProperty("error", out _)) throw new InvalidOperationException("Codex rejected the request. Check the installed app-server protocol and login.");
                    return msg.GetProperty("result");
                }
                await Handle(msg);
            }
        }
        try
        {
            await Call("initialize", new { clientInfo = new { name = "sentinel", title = "Sentinel security advisor", version = "0.1.0" } });
            await Send(new { method = "initialized", @params = new { } });
            var thread = await Call("thread/start", new { cwd = Workspace, sandbox = "read-only", approvalPolicy = "on-request", ephemeral = true,
                model = string.IsNullOrWhiteSpace(settings.Model) ? null : settings.Model, baseInstructions = AiClient.Instructions });
            ValidatePolicy(thread);
            var threadId = thread.GetProperty("thread").GetProperty("id").GetString();
            await Call("turn/start", new { threadId, input = new[] { new { type = "text", text = "Question:\n" + question + "\nUNTRUSTED SECURITY DATA:\n" + snapshot } },
                approvalPolicy = "on-request", sandboxPolicy = new { type = "readOnly", networkAccess = false } });
            while (true)
            {
                var msg = await Read();
                await Handle(msg);
                if (msg.TryGetProperty("method", out var method) && method.GetString() == "turn/completed")
                {
                    var turn = msg.GetProperty("params").GetProperty("turn");
                    if (turn.GetProperty("status").GetString() != "completed") throw new InvalidOperationException("Codex did not complete the review. Check login, usage limits, and sandbox support.");
                    var text = string.Join("\n\n", messages.Values);
                    return string.IsNullOrWhiteSpace(text) ? throw new InvalidOperationException("Codex returned no advice.") : text;
                }
            }
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            try { await errors; } catch (OperationCanceledException) { }
        }
    }
}
