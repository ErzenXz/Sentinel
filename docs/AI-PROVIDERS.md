# AI connections

Security works independently of AI. No connection is made until the user asks the advisor. Providers receive the user's question and optionally the exact sanitized snapshot displayed in the UI (Windows status, independent-engine counters/feed state, and any selected finding evidence). File paths, local hashes, and binary contents are excluded from selected-finding context; error strings are replaced with a generic incomplete-scan message. Replies are not stored by Sentinel; providers may retain requests under their own policies. Credentials are sent only as provider authentication headers, never in the prompt.

| Connection | Base endpoint | Authentication | Model |
|---|---|---|---|
| OpenAI-compatible | `https://api.openai.com/v1/` | API key | Enter an available chat-completions model ID |
| OpenRouter | `https://openrouter.ai/api/v1/` | API key | Enter an available provider/model ID |
| Anthropic | `https://api.anthropic.com/` | API key | Enter an available Claude model ID |
| Ollama | `http://127.0.0.1:11434/` | None by default | Pull a model in Ollama and enter its name |
| LM Studio | `http://127.0.0.1:1234/v1/` | Local server configuration | Enter the loaded model ID; choose OpenAiCompatible |
| Codex app-server | Local official `codex.exe` | Dedicated Codex login | Leave model blank for the account default, or enter an accessible model |

Base endpoints include the API prefix shown above. Sentinel appends `chat/completions`, `v1/messages`, or `api/chat`. Remote endpoints must use HTTPS. HTTP is allowed for loopback only. Redirects are disabled to prevent credentials being forwarded to another endpoint. Only one connection and one DPAPI-encrypted key are stored at a time. Clear the key when moving from a paid provider to a local provider. API requests can incur provider charges.

The API adapter does not have tools, filesystem access, automatic provider fallback, or automatic retry. Provider errors are returned as HTTP status codes without echoing response bodies. Requests time out after three minutes and responses are bounded to 2 MB. A network failure does not change the antivirus status.

## Experimental Codex setup

Install the official Windows Codex CLI. Select the official native `codex.exe`, not a `.cmd` shim, downloaded executable from a third party, or shell wrapper. Set that absolute executable path in Settings, then click **Prepare dedicated Codex home**. In PowerShell:

```powershell
$env:CODEX_HOME = Join-Path $env:LOCALAPPDATA 'Sentinel\codex-home'
& 'C:\path\to\official\codex.exe' login
```

Use the actual official executable path on your computer. Sign in with an account eligible for Codex. Subscription authentication and account limits are controlled by Codex; Sentinel does not extract credentials from ChatGPT or implement third-party subscription token proxies.

Sentinel runs `codex.exe app-server` over stdio on demand. It performs initialization, starts an ephemeral thread, requests a review, consumes final agent messages, checks the turn completion status, and terminates its child process. The dedicated home avoids inheriting the user's developer MCP/skills/configuration. Sentinel writes read-only/on-request settings, disables shell tools and web search, declines execution/file-change approval requests, and rejects other server requests. The client verifies that the thread reports read-only mode and on-request approvals before sending the review. It requests sandbox network access off. It does not claim a filesystem read-root boundary: the locally installed 0.160.0 schema lacks the restricted-read fields shown in some current online documentation. Native shell, execution, apps, plugins, browser, image and additional tool features are disabled through CLI flags; incompatible versions fail at startup. AI is disabled when Sentinel is elevated.

This is an **experimental adapter**, not a certified sandbox boundary. Platform defaults, Codex protocol changes, Windows sandbox support, CLI configuration, and built-in tools require version-specific validation. Do not install third-party Codex tools/plugins in Sentinel's dedicated home. The HTTP adapters are the simpler text-only option. No live account request was made during development.

This separation follows the architecture described in [OpenClaw model providers](https://github.com/openclaw/openclaw/blob/main/docs/concepts/model-providers.md) and [OpenClaw's Codex plugin](https://github.com/openclaw/openclaw/blob/main/extensions/codex/README.md), without reusing their implementation.

Protocol references: [Codex app-server](https://learn.chatgpt.com/docs/app-server), [Ollama chat](https://docs.ollama.com/api/chat), [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create).

## Model discovery (v0.4)

In Settings, choose the provider and base endpoint, enter its key when required, then choose **Discover models**. The editable picker preserves manually entered model IDs. Discovery performs GET metadata only: OpenAI-compatible `/v1/models` when the base ends in `/v1/`, Ollama `/api/tags`, or Anthropic `/v1/models?limit=1000`. Responses are bounded to 1 MiB, 2,000 input entries and 1,000 retained IDs. Pagination is reported rather than fetched automatically. A listed ID is not proof that it supports chat.

The CLI also supports `Sentinel.Scanner.exe models --provider Ollama --endpoint http://127.0.0.1:11434/`. For authenticated remote discovery, supply `SENTINEL_AI_KEY` in the process environment; never pass credentials as CLI arguments. Discovery neither calls inference nor includes your security snapshot. Codex models use its authenticated runtime configuration; this button does not enumerate them.

Protocol references: [OpenAI model listing](https://developers.openai.com/api/reference/resources/models/methods/list), [Ollama local model listing](https://docs.ollama.com/api/tags), [Anthropic model listing](https://platform.claude.com/docs/en/api/models/list).

## Jev decisions (v0.5)

Jev is separate from the chat advisor because it evaluates typed choices instead of generating explanations. Settings → Jev structured decisions offers TypeSafe (`jev-latest`) and Vercel Gateway (`typesafe-ai/jev`) presets with a separate key. Both use the documented TypeSafe-compatible HTTP contract. The provider selector clears the key when switching. Settings and key are stored together with Windows user-scoped DPAPI.

Open Firewall, refresh local review, select an app, optionally inspect its publisher, review the displayed categories/counts and explicitly opt into sharing. One five-second request returns routine/review/urgent plus probabilities. The model cannot lower local priority or authorize a firewall change. Low confidence, malformed responses, quota errors, timeouts and network failures stay manual review. See [firewall design and CLI](FAST-FIREWALL.md).

Live paid inference and provider account validation were not performed. HTTP protocol tests use local fixtures. There is no local Jev weight bundle or claim that the upstream model is open source. Access, cost and data retention are governed by the selected provider. [Official Jev model](https://vercel.com/ai-gateway/models/jev), [TypeSafe HTTP schema](https://api.typesafe.ai/docs), [documented integration paths](https://vercel.com/i/jev-integrations).
