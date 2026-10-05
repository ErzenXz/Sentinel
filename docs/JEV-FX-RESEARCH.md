# Jev and fx research — 2026-10-05

The requested projects were identified as **TypeSafe AI Jev** and **Vercel Labs fx**, then reviewed after packaging v0.4.

Jev is a typed evaluation model rather than a generative chat model. Its official HTTP schema accepts shared state and named questions; choice answers include a chosen option, confidence and per-option probabilities. The Vercel catalog lists `typesafe-ai/jev` as an evaluation model; its public catalog was fetched without credentials to verify this identifier. The direct TypeSafe schema documents `jev-latest`. The Gateway's documented TypeSafe-compatible path supports the same native response naming.

Sources: [TypeSafe OpenAPI](https://api.typesafe.ai/openapi.json), [official TypeSafe JS SDK](https://github.com/typesafe-ai/typesafe-sdk-js/tree/66880ccded6cb642dc1809620c2b108c33730214), [Jev catalog](https://vercel.com/ai-gateway/models/jev), [integration paths](https://vercel.com/i/jev-integrations).

fx is an experimental Zig coding-agent harness with native and WebAssembly embedding surfaces. We inspected commit `cc3c514acc1e2a9c43f545fb119dce8e19cab562`: SDK host ownership, bounded/cancelable events, one active turn, permission gates and its Jev permission-review adapter. The adapter separates typed model decisions from the surrounding permission machinery. Its coding-agent policy is not a Windows antivirus policy and was not copied into Sentinel.

Sources: [fx at the inspected commit](https://github.com/vercel-labs/fx/tree/cc3c514acc1e2a9c43f545fb119dce8e19cab562), [SDK host contract](https://github.com/vercel-labs/fx/blob/cc3c514acc1e2a9c43f545fb119dce8e19cab562/sdk/README.md), [permission gate](https://github.com/vercel-labs/fx/blob/cc3c514acc1e2a9c43f545fb119dce8e19cab562/src/core/permissions/permission_gate.zig), [Jev reviewer](https://github.com/vercel-labs/fx/blob/cc3c514acc1e2a9c43f545fb119dce8e19cab562/src/builtins/gateway/typesafe_permission_reviewer.zig).

Our implementation decision is an inference from those designs: for a native Windows metadata review, fixed local checks and a single bounded evaluation request avoid a general coding-agent loop. Sentinel's own C# host owns capture, privacy projection, request budgets, cache and all OS actions. No shell/filesystem/MCP tool is granted to Jev. A model decision only ranks evidence; the user controls enforcement.

No fx code, binary, JavaScript runtime, model weights or external credentials were bundled. This is an architectural adaptation, not an fx integration or sandbox certification. Sentinel itself remains MIT licensed; upstream Jev API access and model licensing are separate. No upstream latency claim is transferred to Sentinel. Test results establish protocol and failure behavior, not malware detection accuracy or live Jev latency.
