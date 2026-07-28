import assert from "node:assert/strict"
import { spawn, spawnSync } from "node:child_process"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { createServer } from "node:http"
import { tmpdir } from "node:os"
import { delimiter, join, resolve } from "node:path"
import test from "node:test"

const expected = { answer: "bounded result" }
const resultSchema = {
  type: "object",
  properties: { answer: { type: "string" } },
  required: ["answer"],
  additionalProperties: false,
}

test("worker PATH adb shim refuses device access", () => {
  const blocked = spawnSync(resolve("bin/adb"), ["devices"], { encoding: "utf8" })
  assert.equal(blocked.status, 126)
  assert.match(blocked.stderr, /adb is disabled/)
})

test("non-thinking finalizer uses StructuredOutput with required tool choice", async () => {
  const requests = []
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    sendCompletion(response, body, {
      id: "finalizer",
      toolCalls: [structuredOutputCall(expected)],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-finalizer-test-"))
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
      }),
    )
    assert.equal(completed.code, 0, completed.stderr)
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(result.output_transport.profile, "structured_finalizer")
    assert.equal(result.output_transport.request_mode, "prompt_sync")
    assert.equal(result.output_transport.model_calls.length, 1)
    assert.equal(result.output_transport.model_calls[0].thinking_mode, "disabled")
    assert.equal(result.output_transport.model_calls[0].wire_tool_choice, "required")
    assert.equal(requests.length, 1)
    assert.equal(requests[0].body.thinking.type, "disabled")
    assert.equal(requests[0].body.reasoning_effort, undefined)
    assert.equal(requests[0].body.tool_choice, "required")
    assert.deepEqual(toolNames(requests[0].body), ["StructuredOutput"])
    assert.ok(events.some((item) => item.event_type === "model.output.validated"))
    assert.ok(
      events.some(
        (item) =>
          item.event_type === "model.transport.selected" &&
          item.data.request_mode === "prompt_sync",
      ),
    )
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("stable analyzer uses non-thinking tools, then an isolated finalizer", async () => {
  const requests = []
  let workspaceFile
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    if (requests.length === 1) {
      sendCompletion(response, body, {
        id: "stable-read",
        toolCalls: [
          {
            index: 0,
            id: "call-read-stable",
            type: "function",
            function: {
              name: "read",
              arguments: JSON.stringify({ filePath: workspaceFile }),
            },
          },
        ],
        finish: "tool_calls",
      })
      return
    }
    if (requests.length === 2) {
      sendCompletion(response, body, {
        id: "stable-memo",
        content: "The inspected file contains exported provider evidence.",
      })
      return
    }
    sendCompletion(response, body, {
      id: "stable-finalizer",
      toolCalls: [structuredOutputCall(expected)],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-stable-test-"))
  workspaceFile = join(root, "evidence.txt")
  await writeFile(workspaceFile, "exported provider evidence")
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
        profile: stableProfile(),
        explorerPrompt: "Read evidence.txt and produce an evidence memo.",
      }),
    )
    assert.equal(completed.code, 0, completed.stderr)
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(result.usage.calls, 3)
    assert.equal(result.output_transport.profile, "stable_analyzer")
    assert.equal(result.output_transport.model_calls.length, 2)
    assert.equal(
      result.output_transport.model_calls[0].usage.provider_calls,
      2,
    )
    assert.equal(result.output_transport.model_calls[0].thinking_mode, "disabled")
    assert.match(result.output_transport.explorer_memo, /exported provider evidence/)
    assert.equal(requests.length, 3)
    assert.equal(requests[0].body.thinking.type, "disabled")
    assert.equal(requests[0].body.tool_choice, "auto")
    assert.deepEqual(toolNames(requests[0].body), ["bash", "glob", "grep", "read"])
    assert.match(JSON.stringify(requests[0].body.messages), /analysis memo/)
    assert.doesNotMatch(JSON.stringify(requests[0].body.messages), /requested structured contract/)
    assert.match(JSON.stringify(requests[1].body.messages), /exported provider evidence/)
    assert.equal(requests[2].body.thinking.type, "disabled")
    assert.equal(requests[2].body.tool_choice, "required")
    assert.deepEqual(toolNames(requests[2].body), ["StructuredOutput"])
    assert.match(
      JSON.stringify(requests[2].body.messages),
      /required structured contract/,
    )
    assert.match(JSON.stringify(requests[2].body.messages), /EXPLORER_HANDOFF/)
    assert.ok(
      events.some(
        (item) =>
          item.event_type === "model.tool.completed" &&
          item.data.tool === "read" &&
          item.data.input?.filePath === workspaceFile,
      ),
    )
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("empty tool-loop completion is terminalized into a non-empty memo", async () => {
  const requests = []
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    if (requests.length === 1) {
      sendCompletion(response, body, {
        id: "terminalize-tool",
        toolCalls: [
          {
            index: 0,
            id: "call-terminalize-bash",
            type: "function",
            function: {
              name: "bash",
              arguments: JSON.stringify({
                command: "true",
                description: "Finish evidence inspection",
              }),
            },
          },
        ],
        finish: "tool_calls",
      })
      return
    }
    if (requests.length === 2) {
      sendCompletion(response, body, {
        id: "terminalize-empty",
        content: "",
      })
      return
    }
    if (requests.length === 3) {
      sendCompletion(response, body, {
        id: "terminalize-memo",
        content:
          "Inspection completed; request one bounded ordinary-app-UID provider test.",
      })
      return
    }
    sendCompletion(response, body, {
      id: "terminalize-finalizer",
      toolCalls: [structuredOutputCall(expected)],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-terminalize-test-"))
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
        profile: stableProfile(),
      }),
    )
    assert.equal(completed.code, 0, completed.stderr)
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(requests.length, 4)
    assert.equal(result.output_transport.model_calls[0].terminalized, true)
    assert.match(
      result.output_transport.explorer_memo,
      /ordinary-app-UID provider test/,
    )
    assert.deepEqual(toolNames(requests[2].body), [])
    assert.match(JSON.stringify(requests[2].body.messages), /MEMO_TERMINALIZATION/)
    assert.ok(
      events.some((item) => item.event_type === "model.memo.terminalizing"),
    )
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("workspace tools cannot read or shell-cat files outside workspace and /tmp", async () => {
  const requests = []
  const secret = "APKS_TEST_EXTERNAL_BOUNDARY_SECRET"
  const outsideRoot = await mkdtemp(
    join(resolve("."), ".apkscanner-outside-boundary-"),
  )
  const outsideFile = join(outsideRoot, "secret.txt")
  await writeFile(outsideFile, secret)
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    if (requests.length === 1) {
      sendCompletion(response, body, {
        id: "boundary-read",
        toolCalls: [
          {
            index: 0,
            id: "call-read-outside",
            type: "function",
            function: {
              name: "read",
              arguments: JSON.stringify({ filePath: outsideFile }),
            },
          },
        ],
        finish: "tool_calls",
      })
      return
    }
    if (requests.length === 2) {
      sendCompletion(response, body, {
        id: "boundary-bash",
        toolCalls: [
          {
            index: 0,
            id: "call-bash-outside",
            type: "function",
            function: {
              name: "bash",
              arguments: JSON.stringify({
                command: `cat ${JSON.stringify(outsideFile)}`,
                description: "Attempt an out-of-workspace read",
              }),
            },
          },
        ],
        finish: "tool_calls",
      })
      return
    }
    if (requests.length === 3) {
      sendCompletion(response, body, {
        id: "boundary-memo",
        content: "Both external file access attempts were denied.",
      })
      return
    }
    sendCompletion(response, body, {
      id: "boundary-finalizer",
      toolCalls: [structuredOutputCall(expected)],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-boundary-test-"))
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
        profile: stableProfile(),
        explorerPrompt: "Try the assigned checks, then report whether access was denied.",
      }),
    )
    assert.equal(completed.code, 0, completed.stderr)
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(requests.length, 4)
    const providerMessages = JSON.stringify(
      requests.slice(1, 3).flatMap((item) => item.body.messages),
    )
    assert.doesNotMatch(providerMessages, new RegExp(secret))
    assert.match(providerMessages, /denied|permission/i)
    const toolEvents = events.filter(
      (item) =>
        item.event_type === "model.tool.completed" &&
        ["read", "bash"].includes(item.data.tool) &&
        item.data.status === "error",
    )
    assert.equal(toolEvents.length, 2)
    assert.ok(toolEvents.every((item) => item.data.status === "error"))
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
    await rm(outsideRoot, { recursive: true, force: true })
  }
})

test("bash cannot read the provider API key from process environments", async () => {
  const requests = []
  const authorizationHeaders = []
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    authorizationHeaders.push(request.headers.authorization)
    if (requests.length === 1) {
      sendCompletion(response, body, {
        id: "secret-environment-check",
        toolCalls: [
          {
            index: 0,
            id: "call-bash-secret-environment",
            type: "function",
            function: {
              name: "bash",
              arguments: JSON.stringify({
                command:
                  "node -e 'const f=require(\"fs\");let p=process.pid,found=false,checked=0;" +
                  "for(let i=0;i<32&&p>0;i++){try{const e=f.readFileSync(`/proc/${p}/environ`);" +
                  "checked++;if(e.includes(Buffer.from(\"DEEPSEEK_API_KEY=\")))found=true;" +
                  "const s=f.readFileSync(`/proc/${p}/status`,\"utf8\");" +
                  "p=Number(s.match(/^PPid:\\s+(\\d+)/m)?.[1]??0)}catch{break}}" +
                  "console.log(found?\"provider credential found\":`provider credential absent across ${checked} process environments`)'",
                description:
                  "Verify provider credentials are absent from this tool and all ancestor process environments",
              }),
            },
          },
        ],
        finish: "tool_calls",
      })
      return
    }
    if (requests.length === 2) {
      sendCompletion(response, body, {
        id: "secret-environment-memo",
        content: "The provider key is absent from the Bash and worker process environments.",
      })
      return
    }
    sendCompletion(response, body, {
      id: "secret-environment-finalizer",
      toolCalls: [structuredOutputCall(expected)],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-secret-env-test-"))
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
        profile: stableProfile(),
      }),
    )
    assert.equal(
      completed.code,
      0,
      [completed.stderr, completed.stdout].filter(Boolean).join("\n"),
    )
    assert.doesNotMatch(completed.stdout, /integration-test-only/)
    assert.doesNotMatch(completed.stderr, /integration-test-only/)
    const { result } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(requests.length, 3)
    const toolReplay = JSON.stringify(requests[1].body.messages)
    const toolOutput = requests[1].body.messages
      .filter((message) => message.role === "tool")
      .map((message) => message.content)
      .join("\n")
    const checkedProcesses = Number(
      toolOutput.match(/provider credential absent across (\d+) process environments/)?.[1],
    )
    assert.ok(checkedProcesses >= 3, toolOutput)
    assert.doesNotMatch(toolOutput, /provider credential found/)
    assert.doesNotMatch(toolReplay, /integration-test-only/)
    assert.doesNotMatch(toolOutput, /DEEPSEEK_API_KEY=/)
    assert.ok(
      requests.every(
        (item) => !JSON.stringify(item.body).includes("integration-test-only"),
      ),
    )
    assert.doesNotMatch(toolReplay, /OPENCODE_CONFIG_CONTENT=/)
    assert.doesNotMatch(toolReplay, /OPENCODE_SERVER_PASSWORD=/)
    assert.ok(
      authorizationHeaders.every(
        (value) => value === "Bearer integration-test-only",
      ),
    )
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("worker rejects a missing or empty internal provider key", async () => {
  const root = await mkdtemp(join(tmpdir(), "apkscanner-missing-key-test-"))
  const payload = investigationPayload({
    baseURL: "http://127.0.0.1:9",
    profile: finalizerProfile(),
  })
  try {
    for (const options of [
      { includeProviderAPIKey: false },
      { providerAPIKey: "   " },
    ]) {
      const completed = await runWorker(root, payload, options)
      assert.equal(completed.code, 1)
      assert.match(completed.stderr, /_provider_api_key is missing or empty/)
      assert.equal(completed.stdout, "")
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test("thinking explorer omits tool_choice and replays reasoning_content", async () => {
  const requests = []
  let workspaceFile
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    if (requests.length === 1) {
      sendCompletion(response, body, {
        id: "thinking-read",
        reasoningContent: "I need to inspect the assigned evidence file.",
        content: "",
        toolCalls: [
          {
            index: 0,
            id: "call-read-thinking",
            type: "function",
            function: {
              name: "read",
              arguments: JSON.stringify({ filePath: workspaceFile }),
            },
          },
        ],
        finish: "tool_calls",
      })
      return
    }
    if (requests.length === 2) {
      // Keep the provider turn slower than one worker poll so the worker must
      // wait through the intermediate tool-call message instead of treating it
      // as the final memo.
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 750))
      sendCompletion(response, body, {
        id: "thinking-memo",
        reasoningContent: "The tool result supports a bounded memo.",
        content: "Evidence memo: exported provider evidence was inspected.",
      })
      return
    }
    sendCompletion(response, body, {
      id: "thinking-finalizer",
      toolCalls: [structuredOutputCall(expected)],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-thinking-test-"))
  workspaceFile = join(root, "evidence.txt")
  await writeFile(workspaceFile, "exported provider evidence")
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
        profile: thinkingProfile(),
        explorerPrompt: "Read evidence.txt before producing the analysis memo.",
      }),
    )
    assert.equal(completed.code, 0, completed.stderr)
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(result.usage.calls, 3)
    assert.equal(
      result.output_transport.profile,
      "thinking_explorer_then_finalizer",
    )
    assert.equal(result.output_transport.stages[0].thinking_mode, "enabled")
    assert.equal(result.output_transport.stages[0].wire_tool_choice, "omitted")
    assert.equal(
      result.output_transport.provider_wire_requests[0].received_tool_choice,
      "auto",
    )
    assert.equal(
      result.output_transport.provider_wire_requests[0].forwarded_tool_choice,
      null,
    )
    assert.equal(
      result.output_transport.provider_wire_requests[0].stripped_tool_choice,
      true,
    )
    assert.equal(requests.length, 3)
    assert.equal(requests[0].body.thinking.type, "enabled")
    assert.equal(requests[0].body.reasoning_effort, "high")
    assert.equal(requests[0].body.tool_choice, undefined)
    assert.deepEqual(toolNames(requests[0].body), ["bash", "glob", "grep", "read"])
    const replay = JSON.stringify(requests[1].body.messages)
    assert.match(replay, /I need to inspect the assigned evidence file/)
    assert.match(replay, /exported provider evidence/)
    assert.equal(requests[1].body.tool_choice, undefined)
    assert.equal(requests[2].body.thinking.type, "disabled")
    assert.equal(requests[2].body.reasoning_effort, undefined)
    assert.equal(requests[2].body.tool_choice, "required")
    assert.deepEqual(toolNames(requests[2].body), ["StructuredOutput"])
    assert.ok(events.some((item) => item.event_type === "model.tool_loop.waiting"))
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("deep capability performs a real non-thinking provider probe", async () => {
  const requests = []
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    sendCompletion(response, body, {
      id: "capability-probe",
      toolCalls: [structuredOutputCall({ ok: true })],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-capability-test-"))
  try {
    const completed = await runWorker(root, {
      schema_version: "1.0",
      action: "capability",
      model: "deepseek-v4-flash",
      base_url: `http://127.0.0.1:${address.port}`,
      timeout_ms: 10_000,
      live_probe: true,
      tool_profile: "workspace_shell",
      execution_profile: finalizerProfile(),
    })
    assert.equal(completed.code, 0, completed.stderr)
    const { result } = parseWorkerOutput(completed.stdout)
    assert.equal(result.live_probe.ok, true)
    assert.equal(result.live_probe.thinking_mode, "disabled")
    assert.equal(result.max_steps, 1000)
    assert.equal(result.max_provider_requests, 1100)
    assert.equal(requests.length, 1)
    assert.equal(requests[0].body.thinking.type, "disabled")
    assert.equal(requests[0].body.tool_choice, "required")
    assert.deepEqual(toolNames(requests[0].body), ["StructuredOutput"])
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("provider authentication failures are returned as classified audit errors", async () => {
  const api = createServer(async (request, response) => {
    await readJSON(request)
    response.writeHead(401, { "Content-Type": "application/json" })
    response.end(
      JSON.stringify({
        error: {
          message:
            "Authentication Fails (no such user): integration-test-only",
          type: "authentication_error",
        },
      }),
    )
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-provider-error-test-"))
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
        profile: finalizerProfile(),
      }),
    )
    assert.equal(completed.code, 0, completed.stderr)
    assert.doesNotMatch(completed.stdout, /integration-test-only/)
    assert.doesNotMatch(completed.stderr, /integration-test-only/)
    const { result } = parseWorkerOutput(completed.stdout)
    assert.equal(result.error.type, "authentication_error")
    assert.equal(result.error.status_code, 401)
    assert.equal(result.error.retryable, false)
    assert.match(result.error.message, /Authentication Fails/)
    assert.match(result.error.message, /\[redacted\]/)
    assert.equal(
      result.output_transport.provider_wire_requests[0].status_code,
      401,
    )
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("semantic validation rejects inconclusive risk ratings and retries independently", async () => {
  const requests = []
  const semanticSchema = {
    type: "object",
    properties: {
      result: {
        type: "string",
        enum: ["inconclusive", "supported_static"],
      },
      severity_proposal: {
        type: "string",
        enum: ["high", "info"],
      },
      confidence: {
        type: "string",
        enum: ["high", "low"],
      },
      evidence_ids: {
        type: "array",
        items: { type: "string" },
      },
      requested_tests: {
        type: "array",
        items: { type: "object" },
      },
    },
    required: [
      "result",
      "severity_proposal",
      "confidence",
      "evidence_ids",
      "requested_tests",
    ],
    additionalProperties: false,
  }
  const invalid = {
    result: "inconclusive",
    severity_proposal: "high",
    confidence: "high",
    evidence_ids: [],
    requested_tests: [],
  }
  const corrected = {
    ...invalid,
    severity_proposal: "info",
    confidence: "low",
  }
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    sendCompletion(response, body, {
      id: `semantic-${requests.length}`,
      toolCalls: [
        structuredOutputCall(requests.length === 1 ? invalid : corrected),
      ],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-semantic-test-"))
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
        profile: finalizerProfile(),
        phase: "final_evaluation",
        outputSchema: semanticSchema,
      }),
    )
    assert.equal(completed.code, 0, completed.stderr)
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, corrected)
    assert.equal(requests.length, 2)
    assert.equal(result.output_transport.model_calls.length, 2)
    assert.equal(result.output_transport.model_calls[0].accepted, false)
    assert.equal(result.output_transport.model_calls[1].accepted, true)
    assert.deepEqual(
      result.output_transport.model_calls[0].validation_errors.map(
        (item) => item.instance_path,
      ),
      ["/severity_proposal", "/confidence"],
    )
    assert.match(
      JSON.stringify(requests[1].body.messages),
      /apkscannerSemantic/,
    )
    assert.ok(events.some((item) => item.event_type === "model.validation.failed"))
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("semantic validation rejects requested tests outside platform-issued IDs", async () => {
  const requests = []
  const allowedHypothesis = "11111111-1111-1111-1111-111111111111"
  const allowedEntry = "22222222-2222-2222-2222-222222222222"
  const requestSchema = {
    type: "object",
    properties: {
      result: { type: "string", const: "inconclusive" },
      severity_proposal: { type: "string", const: "info" },
      confidence: { type: "string", const: "low" },
      evidence_ids: { type: "array", items: { type: "string" } },
      requested_tests: {
        type: "array",
        items: {
          type: "object",
          properties: {
            hypothesis_id: { type: "string" },
            entry_point_id: { type: "string" },
          },
          required: ["hypothesis_id", "entry_point_id"],
          additionalProperties: false,
        },
      },
    },
    required: [
      "result",
      "severity_proposal",
      "confidence",
      "evidence_ids",
      "requested_tests",
    ],
    additionalProperties: false,
  }
  const base = {
    result: "inconclusive",
    severity_proposal: "info",
    confidence: "low",
    evidence_ids: [],
  }
  const invalid = {
    ...base,
    requested_tests: [
      {
        hypothesis_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        entry_point_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      },
    ],
  }
  const corrected = {
    ...base,
    requested_tests: [
      {
        hypothesis_id: allowedHypothesis,
        entry_point_id: allowedEntry,
      },
    ],
  }
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    sendCompletion(response, body, {
      id: `bounded-id-${requests.length}`,
      toolCalls: [
        structuredOutputCall(requests.length === 1 ? invalid : corrected),
      ],
      finish: "tool_calls",
    })
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")
  const root = await mkdtemp(join(tmpdir(), "apkscanner-bounded-id-test-"))
  try {
    const completed = await runWorker(
      root,
      investigationPayload({
        baseURL: `http://127.0.0.1:${address.port}`,
        profile: finalizerProfile(),
        outputSchema: requestSchema,
        allowedHypothesisIDs: [allowedHypothesis],
        allowedEntryPointIDs: [allowedEntry],
      }),
    )
    assert.equal(completed.code, 0, completed.stderr)
    const { result } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, corrected)
    assert.equal(requests.length, 2)
    assert.deepEqual(
      result.output_transport.model_calls[0].validation_errors.map(
        (item) => item.instance_path,
      ),
      [
        "/requested_tests/0/hypothesis_id",
        "/requested_tests/0/entry_point_id",
      ],
    )
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

function investigationPayload({
  baseURL,
  profile,
  explorerPrompt,
  phase = "test_planning",
  outputSchema = resultSchema,
  timeoutMs = 30_000,
  allowedHypothesisIDs = [],
  allowedEntryPointIDs = [],
}) {
  return {
    schema_version: "1.0",
    action: "investigate",
    prompt: "Return the bounded structured result.",
    explorer_prompt: explorerPrompt ?? "Produce a bounded evidence memo.",
    developer_instructions: "Return only through the required structured contract.",
    explorer_instructions: "Use workspace tools as needed and return only an analysis memo.",
    model: "deepseek-v4-flash",
    base_url: baseURL,
    phase,
    tool_profile: "workspace_shell",
    output_schema: outputSchema,
    execution_profile: profile,
    timeout_ms: timeoutMs,
    allowed_hypothesis_ids: allowedHypothesisIDs,
    allowed_entry_point_ids: allowedEntryPointIDs,
  }
}

function stableProfile() {
  return {
    name: "stable_analyzer",
    output_mode: "analyze_then_finalize",
    stages: [
      {
        name: "analyzer",
        thinking_mode: "disabled",
        reasoning_effort: null,
        output_mode: "text",
        workspace_tools: true,
        wire_tool_choice: "auto",
      },
      {
        name: "finalizer",
        thinking_mode: "disabled",
        reasoning_effort: null,
        output_mode: "structured_output_tool",
        workspace_tools: false,
        wire_tool_choice: "required",
      },
    ],
  }
}

function thinkingProfile() {
  return {
    name: "thinking_explorer_then_finalizer",
    output_mode: "explore_then_finalize",
    stages: [
      {
        name: "explorer",
        thinking_mode: "enabled",
        reasoning_effort: "high",
        output_mode: "text",
        workspace_tools: true,
        wire_tool_choice: "omitted",
      },
      {
        name: "finalizer",
        thinking_mode: "disabled",
        reasoning_effort: null,
        output_mode: "structured_output_tool",
        workspace_tools: false,
        wire_tool_choice: "required",
      },
    ],
  }
}

function finalizerProfile() {
  return {
    name: "structured_finalizer",
    output_mode: "structured_output_tool",
    stages: [
      {
        name: "finalizer",
        thinking_mode: "disabled",
        reasoning_effort: null,
        output_mode: "structured_output_tool",
        workspace_tools: false,
        wire_tool_choice: "required",
      },
    ],
  }
}

function structuredOutputCall(value) {
  return {
    index: 0,
    id: `call-structured-${Math.random().toString(16).slice(2)}`,
    type: "function",
    function: {
      name: "StructuredOutput",
      arguments: JSON.stringify(value),
    },
  }
}

function sendCompletion(
  response,
  body,
  {
    id,
    content,
    reasoningContent,
    toolCalls,
    finish = "stop",
  },
) {
  response.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  })
  response.write(
    event({
      id: `chatcmpl-${id}`,
      object: "chat.completion.chunk",
      created: 1,
      model: body.model,
      choices: [
        {
          index: 0,
          delta: {
            role: "assistant",
            ...(content !== undefined ? { content } : {}),
            ...(reasoningContent !== undefined
              ? { reasoning_content: reasoningContent }
              : {}),
            ...(toolCalls ? { tool_calls: toolCalls } : {}),
          },
          finish_reason: null,
        },
      ],
    }),
  )
  response.write(
    event({
      id: `chatcmpl-${id}`,
      object: "chat.completion.chunk",
      created: 1,
      model: body.model,
      choices: [{ index: 0, delta: {}, finish_reason: finish }],
      usage: {
        prompt_tokens: 12,
        completion_tokens: 4,
        total_tokens: 16,
      },
    }),
  )
  response.end("data: [DONE]\n\n")
}

function toolNames(body) {
  return (body.tools ?? []).map((item) => item.function.name).sort()
}

function runWorker(
  root,
  payload,
  {
    providerAPIKey = "integration-test-only",
    includeProviderAPIKey = true,
  } = {},
) {
  return new Promise((resolvePromise, reject) => {
    const worker = spawn(process.execPath, [resolve("worker.mjs")], {
      cwd: root,
      env: {
        PATH: `${resolve("bin")}${delimiter}${resolve("node_modules/.bin")}${delimiter}${process.env.PATH ?? ""}`,
        HOME: join(root, "home"),
        XDG_DATA_HOME: join(root, "data"),
        XDG_CONFIG_HOME: join(root, "config"),
        XDG_CACHE_HOME: join(root, "cache"),
        XDG_STATE_HOME: join(root, "state"),
        OPENCODE_DISABLE_PROJECT_CONFIG: "1",
        OPENCODE_DISABLE_CLAUDE_CODE: "1",
        OPENCODE_DISABLE_MODELS_FETCH: "1",
        OPENCODE_DISABLE_AUTOUPDATE: "1",
        OPENCODE_PURE: "1",
      },
      stdio: ["pipe", "pipe", "pipe"],
    })
    let stdout = ""
    let stderr = ""
    const timeout = setTimeout(() => {
      worker.kill("SIGKILL")
      reject(new Error("OpenCode integration worker timed out"))
    }, 45_000)
    worker.stdout.setEncoding("utf8")
    worker.stderr.setEncoding("utf8")
    worker.stdout.on("data", (chunk) => {
      stdout += chunk
    })
    worker.stderr.on("data", (chunk) => {
      stderr += chunk
    })
    worker.once("error", reject)
    worker.once("close", (code) => {
      clearTimeout(timeout)
      resolvePromise({ code, stdout, stderr })
    })
    worker.stdin.end(
      JSON.stringify({
        ...payload,
        ...(includeProviderAPIKey
          ? { _provider_api_key: providerAPIKey }
          : {}),
      }),
    )
  })
}

function readJSON(request) {
  return new Promise((resolvePromise, reject) => {
    const chunks = []
    request.on("data", (chunk) => chunks.push(chunk))
    request.once("error", reject)
    request.once("end", () => {
      try {
        resolvePromise(JSON.parse(Buffer.concat(chunks).toString("utf8")))
      } catch (error) {
        reject(error)
      }
    })
  })
}

function listen(server) {
  return new Promise((resolvePromise, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolvePromise)
  })
}

function event(value) {
  return `data: ${JSON.stringify(value)}\n\n`
}

function parseWorkerOutput(output) {
  let result
  const events = []
  for (const line of output.trim().split("\n")) {
    const value = JSON.parse(line)
    if (value.type === "event") events.push(value.event)
    if (value.type === "result") result = value.result
  }
  assert.ok(result, "worker did not emit a result envelope")
  return { result, events }
}
