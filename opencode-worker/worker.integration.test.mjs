import assert from "node:assert/strict"
import { createServer } from "node:http"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { delimiter, join, resolve } from "node:path"
import { spawn, spawnSync } from "node:child_process"
import test from "node:test"

const expected = { answer: "bounded result" }

test("worker PATH adb shim refuses device access", () => {
  const blocked = spawnSync(resolve("bin/adb"), ["devices"], { encoding: "utf8" })
  assert.equal(blocked.status, 126)
  assert.match(blocked.stderr, /adb is disabled/)
})

test("flash can inspect the workspace before returning structured output", async () => {
  const requests = []
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })

    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    })
    response.write(
      event({
        id: "chatcmpl-test",
        object: "chat.completion.chunk",
        created: 1,
        model: body.model,
        choices: [
          {
            index: 0,
            delta: {
              role: "assistant",
              tool_calls: [
                {
                  index: 0,
                  id: "call-structured",
                  type: "function",
                  function: {
                    name: "StructuredOutput",
                    arguments: JSON.stringify(expected),
                  },
                },
              ],
            },
            finish_reason: null,
          },
        ],
      }),
    )
    response.write(
      event({
        id: "chatcmpl-test",
        object: "chat.completion.chunk",
        created: 1,
        model: body.model,
        choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
        usage: {
          prompt_tokens: 12,
          completion_tokens: 4,
          total_tokens: 16,
        },
      }),
    )
    response.end("data: [DONE]\n\n")
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")

  const root = await mkdtemp(join(tmpdir(), "apkscanner-opencode-test-"))
  try {
    const completed = await runWorker(root, {
      schema_version: "1.0",
      action: "investigate",
      prompt: "Return the bounded structured result.",
      developer_instructions: "Use no external tools. Return only structured JSON.",
      model: "deepseek-v4-flash",
      base_url: `http://127.0.0.1:${address.port}`,
      tool_profile: "workspace_shell",
      output_schema: {
        type: "object",
        properties: { answer: { type: "string" } },
        required: ["answer"],
        additionalProperties: false,
      },
      timeout_ms: 10_000,
    })
    assert.equal(
      completed.code,
      0,
      `${completed.stderr}\nrequests=${JSON.stringify(
        requests.slice(0, 5).map((item) => ({
          url: item.url,
          model: item.body.model,
          tool_choice: item.body.tool_choice,
          tools: item.body.tools?.map((tool) => tool.function?.name),
          message_count: item.body.messages?.length,
        })),
        null,
        2,
      )}`,
    )
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(result.usage.provider, "deepseek")
    assert.equal(result.usage.model, "deepseek-v4-flash")
    assert.equal(result.usage.calls, 1)
    assert.equal(result.output_transport.mode, "structured_output_tool")
    assert.equal(requests.length, 1)
    assert.equal(requests[0].url, "/chat/completions")
    assert.equal(requests[0].body.model, "deepseek-v4-flash")
    assert.equal(requests[0].body.tool_choice, "required")
    assert.deepEqual(
      requests[0].body.tools.map((item) => item.function.name),
      ["bash", "glob", "grep", "read", "StructuredOutput"],
    )
    assert.ok(events.some((item) => item.event_type === "model.session.started"))
    assert.ok(events.some((item) => item.event_type === "model.output.validated"))
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("pro avoids required tool choice and retries text JSON through local validation", async () => {
  const requests = []
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    })
    const content = requests.length === 1 ? "{}" : JSON.stringify(expected)
    response.write(
      event({
        id: `chatcmpl-pro-${requests.length}`,
        object: "chat.completion.chunk",
        created: requests.length,
        model: body.model,
        choices: [
          {
            index: 0,
            delta: { role: "assistant", content },
            finish_reason: null,
          },
        ],
      }),
    )
    response.write(
      event({
        id: `chatcmpl-pro-${requests.length}`,
        object: "chat.completion.chunk",
        created: requests.length,
        model: body.model,
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
        usage: {
          prompt_tokens: 10,
          completion_tokens: 2,
          total_tokens: 12,
        },
      }),
    )
    response.end("data: [DONE]\n\n")
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")

  const root = await mkdtemp(join(tmpdir(), "apkscanner-opencode-pro-test-"))
  try {
    const completed = await runWorker(root, {
      schema_version: "1.0",
      action: "investigate",
      prompt:
        "Return one JSON object matching this schema: " +
        '{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"]}.',
      developer_instructions: "Use no external tools. Return only JSON.",
      model: "deepseek-v4-pro",
      base_url: `http://127.0.0.1:${address.port}`,
      tool_profile: "workspace_shell",
      output_schema: {
        type: "object",
        properties: { answer: { type: "string" } },
        required: ["answer"],
        additionalProperties: false,
      },
      timeout_ms: 10_000,
    })
    assert.equal(
      completed.code,
      0,
      `${completed.stderr}\nrequests=${JSON.stringify(requests, null, 2)}`,
    )
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(result.usage.provider, "deepseek")
    assert.equal(result.usage.model, "deepseek-v4-pro")
    assert.equal(result.usage.calls, 2)
    assert.equal(result.output_transport.mode, "prompted_json")
    assert.equal(result.output_transport.format, "text")
    assert.equal(result.output_transport.tool_choice, "auto")
    assert.deepEqual(result.output_transport.tools, ["read", "glob", "grep", "bash"])
    assert.equal(result.output_transport.schema_validator, "ajv@8.20.0")
    assert.equal(result.output_transport.model_calls.length, 2)
    assert.equal(result.output_transport.model_calls[0].accepted, false)
    assert.match(
      result.output_transport.model_calls[0].validation_errors[0].message,
      /required property/,
    )
    assert.equal(result.output_transport.model_calls[1].accepted, true)
    assert.equal(requests.length, 2)
    assert.equal(requests[0].url, "/chat/completions")
    assert.equal(requests[0].body.model, "deepseek-v4-pro")
    assert.notEqual(requests[0].body.tool_choice, "required")
    assert.deepEqual(
      requests[0].body.tools.map((item) => item.function.name).sort(),
      ["bash", "glob", "grep", "read"],
    )
    assert.equal(requests[1].url, "/chat/completions")
    assert.equal(requests[1].body.model, "deepseek-v4-pro")
    assert.equal(requests[1].body.tool_choice, undefined)
    assert.ok(!requests[1].body.tools || requests[1].body.tools.length === 0)
    assert.match(
      JSON.stringify(requests[1].body.messages),
      /VALIDATION_ERRORS_JSON/,
    )
    assert.ok(events.some((item) => item.event_type === "model.validation.failed"))
    assert.ok(events.some((item) => item.event_type === "model.output.validated"))
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

test("pro can call the read tool and then return locally validated JSON", async () => {
  const requests = []
  let workspaceFile
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    })
    if (requests.length === 1) {
      response.write(
        event({
          id: "chatcmpl-pro-tool-1",
          object: "chat.completion.chunk",
          created: 1,
          model: body.model,
          choices: [
            {
              index: 0,
              delta: {
                role: "assistant",
                tool_calls: [
                  {
                    index: 0,
                    id: "call-read",
                    type: "function",
                    function: {
                      name: "read",
                      arguments: JSON.stringify({ filePath: workspaceFile }),
                    },
                  },
                ],
              },
              finish_reason: null,
            },
          ],
        }),
      )
      response.write(
        event({
          id: "chatcmpl-pro-tool-1",
          object: "chat.completion.chunk",
          created: 1,
          model: body.model,
          choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
          usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 },
        }),
      )
    } else {
      response.write(
        event({
          id: "chatcmpl-pro-tool-2",
          object: "chat.completion.chunk",
          created: 2,
          model: body.model,
          choices: [
            {
              index: 0,
              delta: { role: "assistant", content: JSON.stringify(expected) },
              finish_reason: null,
            },
          ],
        }),
      )
      response.write(
        event({
          id: "chatcmpl-pro-tool-2",
          object: "chat.completion.chunk",
          created: 2,
          model: body.model,
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
          usage: { prompt_tokens: 12, completion_tokens: 4, total_tokens: 16 },
        }),
      )
    }
    response.end("data: [DONE]\n\n")
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")

  const root = await mkdtemp(join(tmpdir(), "apkscanner-opencode-pro-tool-test-"))
  workspaceFile = join(root, "evidence.txt")
  await writeFile(workspaceFile, "exported provider evidence")
  try {
    const completed = await runWorker(root, {
      schema_version: "1.0",
      action: "investigate",
      prompt: "Read evidence.txt, then return the required JSON object.",
      developer_instructions: "Inspect only the supplied workspace. Return only JSON.",
      model: "deepseek-v4-pro",
      base_url: `http://127.0.0.1:${address.port}`,
      tool_profile: "workspace_shell",
      output_schema: {
        type: "object",
        properties: { answer: { type: "string" } },
        required: ["answer"],
        additionalProperties: false,
      },
      timeout_ms: 10_000,
    })
    assert.equal(completed.code, 0, completed.stderr)
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(requests.length, 2)
    assert.match(JSON.stringify(requests[1].body.messages), /exported provider evidence/)
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

test("pro can run bash in its workspace and /tmp", async () => {
  const requests = []
  const api = createServer(async (request, response) => {
    const body = await readJSON(request)
    requests.push({ url: request.url, body })
    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    })
    if (requests.length === 1) {
      response.write(
        event({
          id: "chatcmpl-pro-bash-1",
          object: "chat.completion.chunk",
          created: 1,
          model: body.model,
          choices: [
            {
              index: 0,
              delta: {
                role: "assistant",
                tool_calls: [
                  {
                    index: 0,
                    id: "call-bash",
                    type: "function",
                    function: {
                      name: "bash",
                      arguments: JSON.stringify({
                        command:
                          "pwd && printf workspace-ok > ./agent-note.txt && printf tmp-ok > /tmp/agent-note.txt",
                      }),
                    },
                  },
                ],
              },
              finish_reason: null,
            },
          ],
        }),
      )
      response.write(
        event({
          id: "chatcmpl-pro-bash-1",
          object: "chat.completion.chunk",
          created: 1,
          model: body.model,
          choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
          usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 },
        }),
      )
    } else {
      response.write(
        event({
          id: "chatcmpl-pro-bash-2",
          object: "chat.completion.chunk",
          created: 2,
          model: body.model,
          choices: [
            {
              index: 0,
              delta: { role: "assistant", content: JSON.stringify(expected) },
              finish_reason: null,
            },
          ],
        }),
      )
      response.write(
        event({
          id: "chatcmpl-pro-bash-2",
          object: "chat.completion.chunk",
          created: 2,
          model: body.model,
          choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
          usage: { prompt_tokens: 12, completion_tokens: 4, total_tokens: 16 },
        }),
      )
    }
    response.end("data: [DONE]\n\n")
  })
  await listen(api)
  const address = api.address()
  assert(address && typeof address !== "string")

  const root = await mkdtemp(join(tmpdir(), "apkscanner-opencode-pro-bash-test-"))
  try {
    const completed = await runWorker(root, {
      schema_version: "1.0",
      action: "investigate",
      prompt: "Use bash for a bounded workspace check, then return the required JSON.",
      developer_instructions: "Run shell commands only in the workspace or /tmp.",
      model: "deepseek-v4-pro",
      base_url: `http://127.0.0.1:${address.port}`,
      tool_profile: "workspace_shell",
      output_schema: {
        type: "object",
        properties: { answer: { type: "string" } },
        required: ["answer"],
        additionalProperties: false,
      },
      timeout_ms: 10_000,
    })
    assert.equal(completed.code, 0, completed.stderr)
    const { result, events } = parseWorkerOutput(completed.stdout)
    assert.deepEqual(result.result, expected)
    assert.equal(requests.length, 2)
    assert.match(JSON.stringify(requests[1].body.messages), new RegExp(root))
    assert.ok(
      events.some(
        (item) =>
          item.event_type === "model.tool.completed" &&
          item.data.tool === "bash" &&
          item.data.input?.command?.includes("agent-note.txt"),
      ),
    )
  } finally {
    api.close()
    await rm(root, { recursive: true, force: true })
  }
})

function runWorker(root, payload) {
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
        DEEPSEEK_API_KEY: "integration-test-only",
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
    }, 20_000)
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
    worker.stdin.end(JSON.stringify(payload))
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
