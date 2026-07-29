import { randomBytes } from "node:crypto"
import { createServer as createHttpServer } from "node:http"
import { createServer } from "node:net"
import { stdin, stderr, stdout } from "node:process"
import { Readable } from "node:stream"
import { pipeline } from "node:stream/promises"
import { fileURLToPath } from "node:url"
import { createOpencodeClient, createOpencodeServer } from "@opencode-ai/sdk"
import Ajv from "ajv"

const MAX_INPUT_BYTES = 32 * 1024 * 1024
const PROVIDER_ID = "deepseek"
const OPENCODE_VERSION = "1.18.4"
const OUTPUT_MODE_STRUCTURED_TOOL = "structured_output_tool"
const OUTPUT_MODE_ANALYZE_THEN_FINALIZE = "analyze_then_finalize"
const OUTPUT_MODE_EXPLORE_THEN_FINALIZE = "explore_then_finalize"
const PROFILE_STABLE_ANALYZER = "stable_analyzer"
const PROFILE_THINKING_EXPLORER = "thinking_explorer_then_finalizer"
const PROFILE_STRUCTURED_FINALIZER = "structured_finalizer"
const STRUCTURED_RETRY_COUNT = 2
const WORKSPACE_TOOL_PROFILE = "workspace_shell"
const WORKSPACE_TOOLS = ["read", "glob", "grep", "bash"]
const DEFAULT_MAX_AGENT_STEPS = 1_000
const MAX_CONFIGURED_AGENT_STEPS = 1_000
const PROVIDER_REQUEST_HEADROOM = 100
const MAX_EXPLORER_MEMO_BYTES = 128 * 1024
const LOCAL_POLL_INTERVAL_MS = 250
const LOCAL_READ_RETRY_COUNT = 3
const SANITIZED_BASH = fileURLToPath(new URL("./bin/bash", import.meta.url))
const PROVIDER_API_KEY_FIELD = "_provider_api_key"
const PROVIDER_API_KEY_IN_ENVIRONMENT = Object.prototype.hasOwnProperty.call(
  process.env,
  "DEEPSEEK_API_KEY",
)
delete process.env.DEEPSEEK_API_KEY

let server
let sessionID
let workerDeadline
let localServerURL
let localAuthorization
let providerProxy
let providerProxyURL
let providerWireAudit = []
let providerAPIKey
let loopbackProxyAPIKey
let providerRequestCount = 0
let providerRequestLimit = DEFAULT_MAX_AGENT_STEPS + PROVIDER_REQUEST_HEADROOM

async function main() {
  if (PROVIDER_API_KEY_IN_ENVIRONMENT) {
    throw new Error(
      `DEEPSEEK_API_KEY environment delivery is not supported; use ${PROVIDER_API_KEY_FIELD}`,
    )
  }
  const rawPayload = await readPayload()
  providerAPIKey = takeProviderAPIKey(rawPayload)
  const payload = validatePayload(rawPayload)
  providerRequestLimit = payload.max_agent_steps + PROVIDER_REQUEST_HEADROOM
  loopbackProxyAPIKey = randomBytes(32).toString("hex")
  workerDeadline = Date.now() + payload.timeout_ms
  const username = "apkscanner"
  const password = randomBytes(32).toString("hex")
  process.env.OPENCODE_SERVER_USERNAME = username
  process.env.OPENCODE_SERVER_PASSWORD = password

  try {
    providerProxy = await startProviderCompatibilityProxy(payload)
    const serverStartupStartedAt = Date.now()
    try {
      server = await createOpencodeServer({
        hostname: "127.0.0.1",
        port: await reservePort(),
        timeout: Math.min(payload.timeout_ms, 15_000),
        config: buildConfig(payload),
      })
    } catch (error) {
      throw new Error("OpenCode local server startup failed", { cause: error })
    }
    const client = createOpencodeClient({
      baseUrl: server.url,
      directory: process.cwd(),
      headers: {
        Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
      },
    })
    localServerURL = server.url
    localAuthorization = `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`
    emitRuntimeEvent("model.local_server.started", "OpenCode 本地 Server 已启动", {
      phase: payload.phase ?? payload.action,
      startup_ms: Date.now() - serverStartupStartedAt,
    })
    if (payload.action === "capability") {
      return await capability(client, payload)
    }
    return await investigate(client, payload)
  } finally {
    server?.close()
    providerProxy?.close()
  }
}

async function capability(client, payload) {
  unwrap(await client.config.get(), "config.get")
  const configured = unwrap(await client.config.providers(), "config.providers")
  const provider = configured.providers?.find((item) => item.id === PROVIDER_ID)
  if (!provider) {
    throw new Error("DeepSeek provider is unavailable")
  }
  const liveProbe = payload.live_probe
    ? await runLiveProbe(client, payload)
    : undefined
  return {
    schema_version: "1.0",
    server_version: OPENCODE_VERSION,
    provider: PROVIDER_ID,
    models: Object.keys(provider.models ?? {}).sort(),
    output_mode: executionProfile(payload).output_mode,
    tool_profile: WORKSPACE_TOOL_PROFILE,
    workspace_tools: WORKSPACE_TOOLS,
    max_steps: payload.max_agent_steps,
    max_provider_requests: payload.max_agent_steps + PROVIDER_REQUEST_HEADROOM,
    ...(liveProbe ? { live_probe: liveProbe } : {}),
  }
}

async function runLiveProbe(client, payload) {
  const schema = {
    type: "object",
    properties: { ok: { type: "boolean", const: true } },
    required: ["ok"],
    additionalProperties: false,
  }
  const stage = {
    name: "finalizer",
    thinking_mode: "disabled",
    reasoning_effort: null,
    output_mode: OUTPUT_MODE_STRUCTURED_TOOL,
    workspace_tools: false,
    wire_tool_choice: "required",
  }
  const outcome = await runStructuredStage(client, payload, {
    stage,
    promptText: "Return the structured value with ok set to true.",
    schema,
    title: "APK Scanner DeepSeek capability probe",
    maxRetries: 0,
  })
  if (!outcome.ok) {
    throw new Error(`DeepSeek live probe failed: ${outcome.error.message}`)
  }
  return {
    ok: true,
    model: outcome.response.info?.modelID ?? payload.model,
    provider: outcome.response.info?.providerID ?? PROVIDER_ID,
    thinking_mode: "disabled",
    output_mode: OUTPUT_MODE_STRUCTURED_TOOL,
    wire_tool_choice: "required",
    usage: aggregateUsage(outcome.responses, payload),
    provider_wire_requests: providerWireAudit.map((item) => ({ ...item })),
  }
}

async function investigate(client, payload) {
  const profile = executionProfile(payload)
  const calls = []
  const responses = []
  let explorerMemo
  let explorerSessionID

  const analysisStage = profile.stages.find((stage) => stage.output_mode === "text")
  if (analysisStage) {
    const explored = await runTextStage(client, payload, {
      stage: analysisStage,
      promptText: payload.explorer_prompt,
      title:
        analysisStage.thinking_mode === "enabled"
          ? "APK Scanner thinking exploration"
          : "APK Scanner stable analysis",
    })
    calls.push(explored.call)
    responses.push(...explored.responses)
    explorerSessionID = explored.session_id
    if (!explored.ok) {
      return failureEnvelope(payload, {
        response: explored.response,
        responses,
        calls,
        profile,
        error: explored.error,
        explorerSessionID,
      })
    }
    explorerMemo = explored.text
  }

  const structuredStage =
    profile.stages.find((stage) => stage.output_mode === OUTPUT_MODE_STRUCTURED_TOOL)
  const promptText = explorerMemo
    ? finalizerPrompt(payload.prompt, explorerMemo)
    : payload.prompt
  const finalized = await runStructuredStage(client, payload, {
    stage: structuredStage,
    promptText,
    schema: payload.output_schema,
    title:
      profile.name === PROFILE_STABLE_ANALYZER
        ? "APK Scanner stable analysis"
        : "APK Scanner structured finalization",
    maxRetries: STRUCTURED_RETRY_COUNT,
  })
  calls.push(...finalized.calls)
  responses.push(...finalized.responses)
  if (!finalized.ok) {
    return failureEnvelope(payload, {
      response: finalized.response,
      responses,
      calls,
      profile,
      error: finalized.error,
      explorerSessionID,
      explorerMemo,
    })
  }
  return {
    schema_version: "1.0",
    thread_id: finalized.session_id,
    turn_id: finalized.response.info?.id ?? randomBytes(16).toString("hex"),
    result: finalized.result,
    usage: aggregateUsage(responses, payload),
    output_transport: outputTransport({
      profile,
      calls,
      explorerSessionID,
      explorerMemo,
    }),
  }
}

async function runTextStage(client, payload, { stage, promptText, title }) {
  const responses = []
  let response
  let text = ""
  let terminalized = false
  let stageSessionID
  await withSession(client, title, async (createdSessionID) => {
    stageSessionID = createdSessionID
    emitRuntimeEvent("model.turn.started", "DeepSeek 分析阶段开始", {
      stage: stage.name,
      attempt: 1,
      thinking_mode: stage.thinking_mode,
      reasoning_effort: stage.reasoning_effort,
      wire_tool_choice: "omitted",
    })
    response = await promptAsyncAndWait(
      client,
      payload,
      promptText,
      workspaceToolFlags(payload),
      undefined,
      stage.name === "explorer" ? "apkscanner-explorer" : "apkscanner-analyzer",
      stage,
    )
    responses.push(response)
    text = responseText(response.parts ?? [])
    if (!response.info?.error && !text) {
      emitRuntimeEvent(
        "model.memo.terminalizing",
        "分析阶段未产生文本备忘录，正在禁用工具并强制收尾",
        {
          stage: stage.name,
          finish: response.info?.finish ?? null,
          max_agent_steps: payload.max_agent_steps,
        },
      )
      const terminalResponse = await promptAsyncAndWait(
        client,
        payload,
        memoTerminalizationPrompt(stage),
        disabledWorkspaceToolFlags(),
        undefined,
        "apkscanner-memo-writer",
        {
          ...stage,
          name: "memo_writer",
          thinking_mode: "disabled",
          reasoning_effort: null,
          workspace_tools: false,
          wire_tool_choice: "omitted",
        },
      )
      responses.push(terminalResponse)
      response = terminalResponse
      text = responseText(response.parts ?? [])
      terminalized = true
    }
  })
  emitRuntimeEvent("model.response.received", "DeepSeek 分析阶段已返回证据备忘录", {
    stage: stage.name,
    attempt: 1,
    turn_id: response.info?.id ?? null,
  })
  const providerError = response.info?.error
    ? normalizedProviderError(response.info.error)
    : null
  const memoBytes = Buffer.byteLength(text, "utf8")
  const parseError = providerError
    ? null
    : !text
      ? "explorer returned no text memo"
      : memoBytes > MAX_EXPLORER_MEMO_BYTES
        ? `explorer memo exceeds ${MAX_EXPLORER_MEMO_BYTES} bytes`
        : null
  const call = modelCallAudit({
    stage,
    attempt: 1,
    promptText,
    response: terminalized
      ? {
          ...response,
          apkscanner_turn_messages: responses.flatMap(
            (item) => item.apkscanner_turn_messages ?? [item],
          ),
        }
      : response,
    responseTextValue: text,
    parseError,
    validationErrors: [],
    accepted: !providerError && !parseError,
    tools: workspaceToolNames(payload),
  })
  call.terminalized = terminalized
  if (providerError) {
    return {
      ok: false,
      response,
      responses,
      call,
      session_id: stageSessionID,
      error: providerError,
    }
  }
  if (parseError) {
    return {
      ok: false,
      response,
      responses,
      call,
      session_id: stageSessionID,
      error: { type: "empty_or_oversized_explorer_output", message: parseError },
    }
  }
  return {
    ok: true,
    response,
    responses,
    call,
    session_id: stageSessionID,
    text,
  }
}

async function runStructuredStage(
  client,
  payload,
  { stage, promptText, schema, title, maxRetries },
) {
  const validate = new Ajv({ allErrors: true, strict: false }).compile(schema)
  const calls = []
  const responses = []
  let currentPrompt = promptText
  let response
  let stageSessionID

  for (let index = 0; index <= maxRetries; index += 1) {
    await withSession(client, `${title} (${index + 1})`, async (createdSessionID) => {
      stageSessionID = createdSessionID
      emitRuntimeEvent("model.turn.started", "DeepSeek 非思考结构化阶段开始", {
        stage: stage.name,
        attempt: index + 1,
        thinking_mode: "disabled",
        wire_tool_choice: "required",
      })
      emitRuntimeEvent(
        "model.transport.selected",
        "DeepSeek 非思考定稿器使用单次同步结构化请求",
        {
          session_id: sessionID,
          stage: stage.name,
          request_mode: "prompt_sync",
          thinking_mode: "disabled",
          wire_tool_choice: "required",
        },
      )
      response = await promptSync(
        client,
        payload,
        currentPrompt,
        {
          type: "json_schema",
          schema,
        },
      )
    })
    responses.push(response)
    const text = responseText(response.parts ?? [])
    emitRuntimeEvent("model.response.received", "DeepSeek 已返回结构化阶段响应", {
      stage: stage.name,
      attempt: index + 1,
      turn_id: response.info?.id ?? null,
    })
    if (response.info?.error) {
      const error = normalizedProviderError(response.info.error)
      calls.push(
        modelCallAudit({
          stage,
          attempt: index + 1,
          promptText: currentPrompt,
          response,
          responseTextValue: text,
          parseError: null,
          validationErrors: [],
          accepted: false,
          tools: structuredToolNames(payload, stage),
        }),
      )
      return {
        ok: false,
        response,
        responses,
        calls,
        session_id: stageSessionID,
        error,
      }
    }

    const parsed = parseStructuredResult(response)
    const parsedObject =
      parsed.error === null &&
      parsed.value !== null &&
      typeof parsed.value === "object" &&
      !Array.isArray(parsed.value)
    const schemaValid = parsedObject ? validate(parsed.value) : false
    const schemaErrors =
      parsedObject && !schemaValid ? normalizeValidationErrors(validate.errors) : []
    const semanticErrors =
      parsedObject && schemaValid
        ? semanticValidationErrors(parsed.value, payload)
        : []
    const validationErrors = [...schemaErrors, ...semanticErrors]
    const parseError =
      parsed.error ??
      (parsedObject ? null : "top-level structured value must be an object")
    const accepted = parsedObject && schemaValid && semanticErrors.length === 0
    calls.push(
      modelCallAudit({
        stage,
        attempt: index + 1,
        promptText: currentPrompt,
        response,
        responseTextValue: text,
        parseError,
        validationErrors,
        accepted,
        tools: structuredToolNames(payload, stage),
      }),
    )
    if (accepted) {
      emitRuntimeEvent("model.output.validated", "结构化结果已通过本地 Ajv 与语义校验", {
        stage: stage.name,
        attempt: index + 1,
        turn_id: response.info?.id ?? null,
        validator: "ajv@8.20.0",
      })
      return {
        ok: true,
        response,
        responses,
        calls,
        session_id: stageSessionID,
        result: parsed.value,
      }
    }
    emitRuntimeEvent("model.validation.failed", "结构化结果未通过本地 Schema/语义校验", {
      stage: stage.name,
      attempt: index + 1,
      turn_id: response.info?.id ?? null,
      parse_error: parseError,
      validation_error_count: validationErrors.length,
    })
    currentPrompt = structuredCorrectionPrompt(promptText, parseError, validationErrors)
  }
  return {
    ok: false,
    response,
    responses,
    calls,
    session_id: stageSessionID,
    error: {
      type: "schema_validation_error",
      message:
        `Structured output did not pass local schema and semantic validation ` +
        `after ${calls.length} attempts`,
    },
  }
}

async function promptSync(client, payload, promptText, format) {
  try {
    return unwrap(
      await client.session.prompt({
        path: { id: sessionID },
        body: {
          ...promptBody(
            payload,
            promptText,
            disabledWorkspaceToolFlags(),
            "apkscanner-finalizer",
          ),
          format,
        },
      }),
      "session.prompt",
    )
  } catch (error) {
    if (isFetchFailure(error)) {
      throw new Error(
        `OpenCode local server became unreachable during ${payload.phase} structured prompt`,
        { cause: error },
      )
    }
    throw error
  }
}

async function withSession(client, title, operation) {
  const session = unwrap(
    await client.session.create({ body: { title } }),
    "session.create",
  )
  sessionID = session.id
  emitRuntimeEvent("model.session.started", "OpenCode SDK 会话已建立", {
    session_id: sessionID,
    title,
  })
  const eventPump = await startEventPump(client)
  try {
    return await operation(sessionID)
  } finally {
    await eventPump.stop()
    await settleWithin(
      client.session.delete({ path: { id: sessionID } }),
      1_000,
    )
  }
}

async function promptAsyncAndWait(
  client,
  payload,
  promptText,
  tools,
  format,
  agent,
  stage,
) {
  const before = unwrap(
    await localRead(
      () => rawSessionMessages(sessionID),
      "session.messages.before",
    ),
    "session.messages.before",
  )
  const knownMessageIDs = new Set(
    before
      .map((message) => message?.info?.id)
      .filter((value) => typeof value === "string"),
  )
  emitRuntimeEvent(
    "model.transport.selected",
    "DeepSeek 调用使用异步下发与短连接结果轮询",
    {
      session_id: sessionID,
      stage: stage.name,
      request_mode: "prompt_async_poll",
      poll_interval_ms: LOCAL_POLL_INTERVAL_MS,
      thinking_mode: stage.thinking_mode,
      reasoning_effort: stage.reasoning_effort,
      wire_tool_choice: stage.wire_tool_choice,
    },
  )
  unwrap(
    await client.session.promptAsync({
      path: { id: sessionID },
      body: {
        ...promptBody(payload, promptText, tools, agent),
        ...(format ? { format } : {}),
      },
    }),
    "session.prompt_async",
  )

  let toolLoopWaitReported = false
  let idleToolCallSince
  while (Date.now() < workerDeadline) {
    const messages = unwrap(
      await localRead(
        () => rawSessionMessages(sessionID),
        "session.messages.poll",
      ),
      "session.messages.poll",
    )
    const assistantMessages = messages
      .filter(
        (message) =>
          message?.info?.role === "assistant" &&
          !knownMessageIDs.has(message.info.id),
      )
      .map((message, index) => ({ message, index }))
      .sort((left, right) => {
        const leftTime =
          left.message.info.time?.completed ??
          left.message.info.time?.created ??
          0
        const rightTime =
          right.message.info.time?.completed ??
          right.message.info.time?.created ??
          0
        return rightTime - leftTime || right.index - left.index
      })
      .map(({ message }) => message)
    const latestCompleted = assistantMessages.find(
      (message) =>
        message.info.error ||
        message.info.time?.completed ||
        message.info.finish,
    )
    const statuses = unwrap(
      await localRead(
        () => client.session.status(),
        "session.status.poll",
      ),
      "session.status.poll",
    )
    const status = statuses?.[sessionID]
    const idle = !status || status.type === "idle"
    const completedWithToolCall =
      latestCompleted?.info?.finish === "tool-calls"
    if (idle && latestCompleted && !completedWithToolCall) {
      return {
        ...latestCompleted,
        apkscanner_turn_messages: assistantMessages,
      }
    }
    if (idle && latestCompleted && completedWithToolCall) {
      idleToolCallSince ??= Date.now()
      if (Date.now() - idleToolCallSince >= 1_500) {
        return {
          ...latestCompleted,
          apkscanner_turn_messages: assistantMessages,
        }
      }
    } else {
      idleToolCallSince = undefined
    }
    if (
      !toolLoopWaitReported &&
      completedWithToolCall
    ) {
      toolLoopWaitReported = true
      emitRuntimeEvent(
        "model.tool_loop.waiting",
        "OpenCode 已收到工具调用，继续等待工具执行与最终文本响应",
        {
          session_id: sessionID,
          message_id: latestCompleted.info.id,
          session_status: status?.type ?? "idle",
        },
      )
    }
    const remaining = workerDeadline - Date.now()
    if (remaining <= 0) break
    await delay(Math.min(LOCAL_POLL_INTERVAL_MS, remaining))
  }
  throw new Error("OpenCode async prompt exceeded the worker deadline")
}

async function rawSessionMessages(id) {
  if (!localServerURL || !localAuthorization) {
    throw new Error("OpenCode local transport is not initialized")
  }
  const remaining = Math.max(1, workerDeadline - Date.now())
  const response = await fetch(
    new URL(`/session/${encodeURIComponent(id)}/message`, localServerURL),
    {
      headers: { Authorization: localAuthorization },
      signal: AbortSignal.timeout(remaining),
    },
  )
  const text = await response.text()
  if (!response.ok) {
    throw new Error(
      `session.messages raw read failed (${response.status}): ${text.slice(0, 2000)}`,
    )
  }
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new Error(
      `session.messages raw read returned invalid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
}

function promptBody(payload, promptText, tools, agent) {
  const systemInstructions =
    agent === "apkscanner-finalizer"
      ? payload.developer_instructions
      : payload.explorer_instructions ?? payload.developer_instructions
  return {
    agent,
    model: {
      providerID: PROVIDER_ID,
      modelID: payload.model,
    },
    system: systemInstructions,
    tools,
    parts: [{ type: "text", text: promptText }],
  }
}

async function localRead(operation, label) {
  let lastError
  for (let attempt = 1; attempt <= LOCAL_READ_RETRY_COUNT; attempt += 1) {
    try {
      return await operation()
    } catch (error) {
      lastError = error
      if (!isFetchFailure(error) || attempt === LOCAL_READ_RETRY_COUNT) throw error
      const backoffMs = 100 * 2 ** (attempt - 1)
      if (Date.now() + backoffMs >= workerDeadline) throw error
      emitRuntimeEvent("model.transport.retry", "OpenCode 本地读取连接短暂中断，正在重试", {
        session_id: sessionID,
        operation: label,
        attempt,
        backoff_ms: backoffMs,
        error: formatThrownError(error).slice(0, 1000),
      })
      await delay(backoffMs)
    }
  }
  throw lastError
}

function isFetchFailure(error) {
  if (!(error instanceof Error)) return false
  if (error.name === "TypeError" && /fetch failed/i.test(error.message)) return true
  const code = error.cause?.code
  return [
    "ECONNREFUSED",
    "ECONNRESET",
    "EPIPE",
    "UND_ERR_CONNECT_TIMEOUT",
    "UND_ERR_HEADERS_TIMEOUT",
    "UND_ERR_SOCKET",
  ].includes(code)
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds))
}

async function startEventPump(client) {
  const controller = new AbortController()
  const subscription = await client.event.subscribe({ signal: controller.signal })
  const seen = new Set()
  const done = (async () => {
    try {
      for await (const event of subscription.stream) {
        const normalized = normalizeOpenCodeEvent(event, seen)
        if (normalized) {
          emitRuntimeEvent(
            normalized.event_type,
            normalized.message,
            normalized.data,
          )
        }
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        emitRuntimeEvent("model.event_stream.failed", "OpenCode 事件流异常中止", {
          error: formatError(error).slice(0, 1000),
        })
      }
    }
  })()
  return {
    async stop() {
      controller.abort()
      await settleWithin(done, 1_000)
    },
  }
}

async function settleWithin(promise, timeoutMilliseconds) {
  let timeoutID
  try {
    await Promise.race([
      Promise.resolve(promise).catch(() => undefined),
      new Promise((resolvePromise) => {
        timeoutID = setTimeout(resolvePromise, timeoutMilliseconds)
        timeoutID.unref?.()
      }),
    ])
  } finally {
    clearTimeout(timeoutID)
  }
}

function normalizeOpenCodeEvent(event, seen) {
  if (!event || typeof event !== "object") return null
  const properties = event.properties ?? {}
  const part = properties.part
  const eventSessionID =
    properties.sessionID ??
    part?.sessionID ??
    properties.info?.sessionID
  if (eventSessionID && eventSessionID !== sessionID) return null

  if (event.type === "session.status") {
    const status = properties.status?.type ?? "unknown"
    return {
      event_type: "model.session.status",
      message: `OpenCode 会话状态：${status}`,
      data: { session_id: sessionID, status },
    }
  }
  if (event.type === "session.idle") {
    return {
      event_type: "model.session.idle",
      message: "OpenCode 会话已进入空闲状态",
      data: { session_id: sessionID },
    }
  }
  if (event.type === "session.error") {
    return {
      event_type: "model.error",
      message: "OpenCode 会话报告运行错误",
      data: { session_id: sessionID, error: formatError(properties.error).slice(0, 1000) },
    }
  }
  if (event.type !== "message.part.updated" || !part) return null

  if (part.type === "step-start") {
    return once(seen, `step-start:${part.id}`, {
      event_type: "model.step.started",
      message: "OpenCode 开始新的模型步骤",
      data: { session_id: sessionID, message_id: part.messageID, part_id: part.id },
    })
  }
  if (part.type === "step-finish") {
    return once(seen, `step-finish:${part.id}`, {
      event_type: "model.step.completed",
      message: "OpenCode 模型步骤已完成",
      data: {
        session_id: sessionID,
        message_id: part.messageID,
        part_id: part.id,
        reason: part.reason,
        tokens: part.tokens,
        cost: part.cost,
      },
    })
  }
  if (part.type === "reasoning") {
    return once(seen, `reasoning:${part.id}`, {
      event_type: "model.reasoning.started",
      message: "OpenCode 正在整理验证思路",
      data: { session_id: sessionID, message_id: part.messageID, part_id: part.id },
    })
  }
  if (part.type === "text") {
    return once(seen, `text:${part.id}`, {
      event_type: "model.response.started",
      message: "OpenCode 正在生成结构化判断",
      data: { session_id: sessionID, message_id: part.messageID, part_id: part.id },
    })
  }
  if (part.type === "retry") {
    return once(seen, `retry:${part.id}:${part.attempt}`, {
      event_type: "model.retry.started",
      message: "OpenCode 正在重试模型调用",
      data: {
        session_id: sessionID,
        message_id: part.messageID,
        attempt: part.attempt,
      },
    })
  }
  if (part.type === "tool") {
    const status = part.state?.status ?? "unknown"
    return once(seen, `tool:${part.id}:${status}`, {
      event_type: status === "running" ? "model.tool.started" : "model.tool.completed",
      message:
        status === "running"
          ? `OpenCode 开始执行 ${part.tool}`
          : `OpenCode 工具 ${part.tool} 状态：${status}`,
      data: {
        session_id: sessionID,
        message_id: part.messageID,
        part_id: part.id,
        tool: part.tool,
        status,
        input: summarizeToolInput(part.tool, part.state?.input),
        title: typeof part.state?.title === "string" ? part.state.title.slice(0, 500) : null,
      },
    })
  }
  return null
}

function once(seen, key, value) {
  if (seen.has(key)) return null
  seen.add(key)
  return value
}

function failureEnvelope(
  payload,
  {
    response,
    responses,
    calls,
    profile,
    error,
    explorerSessionID,
    explorerMemo,
  },
) {
  return {
    schema_version: "1.0",
    thread_id: sessionID,
    turn_id: response?.info?.id ?? randomBytes(16).toString("hex"),
    error,
    usage: aggregateUsage(responses, payload),
    output_transport: outputTransport({
      profile,
      calls,
      explorerSessionID,
      explorerMemo,
    }),
  }
}

function outputTransport({ profile, calls, explorerSessionID, explorerMemo }) {
  return {
    mode: profile.output_mode,
    profile: profile.name,
    format: "json_schema",
    request_mode: profile.stages.some((stage) => stage.output_mode === "text")
      ? "async_analysis_then_sync_finalize"
      : "prompt_sync",
    stages: profile.stages.map((stage) => ({
      name: stage.name,
      thinking_mode: stage.thinking_mode,
      reasoning_effort: stage.reasoning_effort,
      output_mode: stage.output_mode,
      workspace_tools: stage.workspace_tools,
      wire_tool_choice: stage.wire_tool_choice,
    })),
    ...(explorerSessionID ? { explorer_thread_id: explorerSessionID } : {}),
    ...(explorerMemo ? { explorer_memo: explorerMemo } : {}),
    provider_wire_requests: providerWireAudit.map((item) => ({ ...item })),
    schema_validator: "ajv@8.20.0",
    semantic_validator: "apkscanner@1.0",
    max_provider_requests: providerRequestLimit,
    structured_retry_count: STRUCTURED_RETRY_COUNT,
    model_calls: calls,
  }
}

function buildConfig(payload) {
  const model = `${PROVIDER_ID}/${payload.model}`
  const workspaceTools = workspaceToolNames(payload)
  const externalDirectoryPermission = {
    "*": "deny",
    "/tmp": "allow",
    "/tmp/*": "allow",
    ...Object.fromEntries(
      (payload.external_read_roots ?? []).flatMap((root) => [
        [root, "allow"],
        [`${root}/*`, "allow"],
      ]),
    ),
  }
  const workspacePermission = {
    "*": "deny",
    ...Object.fromEntries(
      workspaceTools
        .filter((tool) => tool !== "bash")
        .map((tool) => [tool, "allow"]),
    ),
    ...(workspaceTools.includes("bash")
      ? {
          bash: payload.allow_adb
            ? { "*": "allow" }
            : {
                "*": "allow",
                adb: "deny",
                "adb *": "deny",
                "*/adb": "deny",
                "*/adb *": "deny",
              },
          external_directory: externalDirectoryPermission,
        }
      : {}),
    StructuredOutput: "allow",
  }
  const finalizerPermission = {
    "*": "deny",
    StructuredOutput: "allow",
  }
  const tools = {
    "*": false,
    ...Object.fromEntries(workspaceTools.map((tool) => [tool, true])),
  }
  return {
    model,
    small_model: model,
    default_agent: "apkscanner-analyzer",
    enabled_providers: [PROVIDER_ID],
    autoupdate: false,
    share: "disabled",
    snapshot: false,
    shell: SANITIZED_BASH,
    plugin: [],
    mcp: {},
    instructions: [],
    tools,
    permission: workspacePermission,
    agent: {
      "apkscanner-analyzer": {
        mode: "primary",
        model,
        prompt: payload.explorer_instructions ?? payload.developer_instructions,
        steps: payload.max_agent_steps,
        options: thinkingOptions("disabled", null),
        permission: workspacePermission,
      },
      "apkscanner-explorer": {
        mode: "primary",
        model,
        prompt: payload.explorer_instructions ?? payload.developer_instructions,
        steps: payload.max_agent_steps,
        options: thinkingOptions(
          "enabled",
          explorerStage(payload)?.reasoning_effort ?? "high",
        ),
        permission: workspacePermission,
      },
      "apkscanner-memo-writer": {
        mode: "primary",
        model,
        prompt:
          "用简体中文将已完成的调查总结为简洁的纯文本证据备忘录。保留 Evidence ID、" +
          "包名、类名、代码符号、路径、命令和 URI 原文。" +
          "Do not call tools and do not emit JSON or tool-call markup.",
        steps: 20,
        options: thinkingOptions("disabled", null),
        permission: {
          "*": "deny",
        },
      },
      "apkscanner-finalizer": {
        mode: "primary",
        model,
        prompt: payload.developer_instructions,
        steps: 20,
        options: thinkingOptions("disabled", null),
        permission: finalizerPermission,
      },
    },
    ...(providerProxyURL
      ? {
          provider: {
            [PROVIDER_ID]: {
              options: {
                baseURL: providerProxyURL,
                apiKey: loopbackProxyAPIKey,
              },
            },
          },
        }
      : {}),
  }
}

function thinkingOptions(mode, effort) {
  return {
    thinking: { type: mode },
    ...(mode === "enabled" && effort ? { reasoningEffort: effort } : {}),
  }
}

async function readPayload() {
  const chunks = []
  let size = 0
  for await (const chunk of stdin) {
    size += chunk.length
    if (size > MAX_INPUT_BYTES) {
      throw new Error("OpenCode worker input exceeds 32 MiB")
    }
    chunks.push(chunk)
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"))
  } catch {
    throw new Error("OpenCode worker input is not valid JSON")
  }
}

function takeProviderAPIKey(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("OpenCode worker payload must be an object")
  }
  const candidate = value[PROVIDER_API_KEY_FIELD]
  delete value[PROVIDER_API_KEY_FIELD]
  if (typeof candidate !== "string" || !candidate.trim()) {
    throw new Error(`OpenCode worker ${PROVIDER_API_KEY_FIELD} is missing or empty`)
  }
  return candidate.trim()
}

function validatePayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("OpenCode worker payload must be an object")
  }
  if (value.schema_version !== "1.0") {
    throw new Error("unsupported OpenCode worker schema version")
  }
  if (!["capability", "investigate"].includes(value.action)) {
    throw new Error("unsupported OpenCode worker action")
  }
  if (
    typeof value.model !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.model)
  ) {
    throw new Error("invalid DeepSeek model ID")
  }
  if (
    !Number.isInteger(value.timeout_ms) ||
    value.timeout_ms < 1_000 ||
    value.timeout_ms > 86_400_000
  ) {
    throw new Error("invalid OpenCode worker timeout")
  }
  if (value.max_agent_steps === undefined || value.max_agent_steps === null) {
    value.max_agent_steps = DEFAULT_MAX_AGENT_STEPS
  }
  if (
    !Number.isInteger(value.max_agent_steps) ||
    value.max_agent_steps < 50 ||
    value.max_agent_steps > MAX_CONFIGURED_AGENT_STEPS
  ) {
    throw new Error("invalid OpenCode max agent steps")
  }
  if (value.base_url !== null && value.base_url !== undefined) {
    validateBaseURL(value.base_url)
  }
  value.execution_profile = validateExecutionProfile(value.execution_profile)
  if (value.action === "investigate") {
    if (typeof value.prompt !== "string" || !value.prompt) {
      throw new Error("investigation prompt is required")
    }
    if (typeof value.developer_instructions !== "string" || !value.developer_instructions) {
      throw new Error("developer instructions are required")
    }
    if (
      typeof value.phase !== "string" ||
      !/^[a-z][a-z0-9_]{0,63}$/.test(value.phase)
    ) {
      throw new Error("investigation phase is required")
    }
    if (
      value.execution_profile.stages.some((stage) => stage.output_mode === "text") &&
      (typeof value.explorer_prompt !== "string" || !value.explorer_prompt)
    ) {
      throw new Error("analysis-stage prompt is required")
    }
    if (
      value.execution_profile.stages.some((stage) => stage.output_mode === "text") &&
      (typeof value.explorer_instructions !== "string" || !value.explorer_instructions)
    ) {
      throw new Error("analysis-stage instructions are required")
    }
    if (
      !value.output_schema ||
      typeof value.output_schema !== "object" ||
      Array.isArray(value.output_schema)
    ) {
      throw new Error("output schema is required")
    }
    if (value.tool_profile !== WORKSPACE_TOOL_PROFILE) {
      throw new Error("unsupported OpenCode tool profile")
    }
    value.permission_profile ??= "strict"
    value.allow_adb ??= false
    value.allow_network ??= false
    value.require_hypothesis_receipts ??= false
    value.external_read_roots ??= []
    if (!["strict", "personal_lab"].includes(value.permission_profile)) {
      throw new Error("unsupported Agent permission profile")
    }
    if (typeof value.allow_adb !== "boolean" || typeof value.allow_network !== "boolean") {
      throw new Error("Agent runtime capabilities must be booleans")
    }
    if (typeof value.require_hypothesis_receipts !== "boolean") {
      throw new Error("require_hypothesis_receipts must be a boolean")
    }
    if (
      !Array.isArray(value.external_read_roots) ||
      value.external_read_roots.some(
        (item) =>
          typeof item !== "string" ||
          !item.startsWith("/") ||
          item.includes("\u0000") ||
          item.includes("\n"),
      )
    ) {
      throw new Error("external_read_roots must contain absolute safe paths")
    }
    value.allowed_hypothesis_ids = validateIdentifierList(
      value.allowed_hypothesis_ids,
      "allowed_hypothesis_ids",
    )
    value.allowed_entry_point_ids = validateIdentifierList(
      value.allowed_entry_point_ids,
      "allowed_entry_point_ids",
    )
    value.allowed_evidence_ids = validateIdentifierList(
      value.allowed_evidence_ids,
      "allowed_evidence_ids",
    )
  }
  return value
}

function validateIdentifierList(value, label) {
  if (value === undefined || value === null) return []
  if (
    !Array.isArray(value) ||
    value.some(
      (item) =>
        typeof item !== "string" ||
        !/^[a-f0-9-]{36}$/.test(item),
    )
  ) {
    throw new Error(`${label} must contain only platform UUIDs`)
  }
  return [...new Set(value)]
}

function validateBaseURL(value) {
  if (typeof value !== "string") {
    throw new Error("DeepSeek base URL must be a string")
  }
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    throw new Error("DeepSeek base URL is invalid")
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
    throw new Error("DeepSeek base URL must use HTTP(S)")
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(
      "DeepSeek base URL must not contain credentials, query parameters, or fragments",
    )
  }
  if (
    parsed.protocol === "http:" &&
    !["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname)
  ) {
    throw new Error("plain HTTP DeepSeek gateways are allowed only on loopback")
  }
  if (
    ["api.deepseek.com", "api.deepseek.com.cn"].includes(parsed.hostname) &&
    !["", "/"].includes(parsed.pathname)
  ) {
    throw new Error(
      "the official DeepSeek base URL must not append /v1 or another path",
    )
  }
}

function validateExecutionProfile(value) {
  const fallback = {
    name: PROFILE_STRUCTURED_FINALIZER,
    output_mode: OUTPUT_MODE_STRUCTURED_TOOL,
    stages: [
      {
        name: "finalizer",
        thinking_mode: "disabled",
        reasoning_effort: null,
        output_mode: OUTPUT_MODE_STRUCTURED_TOOL,
        workspace_tools: false,
        wire_tool_choice: "required",
      },
    ],
  }
  if (value === undefined || value === null) return fallback
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("execution_profile must be an object")
  }
  if (
    ![
      PROFILE_STABLE_ANALYZER,
      PROFILE_THINKING_EXPLORER,
      PROFILE_STRUCTURED_FINALIZER,
    ].includes(value.name)
  ) {
    throw new Error("unsupported OpenCode execution profile")
  }
  if (!Array.isArray(value.stages) || value.stages.length < 1 || value.stages.length > 2) {
    throw new Error("execution_profile stages must contain one or two stages")
  }
  const stages = value.stages.map((stage) => validateExecutionStage(stage))
  const expected =
    value.name === PROFILE_THINKING_EXPLORER
      ? [
          ["explorer", "enabled", "text", true, "omitted"],
          ["finalizer", "disabled", OUTPUT_MODE_STRUCTURED_TOOL, false, "required"],
        ]
      : value.name === PROFILE_STRUCTURED_FINALIZER
        ? [["finalizer", "disabled", OUTPUT_MODE_STRUCTURED_TOOL, false, "required"]]
        : [
            ["analyzer", "disabled", "text", true, "auto"],
            ["finalizer", "disabled", OUTPUT_MODE_STRUCTURED_TOOL, false, "required"],
          ]
  if (
    stages.length !== expected.length ||
    stages.some(
      (stage, index) =>
        stage.name !== expected[index][0] ||
        stage.thinking_mode !== expected[index][1] ||
        stage.output_mode !== expected[index][2] ||
        stage.workspace_tools !== expected[index][3] ||
        stage.wire_tool_choice !== expected[index][4],
    )
  ) {
    throw new Error("execution_profile stages do not match the selected profile")
  }
  const outputMode =
    value.name === PROFILE_THINKING_EXPLORER
      ? OUTPUT_MODE_EXPLORE_THEN_FINALIZE
      : value.name === PROFILE_STABLE_ANALYZER
        ? OUTPUT_MODE_ANALYZE_THEN_FINALIZE
        : OUTPUT_MODE_STRUCTURED_TOOL
  if (value.output_mode !== outputMode) {
    throw new Error("execution_profile output_mode does not match the selected profile")
  }
  return { name: value.name, output_mode: outputMode, stages }
}

function validateExecutionStage(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("execution stage must be an object")
  }
  if (!["analyzer", "explorer", "finalizer"].includes(value.name)) {
    throw new Error("unsupported execution stage")
  }
  if (!["enabled", "disabled"].includes(value.thinking_mode)) {
    throw new Error("invalid execution stage thinking mode")
  }
  if (![null, undefined, "high", "max"].includes(value.reasoning_effort)) {
    throw new Error("invalid DeepSeek reasoning effort")
  }
  if (value.thinking_mode === "enabled" && !["high", "max"].includes(value.reasoning_effort)) {
    throw new Error("thinking stages require high or max reasoning effort")
  }
  if (!["text", OUTPUT_MODE_STRUCTURED_TOOL].includes(value.output_mode)) {
    throw new Error("invalid execution stage output mode")
  }
  if (typeof value.workspace_tools !== "boolean") {
    throw new Error("execution stage workspace_tools must be boolean")
  }
  if (!["auto", "omitted", "required"].includes(value.wire_tool_choice)) {
    throw new Error("invalid execution stage wire_tool_choice")
  }
  return {
    name: value.name,
    thinking_mode: value.thinking_mode,
    reasoning_effort: value.reasoning_effort ?? null,
    output_mode: value.output_mode,
    workspace_tools: value.workspace_tools,
    wire_tool_choice: value.wire_tool_choice,
  }
}

function unwrap(response, label) {
  if (response?.error) {
    throw new Error(`${label} failed: ${formatError(response.error)}`)
  }
  return response?.data ?? response
}

function formatError(value) {
  if (typeof value === "string") return value
  if (value?.message) return String(value.message)
  return JSON.stringify(value) ?? String(value ?? "unknown error")
}

function executionProfile(payload) {
  return payload.execution_profile ?? validateExecutionProfile(undefined)
}

function explorerStage(payload) {
  return executionProfile(payload).stages.find((stage) => stage.name === "explorer")
}

function responseText(parts) {
  return parts
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("\n")
    .trim()
}

function parseTextJson(text) {
  const match = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/)
  try {
    return { value: JSON.parse(match?.[1] ?? text), error: null }
  } catch (error) {
    return {
      value: undefined,
      error: error instanceof Error ? error.message : "response is not valid JSON",
    }
  }
}

function parseStructuredResult(response) {
  const structured =
    response.info?.structured ??
    response.info?.structured_output
  if (structured !== undefined) {
    return { value: structured, error: null }
  }
  const text = responseText(response.parts ?? [])
  if (!text) {
    return { value: undefined, error: "OpenCode returned no structured result" }
  }
  return parseTextJson(text)
}

function normalizeValidationErrors(errors) {
  return (errors ?? []).map((error) => ({
    instance_path: error.instancePath,
    schema_path: error.schemaPath,
    keyword: error.keyword,
    params: error.params,
    message: error.message ?? "schema validation failed",
  }))
}

function semanticValidationErrors(value, payload) {
  if (!Object.prototype.hasOwnProperty.call(value, "result")) return []
  const errors = []
  const add = (instancePath, message) => {
    errors.push({
      instance_path: instancePath,
      schema_path: "#/apkscanner/semantic",
      keyword: "apkscannerSemantic",
      params: {},
      message,
    })
  }
  if (Array.isArray(value.evidence_ids)) {
    const allowedEvidence = payload.allowed_evidence_ids ?? []
    value.evidence_ids = value.evidence_ids.map((evidenceID) => {
      if (
        typeof evidenceID !== "string" ||
        allowedEvidence.includes(evidenceID) ||
        evidenceID.length < 8
      ) {
        return evidenceID
      }
      const matches = allowedEvidence.filter((candidate) =>
        candidate.startsWith(evidenceID),
      )
      return matches.length === 1 ? matches[0] : evidenceID
    })
  }
  if (value.result === "refuted_static" && value.severity_proposal !== "info") {
    add(
      "/severity_proposal",
      "refuted_static must use info because the risk hypothesis was rejected",
    )
  }
  if (
    [
      "supported_static",
      "refuted_static",
      "reproduced_blackbox",
      "not_reproduced",
    ].includes(value.result) &&
    (!Array.isArray(value.evidence_ids) || value.evidence_ids.length === 0)
  ) {
    add(
      "/evidence_ids",
      `${value.result} requires at least one platform-issued evidence ID`,
    )
  }
  if (Array.isArray(value.evidence_ids)) {
    const allowedEvidence = new Set(payload.allowed_evidence_ids ?? [])
    value.evidence_ids.forEach((evidenceID, index) => {
      if (typeof evidenceID === "string" && !allowedEvidence.has(evidenceID)) {
        add(
          `/evidence_ids/${index}`,
          "evidence ID must exactly match a full platform-issued ID for this task",
        )
      }
    })
  }
  if (
    ["final_evaluation", "recovery_evaluation"].includes(payload.phase) &&
    Array.isArray(value.requested_tests) &&
    value.requested_tests.length > 0
  ) {
    add(
      "/requested_tests",
      `${payload.phase} must not request additional tests`,
    )
  }
  if (Array.isArray(value.requested_tests)) {
    const allowedHypotheses = new Set(payload.allowed_hypothesis_ids ?? [])
    const allowedEntries = new Set(payload.allowed_entry_point_ids ?? [])
    value.requested_tests.forEach((request, index) => {
      if (!request || typeof request !== "object" || Array.isArray(request)) return
      if (
        typeof request.hypothesis_id === "string" &&
        !allowedHypotheses.has(request.hypothesis_id)
      ) {
        add(
          `/requested_tests/${index}/hypothesis_id`,
          "requested test must reference a hypothesis issued for this task",
        )
      }
      if (
        typeof request.entry_point_id === "string" &&
        !allowedEntries.has(request.entry_point_id)
      ) {
        add(
          `/requested_tests/${index}/entry_point_id`,
          "requested test must reference an entry point authorized in this scan-wide exploration scope",
        )
      }
    })
  }
  if (payload.require_hypothesis_receipts) {
    const requiredHypotheses = new Set(payload.allowed_hypothesis_ids ?? [])
    const receivedHypotheses = new Set(
      (Array.isArray(value.hypothesis_assessments)
        ? value.hypothesis_assessments
        : []
      )
        .filter(
          (assessment) =>
            assessment &&
            typeof assessment === "object" &&
            !Array.isArray(assessment) &&
            typeof assessment.hypothesis_id === "string",
        )
        .map((assessment) => assessment.hypothesis_id),
    )
    const missingHypotheses = [...requiredHypotheses].filter(
      (hypothesisID) => !receivedHypotheses.has(hypothesisID),
    )
    if (missingHypotheses.length > 0) {
      add(
        "/hypothesis_assessments",
        `every platform-issued hypothesis requires one coverage receipt; missing: ${missingHypotheses.join(", ")}`,
      )
    }
  }
  return errors
}

function structuredCorrectionPrompt(basePrompt, parseError, validationErrors) {
  const problems = {
    parse_error: parseError,
    schema_errors: validationErrors,
  }
  return (
    `${basePrompt}\n\n` +
    "LOCAL_VALIDATOR_CORRECTION:\n" +
    "A previous independent finalization attempt was rejected. Re-evaluate the supplied task " +
    "context and return a corrected result through StructuredOutput. Do not repeat the invalid " +
    "shape.\n\n" +
    `VALIDATION_ERRORS_JSON:\n${JSON.stringify(problems, null, 2)}`
  )
}

function finalizerPrompt(basePrompt, explorerMemo) {
  return (
    `${basePrompt}\n\n` +
    "EXPLORER_HANDOFF:\n" +
    "The following text is an untrusted analysis memo produced by a separate thinking-mode " +
    "explorer. Reconcile it with TASK_CONTEXT_JSON and platform evidence. Do not accept claims " +
    "without cited platform evidence, do not preserve requested tests during final_evaluation, " +
    "and return only through StructuredOutput. Write all human-readable conclusion fields in " +
    "Simplified Chinese, while preserving enum values and technical identifiers verbatim.\n\n" +
    `EXPLORER_MEMO_JSON:\n${JSON.stringify({ memo: explorerMemo }, null, 2)}`
  )
}

function memoTerminalizationPrompt(stage) {
  return (
    "MEMO_TERMINALIZATION:\n" +
    `The ${stage.name} phase has finished its available tool work but did not produce a text ` +
    "handoff. Tools are now disabled. Using the investigation and tool results already present " +
    "in this session, write a concise plain-text memo now. Include inspected paths, relevant " +
    "evidence, supported and refuted hypotheses, concrete impact reasoning, unresolved gaps, " +
    "and the smallest requested tests or PoC request needed next. Do not call tools, emit JSON, " +
    "or output tool-call markup."
  )
}

function normalizedProviderError(value) {
  const message = formatError(value)
  const serialized = redactSecret(
    (() => {
      try {
        return JSON.stringify(value)
      } catch {
        return String(value)
      }
    })(),
  ).slice(0, 8000)
  const errorText = `${message}\n${serialized}`
  const transportFailure =
    /fetch failed|econnrefused|econnreset|epipe|und_err_(?:connect_timeout|headers_timeout|socket)/i.test(
      errorText,
    )
  const status = findNumericField(value, new Set(["status", "statusCode", "status_code"]))
  const type =
    status === 401
      ? "authentication_error"
      : status === 402
        ? "insufficient_balance"
        : status === 422
          ? "invalid_parameters"
          : status === 429
            ? "rate_limit_error"
            : status && status >= 500
              ? "provider_unavailable"
              : transportFailure
                ? "transport_error"
                : /tool_choice/i.test(errorText)
                  ? "thinking_tool_choice_conflict"
                  : /reasoning_content/i.test(errorText)
                    ? "reasoning_replay_error"
                    : "provider_error"
  return {
    type,
    message: redactSecret(message).slice(0, 4000),
    status_code: status ?? null,
    retryable:
      transportFailure ||
      status === 429 ||
      Boolean(status && status >= 500),
    details: serialized,
  }
}

function findNumericField(value, names, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return undefined
  seen.add(value)
  for (const [key, item] of Object.entries(value)) {
    if (names.has(key) && Number.isInteger(item)) return item
  }
  for (const item of Object.values(value)) {
    const found = findNumericField(item, names, seen)
    if (found !== undefined) return found
  }
  return undefined
}

function redactSecret(value) {
  const secret = providerAPIKey
  return secret ? String(value).replaceAll(secret, "[redacted]") : String(value)
}

function modelCallAudit({
  stage,
  attempt,
  promptText,
  response,
  responseTextValue,
  parseError,
  validationErrors,
  accepted,
  tools,
}) {
  const turnMessages = response.apkscanner_turn_messages ?? [response]
  return {
    stage: stage.name,
    attempt,
    turn_id: response.info?.id ?? null,
    prompt: promptText,
    response_text: responseTextValue,
    parse_error: parseError,
    validation_errors: validationErrors,
    accepted,
    tools,
    thinking_mode: stage.thinking_mode,
    reasoning_effort: stage.reasoning_effort,
    wire_tool_choice: stage.wire_tool_choice,
    provider_error: response.info?.error
      ? normalizedProviderError(response.info.error)
      : null,
    usage: {
      tokens: turnMessages.reduce(
        (total, message) => mergeNumericObjects(total, message.info?.tokens ?? {}),
        {},
      ),
      cost: turnMessages.reduce(
        (total, message) => total + (message.info?.cost ?? 0),
        0,
      ),
      finish: response.info?.finish ?? null,
      provider_calls: turnMessages.length,
    },
    turn_message_ids: turnMessages
      .map((message) => message.info?.id)
      .filter((value) => typeof value === "string"),
  }
}

function workspaceToolNames(payload) {
  return payload.tool_profile === WORKSPACE_TOOL_PROFILE ? WORKSPACE_TOOLS : []
}

function structuredToolNames(payload, stage) {
  return [
    ...(stage.workspace_tools ? workspaceToolNames(payload) : []),
    "StructuredOutput",
  ]
}

function workspaceToolFlags(payload) {
  return Object.fromEntries(workspaceToolNames(payload).map((tool) => [tool, true]))
}

function disabledWorkspaceToolFlags() {
  return Object.fromEntries(WORKSPACE_TOOLS.map((tool) => [tool, false]))
}

function enabledToolNames(flags) {
  return Object.entries(flags ?? {})
    .filter(([, enabled]) => enabled)
    .map(([name]) => name)
    .sort()
}

function summarizeToolInput(tool, input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null
  const allowed =
    tool === "read"
      ? ["filePath", "offset", "limit"]
      : tool === "glob"
        ? ["pattern", "path"]
        : tool === "grep"
          ? ["pattern", "path", "include"]
          : tool === "bash"
            ? ["command", "workdir", "timeout"]
            : []
  return Object.fromEntries(
    allowed
      .filter((key) => input[key] !== undefined)
      .map((key) => [
        key,
        typeof input[key] === "string" ? input[key].slice(0, 1000) : input[key],
      ]),
  )
}

function aggregateUsage(responses, payload) {
  const modelResponses = responses.flatMap(
    (response) => response.apkscanner_turn_messages ?? [response],
  )
  const final = responses.at(-1)
  return {
    tokens: modelResponses.reduce(
      (total, response) => mergeNumericObjects(total, response.info?.tokens ?? {}),
      {},
    ),
    cost: modelResponses.reduce(
      (total, response) => total + (response.info?.cost ?? 0),
      0,
    ),
    finish: final?.info?.finish ?? null,
    provider: final?.info?.providerID ?? PROVIDER_ID,
    model: final?.info?.modelID ?? payload.model,
    calls: modelResponses.length,
  }
}

function mergeNumericObjects(left, right) {
  const output = { ...left }
  for (const [key, value] of Object.entries(right)) {
    if (typeof value === "number") {
      output[key] = (typeof output[key] === "number" ? output[key] : 0) + value
      continue
    }
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const existing =
        output[key] && typeof output[key] === "object" && !Array.isArray(output[key])
          ? output[key]
          : {}
      output[key] = mergeNumericObjects(existing, value)
    }
  }
  return output
}

async function startProviderCompatibilityProxy(payload) {
  const targetBase = new URL(payload.base_url ?? "https://api.deepseek.com")
  const proxy = createHttpServer(async (request, response) => {
    let audit
    try {
      const incomingURL = new URL(request.url ?? "/", "http://127.0.0.1")
      if (
        request.method !== "POST" ||
        incomingURL.pathname !== "/chat/completions" ||
        incomingURL.search
      ) {
        sendProviderProxyError(response, 404, "unsupported_proxy_route")
        return
      }
      if (
        !loopbackProxyAPIKey ||
        request.headers.authorization !== `Bearer ${loopbackProxyAPIKey}`
      ) {
        sendProviderProxyError(response, 401, "invalid_proxy_authentication")
        return
      }
      providerRequestCount += 1
      if (providerRequestCount > providerRequestLimit) {
        sendProviderProxyError(response, 429, "provider_request_limit_exceeded")
        return
      }
      const bodyBuffer = await readIncomingBody(request)
      let forwardedBody = bodyBuffer
      if (bodyBuffer.length > 0 && request.url?.includes("/chat/completions")) {
        const body = JSON.parse(bodyBuffer.toString("utf8"))
        const thinkingMode = body?.thinking?.type ?? "provider_default"
        const receivedToolChoice =
          Object.prototype.hasOwnProperty.call(body, "tool_choice")
            ? body.tool_choice
            : null
        if (thinkingMode === "enabled" && receivedToolChoice !== null) {
          delete body.tool_choice
          forwardedBody = Buffer.from(JSON.stringify(body))
        }
        audit = {
          thinking_mode: thinkingMode,
          received_tool_choice: receivedToolChoice,
          forwarded_tool_choice:
            Object.prototype.hasOwnProperty.call(body, "tool_choice")
              ? body.tool_choice
              : null,
          stripped_tool_choice:
            thinkingMode === "enabled" && receivedToolChoice !== null,
          model: typeof body.model === "string" ? body.model : null,
          status_code: null,
          transport_error: null,
        }
        providerWireAudit.push(audit)
      }

      const target = new URL(targetBase)
      const prefix = targetBase.pathname.replace(/\/+$/, "")
      target.pathname = `${prefix}${incomingURL.pathname}`
      target.search = incomingURL.search
      const headers = {}
      for (const [name, value] of Object.entries(request.headers)) {
        if (
          value === undefined ||
          ["host", "content-length", "connection", "transfer-encoding"].includes(
            name.toLowerCase(),
          )
        ) {
          continue
        }
        headers[name] = Array.isArray(value) ? value.join(", ") : value
      }
      headers.authorization = `Bearer ${providerAPIKey}`
      const remaining = Math.max(1, workerDeadline - Date.now())
      const upstream = await fetch(target, {
        method: request.method,
        headers,
        body:
          request.method === "GET" || request.method === "HEAD"
            ? undefined
            : forwardedBody,
        signal: AbortSignal.timeout(remaining),
      })
      if (audit) audit.status_code = upstream.status
      response.statusCode = upstream.status
      for (const [name, value] of upstream.headers.entries()) {
        if (
          ["content-length", "content-encoding", "transfer-encoding", "connection"].includes(
            name.toLowerCase(),
          )
        ) {
          continue
        }
        response.setHeader(name, value)
      }
      if (!upstream.body) {
        response.end()
        return
      }
      await pipeline(Readable.fromWeb(upstream.body), response)
    } catch (error) {
      if (audit) {
        audit.transport_error = redactSecret(formatThrownError(error)).slice(0, 2000)
      }
      emitRuntimeEvent("model.provider_proxy.failed", "DeepSeek 兼容转发失败", {
        error: redactSecret(formatThrownError(error)).slice(0, 2000),
      })
      if (response.headersSent) {
        response.destroy()
        return
      }
      response.writeHead(502, { "Content-Type": "application/json" })
      response.end(
        JSON.stringify({
          error: {
            type: "provider_proxy_error",
            message: "DeepSeek compatibility proxy failed",
          },
        }),
      )
    }
  })
  await new Promise((resolvePromise, reject) => {
    proxy.once("error", reject)
    proxy.listen(0, "127.0.0.1", resolvePromise)
  })
  const address = proxy.address()
  if (!address || typeof address === "string") {
    proxy.close()
    throw new Error("failed to start DeepSeek compatibility proxy")
  }
  providerProxyURL = `http://127.0.0.1:${address.port}`
  return proxy
}

function sendProviderProxyError(response, status, type) {
  response.writeHead(status, { "Content-Type": "application/json" })
  response.end(
    JSON.stringify({
      error: {
        type,
        message: "DeepSeek compatibility proxy rejected the request",
      },
    }),
  )
}

function readIncomingBody(request) {
  return new Promise((resolvePromise, reject) => {
    const chunks = []
    let size = 0
    request.on("data", (chunk) => {
      size += chunk.length
      if (size > MAX_INPUT_BYTES) {
        reject(new Error("DeepSeek proxy request exceeds 32 MiB"))
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.once("error", reject)
    request.once("end", () => resolvePromise(Buffer.concat(chunks)))
  })
}

function reservePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer()
    probe.unref()
    probe.once("error", reject)
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address()
      if (!address || typeof address === "string") {
        probe.close()
        reject(new Error("failed to reserve an OpenCode server port"))
        return
      }
      probe.close((error) => {
        if (error) reject(error)
        else resolve(address.port)
      })
    })
  })
}

for (const name of ["SIGINT", "SIGTERM"]) {
  process.on(name, () => {
    server?.close()
    process.exit(128 + (name === "SIGINT" ? 2 : 15))
  })
}

main()
  .then((result) => emitFinalRecord({ type: "result", result }, 0))
  .catch((error) => {
    const message = formatThrownError(error)
    stderr.write(redactSecret(message), () => process.exit(1))
  })

function formatThrownError(error) {
  if (!(error instanceof Error)) return String(error)
  const lines = [error.stack ?? `${error.name}: ${error.message}`]
  const seen = new Set([error])
  let cause = error.cause
  while (cause && !seen.has(cause)) {
    seen.add(cause)
    if (cause instanceof Error) {
      const code = typeof cause.code === "string" ? ` [${cause.code}]` : ""
      lines.push(`Caused by${code}: ${cause.stack ?? `${cause.name}: ${cause.message}`}`)
      cause = cause.cause
    } else {
      lines.push(`Caused by: ${formatError(cause)}`)
      break
    }
  }
  return lines.join("\n")
}

function emitRuntimeEvent(eventType, message, data = {}) {
  emitRecord({
    type: "event",
    event: {
      event_type: eventType,
      message,
      data,
    },
  })
}

function emitRecord(value) {
  const serialized = JSON.stringify(value)
  stdout.write(`${redactSecret(serialized)}\n`)
}

function emitFinalRecord(value, exitCode) {
  const serialized = JSON.stringify(value)
  stdout.write(`${redactSecret(serialized)}\n`, () => process.exit(exitCode))
}
