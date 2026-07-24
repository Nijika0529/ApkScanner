import { randomBytes } from "node:crypto"
import { createServer } from "node:net"
import { stdin, stderr, stdout } from "node:process"
import { createOpencodeClient, createOpencodeServer } from "@opencode-ai/sdk"
import Ajv from "ajv"

const MAX_INPUT_BYTES = 32 * 1024 * 1024
const PROVIDER_ID = "deepseek"
const OPENCODE_VERSION = "1.18.4"
const OUTPUT_MODE_PROMPTED_JSON = "prompted_json"
const OUTPUT_MODE_STRUCTURED_TOOL = "structured_output_tool"
const PROMPTED_JSON_RETRY_COUNT = 2

let server
let sessionID

async function main() {
  const payload = validatePayload(await readPayload())
  const controller = new AbortController()
  const timeout = setTimeout(
    () => controller.abort(new Error("OpenCode worker deadline exceeded")),
    payload.timeout_ms,
  )
  const username = "apkscanner"
  const password = randomBytes(32).toString("hex")
  process.env.OPENCODE_SERVER_USERNAME = username
  process.env.OPENCODE_SERVER_PASSWORD = password

  try {
    server = await createOpencodeServer({
      hostname: "127.0.0.1",
      port: await reservePort(),
      signal: controller.signal,
      timeout: Math.min(payload.timeout_ms, 15_000),
      config: buildConfig(payload),
    })
    const client = createOpencodeClient({
      baseUrl: server.url,
      directory: process.cwd(),
      headers: {
        Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
      },
    })
    if (payload.action === "capability") {
      return await capability(client, payload)
    }
    return await investigate(client, payload)
  } finally {
    clearTimeout(timeout)
    server?.close()
  }
}

async function capability(client, payload) {
  unwrap(await client.config.get(), "config.get")
  const configured = unwrap(await client.config.providers(), "config.providers")
  const provider = configured.providers?.find((item) => item.id === PROVIDER_ID)
  if (!provider) {
    throw new Error("DeepSeek provider is unavailable")
  }
  return {
    schema_version: "1.0",
    server_version: OPENCODE_VERSION,
    provider: PROVIDER_ID,
    models: Object.keys(provider.models ?? {}).sort(),
    output_mode: outputModeForModel(payload.model),
  }
}

async function investigate(client, payload) {
  const session = unwrap(
    await client.session.create({
      body: { title: "APK Scanner security investigation" },
    }),
    "session.create",
  )
  sessionID = session.id
  emitRuntimeEvent("model.session.started", "OpenCode SDK 会话已建立", {
    session_id: sessionID,
  })
  const eventPump = await startEventPump(client)
  try {
    if (outputModeForModel(payload.model) === OUTPUT_MODE_PROMPTED_JSON) {
      return await investigatePromptedJson(client, payload)
    }
    return await investigateStructuredOutput(client, payload)
  } finally {
    await eventPump.stop()
    await client.session.delete({ path: { id: sessionID } }).catch(() => undefined)
  }
}

async function investigateStructuredOutput(client, payload) {
  emitRuntimeEvent("model.turn.started", "OpenCode 开始生成结构化判断", {
    attempt: 1,
    output_mode: OUTPUT_MODE_STRUCTURED_TOOL,
  })
  const response = await prompt(client, payload, payload.prompt, {
    type: "json_schema",
    schema: payload.output_schema,
    retryCount: 2,
  })
  if (response.info?.error) {
    throw new Error(`OpenCode model error: ${formatError(response.info.error)}`)
  }
  emitRuntimeEvent("model.response.received", "OpenCode 已返回模型响应", {
    attempt: 1,
    turn_id: response.info?.id ?? null,
  })
  const result =
    response.info?.structured ??
    response.info?.structured_output ??
    parseTextJson(responseText(response.parts ?? [])).value
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("OpenCode returned no structured investigation result")
  }
  emitRuntimeEvent("model.output.validated", "OpenCode 结构化输出已通过校验", {
    attempt: 1,
    turn_id: response.info?.id ?? null,
  })
  return {
    schema_version: "1.0",
    thread_id: sessionID,
    turn_id: response.info?.id ?? randomBytes(16).toString("hex"),
    result,
    usage: aggregateUsage([response], payload),
    output_transport: {
      mode: OUTPUT_MODE_STRUCTURED_TOOL,
      format: "json_schema",
      tool_choice: "required",
      tools: ["StructuredOutput"],
      schema_validator: "opencode",
      retry_count: 2,
      model_calls: [
        modelCallAudit({
          attempt: 1,
          promptText: payload.prompt,
          response,
          responseTextValue: responseText(response.parts ?? []),
          parseError: null,
          validationErrors: [],
          accepted: true,
        }),
      ],
    },
  }
}

async function investigatePromptedJson(client, payload) {
  const validate = new Ajv({ allErrors: true, strict: false }).compile(payload.output_schema)
  const calls = []
  const responses = []
  let promptText = payload.prompt

  for (let index = 0; index <= PROMPTED_JSON_RETRY_COUNT; index += 1) {
    emitRuntimeEvent("model.turn.started", "DeepSeek Pro 开始生成纯文本 JSON", {
      attempt: index + 1,
      output_mode: OUTPUT_MODE_PROMPTED_JSON,
    })
    const response = await prompt(client, payload, promptText, { type: "text" })
    responses.push(response)
    const text = responseText(response.parts ?? [])
    emitRuntimeEvent("model.response.received", "DeepSeek Pro 已返回模型响应", {
      attempt: index + 1,
      turn_id: response.info?.id ?? null,
    })
    if (response.info?.error) {
      calls.push(
        modelCallAudit({
          attempt: index + 1,
          promptText,
          response,
          responseTextValue: text,
          parseError: null,
          validationErrors: [],
          accepted: false,
        }),
      )
      return promptedJsonFailure(
        payload,
        response,
        responses,
        calls,
        "provider_error",
        `OpenCode model error: ${formatError(response.info.error)}`,
      )
    }

    const parsed = parseTextJson(text)
    const parsedObject =
      parsed.error === null &&
      parsed.value !== null &&
      typeof parsed.value === "object" &&
      !Array.isArray(parsed.value)
    const schemaValid = parsedObject ? validate(parsed.value) : false
    const valid = parsedObject && schemaValid
    const validationErrors =
      parsedObject && !schemaValid ? normalizeValidationErrors(validate.errors) : []
    const parseError =
      parsed.error ??
      (parsed.value === null || typeof parsed.value !== "object" || Array.isArray(parsed.value)
        ? "top-level JSON value must be an object"
        : null)
    calls.push(
      modelCallAudit({
        attempt: index + 1,
        promptText,
        response,
        responseTextValue: text,
        parseError,
        validationErrors,
        accepted: Boolean(valid),
      }),
    )
    if (valid) {
      emitRuntimeEvent("model.output.validated", "DeepSeek Pro 输出已通过 Ajv 校验", {
        attempt: index + 1,
        turn_id: response.info?.id ?? null,
        validator: "ajv@8.20.0",
      })
      return {
        schema_version: "1.0",
        thread_id: sessionID,
        turn_id: response.info?.id ?? randomBytes(16).toString("hex"),
        result: parsed.value,
        usage: aggregateUsage(responses, payload),
        output_transport: promptedJsonTransport(calls),
      }
    }
    emitRuntimeEvent("model.validation.failed", "DeepSeek Pro 输出未通过本地 JSON 校验", {
      attempt: index + 1,
      turn_id: response.info?.id ?? null,
      parse_error: parseError,
      validation_error_count: validationErrors.length,
    })
    promptText = correctionPrompt(parseError, validationErrors)
  }

  const response = responses.at(-1)
  return promptedJsonFailure(
    payload,
    response,
    responses,
    calls,
    "schema_validation_error",
    `DeepSeek text output did not satisfy the JSON schema after ${calls.length} attempts`,
  )
}

function prompt(client, payload, promptText, format) {
  return client.session
    .prompt({
      path: { id: sessionID },
      body: {
        agent: "apkscanner",
        model: {
          providerID: PROVIDER_ID,
          modelID: payload.model,
        },
        system: payload.developer_instructions,
        format,
        parts: [{ type: "text", text: promptText }],
      },
    })
    .then((response) => unwrap(response, "session.prompt"))
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
      await done.catch(() => undefined)
    },
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

function promptedJsonFailure(payload, response, responses, calls, type, message) {
  return {
    schema_version: "1.0",
    thread_id: sessionID,
    turn_id: response?.info?.id ?? randomBytes(16).toString("hex"),
    error: { type, message },
    usage: aggregateUsage(responses, payload),
    output_transport: promptedJsonTransport(calls),
  }
}

function promptedJsonTransport(calls) {
  return {
    mode: OUTPUT_MODE_PROMPTED_JSON,
    format: "text",
    tool_choice: "omitted",
    tools: [],
    schema_validator: "ajv@8.20.0",
    retry_count: PROMPTED_JSON_RETRY_COUNT,
    model_calls: calls,
  }
}

function buildConfig(payload) {
  const model = `${PROVIDER_ID}/${payload.model}`
  const structuredOutput =
    outputModeForModel(payload.model) === OUTPUT_MODE_STRUCTURED_TOOL
  const permission = structuredOutput
    ? { "*": "deny", StructuredOutput: "allow" }
    : { "*": "deny" }
  return {
    model,
    small_model: model,
    default_agent: "apkscanner",
    enabled_providers: [PROVIDER_ID],
    autoupdate: false,
    share: "disabled",
    snapshot: false,
    plugin: [],
    mcp: {},
    instructions: [],
    tools: { "*": false },
    permission,
    agent: {
      apkscanner: {
        mode: "primary",
        model,
        prompt: payload.developer_instructions,
        steps: 4,
        permission,
      },
    },
    ...(payload.base_url
      ? {
          provider: {
            [PROVIDER_ID]: {
              options: { baseURL: payload.base_url },
            },
          },
        }
      : {}),
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
  if (value.base_url !== null && value.base_url !== undefined) {
    validateBaseURL(value.base_url)
  }
  if (value.action === "investigate") {
    if (typeof value.prompt !== "string" || !value.prompt) {
      throw new Error("investigation prompt is required")
    }
    if (typeof value.developer_instructions !== "string" || !value.developer_instructions) {
      throw new Error("developer instructions are required")
    }
    if (
      !value.output_schema ||
      typeof value.output_schema !== "object" ||
      Array.isArray(value.output_schema)
    ) {
      throw new Error("output schema is required")
    }
  }
  return value
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

function outputModeForModel(model) {
  return /^deepseek-v4-pro(?:$|[-._])/.test(model.trim().toLowerCase())
    ? OUTPUT_MODE_PROMPTED_JSON
    : OUTPUT_MODE_STRUCTURED_TOOL
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

function normalizeValidationErrors(errors) {
  return (errors ?? []).map((error) => ({
    instance_path: error.instancePath,
    schema_path: error.schemaPath,
    keyword: error.keyword,
    params: error.params,
    message: error.message ?? "schema validation failed",
  }))
}

function correctionPrompt(parseError, validationErrors) {
  const problems = {
    parse_error: parseError,
    schema_errors: validationErrors,
  }
  return (
    "Your previous answer was rejected by the local JSON Schema validator. " +
    "Return one corrected JSON object only, without Markdown, commentary, or tool calls.\n\n" +
    `VALIDATION_ERRORS_JSON:\n${JSON.stringify(problems, null, 2)}`
  )
}

function modelCallAudit({
  attempt,
  promptText,
  response,
  responseTextValue,
  parseError,
  validationErrors,
  accepted,
}) {
  return {
    attempt,
    turn_id: response.info?.id ?? null,
    prompt: promptText,
    response_text: responseTextValue,
    parse_error: parseError,
    validation_errors: validationErrors,
    accepted,
    usage: {
      tokens: response.info?.tokens ?? {},
      cost: response.info?.cost ?? 0,
      finish: response.info?.finish ?? null,
    },
  }
}

function aggregateUsage(responses, payload) {
  const final = responses.at(-1)
  return {
    tokens: responses.reduce(
      (total, response) => mergeNumericObjects(total, response.info?.tokens ?? {}),
      {},
    ),
    cost: responses.reduce((total, response) => total + (response.info?.cost ?? 0), 0),
    finish: final?.info?.finish ?? null,
    provider: final?.info?.providerID ?? PROVIDER_ID,
    model: final?.info?.modelID ?? payload.model,
    calls: responses.length,
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
  .then((result) => emitRecord({ type: "result", result }))
  .catch((error) => {
    const secret = process.env.DEEPSEEK_API_KEY
    const message = error instanceof Error ? error.stack ?? error.message : String(error)
    stderr.write(secret ? message.replaceAll(secret, "[redacted]") : message)
    process.exitCode = 1
  })

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
  const secret = process.env.DEEPSEEK_API_KEY
  const serialized = JSON.stringify(value)
  stdout.write(`${secret ? serialized.replaceAll(secret, "[redacted]") : serialized}\n`)
}
