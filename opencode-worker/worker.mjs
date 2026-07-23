import { randomBytes } from "node:crypto"
import { createServer } from "node:net"
import { stdin, stderr, stdout } from "node:process"
import { createOpencodeClient, createOpencodeServer } from "@opencode-ai/sdk"

const MAX_INPUT_BYTES = 32 * 1024 * 1024
const PROVIDER_ID = "deepseek"
const OPENCODE_VERSION = "1.18.4"

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
      return await capability(client)
    }
    return await investigate(client, payload)
  } finally {
    clearTimeout(timeout)
    server?.close()
  }
}

async function capability(client) {
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
  try {
    const response = unwrap(
      await client.session.prompt({
        path: { id: sessionID },
        body: {
          agent: "apkscanner",
          model: {
            providerID: PROVIDER_ID,
            modelID: payload.model,
          },
          system: payload.developer_instructions,
          format: {
            type: "json_schema",
            schema: payload.output_schema,
            retryCount: 2,
          },
          parts: [{ type: "text", text: payload.prompt }],
        },
      }),
      "session.prompt",
    )
    if (response.info?.error) {
      throw new Error(`OpenCode model error: ${formatError(response.info.error)}`)
    }
    const result =
      response.info?.structured ??
      response.info?.structured_output ??
      parseTextFallback(response.parts ?? [])
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new Error("OpenCode returned no structured investigation result")
    }
    return {
      schema_version: "1.0",
      thread_id: sessionID,
      turn_id: response.info?.id ?? randomBytes(16).toString("hex"),
      result,
      usage: {
        tokens: response.info?.tokens ?? {},
        cost: response.info?.cost ?? 0,
        finish: response.info?.finish ?? null,
        provider: response.info?.providerID ?? PROVIDER_ID,
        model: response.info?.modelID ?? payload.model,
      },
    }
  } finally {
    await client.session.delete({ path: { id: sessionID } }).catch(() => undefined)
  }
}

function buildConfig(payload) {
  const model = `${PROVIDER_ID}/${payload.model}`
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
    permission: { "*": "deny", StructuredOutput: "allow" },
    agent: {
      apkscanner: {
        mode: "primary",
        model,
        prompt: payload.developer_instructions,
        steps: 4,
        permission: { "*": "deny", StructuredOutput: "allow" },
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
  return JSON.stringify(value)
}

function parseTextFallback(parts) {
  const text = parts
    .filter((part) => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("\n")
    .trim()
  const match = text.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/)
  try {
    return JSON.parse(match?.[1] ?? text)
  } catch {
    return undefined
  }
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
  .then((result) => stdout.write(JSON.stringify(result)))
  .catch((error) => {
    const secret = process.env.DEEPSEEK_API_KEY
    const message = error instanceof Error ? error.stack ?? error.message : String(error)
    stderr.write(secret ? message.replaceAll(secret, "[redacted]") : message)
    process.exitCode = 1
  })
