import base64url from "base64url"
import { httpbis } from "./http-message-signatures/index.js"
import { parseItem, serializeList } from "structured-headers"
import { httpsig_from } from "./httpsig.js"
import { structured_to } from "./structured.js"
import { result } from "./send-utils.js"

const {
  augmentHeaders,
  createSignatureBase,
  createSigningParameters,
  formatSignatureBase,
} = httpbis

const toMsg = async req => {
  let msg = {}
  req?.headers?.forEach((v, k) => {
    msg[k] = v
  })
  if (req.body) {
    const arrayBuffer = await req.arrayBuffer()
    msg.body =
      typeof Buffer !== "undefined"
        ? Buffer.from(arrayBuffer) // Node.js
        : new Uint8Array(arrayBuffer) // Browser
  }

  return msg
}

export async function send(signedMsg, fetchImpl = fetch) {
  const fetchOptions = {
    method: signedMsg.method,
    headers: signedMsg.headers,
    redirect: "follow",
  }
  if (
    signedMsg.body !== undefined &&
    signedMsg.method !== "GET" &&
    signedMsg.method !== "HEAD"
  ) {
    fetchOptions.body = signedMsg.body
  }

  const response = await fetchImpl(signedMsg.url, fetchOptions)
  if (response.status >= 400) {
    throw new Error(`${response.status}: ${await response.text()}`)
  }
  return await result(response)
}

export const httpSigName = address => {
  const decoded = base64url.toBuffer(address)
  const hexString = [...decoded.subarray(1, 9)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("")
  return `http-sig-${hexString}`
}

const toView = value => {
  if (ArrayBuffer.isView(value)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
  } else if (typeof value === "string") return base64url.toBuffer(value)

  throw new Error(
    "Value must be Uint8Array, ArrayBuffer, or base64url-encoded string"
  )
}

// Helper to convert Uint8Array to standard base64
const toStandardBase64 = (bytes) => {
  // Convert Uint8Array to Buffer if needed
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes)
  return buffer.toString('base64')
}

// CRITICAL: These components are "derived" in RFC 9421 and HyperBEAM adds @ prefix
// to them in the signature-params line. We must match this behavior.
// See dev_codec_httpsig_siginfo.erl DERIVED_COMPONENTS
const DERIVED_COMPONENTS = [
  'method',
  'target-uri',
  'authority',
  'scheme',
  'request-target',
  'path',
  'query',
  'query-param',
]

// Add @ prefix to derived component names (for params line only)
const addDerivedSpecifiers = (componentName) => {
  // Remove existing @ prefix if present, then add if derived
  const stripped = componentName.startsWith('@') ? componentName.slice(1) : componentName
  if (DERIVED_COMPONENTS.includes(stripped)) {
    return `@${stripped}`
  }
  return componentName
}

export const toHttpSigner = signer => {
  const params = ["alg", "keyid"].sort()
  return async ({ request, fields }) => {
    let signatureBase
    let signatureInput
    let createCalled = false

    const create = injected => {
      createCalled = true

      const { publicKey, alg = "rsa-pss-sha512" } = injected

      const publicKeyBuffer = toView(publicKey)

      // FIX: Use standard base64 for keyid with "publickey:" prefix
      // HyperBEAM's apply_scheme uses Erlang's base64:decode which expects standard base64
      // (see dev_codec_httpsig_keyid.erl line 100)
      // The commitment's keyid field must exactly match what's in the signature-params
      const signingParameters = createSigningParameters({
        params,
        paramValues: {
          keyid: `publickey:${toStandardBase64(publicKeyBuffer)}`,
          alg,
        },
      })

      // SORT THE FIELDS HERE to match Erlang's lists:sort(maps:keys(Enc))
      const sortedFields = [...fields].sort()

      const signatureBaseArray = createSignatureBase(
        { fields: sortedFields },
        request
      )
      // CRITICAL: HyperBEAM adds @ prefix to derived components in the params line
      // The component lines use the original names, but the params line uses @-prefixed names
      // for derived components (authority, path, method, etc.)
      signatureInput = serializeList([
        [
          signatureBaseArray.map(([item]) => {
            // Item is like '"authority"' - need to extract, add specifier, re-quote
            const unquoted = item.replace(/^"|"$/g, '')
            const withSpecifier = addDerivedSpecifiers(unquoted)
            return parseItem(`"${withSpecifier}"`)
          }),
          signingParameters,
        ],
      ])

      signatureBaseArray.push(['"@signature-params"', [signatureInput]])
      signatureBase = formatSignatureBase(signatureBaseArray)
      return new TextEncoder().encode(signatureBase)
    }
    const result = await signer(create, "httpsig")
    if (!createCalled) {
      throw new Error(
        "create() must be invoked in order to construct the data to sign"
      )
    }

    if (!result.signature || !result.address) {
      throw new Error("Signer must return signature and address")
    }

    const signatureBuffer = toView(result.signature)
    const signedHeaders = augmentHeaders(
      request.headers,
      signatureBuffer,
      signatureInput,
      httpSigName(result.address)
    )
    const finalHeaders = {}
    for (const [key, value] of Object.entries(signedHeaders)) {
      if (key === "Signature" || key === "Signature-Input") {
        finalHeaders[key.toLowerCase()] = value
      } else finalHeaders[key] = value
    }

    return { ...request, headers: finalHeaders }
  }
}
