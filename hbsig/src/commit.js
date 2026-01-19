import { id, base, hashpath, rsaid, hmacid } from "./id.js"
import { toAddr } from "./utils.js"
import { extractPubKey } from "./signer-utils.js"
import { verify } from "./signer-utils.js"
import { decodeSigInput } from "./parser.js"
import base64url from "base64url"

/**
 * Create a commitment structure for HyperBEAM
 *
 * FIX: Updated to match HyperBEAM's expected commitment format:
 * - Added 'type' field (algorithm name)
 * - Added 'keyid' field (publickey:base64 for RSA, constant:ao for HMAC)
 * - Added 'committed' field (list of signed components)
 * - Signature is raw base64, not RFC 9421 structured field format
 * - HMAC signature equals HMAC ID (deterministic)
 * - Removed signature-input from commitment body (only needed in HTTP headers)
 *
 * @see https://github.com/ArweaveOasis/wao/issues/XXX
 */
export const commit = async (obj, opts) => {
  // CRITICAL: Pass path: false to prevent signing @path component
  // HyperBEAM commitment verification doesn't expect path in the committed fields
  // when spawning a process (only for messages to a process)
  const signingOpts = { path: opts.path !== undefined ? opts.path : false }
  const msg = await opts.signer(obj, signingOpts)
  const {
    decodedSignatureInput: { components },
  } = await verify(msg)

  let body = {}

  // Check for inline-body-key
  const inlineBodyKey = msg.headers["inline-body-key"]

  // Build body from components
  // Note: signature-input has @-prefixed derived components (e.g., @authority)
  // but the actual headers and body keys don't have the @ prefix
  for (const v of components) {
    // Strip @ prefix from derived components to get the actual header key
    const headerKey = v.startsWith('@') ? v.slice(1) : v
    // For body, use the key without @ prefix
    body[headerKey] = msg.headers[headerKey]
  }

  // Handle body resolution
  if (msg.body) {
    let bodyContent

    if (msg.body instanceof Blob) {
      const arrayBuffer = await msg.body.arrayBuffer()
      bodyContent = Buffer.from(arrayBuffer)
    } else {
      bodyContent = msg.body
    }

    // If inline-body-key is "data", put content in data field
    if (inlineBodyKey === "data") {
      body.data = bodyContent
    } else {
      body.body = bodyContent
    }
  }

  // Remove inline-body-key from the final body as it's just metadata
  delete body["inline-body-key"]

  const hmacId = hmacid(msg.headers)
  const rsaId = rsaid(msg.headers)
  const pub = extractPubKey(msg.headers)
  const committer = toAddr(pub.toString("base64"))

  // Parse signature-input to extract params (keyid, tag, alg)
  const signatureInputHeader = msg.headers["signature-input"] || msg.headers["Signature-Input"]
  const decodedSigs = decodeSigInput(signatureInputHeader)
  const sigEntries = Object.entries(decodedSigs || {})
  const [sigName, sigData] = sigEntries[0] || [null, {}]
  const sigParams = sigData?.params || {}

  // Parse RFC 9421 structured field signature to extract raw base64 value
  // RFC 9421 format: "label=:base64value:" - HyperBEAM expects just "base64value"
  const parseRfc9421Signature = (sigStr) => {
    if (!sigStr) return sigStr
    const match = sigStr.match(/^[^=]+=:([^:]+):$/)
    return match ? match[1] : sigStr
  }

  // Convert standard base64 to base64url (HyperBEAM uses b64fast which expects base64url)
  const toBase64url = (base64) => {
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '')
  }

  // Extract and convert signature from standard base64 to base64url
  const rawSignatureBase64 = parseRfc9421Signature(msg.headers.signature)
  const rawSignature = toBase64url(rawSignatureBase64)

  // Build 'committed' field listing signed components (required by HyperBEAM)
  // Strip @ prefix from all derived components - HyperBEAM adds them back via add_derived_specifiers
  const committedFields = components.map(v => v.startsWith('@') ? v.slice(1) : v)

  // Get the keyid - must match EXACTLY what's in the signature-input
  // send.js now includes the "publickey:" prefix in the keyid
  // The commitment's keyid must be identical for verification to work
  const keyid = sigParams.keyid || `publickey:${pub.toString('base64')}`

  // RSA commitment (with committer)
  // HyperBEAM expects: type, keyid, signature, committed, commitment-device, committer
  // The keyid must match exactly what was in the signature-input for verification
  const rsaCommitment = {
    "commitment-device": "httpsig@1.0",
    type: "rsa-pss-sha512",
    keyid: keyid,
    committer: committer,
    signature: rawSignature,
    committed: committedFields,
  }

  // Add tag if present in signature params (hashpath)
  if (sigParams.tag) {
    rsaCommitment.tag = sigParams.tag
  }

  // HMAC commitment (no committer, keyid is "constant:ao")
  // For HMAC, the signature IS the HMAC ID (they're the same value)
  // This is because HMAC is deterministic - can be recomputed from message content
  const hmacCommitment = {
    "commitment-device": "httpsig@1.0",
    type: "hmac-sha256",
    keyid: "constant:ao",
    signature: hmacId,
    committed: committedFields,
  }

  const committed = {
    commitments: {
      [rsaId]: rsaCommitment,
      [hmacId]: hmacCommitment,
    },
    ...body,
  }
  return committed
}
