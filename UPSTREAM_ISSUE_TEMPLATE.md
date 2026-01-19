# Upstream Issue/PR for ArweaveOasis/wao

## Issue Title
```
hbsig: HTTP signature verification fails with HyperBEAM httpsig@1.0
```

## Issue Body

Copy everything below to create an issue at **https://github.com/ArweaveOasis/wao/issues/new**

---

## Problem

The `hbsig` library produces HTTP message signatures that fail verification on HyperBEAM with `{process_not_verified, ...}` errors. Both RSA-PSS-SHA512 and HMAC-SHA256 commitments fail.

## Root Causes

After debugging against HyperBEAM source code (`dev_codec_httpsig.erl`), I identified several format mismatches:

### 1. HMAC keyid/key format mismatch

**Current behavior:**
```javascript
keyid: "hmac:ao" // or similar
```

**HyperBEAM expects:**
```javascript
keyid: "constant:ao"
key: "constant:ao"
```

See `dev_codec_httpsig_keyid.erl` line 24:
```erlang
-define(HMAC_DEFAULT_KEY, <<"constant:ao">>).
```

### 2. Missing `@` prefix for derived components in signature-params

HyperBEAM's `signature_params_line()` function calls `add_derived_specifiers()` which adds `@` prefix to derived components like `authority`, `path`, `method`, etc.

**Current behavior:**
```
"@signature-params": ("authority" "data-protocol" ...);alg="...";keyid="..."
```

**HyperBEAM expects:**
```
"@signature-params": ("@authority" "data-protocol" ...);alg="...";keyid="..."
```

The component LINES should NOT have `@` prefix, but the params line MUST have it for derived components (authority, path, method, target-uri, scheme, request-target, query, query-param).

### 3. Committed field should not have `@` prefix

When sending the commitment, the `committed` array should contain `["authority", ...]` not `["@authority", ...]`. HyperBEAM adds the `@` back via `add_derived_specifiers()` during verification.

### 4. commit() path option not passed correctly

The `commit()` function passes the full options object to the signer instead of extracting the `path` option, causing path to always be included in signatures.

## Reproduction

```javascript
import { createSigner } from '@permaweb/aoconnect';
import { commit, signer as createSignerFn } from 'wao/hbsig';

const jwk = /* your wallet */;
const HB_URL = 'http://your-hyperbeam:8734';

const aoSigner = createSigner(jwk, HB_URL);
const signerFn = createSignerFn({ signer: aoSigner, url: HB_URL });

const processMsg = {
  "Data-Protocol": "ao",
  Variant: "ao.TN.1",
  device: "process@1.0",
  Type: "Process",
  Authority: "scheduler-address",
  Scheduler: "scheduler-address",
  Module: "module-id",
  "execution-device": "genesis-wasm@1.0",
  "random-seed": "seed-123",
};

const committed = await commit(processMsg, { signer: signerFn });
// This commitment will fail verification on HyperBEAM with:
// {process_not_verified, ...}
```

## Environment

- HyperBEAM version: 1230ubn1 (production)
- wao version: latest from main branch

## Proposed Fix

I have a working fix: https://github.com/credentum/wao/commit/97af99a

The fix modifies:
- `hbsig/src/id.js` - HMAC keyid/key format and derived component handling
- `hbsig/src/send.js` - Add `@` prefix to derived components in params line
- `hbsig/src/commit.js` - Strip `@` prefix from committed field, fix path option
- `hbsig/src/httpsig.js` and `structured.js` - Preserve key casing for commitment IDs

**Test Results** (against HyperBEAM production):
- ✅ RSA-PSS-SHA512 commitments verify successfully
- ✅ HMAC-SHA256 commitments verify successfully
- ✅ HMAC ID matches expected value
- ✅ Process spawn via commit() function succeeds

Happy to submit a PR if this approach looks correct!

---

## How to Create the Upstream PR

After creating the issue, to submit a PR:

### Option 1: GitHub Web UI

1. Go to https://github.com/ArweaveOasis/wao
2. Click "Pull requests" → "New pull request"
3. Click "compare across forks"
4. Set:
   - Base repository: `ArweaveOasis/wao`
   - Base: `main`
   - Head repository: `credentum/wao`
   - Compare: `main`
5. Create the PR

### Option 2: GitHub CLI (if you have permissions)

```bash
gh pr create --repo ArweaveOasis/wao \
  --head credentum:main \
  --title "fix(hbsig): match HyperBEAM httpsig@1.0 verification format" \
  --body-file UPSTREAM_PR_BODY.md
```

---

## PR Title
```
fix(hbsig): match HyperBEAM httpsig@1.0 verification format
```

## PR Body

```markdown
## Summary

Fixes HTTP message signature verification to match HyperBEAM's httpsig@1.0 commitment device format. Previously, commitments created by hbsig failed verification with `{process_not_verified, ...}` errors.

Closes #[ISSUE_NUMBER]

## Changes

### 1. HMAC ID computation (`id.js`)
- Add `@` prefix to derived components in signature-params line
- Use `"constant:ao"` for both keyid and key
- Match HyperBEAM's `add_derived_specifiers()` behavior

### 2. RSA signature (`send.js`)
- Add `@` prefix to derived components in signature-params line (not component lines)
- Derived components: authority, path, method, target-uri, scheme, request-target, query, query-param

### 3. Commitment format (`commit.js`)
- Strip `@` prefix from committed field (HyperBEAM adds it back)
- Fix path option passing (default to `path: false`)
- Convert signature to base64url

### 4. Commitment ID (`httpsig.js`, `structured.js`)
- Preserve original key casing for commitment IDs

## Test Results

Tested against HyperBEAM production (version 1230ubn1):
- ✅ RSA-PSS-SHA512 commitments verify successfully
- ✅ HMAC-SHA256 commitments verify successfully
- ✅ HMAC ID matches expected value
- ✅ Process spawn via `commit()` function succeeds
```
