# swall-transparency-log

Public archive and independent witness for the [SWALL](https://github.com/adhvan-io/swall) transparency log.

## What this repo does

Every time SWALL issues a credential, it appends a leaf to a Merkle tree and publishes a **Signed Tree Head (STH)** — a snapshot of the tree root signed with the authority Ed25519 key. That STH is committed to this repo as `sth/{YYYY-MM-DD}/{treeSize}.json`.

Every 10 minutes, a GitHub Actions workflow in this repo:

1. Fetches the latest STH from the SWALL API
2. Verifies the authority signature — refuses to co-sign if it doesn't check out
3. Signs the same payload with an **independent witness key**
4. Posts the co-signature back to the API (stored in Firestore, served to browsers)
5. Updates the archive file in this repo to add `witnessSignature`

The result: each archived STH carries two independent Ed25519 signatures. Anyone can verify both without trusting any server.

## Archive format

```
sth/
  2026-05-18/
    862.json   ← STH for tree_size=862
    863.json
    ...
  2026-05-19/
    ...
```

Each file:

```json
{
  "sth": {
    "root": "502834a9d459c0ef...",
    "treeSize": 904,
    "timestamp": "2026-05-19T02:46:08.411Z",
    "nodeId": "did:web:try.adhvan.io:swall:authority"
  },
  "signature": "K4b3A-dD7UQ3fGL...",
  "witnessSignature": "ozvY-AfbjBhv...",
  "witnessKeyId": "did:web:...:swall:witness#key-1",
  "witnessedAt": "2026-05-19T02:50:01.000Z"
}
```

Files without `witnessSignature` were committed by the API but not yet co-signed (the witness cron runs every 10 minutes).

## Verifying a signature

Using the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) or Node.js `crypto`:

```js
import { canonicalize } from 'json-canonicalize';

const sthFile = await fetch(
  'https://raw.githubusercontent.com/adhvan-io/swall-transparency-log/main/sth/2026-05-19/904.json'
).then(r => r.json());

const payload = new TextEncoder().encode(canonicalize(sthFile.sth));

// Verify authority signature
const authorityKey = await fetchEd25519Key('https://try.adhvan.io/.well-known/did.json');
const authorityOk  = await crypto.subtle.verify('Ed25519', authorityKey, fromB64url(sthFile.signature), payload);

// Verify witness signature
const witnessKey = await fetchEd25519Key('https://try.adhvan.io/.well-known/witness-did.json');
const witnessOk  = await crypto.subtle.verify('Ed25519', witnessKey, fromB64url(sthFile.witnessSignature), payload);
```

Both signatures cover the same canonical JSON payload (`json-canonicalize` of the `sth` object).

## Witness key

The witness public key is published at:

```
https://swall-api-836381891643.asia-northeast1.run.app/.well-known/witness-did.json
```

The signing workflow is `.github/workflows/witness.yml` in this repo. The `WITNESS_PRIVATE_KEY` lives in GitHub Actions Secrets and is never exposed.

## Why a public witness?

A transparency log is only useful if its append-only property is independently verifiable. The authority signature proves the SWALL server signed a given tree head. The witness signature proves an **independent process** (this GitHub Actions workflow, auditable by anyone) also saw and validated that tree head. Together they make silent log equivocation detectable.
