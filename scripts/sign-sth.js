#!/usr/bin/env node
/**
 * SWALL witness signing script — called by GitHub Actions on each run.
 *
 * Steps:
 *   1. GET /swall/log/sth/latest  — fetch the latest Signed Tree Head
 *   2. GET /.well-known/did.json  — fetch SWALL authority public key
 *   3. Verify the authority Ed25519 signature (refuse to co-sign invalid STHs)
 *   4. Sign the same STH payload with the witness private key
 *   5. POST /swall/log/sth/witness — submit co-signature to the API
 *   6. Update sth/{date}/{treeSize}.json in this repo with witnessSignature
 *
 * Required environment variables:
 *   WITNESS_PRIVATE_KEY  — base64url-encoded raw 32-byte Ed25519 private key
 *                          (store in GitHub Secrets, never commit)
 *   SWALL_API_BASE       — e.g. https://swall-api-836381891643.asia-northeast1.run.app
 *
 * Optional:
 *   WITNESS_KEY_ID       — key identifier to embed in co-signature
 *
 * Exit codes:
 *   0 — co-signed successfully (or already co-signed — idempotent)
 *   1 — fatal error (API unreachable, invalid signature, bad env)
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const { createPrivateKey, createPublicKey, sign: cryptoSign, verify: cryptoVerify } = require('crypto');
const { canonicalize } = require('json-canonicalize');

const API_BASE = (process.env.SWALL_API_BASE || '').replace(/\/$/, '');
if (!API_BASE) fatal('SWALL_API_BASE env var is required');

const PRIV_B64URL = process.env.WITNESS_PRIVATE_KEY || '';
if (!PRIV_B64URL) fatal('WITNESS_PRIVATE_KEY env var is required');

// Ed25519 DER wrappers
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX  = Buffer.from('302a300506032b6570032100', 'hex');

// Base58btc alphabet (for parsing DID multibase public keys)
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function fromB64url(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function toB64url(b) {
  return Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base58Decode(str) {
  let n = 0n;
  for (const c of str) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`base58: invalid char '${c}'`);
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

function loadPrivateKey(b64url) {
  const raw = fromB64url(b64url);
  if (raw.length !== 32) throw new Error(`Expected 32-byte private key, got ${raw.length}`);
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' });
}

function rawBytesToPublicKey(raw32) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw32)]), format: 'der', type: 'spki' });
}

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} → HTTP ${res.status}`);
  return res.json();
}

async function postJSON(url, body) {
  const res = await fetch(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`POST ${url} → HTTP ${res.status}: ${text}`);
  }
  return res.json();
}

function extractAuthorityPublicKey(didDoc) {
  const vm = (didDoc.verificationMethod || [])[0];
  if (!vm) throw new Error('No verificationMethod in authority DID document');

  if (vm.publicKeyMultibase) {
    const decoded = base58Decode(vm.publicKeyMultibase.slice(1)); // strip 'z' prefix
    if (decoded.length < 34) throw new Error('Unexpected multibase key length');
    return decoded.slice(2); // strip 2-byte multicodec prefix 0xed 0x01
  }
  if (vm.publicKeyJwk?.x) {
    return fromB64url(vm.publicKeyJwk.x);
  }
  throw new Error('Unsupported verificationMethod format');
}

function fatal(msg) {
  console.error('[witness] FATAL:', msg);
  process.exit(1);
}

// Updates sth/{YYYY-MM-DD}/{treeSize}.json in this repo with the witness co-signature.
// The file is written by publishToGitHub() in the SWALL API on every STH creation.
function updateArchive(sth, witnessSignature, witnessKeyId, witnessedAt) {
  const repoRoot = process.env.GITHUB_WORKSPACE || path.resolve(__dirname, '..');
  const dateStr  = sth.timestamp.split('T')[0]; // YYYY-MM-DD
  const filePath = path.join(repoRoot, 'sth', dateStr, `${sth.treeSize}.json`);

  if (!fs.existsSync(filePath)) {
    console.warn(`[witness] Archive file not found: sth/${dateStr}/${sth.treeSize}.json`);
    console.warn('[witness] API may not have committed it yet — witness signature stored in Firestore only');
    return;
  }

  const record = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (record.witnessSignature) {
    console.log(`[witness] Archive already has witness signature — skipping file update`);
    return;
  }

  record.witnessSignature = witnessSignature;
  record.witnessKeyId     = witnessKeyId;
  record.witnessedAt      = witnessedAt;
  fs.writeFileSync(filePath, JSON.stringify(record, null, 2) + '\n');
  console.log(`[witness] Updated archive: sth/${dateStr}/${sth.treeSize}.json`);
}

// ── Main ──────────────────────────────────────────────────────────────────────

(async () => {
  // 1. Fetch latest STH
  const sthData = await fetchJSON(`${API_BASE}/swall/log/sth/latest`)
    .catch(e => fatal(`Failed to fetch STH: ${e.message}`));

  const { sth, signature: authoritySignature } = sthData;
  if (!sth || !authoritySignature) fatal('Malformed STH response: missing sth or signature');

  // Already co-signed? Update archive only (idempotent re-entry after a push conflict).
  if (sthData.witnessSignature) {
    console.log(`[witness] treeSize=${sth.treeSize} already co-signed — updating archive only`);
    updateArchive(sth, sthData.witnessSignature, sthData.witnessKeyId, sthData.witnessedAt);
    process.exit(0);
  }

  // 2. Fetch authority public key
  const didDoc = await fetchJSON(`${API_BASE}/.well-known/did.json`)
    .catch(e => fatal(`Failed to fetch authority DID: ${e.message}`));

  let authorityPubKeyRaw;
  try {
    authorityPubKeyRaw = extractAuthorityPublicKey(didDoc);
  } catch (e) {
    fatal(`Cannot parse authority public key: ${e.message}`);
  }
  const authorityPubKey = rawBytesToPublicKey(authorityPubKeyRaw);

  // 3. Verify authority signature — refuse to co-sign an invalid STH
  const payload    = Buffer.from(canonicalize(sth));
  const authSigBuf = fromB64url(authoritySignature);
  const authValid  = cryptoVerify(null, payload, authorityPubKey, authSigBuf);
  if (!authValid) fatal(`Authority signature invalid for treeSize=${sth.treeSize} — refusing to co-sign`);

  console.log(`[witness] Authority signature verified ✓ treeSize=${sth.treeSize} root=${sth.root.slice(0, 16)}…`);

  // 4. Sign with witness private key
  const privKey          = loadPrivateKey(PRIV_B64URL);
  const witnessSigBuf    = cryptoSign(null, payload, privKey);
  const witnessSignature = toB64url(witnessSigBuf);

  const hostMatch = API_BASE.match(/https?:\/\/([^/]+)/);
  const host      = hostMatch ? hostMatch[1] : 'swall-api';
  const witnessKeyId =
    process.env.WITNESS_KEY_ID ||
    `did:web:${host.replace(/:/g, '%3A')}:swall:witness#key-1`;

  // 5. Submit co-signature to the API (stores in Firestore, served to browsers)
  const result = await postJSON(`${API_BASE}/swall/log/sth/witness`, {
    sth,
    witnessSignature,
    witnessKeyId,
  }).catch(e => fatal(`Failed to submit co-signature: ${e.message}`));

  const witnessedAt = result.witnessedAt || new Date().toISOString();

  if (result.alreadyCosigned) {
    console.log(`[witness] treeSize=${sth.treeSize} already co-signed (race) — ok`);
  } else {
    console.log(`[witness] Co-signed ✓ treeSize=${result.treeSize} at ${witnessedAt}`);
  }

  // 6. Update the archive file in this repo with the witness co-signature
  updateArchive(sth, witnessSignature, witnessKeyId, witnessedAt);
})();
