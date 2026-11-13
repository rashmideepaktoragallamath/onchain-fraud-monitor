"use strict";
// Merkle batching for alert anchoring. Pure Node, no dependencies, so it can be unit-tested
// without Hardhat. It must produce exactly the hashes MerkleAnchor.sol recomputes on-chain:
//
//   leaf   = keccak256( keccak256( txHash(32) | subject(20) | riskScore(1) | reasonMask(2) ) )
//   parent = keccak256( min(a,b) | max(a,b) )          (sorted pair, so a proof needs no left/right flags)
//   an odd node at the end of a level is carried up unchanged (never duplicated)

// ---- Keccak-256 (the Ethereum variant, padding byte 0x01; NOT NIST SHA3-256) -------------
const MASK = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROT = [
  [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]; // ROT[x][y]
const rol = (v, n) => (n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & MASK);

function keccakF(s) {
  for (let round = 0; round < 24; round++) {
    const c = [];
    for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d;
    }
    const b = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(s[x + 5 * y], ROT[x][y]);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) s[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y] & MASK);
    }
    s[0] ^= RC[round];
  }
}

/** keccak256 of a Buffer/Uint8Array -> Buffer(32). */
function keccak256(data) {
  const rate = 136;
  const input = Buffer.from(data);
  const padded = Buffer.alloc(Math.ceil((input.length + 1) / rate) * rate);
  input.copy(padded);
  padded[input.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  const s = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) s[i] ^= padded.readBigUInt64LE(off + i * 8);
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(s[i], i * 8);
  return out;
}

// ---- helpers --------------------------------------------------------------------------------
const hex = (buf) => "0x" + Buffer.from(buf).toString("hex");
const fromHex = (h, bytes) => {
  if (!new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(h)) throw new Error(`expected ${bytes} bytes of hex, got ${h}`);
  return Buffer.from(h.slice(2), "hex");
};

/** Leaf for one alert; the same value MerkleAnchor.leafOf() returns. */
function leafHash({ txHash, subject, score, mask }) {
  if (!Number.isInteger(score) || score < 1 || score > 100) throw new Error("risk score must be 1-100");
  if (!Number.isInteger(mask) || mask < 1 || mask > 0xffff) throw new Error("reason mask must fit in 16 bits");
  const packed = Buffer.concat([fromHex(txHash, 32), fromHex(subject, 20), Buffer.from([score]), Buffer.from([mask >> 8, mask & 0xff])]);
  return keccak256(keccak256(packed));
}

const hashPair = (a, b) => keccak256(Buffer.compare(a, b) <= 0 ? Buffer.concat([a, b]) : Buffer.concat([b, a]));

/** Build every level of the tree. levels[0] = leaves, last level = [root]. */
function buildTree(leaves) {
  if (leaves.length === 0) throw new Error("cannot build a tree with no leaves");
  const levels = [leaves.map((l) => Buffer.from(l))];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(i + 1 < prev.length ? hashPair(prev[i], prev[i + 1]) : prev[i]);
    levels.push(next);
  }
  return levels;
}

/** Sibling hashes from leaf `index` to the root. */
function proofFor(levels, index) {
  const proof = [];
  let i = index;
  for (let l = 0; l < levels.length - 1; l++) {
    const sibling = i ^ 1;
    if (sibling < levels[l].length) proof.push(levels[l][sibling]);
    i >>= 1;
  }
  return proof;
}

/** Same check MerkleAnchor.verify() runs on-chain. */
function verifyProof(root, leaf, proof) {
  let h = Buffer.from(leaf);
  for (const p of proof) h = hashPair(h, Buffer.from(p));
  return Buffer.compare(h, Buffer.from(root)) === 0;
}

/**
 * Turn validated alerts into one batch: a root to anchor and one proof per alert.
 * `alerts` items: { txHash, subject, score, mask } (see anchor-lib.validateItem).
 */
function buildBatch(alerts) {
  const leaves = alerts.map(leafHash);
  const levels = buildTree(leaves);
  const root = levels[levels.length - 1][0];
  return {
    root: hex(root),
    count: alerts.length,
    proofs: alerts.map((a, i) => ({
      txHash: a.txHash,
      subject: a.subject,
      score: a.score,
      mask: a.mask,
      leaf: hex(leaves[i]),
      proof: proofFor(levels, i).map(hex),
    })),
  };
}

module.exports = { keccak256, leafHash, hashPair, buildTree, proofFor, verifyProof, buildBatch, hex };
