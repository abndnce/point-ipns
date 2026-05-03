#!/usr/bin/env node

import { keys } from '@libp2p/crypto';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';
import { createIPNSRecord, marshalIPNSRecord } from 'ipns';
import { base36 } from 'multiformats/bases/base36';

const RECORD_TTL_MS = 48 * 3600_000;
const CACHE_TTL_MS = 5 * 60000;

const keyHex = process.env.IPNS_KEY;
const cid = process.argv[2];

if (!keyHex) {
  console.error('Set IPNS_KEY env var (hex-encoded Ed25519 private key)');
  process.exit(1);
}
if (!cid) {
  console.error('Usage: point-ipns <cid>');
  process.exit(1);
}

const rawKey = Uint8Array.fromHex(keyHex);
const privateKey = await keys.generateKeyPairFromSeed('Ed25519', rawKey);
const name = peerIdFromPrivateKey(privateKey).toCID().toString(base36);

const record = await createIPNSRecord(privateKey, `/ipfs/${cid}`, 0, RECORD_TTL_MS, {
  ttlNs: CACHE_TTL_MS * 1_000_000,
});

function fieldBytes(tag: number, val: Uint8Array): Uint8Array {
  return new Uint8Array([(tag << 3) | 2, ...varint(val.length), ...val]);
}
function fieldVarint(tag: number, val: number): Uint8Array {
  return new Uint8Array([(tag << 3) | 0, ...varint(val)]);
}
function varint(n: number): number[] {
  const out: number[] = [];
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  out.push(n);
  return out;
}
function concat(arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((s, a) => s + a.length, 0));
  let i = 0;
  for (const a of arrays) {
    out.set(a, i);
    i += a.length;
  }
  return out;
}

const pubKey = privateKey.publicKey.raw;
const pubKeyMsg = concat([fieldVarint(1, 1), fieldBytes(2, pubKey)]);

const protobuf = concat([marshalIPNSRecord(record), fieldBytes(7, pubKeyMsg)]);

const res = await fetch(`https://delegated-ipfs.dev/routing/v1/ipns/${name}`, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/vnd.ipfs.ipns-record' },
  body: protobuf,
});

if (res.ok) {
  console.log(`${cid} → ${name}`);
} else {
  console.error(`${res.status} ${await res.text()}`);
  process.exit(1);
}
