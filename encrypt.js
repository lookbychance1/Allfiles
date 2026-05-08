/**
 * Multi-layer data protection module
 * Each layer uses a different technique
 */
require('dotenv').config(); 
const crypto = require('crypto');

// Layer keys derived from environment or defaults
const K1 = process.env.EK1 || 'nPgS3cur3K3y2024xQz';
const K2 = process.env.EK2 || 'M3dQ!z@Rv9#pL1mN';
const K3 = process.env.EK3 || 'Xk7$Bw2^Tn8&Ys4*';

function deriveKey(secret, salt, len = 32) {
  return crypto.scryptSync(secret, salt, len);
}

// Technique A: AES-256-GCM
function layerA_encode(data) {
  const iv = crypto.randomBytes(12);
  const salt = crypto.randomBytes(16);
  const key = deriveKey(K1, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, enc]).toString('base64');
}
function layerA_decode(b64) {
  const buf = Buffer.from(b64, 'base64');
  const salt = buf.slice(0, 16);
  const iv = buf.slice(16, 28);
  const tag = buf.slice(28, 44);
  const enc = buf.slice(44);
  const key = deriveKey(K1, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

// Technique B: XOR + base62 shuffle
function layerB_encode(data) {
  const keyBuf = Buffer.from(K2 + K2 + K2 + K2);
  const buf = Buffer.from(data, 'utf8');
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ keyBuf[i % keyBuf.length] ^ (i % 251);
  }
  // Interleave with position encoding
  const hex = out.toString('hex');
  const chunks = [];
  for (let i = 0; i < hex.length; i += 4) chunks.push(hex.slice(i, i+4));
  return chunks.reverse().join('~');
}
function layerB_decode(data) {
  const chunks = data.split('~').reverse();
  const hex = chunks.join('');
  const buf = Buffer.from(hex, 'hex');
  const keyBuf = Buffer.from(K2 + K2 + K2 + K2);
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ keyBuf[i % keyBuf.length] ^ (i % 251);
  }
  return out.toString('utf8');
}

// Technique C: Chacha-like substitution cipher + base64url
function layerC_encode(data) {
  const seed = K3;
  let state = 0;
  for (let i = 0; i < seed.length; i++) state = (state * 31 + seed.charCodeAt(i)) >>> 0;
  const buf = Buffer.from(data, 'utf8');
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    state = (state ^ (state << 13)) >>> 0;
    state = (state ^ (state >> 7)) >>> 0;
    state = (state ^ (state << 17)) >>> 0;
    out[i] = (buf[i] + (state & 0xFF)) & 0xFF;
  }
  return out.toString('base64url');
}
function layerC_decode(data) {
  const seed = K3;
  let state = 0;
  for (let i = 0; i < seed.length; i++) state = (state * 31 + seed.charCodeAt(i)) >>> 0;
  const buf = Buffer.from(data, 'base64url');
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    state = (state ^ (state << 13)) >>> 0;
    state = (state ^ (state >> 7)) >>> 0;
    state = (state ^ (state << 17)) >>> 0;
    out[i] = (buf[i] - (state & 0xFF) + 256) & 0xFF;
  }
  return out.toString('utf8');
}

// Final encode: C → B → A (three independent layers)
function protect(plaintext) {
  const s1 = layerC_encode(plaintext);
  const s2 = layerB_encode(s1);
  const s3 = layerA_encode(s2);
  return s3;
}

function unprotect(ciphertext) {
  const s2 = layerA_decode(ciphertext);
  const s1 = layerB_decode(s2);
  const plain = layerC_decode(s1);
  return plain;
}

module.exports = { protect, unprotect };
