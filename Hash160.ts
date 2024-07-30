import crypto from "crypto";

export function hash160(buf: Buffer): Buffer {
  return crypto
    .createHash("ripemd160")
    .update(crypto.createHash("sha256").update(buf).digest())
    .digest();
}

// Additional utility functions

export function sha1(buf: Buffer): Buffer {
  return crypto.createHash("sha1").update(buf).digest();
}

export function sha512(buf: Buffer): Buffer {
  return crypto.createHash("sha512").update(buf).digest();
}

export function hmacSha256(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac("sha256", key).update(data).digest();
}

export function hmacSha512(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac("sha512", key).update(data).digest();
}

export function hmacSha1(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac("sha1", key).update(data).digest();
}

export function hmacRipemd160(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac("ripemd160", key).update(data).digest();
}

export function ecdsaSign(privateKey: string, data: Buffer): Buffer {
  const sign = crypto.createSign("sha256");
  sign.update(data);
  sign.end();
  return sign.sign(privateKey);
}

export function ecdsaVerify(publicKey: string, signature: Buffer, data: Buffer): boolean {
  const verify = crypto.createVerify("sha256");
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature);
}

export function aesCbcEncrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function aesCbcDecrypt(key: Buffer, iv: Buffer, encrypted: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

export function aesEcbEncrypt(key: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-ecb", key, null);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function aesEcbDecrypt(key: Buffer, encrypted: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-ecb", key, null);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

export function hmacBlake2b512(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac("blake2b512", key).update(data).digest();
}

export function hmacBlake2s256(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac("blake2s256", key).update(data).digest();
}

export function generateRandomHex(length: number): string {
  return crypto.randomBytes(length).toString("hex");
}

export function generateRandomBase64(length: number): string {
  return crypto.randomBytes(length).toString("base64");
}

export function hkdfExpand(prk: Buffer, info: Buffer, length: number, hash: string = "sha256"): Buffer {
  const hashLen = crypto.createHash(hash).digest().length;
  const n = Math.ceil(length / hashLen);
  const t = Buffer.alloc(hashLen * n);
  let tPrev = Buffer.alloc(0);

  for (let i = 0; i < n; i++) {
    const hmac = crypto.createHmac(hash, prk);
    hmac.update(tPrev);
    hmac.update(info);
    hmac.update(Buffer.from([i + 1]));
    tPrev = hmac.digest();
    tPrev.copy(t, i * hashLen);
  }

  return t.slice(0, length);
}

export function xorBuffers(buf1: Buffer, buf2: Buffer): Buffer {
  const length = Math.min(buf1.length, buf2.length);
  const result = Buffer.alloc(length);

  for (let i = 0; i < length; i++) {
    result[i] = buf1[i] ^ buf2[i];
  }

  return result;
}

export function pbkdf2DeriveKey(password: Buffer, salt: Buffer, iterations: number, keyLength: number, hash: string = "sha256"): Buffer {
  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, hash);
}

export function generateKeyPair(type: "rsa" | "ec" = "rsa", options?: crypto.RSAKeyPairKeyObjectOptions | crypto.ECKeyPairKeyObjectOptions): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync(type, options || {});
  return { publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(), privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString() };
}

export function randomBigInt(bits: number): bigint {
  const bytes = Math.ceil(bits / 8);
  const buf = crypto.randomBytes(bytes);
  buf[0] = buf[0] & (2 ** (bits % 8) - 1);
  return bigFromBufLE(buf);
}

export function sha384(buf: Buffer): Buffer {
  return crypto.createHash("sha384").update(buf).digest();
}

export function hashWithSalt(data: Buffer, salt: Buffer, hash: string = "sha256"): Buffer {
  return crypto.createHash(hash).update(data).update(salt).digest();
}

export function constantTimeEquals(buf1: Buffer, buf2: Buffer): boolean {
  if (buf1.length !== buf2.length) return false;
  return crypto.timingSafeEqual(buf1, buf2);
}
