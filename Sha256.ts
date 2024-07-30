import crypto from "crypto";

export function sha256(buf: Buffer): Buffer {
  return crypto.createHash("sha256").update(buf).digest();
}

export function md5(buf: Buffer): Buffer {
  return crypto.createHash("md5").update(buf).digest();
}

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

export function aesEncrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted;
}

export function aesDecrypt(key: Buffer, iv: Buffer, encrypted: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}

export function generateKey(size: number): Buffer {
  return crypto.randomBytes(size);
}

export function generateIv(): Buffer {
  return crypto.randomBytes(16);
}

export function deriveKey(password: string, salt: Buffer, iterations: number, keyLength: number): Buffer {
  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, "sha512");
}

export function generateSalt(size: number = 16): Buffer {
  return crypto.randomBytes(size);
}

export function sign(data: Buffer, privateKey: string): Buffer {
  const sign = crypto.createSign("SHA256");
  sign.update(data);
  sign.end();
  return sign.sign(privateKey);
}

export function verify(data: Buffer, signature: Buffer, publicKey: string): boolean {
  const verify = crypto.createVerify("SHA256");
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature);
}

export function rsaEncrypt(publicKey: string, data: Buffer): Buffer {
  return crypto.publicEncrypt(publicKey, data);
}

export function rsaDecrypt(privateKey: string, encrypted: Buffer): Buffer {
  return crypto.privateDecrypt(privateKey, encrypted);
}

export function generateRsaKeyPair(size: number): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: size,
  });
  return { publicKey: publicKey.export({ type: "pkcs1", format: "pem" }).toString(), privateKey: privateKey.export({ type: "pkcs1", format: "pem" }).toString() };
}

export function generateEcdsaKeyPair(curve: string): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: curve,
  });
  return { publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(), privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString() };
}

export function ecdsaSign(data: Buffer, privateKey: string): Buffer {
  const sign = crypto.createSign("SHA256");
  sign.update(data);
  sign.end();
  return sign.sign(privateKey);
}

export function ecdsaVerify(data: Buffer, signature: Buffer, publicKey: string): boolean {
  const verify = crypto.createVerify("SHA256");
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature);
}

export function hkdfExtract(salt: Buffer, ikm: Buffer, hash: string = "sha256"): Buffer {
  return crypto.createHmac(hash, salt).update(ikm).digest();
}

export function hkdfExpand(prk: Buffer, info: Buffer, length: number, hash: string = "sha256"): Buffer {
  const hashLen = crypto.createHash(hash).digest().length;
  const blocks = Math.ceil(length / hashLen);
  let okm = Buffer.alloc(0);
  let previousBlock = Buffer.alloc(0);
  for (let i = 0; i < blocks; i++) {
    const hmac = crypto.createHmac(hash, prk);
    hmac.update(Buffer.concat([previousBlock, info, Buffer.from([i + 1])]));
    previousBlock = hmac.digest();
    okm = Buffer.concat([okm, previousBlock]);
  }
  return okm.slice(0, length);
}

export function hkdf(salt: Buffer, ikm: Buffer, info: Buffer, length: number, hash: string = "sha256"): Buffer {
  const prk = hkdfExtract(salt, ikm, hash);
  return hkdfExpand(prk, info, length, hash);
}

export function generateNonce(length: number): Buffer {
  return crypto.randomBytes(length);
}

export function poly1305KeyGen(key: Buffer, nonce: Buffer): Buffer {
  const subKey = Buffer.alloc(32);
  crypto.createHmac("sha256", key).update(nonce).digest().copy(subKey);
  return subKey;
}

export function poly1305Mac(key: Buffer, data: Buffer): Buffer {
  return crypto.createHmac("sha256", key).update(data).digest().slice(0, 16);
}

export function xorBuffer(buf1: Buffer, buf2: Buffer): Buffer {
  if (buf1.length !== buf2.length) throw new Error("Buffers must be of the same length");
  const result = Buffer.alloc(buf1.length);
  for (let i = 0; i < buf1.length; i++) {
    result[i] = buf1[i] ^ buf2[i];
  }
  return result;
}

export function salsa20Encrypt(key: Buffer, nonce: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv("salsa20", key, nonce);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted;
}

export function salsa20Decrypt(key: Buffer, nonce: Buffer, encrypted: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("salsa20", key, nonce);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}

export function argon2Hash(password: Buffer, salt: Buffer, options: crypto.Argon2Options): Buffer {
  return crypto.scryptSync(password, salt, options.length, options);
}

export function bcryptHash(password: Buffer, salt: Buffer, rounds: number): Buffer {
  return crypto.pbkdf2Sync(password, salt, rounds, 64, "sha512");
}

export function scryptHash(password: Buffer, salt: Buffer, cost: number, blockSize: number, parallelization: number): Buffer {
  return crypto.scryptSync(password, salt, cost * blockSize * parallelization);
}
