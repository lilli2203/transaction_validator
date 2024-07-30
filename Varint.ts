import { Readable } from "stream";
import { bigFromBufLE } from "./BigIntUtil";

export function decodeVarint(stream: Readable): bigint {
  const i = stream.read(1).readUInt8();

  if (i === 0xfd) {
    return bigFromBufLE(stream.read(2));
  } else if (i === 0xfe) {
    return bigFromBufLE(stream.read(4));
  } else if (i === 0xff) {
    return bigFromBufLE(stream.read(8));
  } else {
    return BigInt(i);
  }
}

export function encodeVarint(i: bigint | number): Buffer {
  if (i < BigInt("0xfd")) {
    return Buffer.from([Number(i)]);
  } else if (i < BigInt("0x10000")) {
    const buf = Buffer.alloc(3);
    buf[0] = 0xfd;
    buf.writeUInt16LE(Number(i), 1);
    return buf;
  } else if (i < BigInt("0x100000000")) {
    const buf = Buffer.alloc(5);
    buf[0] = 0xfe;
    buf.writeUInt32LE(Number(i), 1);
    return buf;
  } else if (i < BigInt("0x10000000000000000")) {
    const buf = Buffer.alloc(9);
    buf[0] = 0xff;
    buf.writeBigUInt64LE(BigInt(i), 1);
    return buf;
  } else {
    throw new Error(`Integer too large ${i}`);
  }
}

// Additional utility functions

import crypto from "crypto";

export function ripemd160(buf: Buffer): Buffer {
  return crypto.createHash("ripemd160").update(buf).digest();
}

export function sha3_256(buf: Buffer): Buffer {
  return crypto.createHash("sha3-256").update(buf).digest();
}

export function keccak256(buf: Buffer): Buffer {
  return crypto.createHash("keccak256").update(buf).digest();
}

export function generateEcdhKeyPair(curve: string = "secp256k1"): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: curve,
  });
  return { publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(), privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString() };
}

export function ecdhComputeSecret(privateKey: string, publicKey: string): Buffer {
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(Buffer.from(privateKey, "hex"));
  return ecdh.computeSecret(Buffer.from(publicKey, "hex"));
}

export function aesGcmEncrypt(key: Buffer, iv: Buffer, data: Buffer, aad: Buffer): { ciphertext: Buffer; authTag: Buffer } {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, authTag };
}

export function aesGcmDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer, aad: Buffer, authTag: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function createHmac(key: Buffer, data: Buffer, algorithm: string = "sha256"): Buffer {
  return crypto.createHmac(algorithm, key).update(data).digest();
}

export function randomInt(min: number, max: number): number {
  return crypto.randomInt(min, max);
}

export function hkdfDeriveKey(ikm: Buffer, salt: Buffer, info: Buffer, keyLength: number, hash: string = "sha256"): Buffer {
  const prk = crypto.createHmac(hash, salt).update(ikm).digest();
  const hkdf = crypto.createHmac(hash, prk);
  hkdf.update(info);
  return hkdf.digest().slice(0, keyLength);
}

export function rsaSign(privateKey: string, data: Buffer): Buffer {
  const sign = crypto.createSign("SHA256");
  sign.update(data);
  sign.end();
  return sign.sign(privateKey);
}

export function rsaVerify(publicKey: string, signature: Buffer, data: Buffer): boolean {
  const verify = crypto.createVerify("SHA256");
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature);
}

export function randomBytes(length: number): Buffer {
  return crypto.randomBytes(length);
}

export function encryptWithPublicKey(publicKey: string, data: Buffer): Buffer {
  return crypto.publicEncrypt(publicKey, data);
}

export function decryptWithPrivateKey(privateKey: string, encrypted: Buffer): Buffer {
  return crypto.privateDecrypt(privateKey, encrypted);
}

export function deriveKeyPbkdf2(password: Buffer, salt: Buffer, iterations: number, keyLength: number, hash: string = "sha512"): Buffer {
  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, hash);
}

export function scryptKdf(password: Buffer, salt: Buffer, keyLength: number, cost: number = 16384, blockSize: number = 8, parallelization: number = 1): Buffer {
  return crypto.scryptSync(password, salt, keyLength, { N: cost, r: blockSize, p: parallelization });
}

export function hashPassword(password: string, salt: Buffer, algorithm: string = "sha256"): Buffer {
  const hash = crypto.createHash(algorithm);
  hash.update(password);
  hash.update(salt);
  return hash.digest();
}

export function aesCtrEncrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function aesCtrDecrypt(key: Buffer, iv: Buffer, encrypted: Buffer): Buffer {
  const decipher = crypto.createDecipheriv("aes-256-ctr", key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
