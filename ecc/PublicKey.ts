import { ec } from "elliptic";
import { createHash } from "crypto";

export class PublicKey {
  private ec: ec;
  private key: ec.KeyPair;

  constructor(publicKeyHex: string | Buffer) {
    this.ec = new ec("secp256k1");
    this.key = this.ec.keyFromPublic(publicKeyHex, "hex");
  }

  verify(signature: any, msgHash: any): boolean {
    return this.key.verify(msgHash, signature);
  }

  static fromPrivateKey(privateKeyHex: string): PublicKey {
    const ecInstance = new ec("secp256k1");
    const keyPair = ecInstance.keyFromPrivate(privateKeyHex, "hex");
    const publicKeyHex = keyPair.getPublic().encode("hex", true);
    return new PublicKey(publicKeyHex);
  }

  toCompressed(): string {
    return this.key.getPublic().encode("hex", true);
  }

  toUncompressed(): string {
    return this.key.getPublic().encode("hex", false);
  }
  
  toBuffer(): Buffer {
    return Buffer.from(this.toCompressed(), "hex");
  }

  static hashMessage(message: string | Buffer): Buffer {
    return createHash("sha256").update(message).digest();
  }

  verifyMessage(message: string | Buffer, signature: any): boolean {
    const msgHash = PublicKey.hashMessage(message);
    return this.verify(signature, msgHash);
  }

  static recoverPublicKey(msgHash: Buffer, signature: any): PublicKey {
    const ecInstance = new ec("secp256k1");
    const key = ecInstance.recoverPubKey(msgHash, signature, signature.recoveryParam);
    const publicKeyHex = key.encode("hex", true);
    return new PublicKey(publicKeyHex);
  }

  static generatePrivateKey(): string {
    const ecInstance = new ec("secp256k1");
    const keyPair = ecInstance.genKeyPair();
    return keyPair.getPrivate().toString("hex");
  }

  toPEM(): string {
    const publicKey = this.toUncompressed();
    const pemKey = `-----BEGIN PUBLIC KEY-----\n${Buffer.from(publicKey, "hex").toString("base64")}\n-----END PUBLIC KEY-----`;
    return pemKey;
  }

  static fromPEM(pemKey: string): PublicKey {
    const base64Key = pemKey
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replace(/\n/g, "");
    const publicKeyHex = Buffer.from(base64Key, "base64").toString("hex");
    return new PublicKey(publicKeyHex);
  }
}

const privateKey = PublicKey.generatePrivateKey();
console.log(`Private Key: ${privateKey}`);

const publicKey = PublicKey.fromPrivateKey(privateKey);
console.log(`Public Key (Compressed): ${publicKey.toCompressed()}`);
console.log(`Public Key (Uncompressed): ${publicKey.toUncompressed()}`);

const pemKey = publicKey.toPEM();
console.log(`Public Key (PEM): ${pemKey}`);

const importedPublicKey = PublicKey.fromPEM(pemKey);
console.log(`Imported Public Key: ${importedPublicKey.toCompressed()}`);

const message = "Hello, blockchain!";
const msgHash = PublicKey.hashMessage(message);

const signature = publicKey.key.sign(msgHash);
const isValid = publicKey.verifyMessage(message, signature);
console.log(`Signature is valid: ${isValid}`);

const recoveredPublicKey = PublicKey.recoverPublicKey(msgHash, signature);
console.log(`Recovered Public Key: ${recoveredPublicKey.toCompressed()}`);
