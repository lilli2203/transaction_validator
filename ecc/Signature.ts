import { bigToBuf, bigFromBuf } from "../util/BigIntUtil";
import * as bufutil from "../util/BufferUtil";
import { ec as EC } from "elliptic";
import { createHash } from "crypto";

const ec = new EC("secp256k1");

export class Signature {
  constructor(readonly r: bigint, readonly s: bigint) {}

  public static parse(buffer: Buffer): Signature {
    let pos = 0;

    const prefix = buffer.readUInt8(pos);
    if (prefix !== 0x30) {
      throw new Error("Bad signature");
    }
    pos += 1;

    const len = buffer.readUInt8(pos);
    if (len + 2 !== buffer.length) {
      throw new Error("Bad signature length");
    }
    pos += 1;
    let marker = buffer.readUInt8(pos);
    if (marker !== 0x02) {
      throw new Error("Bad signature");
    }
    pos += 1;
    const rlen = buffer.readUInt8(pos);
    pos += 1;

    const r = bigFromBuf(buffer.slice(pos, pos + rlen));
    pos += rlen;

    marker = buffer.readUInt8(pos);
    if (marker !== 0x02) {
      throw new Error("Bad signature");
    }
    pos += 1;

    const slen = buffer.readUInt8(pos);
    pos += 1;

    const s = bigFromBuf(buffer.slice(pos, pos + slen));
    pos += slen;

    return new Signature(r, s);
  }

  public toString(): string {
    return `Signature_${this.r}_${this.s}`;
  }

  public der(): Buffer {
    const encodePart = (v: bigint) => {
      let bytes = bigToBuf(v);

      bytes = bufutil.lstrip(bytes, 0x00);

      if (bytes[0] & 0x80) {
        bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
      }

      return Buffer.concat([Buffer.from([2, bytes.length]), bytes]);
    };

    const r = encodePart(this.r);
    const s = encodePart(this.s);

    return Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]);
  }

  public verify(message: string | Buffer, publicKey: string | Buffer): boolean {
    const msgHash = Signature.hashMessage(message);
    const key = ec.keyFromPublic(publicKey, "hex");
    return key.verify(msgHash, { r: bigToBuf(this.r), s: bigToBuf(this.s) });
  }

  public static sign(message: string | Buffer, privateKey: string): Signature {
    const msgHash = Signature.hashMessage(message);
    const key = ec.keyFromPrivate(privateKey, "hex");
    const sig = key.sign(msgHash);
    return new Signature(bigFromBuf(sig.r.toArrayLike(Buffer)), bigFromBuf(sig.s.toArrayLike(Buffer)));
  }

  public static hashMessage(message: string | Buffer): Buffer {
    return createHash("sha256").update(message).digest();
  }

  public toHex(): string {
    return this.der().toString("hex");
  }

  public toBuffer(): Buffer {
    return this.der();
  }

  public static fromHex(hex: string): Signature {
    return Signature.parse(Buffer.from(hex, "hex"));
  }
  public split(): { r: Buffer; s: Buffer } {
    return {
      r: bigToBuf(this.r),
      s: bigToBuf(this.s),
    };
  }
  public static combine(r: Buffer, s: Buffer): Signature {
    return new Signature(bigFromBuf(r), bigFromBuf(s));
  }
}
const privateKey = ec.genKeyPair().getPrivate("hex");
const message = "Hello, blockchain!";
const signature = Signature.sign(message, privateKey);
console.log(`Signature: ${signature.toHex()}`);
const publicKey = ec.keyFromPrivate(privateKey).getPublic("hex");
const isValid = signature.verify(message, publicKey);
console.log(`Signature is valid: ${isValid}`);
const signatureBuffer = signature.toBuffer();
const parsedSignature = Signature.parse(signatureBuffer);
console.log(`Parsed Signature: ${parsedSignature.toHex()}`);
const { r, s } = signature.split();
const combinedSignature = Signature.combine(r, s);
console.log(`Combined Signature: ${combinedSignature.toHex()}`);
