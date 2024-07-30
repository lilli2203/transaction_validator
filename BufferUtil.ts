import { Readable } from "stream";
import { bigToBufLE } from "./BigIntUtil";

export function lstrip(buf: Buffer, match: number) {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== match) return Buffer.from(buf.slice(i));
  }
  return Buffer.alloc(0);
}

export function rstrip(buf: Buffer, match: number) {
  for (let i = buf.length - 1; i >= 0; i--) {
    if (buf[i] !== match) return Buffer.from(buf.slice(0, i + 1));
  }
  return Buffer.alloc(0);
}

export function combine(...buf: Buffer[]): Buffer {
  return Buffer.concat(buf);
}

export function combineLE(...vals: (number | bigint | Buffer)[]): Buffer {
  const bufs: Buffer[] = [];
  for (const val of vals) {
    if (val instanceof Buffer) {
      bufs.push(val);
    } else {
      bufs.push(bigToBufLE(BigInt(val)));
    }
  }
  return Buffer.concat(bufs);
}

export function bufToStream(buf: Buffer, end: boolean = true): Readable {
  const stream = new Readable();
  stream.push(buf);
  if (end) stream.push(null);
  return stream;
}

export function writeBytes(from: Buffer, to: Buffer, offset: number = 0) {
  for (let i = 0; i < from.length; i++) {
    to.writeUInt8(from[i], offset);
    offset += 1;
  }
}

export function writeBytesReverse(from: Buffer, to: Buffer, offset: number = 0) {
  for (let i = from.length - 1; i >= 0; i--) {
    to.writeUInt8(from[i], offset);
    offset += 1;
  }
}

export function streamFromHex(hex: string) {
  return bufToStream(Buffer.from(hex, "hex"));
}

// Additional functions

export function bufferToHex(buf: Buffer): string {
  return buf.toString("hex");
}

export function hexToBuffer(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

export function bufferToBase64(buf: Buffer): string {
  return buf.toString("base64");
}

export function base64ToBuffer(base64: string): Buffer {
  return Buffer.from(base64, "base64");
}

export function bufferToUtf8(buf: Buffer): string {
  return buf.toString("utf8");
}

export function utf8ToBuffer(utf8: string): Buffer {
  return Buffer.from(utf8, "utf8");
}

export function bufferToBinary(buf: Buffer): string {
  return [...buf].map(byte => byte.toString(2).padStart(8, "0")).join("");
}

export function binaryToBuffer(binary: string): Buffer {
  const bytes = binary.match(/.{1,8}/g)?.map(byte => parseInt(byte, 2));
  if (!bytes) throw new Error("Invalid binary string");
  return Buffer.from(bytes);
}

export function randomBuffer(length: number): Buffer {
  return crypto.randomBytes(length);
}

export function bufferToHexStream(buf: Buffer): Readable {
  const hexString = bufferToHex(buf);
  return bufToStream(Buffer.from(hexString, "utf8"));
}

export function streamToBuffer(stream: Readable): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on("data", chunk => chunks.push(chunk));
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", err => reject(err));
  });
}

export function readBytesFromStream(stream: Readable, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytesRead = 0;
    stream.on("data", chunk => {
      chunks.push(chunk);
      bytesRead += chunk.length;
      if (bytesRead >= length) {
        stream.pause();
        resolve(Buffer.concat(chunks, length));
      }
    });
    stream.on("end", () => resolve(Buffer.concat(chunks, length)));
    stream.on("error", err => reject(err));
  });
}

export function bufferToStreamWithSize(buf: Buffer): Readable {
  const sizeBuffer = Buffer.alloc(4);
  sizeBuffer.writeUInt32BE(buf.length, 0);
  return bufToStream(Buffer.concat([sizeBuffer, buf]));
}

export function streamToBufferWithSize(stream: Readable): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sizeBuffer = Buffer.alloc(4);
    let bytesRead = 0;
    stream.read(sizeBuffer, 0, 4);
    const size = sizeBuffer.readUInt32BE(0);
    const chunks: Buffer[] = [];
    stream.on("data", chunk => {
      chunks.push(chunk);
      bytesRead += chunk.length;
      if (bytesRead >= size) {
        stream.pause();
        resolve(Buffer.concat(chunks, size));
      }
    });
    stream.on("end", () => resolve(Buffer.concat(chunks, size)));
    stream.on("error", err => reject(err));
  });
}

export function combineBuffers(buffers: Buffer[]): Buffer {
  return Buffer.concat(buffers);
}

export function splitBuffer(buf: Buffer, size: number): Buffer[] {
  const result: Buffer[] = [];
  for (let i = 0; i < buf.length; i += size) {
    result.push(buf.slice(i, i + size));
  }
  return result;
}

export function xorBuffers(buf1: Buffer, buf2: Buffer): Buffer {
  if (buf1.length !== buf2.length) throw new Error("Buffers must be of the same length");
  const result = Buffer.alloc(buf1.length);
  for (let i = 0; i < buf1.length; i++) {
    result[i] = buf1[i] ^ buf2[i];
  }
  return result;
}

export function createZeroBuffer(length: number): Buffer {
  return Buffer.alloc(length, 0);
}

export function createOneBuffer(length: number): Buffer {
  return Buffer.alloc(length, 1);
}

export function incrementBuffer(buf: Buffer): Buffer {
  const result = Buffer.from(buf);
  for (let i = buf.length - 1; i >= 0; i--) {
    if (result[i] < 255) {
      result[i]++;
      break;
    } else {
      result[i] = 0;
    }
  }
  return result;
}

export function decrementBuffer(buf: Buffer): Buffer {
  const result = Buffer.from(buf);
  for (let i = buf.length - 1; i >= 0; i--) {
    if (result[i] > 0) {
      result[i]--;
      break;
    } else {
      result[i] = 255;
    }
  }
  return result;
}

export function isBufferEmpty(buf: Buffer): boolean {
  return buf.every(byte => byte === 0);
}
