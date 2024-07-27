import { Script } from "../Script";
import { OpCode } from "../operations/opcode";
import { createHash } from "crypto";

export function p2pkhLock(h160: Buffer): Script {
  return new Script([
    OpCode.OP_DUP,
    OpCode.OP_HASH160,
    h160,
    OpCode.OP_EQUALVERIFY,
    OpCode.OP_CHECKSIG,
  ]);
}

export function p2shLock(h160: Buffer): Script {
  return new Script([
    OpCode.OP_HASH160,
    h160,
    OpCode.OP_EQUAL,
  ]);
}

export function p2wpkhLock(h160: Buffer): Script {
  return new Script([
    OpCode.OP_0,
    h160,
  ]);
}

export function parseScript(buffer: Buffer): Script {
  return new Script([...buffer]);
}

export function doubleSha256(buffer: Buffer): Buffer {
  return createHash("sha256").update(createHash("sha256").update(buffer).digest()).digest();
}

export function hash160(buffer: Buffer): Buffer {
  const sha256Hash = createHash("sha256").update(buffer).digest();
  return createHash("ripemd160").update(sha256Hash).digest();
}

export function publicKeyToP2PKHAddress(publicKey: Buffer): string {
  const h160 = hash160(publicKey);
  return `1${h160.toString('hex')}`;
}

export function scriptToP2SHAddress(script: Script): string {
  const h160 = hash160(script.serialize());
  return `3${h160.toString('hex')}`;
}

export function publicKeyToP2WPKHAddress(publicKey: Buffer): string {
  const h160 = hash160(publicKey);
  return `bc1${h160.toString('hex')}`;
}

const publicKey = Buffer.from('04a34f...', 'hex'); 
const p2pkhScript = p2pkhLock(hash160(publicKey));
console.log(`P2PKH Script: ${p2pkhScript.toString()}`);

const redeemScript = new Script([OpCode.OP_RETURN, Buffer.from('Hello, world!')]);
const p2shScript = p2shLock(hash160(redeemScript.serialize()));
console.log(`P2SH Script: ${p2shScript.toString()}`);

const p2wpkhScript = p2wpkhLock(hash160(publicKey));
console.log(`P2WPKH Script: ${p2wpkhScript.toString()}`);

const p2pkhAddress = publicKeyToP2PKHAddress(publicKey);
console.log(`P2PKH Address: ${p2pkhAddress}`);

const p2shAddress = scriptToP2SHAddress(redeemScript);
console.log(`P2SH Address: ${p2shAddress}`);

const p2wpkhAddress = publicKeyToP2WPKHAddress(publicKey);
console.log(`P2WPKH Address: ${p2wpkhAddress}`);
