import { combine } from "./util/BufferUtil";
import { bigToBufLE, bigFromBufLE } from "./util/BigIntUtil";
import { Script } from "./Script";

export class TxOut {
  public amount: bigint;
  public scriptPubKey: Script;

  constructor(amount: bigint, scriptPubKey: Script) {
    this.amount = amount;
    this.scriptPubKey = scriptPubKey;
  }

  public toString(): string {
    return `${this.amount}:${this.scriptPubKey}`;
  }

  public serialize(): Buffer {
    return combine(bigToBufLE(this.amount, 8), this.scriptPubKey.serialize());
  }

  public static parse(buffer: Buffer): TxOut {
    const amount = bigFromBufLE(buffer.slice(0, 8));
    const scriptPubKey = Script.parse(buffer.slice(8));
    return new TxOut(amount, scriptPubKey);
  }

  public isP2PKH(): boolean {
    return this.scriptPubKey.isP2PKH();
  }

  public isP2WPKH(): boolean {
    return this.scriptPubKey.isP2WPKH();
  }

  public equals(other: TxOut): boolean {
    return (
      this.amount === other.amount &&
      this.scriptPubKey.equals(other.scriptPubKey)
    );
  }
}

// Example utility functions for Buffer and BigInt manipulation

import { Buffer } from "buffer";

export function combine(...buffers: Buffer[]): Buffer {
  return Buffer.concat(buffers);
}

export function bigToBufLE(num: bigint, length: number): Buffer {
  const hex = num.toString(16).padStart(length * 2, "0");
  const buffer = Buffer.from(hex, "hex");
  return buffer.reverse();
}

export function bigFromBufLE(buffer: Buffer): bigint {
  return BigInt(`0x${buffer.reverse().toString("hex")}`);
}

// Script class modifications

import { Buffer } from "buffer";
import { OpCode } from "./operations/opcode";
import { decodeNum, encodeNum } from "./util/BigIntUtil";

export class Script {
  private commands: (OpCode | Buffer)[];

  constructor(commands: (OpCode | Buffer)[] = []) {
    this.commands = commands;
  }

  public toString(): string {
    return this.commands.map((cmd) => cmd.toString()).join(" ");
  }

  public serialize(): Buffer {
    const parts = this.commands.map((cmd) =>
      Buffer.isBuffer(cmd) ? Buffer.concat([Buffer.from([cmd.length]), cmd]) : Buffer.from([cmd])
    );
    return Buffer.concat(parts);
  }

  public static parse(buffer: Buffer): Script {
    const commands: (OpCode | Buffer)[] = [];
    let i = 0;

    while (i < buffer.length) {
      const opcode = buffer[i];

      if (opcode <= OpCode.OP_PUSHDATA4) {
        let size = opcode;
        i += 1;

        if (opcode === OpCode.OP_PUSHDATA1) {
          size = buffer[i];
          i += 1;
        } else if (opcode === OpCode.OP_PUSHDATA2) {
          size = buffer.readUInt16LE(i);
          i += 2;
        } else if (opcode === OpCode.OP_PUSHDATA4) {
          size = buffer.readUInt32LE(i);
          i += 4;
        }

        commands.push(buffer.slice(i, i + size));
        i += size;
      } else {
        commands.push(opcode);
        i += 1;
      }
    }

    return new Script(commands);
  }

  public isP2PKH(): boolean {
    return (
      this.commands.length === 5 &&
      this.commands[0] === OpCode.OP_DUP &&
      this.commands[1] === OpCode.OP_HASH160 &&
      Buffer.isBuffer(this.commands[2]) &&
      this.commands[2].length === 20 &&
      this.commands[3] === OpCode.OP_EQUALVERIFY &&
      this.commands[4] === OpCode.OP_CHECKSIG
    );
  }

  public isP2WPKH(): boolean {
    return (
      this.commands.length === 2 &&
      this.commands[0] === OpCode.OP_0 &&
      Buffer.isBuffer(this.commands[1]) &&
      this.commands[1].length === 20
    );
  }

  public equals(other: Script): boolean {
    if (this.commands.length !== other.commands.length) {
      return false;
    }

    for (let i = 0; i < this.commands.length; i++) {
      if (Buffer.isBuffer(this.commands[i]) && Buffer.isBuffer(other.commands[i])) {
        if (!this.commands[i].equals(other.commands[i])) {
          return false;
        }
      } else if (this.commands[i] !== other.commands[i]) {
        return false;
      }
    }

    return true;
  }
}


const scriptPubKey = new Script([
  OpCode.OP_DUP,
  OpCode.OP_HASH160,
  Buffer.from("89abcdef0123456789abcdef0123456789abcdef", "hex"),
  OpCode.OP_EQUALVERIFY,
  OpCode.OP_CHECKSIG,
]);

const txOut = new TxOut(1000n, scriptPubKey);

const serializedTxOut = txOut.serialize();
console.log("Serialized TxOut:", serializedTxOut.toString("hex"));

const parsedTxOut = TxOut.parse(serializedTxOut);
console.log("Parsed TxOut:", parsedTxOut.toString());

console.log("Is P2PKH:", parsedTxOut.isP2PKH());
console.log("Is P2WPKH:", parsedTxOut.isP2WPKH());
console.log("Equals:", txOut.equals(parsedTxOut));
