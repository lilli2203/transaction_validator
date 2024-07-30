export function bigToBuf(num: bigint, len?: number): Buffer {
  let str = num.toString(16);
  if (len) str = str.padStart(len * 2, "0");
  else if (str.length % 2 === 1) str = "0" + str;
  return Buffer.from(str, "hex");
}

export function bigToBufLE(num: bigint, len?: number): Buffer {
  return bigToBuf(num, len).reverse();
}

export function bigFromBuf(buf: Buffer): bigint {
  return BigInt("0x" + buf.toString("hex"));
}

export function bigFromBufLE(buf: Buffer): bigint {
  return bigFromBuf(Buffer.from(buf).reverse());
}

export function bufToHex(buf: Buffer): string {
  return buf.toString("hex");
}


export function hexToBuf(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}


export function bufToBinary(buf: Buffer): string {
  return [...buf].map(byte => byte.toString(2).padStart(8, "0")).join("");
}


export function binaryToBuf(bin: string): Buffer {
  const bytes = bin.match(/.{1,8}/g)?.map(byte => parseInt(byte, 2));
  if (!bytes) throw new Error("Invalid binary string");
  return Buffer.from(bytes);
}


export function isValidHex(hex: string): boolean {
  return /^[0-9a-fA-F]*$/.test(hex);
}


export function isValidBinary(bin: string): boolean {
  return /^[01]*$/.test(bin);
}


export function bigToBinary(num: bigint): string {
  return num.toString(2);
}


export function binaryToBig(bin: string): bigint {
  if (!isValidBinary(bin)) throw new Error("Invalid binary string");
  return BigInt("0b" + bin);
}


export function bigToDecimal(num: bigint): string {
  return num.toString(10);
}


export function decimalToBig(dec: string): bigint {
  if (!/^\d+$/.test(dec)) throw new Error("Invalid decimal string");
  return BigInt(dec);
}


export function addBig(a: bigint, b: bigint): bigint {
  return a + b;
}


export function subtractBig(a: bigint, b: bigint): bigint {
  return a - b;
}


export function multiplyBig(a: bigint, b: bigint): bigint {
  return a * b;
}


export function divideBig(a: bigint, b: bigint): bigint {
  if (b === BigInt(0)) throw new Error("Division by zero");
  return a / b;
}


export function modBig(a: bigint, b: bigint): bigint {
  return a % b;
}


export function powBig(base: bigint, exponent: bigint): bigint {
  return base ** exponent;
}


export function gcdBig(a: bigint, b: bigint): bigint {
  while (b !== BigInt(0)) {
    const temp = b;
    b = a % b;
    a = temp;
  }
  return a;
}


export function lcmBig(a: bigint, b: bigint): bigint {
  return (a * b) / gcdBig(a, b);
}


export function compareBig(a: bigint, b: bigint): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}


export function isEvenBig(num: bigint): boolean {
  return num % BigInt(2) === BigInt(0);
}


export function isOddBig(num: bigint): boolean {
  return num % BigInt(2) !== BigInt(0);
}


export function absBig(num: bigint): bigint {
  return num < BigInt(0) ? -num : num;
}


export function bigToLEBuffer(num: bigint, len?: number): Buffer {
  return bigToBuf(num, len).reverse();
}


export function leBufferToBig(buf: Buffer): bigint {
  return bigFromBuf(buf.reverse());
}

export function isPrimeBig(num: bigint): boolean {
  if (num <= BigInt(1)) return false;
  if (num <= BigInt(3)) return true;
  if (num % BigInt(2) === BigInt(0) || num % BigInt(3) === BigInt(0)) return false;
  for (let i = BigInt(5); i * i <= num; i += BigInt(6)) {
    if (num % i === BigInt(0) || num % (i + BigInt(2)) === BigInt(0)) return false;
  }
  return true;
}

export function randomBig(bits: number): bigint {
  const bytes = Math.ceil(bits / 8);
  const buf = crypto.randomBytes(bytes);
  buf[0] = buf[0] & (2 ** (bits % 8) - 1); 
  return bigFromBuf(buf);
}

export function bufToUtf8(buf: Buffer): string {
  return buf.toString('utf8');
}

export function utf8ToBuf(str: string): Buffer {
  return Buffer.from(str, 'utf8');
}
