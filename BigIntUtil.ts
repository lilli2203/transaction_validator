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

export function numberToBig(num: number): bigint {
  return BigInt(num);
}

export function bigToNumber(big: bigint): number {
  return Number(big);
}

export function isPowerOfTwoBig(num: bigint): boolean {
  return (num & (num - BigInt(1))) === BigInt(0) && num !== BigInt(0);
}

export function bitLengthBig(num: bigint): number {
  return num.toString(2).length;
}

export function bufToBase64(buf: Buffer): string {
  return buf.toString('base64');
}

export function base64ToBuf(base64: string): Buffer {
  return Buffer.from(base64, 'base64');
}

export function leftShiftBig(num: bigint, bits: number): bigint {
  return num << BigInt(bits);
}

export function rightShiftBig(num: bigint, bits: number): bigint {
  return num >> BigInt(bits);
}

export function stringToBig(str: string, base: number = 10): bigint {
  return BigInt(parseInt(str, base));
}

export function bigToString(num: bigint, base: number = 10): string {
  return num.toString(base);
}

export function xorBig(a: bigint, b: bigint): bigint {
  return a ^ b;
}

export function andBig(a: bigint, b: bigint): bigint {
  return a & b;
}

export function orBig(a: bigint, b: bigint): bigint {
  return a | b;
}

export function notBig(a: bigint): bigint {
  return ~a;
}

export function isNegativeBig(num: bigint): boolean {
  return num < BigInt(0);
}

export function isPositiveBig(num: bigint): boolean {
  return num > BigInt(0);
}

export function isZeroBig(num: bigint): boolean {
  return num === BigInt(0);
}

export function minBig(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

export function maxBig(a: bigint, b: bigint): bigint {
  return a > b ? a : b;
}

export function randomBigRange(min: bigint, max: bigint): bigint {
  const range = max - min + BigInt(1);
  const randomValue = randomBig(range.toString(2).length);
  return min + (randomValue % range);
}

export function modExpBig(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = BigInt(1);
  base = base % mod;
  while (exp > 0) {
    if (exp % BigInt(2) === BigInt(1)) {
      result = (result * base) % mod;
    }
    exp = exp >> BigInt(1);
    base = (base * base) % mod;
  }
  return result;
}

export function bigToByteArray(num: bigint, byteLength: number = Math.ceil(num.toString(2).length / 8)): Buffer {
  const hex = num.toString(16).padStart(byteLength * 2, '0');
  return Buffer.from(hex, 'hex');
}

export function byteArrayToBig(buf: Buffer): bigint {
  return BigInt('0x' + buf.toString('hex'));
}

export function padBuffer(buf: Buffer, length: number, padding: number = 0): Buffer {
  if (buf.length >= length) return buf;
  const padBuf = Buffer.alloc(length - buf.length, padding);
  return Buffer.concat([padBuf, buf]);
}

export function concatBuffers(...buffers: Buffer[]): Buffer {
  return Buffer.concat(buffers);
}

export function rotateLeftBuffer(buf: Buffer, bits: number): Buffer {
  const byteShift = Math.floor(bits / 8);
  const bitShift = bits % 8;
  const rotated = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    rotated[i] = (buf[(i + byteShift) % buf.length] << bitShift) | (buf[(i + byteShift + 1) % buf.length] >> (8 - bitShift));
  }
  return rotated;
}

export function rotateRightBuffer(buf: Buffer, bits: number): Buffer {
  const byteShift = Math.floor(bits / 8);
  const bitShift = bits % 8;
  const rotated = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    rotated[i] = (buf[(i - byteShift + buf.length) % buf.length] >> bitShift) | (buf[(i - byteShift - 1 + buf.length) % buf.length] << (8 - bitShift));
  }
  return rotated;
}

export function randomBuffer(length: number): Buffer {
  return crypto.randomBytes(length);
}

export function sha256Buffer(buf: Buffer): Buffer {
  return crypto.createHash('sha256').update(buf).digest();
}

export function md5Buffer(buf: Buffer): Buffer {
  return crypto.createHash('md5').update(buf).digest();
}

export function utf8ToBase64(str: string): string {
  return Buffer.from(str, 'utf8').toString('base64');
}

export function base64ToUtf8(base64: string): string {
  return Buffer.from(base64, 'base64').toString('utf8');
}

export function splitBuffer(buf: Buffer, chunkSize: number): Buffer[] {
  const chunks: Buffer[] = [];
  for (let i = 0; i < buf.length; i += chunkSize) {
    chunks.push(buf.slice(i, i + chunkSize));
  }
  return chunks;
}

export function mergeBuffers(buffers: Buffer[]): Buffer {
  return Buffer.concat(buffers);
}

export function bufferToByteArray(buf: Buffer): number[] {
  return [...buf];
}

export function byteArrayToBuffer(arr: number[]): Buffer {
  return Buffer.from(arr);
}
