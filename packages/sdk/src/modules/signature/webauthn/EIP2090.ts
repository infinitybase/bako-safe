export function EIP2090_encode(
  signatureCompact: Uint8Array,
  parity: number,
): Uint8Array {
  if (signatureCompact[32] >> 7 !== 0) {
    throw new Error(`Non-normalized signature ${signatureCompact}`);
  }
  const v = parity;
  signatureCompact[32] = (v << 7) | (signatureCompact[32] & 0x7f);
  return signatureCompact;
}

export function EIP2090_decode(signatureCompact: Uint8Array): {
  signature: Uint8Array;
  v: number;
} {
  const v = (signatureCompact[32] & 0x80) !== 0;
  signatureCompact[32] = signatureCompact[32] & 0x7f;
  return {
    signature: signatureCompact,
    v: v ? 1 : 0,
  };
}
