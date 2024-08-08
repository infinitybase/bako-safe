export function toBase64(buffer: ArrayBuffer | Uint8Array): string {
  const base64 = String.fromCharCode(...new Uint8Array(buffer));
  return base64.replaceAll('+', '-').replaceAll('/', '_');
}

export function fromBase64(base64: string): ArrayBuffer {
  const t = base64.replaceAll('-', '+').replaceAll('_', '/');
  return Uint8Array.from(window.atob(t), (c) => c.charCodeAt(0)).buffer;
}

export function hexToASCII(hex: string): Uint8Array {
  return Uint8Array.from(
    hex
      .slice(2)
      .split('')
      .map((c: string) => c.charCodeAt(0)),
  );
}

export function findIndex(
  bytes: Uint8Array,
  bytesToSearch: Uint8Array,
): number {
  let acc = 0;
  let index = -1;

  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === bytesToSearch[acc]) {
      if (acc === bytesToSearch.length - 1) {
        index = i - acc;
        break;
      }
      acc += 1;
      continue;
    }
    acc = 0;
  }

  return index;
}
