import path from "node:path";

export const INTERFACE_PATTERN = /^[a-zA-Z0-9_.:@-]{1,64}$/;
export function validateInterface(value: string): string {
  if (!INTERFACE_PATTERN.test(value)) {
    throw new Error("Ungültiger Interface-Name");
  }
  return value;
}
export function validateLimit(
  value: unknown,
  min: number,
  max: number,
  name: string,
): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${name} muss zwischen ${min} und ${max} liegen`);
  }
  return n;
}
export function safeCaptureName(value: string): string {
  const name = path.basename(String(value));
  if (
    name !== value ||
    !/^[-a-zA-Z0-9_. ]{1,120}\.(pcap|pcapng)$/i.test(name)
  ) {
    throw new Error("Ungültiger Capture-Dateiname");
  }
  return name;
}
export function resolveCapturePath(root: string, name: string): string {
  const safe = safeCaptureName(name),
    resolved = path.resolve(root, safe),
    base = path.resolve(root) + path.sep;
  if (!resolved.startsWith(base)) {
    throw new Error("Pfad außerhalb des Capture-Verzeichnisses");
  }
  return resolved;
}
export function validateFilter(value: string, max = 2048): string {
  const filter = String(value || "").trim();
  if (filter.length > max || filter.includes("\0") || /[\r\n]/.test(filter)) {
    throw new Error("Filter enthält ungültige Zeichen oder ist zu lang");
  }
  return filter;
}
