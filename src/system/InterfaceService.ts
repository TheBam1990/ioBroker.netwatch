import os from "node:os";
import fs from "node:fs/promises";
import type { InterfaceInfo } from "../types";
async function readNumber(file: string): Promise<number> {
  try {
    return Number((await fs.readFile(file, "utf8")).trim()) || 0;
  } catch {
    return 0;
  }
}
export async function listInterfaces(): Promise<InterfaceInfo[]> {
  const all = os.networkInterfaces();
  return Promise.all(
    Object.entries(all).map(async ([name, addresses]) => ({
      name,
      ipv4: (addresses || [])
        .filter((a) => a.family === "IPv4")
        .map((a) => a.address),
      ipv6: (addresses || [])
        .filter((a) => a.family === "IPv6")
        .map((a) => a.address),
      mac: (addresses || []).find((a) => a.mac && a.mac !== "00:00:00:00:00:00")
        ?.mac,
      status: await fs
        .readFile(`/sys/class/net/${name}/operstate`, "utf8")
        .then((x) => x.trim())
        .catch(() => "unknown"),
      rxBytes: await readNumber(`/sys/class/net/${name}/statistics/rx_bytes`),
      txBytes: await readNumber(`/sys/class/net/${name}/statistics/tx_bytes`),
    })),
  );
}
