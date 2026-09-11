import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
const execFileAsync = promisify(execFile);
export interface DependencyStatus {
  available: boolean;
  version?: string;
  error?: string;
}
export interface DependencyReport {
  ready: boolean;
  platform: string;
  tshark: DependencyStatus;
  dumpcap: DependencyStatus;
  capturePermission: DependencyStatus;
  instructions: {
    install: string[];
    permissions: string[];
    verify: string[];
  };
}
export async function checkBinary(
  binary: "tshark" | "dumpcap",
): Promise<DependencyStatus> {
  try {
    const { stdout, stderr } = await execFileAsync(binary, ["--version"], {
      timeout: 8000,
      maxBuffer: 256_000,
    });
    return {
      available: true,
      version: `${stdout}\n${stderr}`
        .split("\n")
        .find((line) => line.trim())
        ?.trim(),
    };
  } catch (error) {
    return {
      available: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
async function checkCapturePermission(): Promise<DependencyStatus> {
  try {
    const { stdout, stderr } = await execFileAsync("dumpcap", ["-D"], {
      timeout: 8000,
      maxBuffer: 256_000,
    });
    const interfaces = `${stdout}\n${stderr}`
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    return interfaces.length
      ? {
          available: true,
          version: `${interfaces.length} Capture-Interfaces verfügbar`,
        }
      : { available: false, error: "dumpcap findet keine Interfaces" };
  } catch (error: any) {
    return {
      available: false,
      error: String(error?.stderr || error?.message || error).trim(),
    };
  }
}
export async function checkDependencies(): Promise<DependencyReport> {
  const [tshark, dumpcap] = await Promise.all([
    checkBinary("tshark"),
    checkBinary("dumpcap"),
  ]);
  const capturePermission = dumpcap.available
    ? await checkCapturePermission()
    : { available: false, error: "dumpcap ist nicht installiert" };
  const instructions = {
    install: ["sudo apt update", "sudo apt install -y tshark"],
    permissions: [
      "sudo dpkg-reconfigure wireshark-common",
      "sudo usermod -aG wireshark iobroker",
      "sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap",
      "sudo systemctl restart iobroker",
    ],
    verify: ["getcap /usr/bin/dumpcap", "sudo -u iobroker dumpcap -D"],
  };
  return {
    ready: tshark.available && dumpcap.available && capturePermission.available,
    platform: `${os.platform()} ${os.release()} (${os.arch()})`,
    tshark,
    dumpcap,
    capturePermission,
    instructions,
  };
}
export async function validateDisplayFilter(
  filter: string,
): Promise<{ valid: boolean; error?: string }> {
  if (!filter) {
    return { valid: true };
  }
  const testFile = path.join(
    os.tmpdir(),
    `netwatch-filter-${process.pid}-${crypto.randomBytes(4).toString("hex")}.pcap`,
  );
  try {
    // A valid, empty classic-PCAP header. /dev/null is unsuitable because
    // tshark reports an invalid capture before it can validate the filter.
    await fs.writeFile(
      testFile,
      Buffer.from("d4c3b2a1020004000000000000000000ffff000001000000", "hex"),
      { mode: 0o600 },
    );
    await execFileAsync("tshark", ["-Y", filter, "-r", testFile], {
      timeout: 8000,
      maxBuffer: 256_000,
    });
    return { valid: true };
  } catch (error: any) {
    const message = String(error?.stderr || error?.message || error)
      .replace(/^tshark:\s*/, "")
      .trim();
    return {
      valid: false,
      error: message || "Ungültiger Wireshark-Display-Filter",
    };
  } finally {
    await fs.unlink(testFile).catch(() => undefined);
  }
}
