import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
export class TsharkService {
  async detail(file: string, id: number): Promise<unknown> {
    const stdout = await this.run([
      "-n",
      "-r",
      file,
      "-Y",
      `frame.number == ${id}`,
      "-c",
      "1",
      "-T",
      "json",
    ]);
    return JSON.parse(stdout)[0] || null;
  }
  async hex(file: string, id: number): Promise<string> {
    const stdout = await this.run([
      "-n",
      "-r",
      file,
      "-Y",
      `frame.number == ${id}`,
      "-c",
      "1",
      "-x",
    ]);
    return stdout;
  }
  async analyze(file: string, filter = "", limit = 10000): Promise<string> {
    const args = ["-n", "-r", file];
    if (filter) {
      args.push("-Y", filter);
    }
    args.push("-c", String(limit), ...this.fastArgs());
    return this.run(args);
  }

  private async run(args: string[]): Promise<string> {
    const output = path.join(
      os.tmpdir(),
      `netwatch-tshark-${crypto.randomBytes(8).toString("hex")}.out`,
    );
    const fd = fs.openSync(output, "wx", 0o600);
    let stderr = "";
    try {
      await new Promise<void>((resolve, reject) => {
        const child = spawn("tshark", args, {
          stdio: ["ignore", fd, "pipe"],
        });
        child.stderr!.on("data", (data) => {
          stderr = `${stderr}${String(data)}`.slice(-8000);
        });
        child.once("error", reject);
        child.once("exit", (code, signal) => {
          if (code === 0) resolve();
          else
            reject(
              new Error(stderr.trim() || `tshark beendet (${code ?? signal})`),
            );
        });
      });
      return await fs.promises.readFile(output, "utf8");
    } finally {
      fs.closeSync(fd);
      await fs.promises.unlink(output).catch(() => undefined);
    }
  }
  fastArgs(): string[] {
    return [
      "-T",
      "fields",
      "-E",
      "separator=/t",
      "-E",
      "quote=d",
      "-E",
      "occurrence=f",
      "-e",
      "frame.number",
      "-e",
      "frame.time_epoch",
      "-e",
      "frame.len",
      "-e",
      "frame.cap_len",
      "-e",
      "eth.src",
      "-e",
      "eth.dst",
      "-e",
      "ip.src",
      "-e",
      "ip.dst",
      "-e",
      "ipv6.src",
      "-e",
      "ipv6.dst",
      "-e",
      "tcp.srcport",
      "-e",
      "tcp.dstport",
      "-e",
      "udp.srcport",
      "-e",
      "udp.dstport",
      "-e",
      "_ws.col.Protocol",
      "-e",
      "_ws.col.Info",
      "-e",
      "frame.protocols",
      "-e",
      "data.data",
    ];
  }
}
