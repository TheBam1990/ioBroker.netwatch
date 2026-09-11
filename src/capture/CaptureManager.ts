import { EventEmitter } from "node:events";
import type { ChildProcess } from "node:child_process";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import type { CaptureSession } from "../types";
import { validateFilter, validateInterface } from "../security/InputValidator";
import { parseFieldsLine } from "../tshark/TsharkParser";
import type { TsharkService } from "../tshark/TsharkService";

export class CaptureManager extends EventEmitter {
  private capture?: ChildProcess;
  private eventPath?: string;
  private eventTimer?: NodeJS.Timeout;
  private eventOffset = 0;
  private eventRemainder = "";
  private draining = false;
  private lastPacketId = 0;
  private session?: CaptureSession;
  private stopping = false;
  private processError = "";

  constructor(
    private directory: string,
    private tsharkService: TsharkService,
  ) {
    super();
  }

  current(): CaptureSession | undefined {
    return this.session ? { ...this.session } : undefined;
  }

  async start(
    iface: string,
    captureFilter = "",
    displayFilter = "",
  ): Promise<CaptureSession> {
    if (this.capture) {
      throw new Error("Capture läuft bereits");
    }
    validateInterface(iface);
    validateFilter(captureFilter);
    validateFilter(displayFilter);
    await fs.promises.mkdir(this.directory, { recursive: true, mode: 0o750 });
    const id = `${new Date().toISOString().replace(/[:.]/g, "-")}-${crypto.randomBytes(3).toString("hex")}`;
    const filePath = path.join(this.directory, `${id}.pcapng`);
    this.session = {
      id,
      startedAt: Date.now(),
      interface: iface,
      captureFilter,
      displayFilter,
      packetCount: 0,
      byteCount: 0,
      filePath,
      status: "running",
    };
    this.stopping = false;
    this.processError = "";

    this.eventPath = path.join(this.directory, `.${id}.events`);
    await fs.promises.writeFile(this.eventPath, "", { mode: 0o600 });
    this.eventOffset = 0;
    this.eventRemainder = "";
    this.lastPacketId = 0;
    const args = ["-q", "-i", iface, "-w", filePath];
    if (captureFilter) {
      args.push("-f", captureFilter);
    }
    this.capture = spawn("dumpcap", args, {
      stdio: ["ignore", "ignore", "pipe"],
      detached: true,
    });
    const child = this.capture;
    this.eventTimer = setInterval(
      () => void this.analyzeSnapshot(iface, displayFilter),
      500,
    );
    child.stderr!.on("data", (data) => {
      const message = String(data);
      this.processError = `${this.processError}${message}`.slice(-4000);
      this.emit("log", message.trim());
    });
    child.once("error", (error) => this.fail(error));
    child.once("exit", (code, signal) => {
      void this.analyzeSnapshot(iface, displayFilter);
      if (this.capture === child) {
        this.capture = undefined;
      }
      if (!this.stopping) {
        this.fail(
          new Error(
            this.processError.trim() ||
              `Capture-Pipeline unerwartet beendet (${code ?? signal})`,
          ),
        );
      }
    });
    this.emit("status", this.current());
    return this.current()!;
  }

  pause(): void {
    if (!this.capture || this.session?.status !== "running") {
      throw new Error("Kein laufender Capture");
    }
    this.signalGroup("SIGSTOP");
    this.session.status = "paused";
    this.emit("status", this.current());
  }

  resume(): void {
    if (!this.capture || this.session?.status !== "paused") {
      throw new Error("Capture ist nicht pausiert");
    }
    this.signalGroup("SIGCONT");
    this.session.status = "running";
    this.emit("status", this.current());
  }

  async stop(): Promise<CaptureSession | undefined> {
    if (!this.session) {
      return undefined;
    }
    this.stopping = true;
    if (this.session.status === "paused") {
      this.signalGroup("SIGCONT");
    }
    const child = this.capture;
    if (child) {
      const exited = new Promise<void>((resolve) =>
        child.once("exit", () => resolve()),
      );
      this.signalGroup("SIGINT");
      await Promise.race([
        exited,
        new Promise<void>((resolve) => setTimeout(resolve, 3000)),
      ]);
      if (this.capture) {
        this.signalGroup("SIGTERM");
      }
    }
    this.capture = undefined;
    this.clearEventTimer();
    await this.analyzeSnapshot(
      this.session.interface,
      this.session.displayFilter || "",
    );
    await this.removeEventFile();
    this.session.status = "stopped";
    this.session.stoppedAt = Date.now();
    this.emit("status", this.current());
    return this.current();
  }

  async shutdown(): Promise<void> {
    await this.stop().catch(() => undefined);
    this.removeAllListeners();
  }

  private signalGroup(signal: NodeJS.Signals): void {
    if (!this.capture?.pid) {
      return;
    }
    try {
      process.kill(-this.capture.pid, signal);
    } catch {
      this.capture.kill(signal);
    }
  }

  private fail(error: Error): void {
    if (this.stopping) {
      return;
    }
    this.stopping = true;
    this.signalGroup("SIGTERM");
    this.capture = undefined;
    this.clearEventTimer();
    void this.removeEventFile();
    if (this.session) {
      this.session.status = "error";
      this.session.stoppedAt = Date.now();
    }
    this.emit("captureError", error);
    this.emit("status", this.current());
  }

  private clearEventTimer(): void {
    if (this.eventTimer) {
      clearInterval(this.eventTimer);
      this.eventTimer = undefined;
    }
  }

  private async drainEvents(iface: string): Promise<void> {
    if (!this.eventPath || this.draining) {
      return;
    }
    this.draining = true;
    try {
      const file = await fs.promises.open(this.eventPath, "r");
      try {
        const size = (await file.stat()).size;
        const length = Math.min(
          Math.max(0, size - this.eventOffset),
          1024 * 1024,
        );
        if (length === 0) {
          return;
        }
        const buffer = Buffer.allocUnsafe(length);
        const { bytesRead } = await file.read(
          buffer,
          0,
          length,
          this.eventOffset,
        );
        this.eventOffset += bytesRead;
        const text =
          this.eventRemainder + buffer.subarray(0, bytesRead).toString("utf8");
        const lines = text.split(/\r?\n/);
        this.eventRemainder = lines.pop() || "";
        for (const line of lines) {
          const packet = parseFieldsLine(line, iface);
          if (packet && this.session) {
            this.session.packetCount++;
            this.session.byteCount += packet.length;
            this.emit("packet", packet);
          }
        }
      } finally {
        await file.close();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        this.emit("log", `Ereignisdatei: ${String(error)}`);
      }
    } finally {
      this.draining = false;
    }
  }

  private async analyzeSnapshot(
    iface: string,
    displayFilter: string,
  ): Promise<void> {
    if (!this.session?.filePath || this.draining) {
      return;
    }
    this.draining = true;
    const snapshot = path.join(
      os.tmpdir(),
      `netwatch-${this.session.id}.pcapng`,
    );
    try {
      await fs.promises.copyFile(this.session.filePath, snapshot);
      const output = await this.tsharkService.analyze(
        snapshot,
        displayFilter,
        100000,
      );
      for (const line of output.split(/\r?\n/)) {
        const packet = parseFieldsLine(line, iface);
        if (packet && packet.id > this.lastPacketId && this.session) {
          this.lastPacketId = packet.id;
          this.session.packetCount++;
          this.session.byteCount += packet.length;
          this.emit("packet", packet);
        }
      }
    } catch (error) {
      this.emit("log", `Snapshot-Analyse: ${String(error)}`);
    } finally {
      await fs.promises.unlink(snapshot).catch(() => undefined);
      this.draining = false;
    }
  }

  private async removeEventFile(): Promise<void> {
    const eventPath = this.eventPath;
    this.eventPath = undefined;
    if (eventPath) {
      await fs.promises.unlink(eventPath).catch(() => undefined);
    }
  }
}
