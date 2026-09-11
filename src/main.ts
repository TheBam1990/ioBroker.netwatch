import * as utils from "@iobroker/adapter-core";
import path from "node:path";
import fs from "node:fs/promises";
import crypto from "node:crypto";
import { RingBuffer } from "./packets/RingBuffer";
import type { NetworkPacket } from "./types";
import { Aggregator } from "./analytics/Aggregator";
import { TsharkService } from "./tshark/TsharkService";
import { CaptureManager } from "./capture/CaptureManager";
import { ApiServer } from "./api/ApiServer";
import {
  checkDependencies,
  type DependencyReport,
} from "./system/DependencyService";
import { listInterfaces } from "./system/InterfaceService";
interface NetwatchConfig {
  captureInterface: string;
  autoStart: boolean;
  memoryPacketLimit: number;
  captureDirectory: string;
  maxCaptureSizeMb: number;
  maxTotalStorageMb: number;
  retentionDays: number;
  webEnabled: boolean;
  webBind: string;
  webPort: number;
  webUsername: string;
  webPassword: string;
  statisticsIntervalSec: number;
}
export class Netwatch extends utils.Adapter {
  private packets!: RingBuffer<NetworkPacket>;
  private aggregator = new Aggregator();
  private tshark = new TsharkService();
  private capture?: CaptureManager;
  private api?: ApiServer;
  private stateTimer?: NodeJS.Timeout;
  private fileTimer?: NodeJS.Timeout;
  private deps?: DependencyReport;
  private shuttingDown = false;
  declare config: NetwatchConfig;
  constructor(options: Partial<utils.AdapterOptions> = {}) {
    super({ ...options, name: "netwatch" });
    this.on("ready", () => void this.onReady());
    this.on("unload", (cb) => void this.onUnload(cb));
    this.on("message", (obj) => void this.onMessage(obj));
  }
  private async onReady(): Promise<void> {
    try {
      await this.setStateAsync("info.connection", false, true);
      this.packets = new RingBuffer(
        Math.max(
          1000,
          Math.min(Number(this.config.memoryPacketLimit) || 50000, 100000),
        ),
      );
      this.deps = await checkDependencies();
      await this.setStateAsync(
        "info.tsharkAvailable",
        this.deps.tshark.available,
        true,
      );
      await this.setStateAsync(
        "info.dumpcapAvailable",
        this.deps.dumpcap.available,
        true,
      );
      await this.setStateAsync(
        "info.capturePermission",
        this.deps.capturePermission.available,
        true,
      );
      await this.setStateAsync("info.setupRequired", !this.deps.ready, true);
      await this.setStateAsync(
        "info.setupHint",
        this.deps.ready
          ? "System ist für Paketmitschnitte bereit"
          : [
              ...this.deps.instructions.install,
              ...this.deps.instructions.permissions,
            ].join(" && "),
        true,
      );
      const captureDir = this.captureDirectory();
      await fs.mkdir(captureDir, { recursive: true, mode: 0o750 });
      this.capture = new CaptureManager(captureDir, this.tshark);
      this.capture.on("packet", (packet: NetworkPacket) => {
        this.packets.push(packet);
        this.aggregator.add(packet);
      });
      this.capture.on("log", (line: string) => {
        if (line) {
          this.log.debug(line);
        }
      });
      this.capture.on("captureError", (error: Error) => {
        this.log.error(`Capture: ${error.message}`);
        void this.setStateAsync("info.lastError", error.message, true);
      });
      this.capture.on("status", () => void this.syncStates());
      if (this.config.webEnabled !== false) {
        const password = this.webPassword();
        this.api = new ApiServer(
          {
            host: this.config.webBind || "127.0.0.1",
            port: Number(this.config.webPort) || 8110,
            username: this.config.webUsername || "admin",
            password,
            webRoot: path.join(__dirname, "../../web"),
            captureDirectory: captureDir,
            maxUploadMb: Math.min(
              Number(this.config.maxCaptureSizeMb) || 500,
              2048,
            ),
          },
          this.capture,
          this.packets,
          this.aggregator,
          this.tshark,
          () => this.deps,
          () => this.refreshDependencies(),
        );
        await this.api.start();
        this.log.info(
          `Web UI: http://${this.config.webBind || "127.0.0.1"}:${Number(this.config.webPort) || 8110}`,
        );
      }
      this.stateTimer = setInterval(
        () => void this.syncStates(),
        Math.max(1, Number(this.config.statisticsIntervalSec) || 2) * 1000,
      );
      this.fileTimer = setInterval(
        () => void this.enforceStorageLimits(),
        30000,
      );
      await this.syncStates();
      await this.setStateAsync("info.connection", true, true);
      await this.setStateAsync("info.lastError", "", true);
      if (!this.deps.ready) {
        const msg =
          "Systemeinrichtung unvollständig. Details: Weboberfläche → Einstellungen.";
        this.log.warn(msg);
        await this.setStateAsync("info.lastError", msg, true);
      } else if (this.config.autoStart && this.config.captureInterface) {
        await this.capture
          .start(this.config.captureInterface)
          .catch((e) => this.log.error(e.message));
      }
    } catch (error) {
      this.log.error(
        `Start fehlgeschlagen: ${error instanceof Error ? error.stack || error.message : String(error)}`,
      );
      await this.setStateAsync("info.lastError", String(error), true).catch(
        () => undefined,
      );
    }
  }
  private async refreshDependencies(): Promise<DependencyReport> {
    this.deps = await checkDependencies();
    await Promise.all([
      this.setStateAsync(
        "info.tsharkAvailable",
        this.deps.tshark.available,
        true,
      ),
      this.setStateAsync(
        "info.dumpcapAvailable",
        this.deps.dumpcap.available,
        true,
      ),
      this.setStateAsync(
        "info.capturePermission",
        this.deps.capturePermission.available,
        true,
      ),
      this.setStateAsync("info.setupRequired", !this.deps.ready, true),
      this.setStateAsync(
        "info.setupHint",
        this.deps.ready
          ? "System ist für Paketmitschnitte bereit"
          : [
              ...this.deps.instructions.install,
              ...this.deps.instructions.permissions,
            ].join(" && "),
        true,
      ),
    ]);
    return this.deps;
  }
  private captureDirectory(): string {
    const configured = String(this.config.captureDirectory || "").trim();
    const base = utils.getAbsoluteDefaultDataDir();
    return configured
      ? path.resolve(configured)
      : path.join(base, "netwatch.0", "captures");
  }
  private webPassword(): string {
    const configured = String(this.config.webPassword || "");
    if (configured) {
      return this.decrypt(this.config.webPassword);
    }
    const token = crypto.randomBytes(15).toString("base64url");
    this.log.warn(
      `Kein Web-Passwort konfiguriert. Ein temporäres Passwort wurde erzeugt: ${token}`,
    );
    return token;
  }
  private async syncStates(): Promise<void> {
    const current = this.capture?.current(),
      analytics = this.aggregator.snapshot(),
      runtime = current ? (Date.now() - current.startedAt) / 1000 : 0;
    await Promise.all([
      this.setStateAsync(
        "capture.running",
        current?.status === "running",
        true,
      ),
      this.setStateAsync("capture.paused", current?.status === "paused", true),
      this.setStateAsync("capture.interface", current?.interface || "", true),
      this.setStateAsync(
        "capture.packetCount",
        current?.packetCount || 0,
        true,
      ),
      this.setStateAsync("capture.byteCount", current?.byteCount || 0, true),
      this.setStateAsync(
        "capture.packetsPerSecond",
        runtime
          ? Math.round(((current?.packetCount || 0) / runtime) * 100) / 100
          : 0,
        true,
      ),
      this.setStateAsync(
        "capture.bytesPerSecond",
        runtime ? Math.round((current?.byteCount || 0) / runtime) : 0,
        true,
      ),
      this.setStateAsync("statistics.devices", analytics.devices.length, true),
      this.setStateAsync(
        "statistics.conversations",
        analytics.conversations.length,
        true,
      ),
      ...["TCP", "UDP", "ICMP", "DNS", "MQTT", "TLS"].map((p) =>
        this.setStateAsync(
          `protocols.${p.toLowerCase()}.packets`,
          analytics.protocols[p] || 0,
          true,
        ),
      ),
    ]);
  }
  private async enforceStorageLimits(): Promise<void> {
    try {
      const dir = this.captureDirectory(),
        entries = await fs.readdir(dir),
        files = (
          await Promise.all(
            entries
              .filter((x) => /\.pcap(ng)?$/i.test(x))
              .map(async (name) => ({
                name,
                path: path.join(dir, name),
                stat: await fs.stat(path.join(dir, name)),
              })),
          )
        ).sort((a, b) => a.stat.mtimeMs - b.stat.mtimeMs),
        active = this.capture?.current()?.filePath,
        maxFile = (Number(this.config.maxCaptureSizeMb) || 500) * 1024 * 1024;
      if (active) {
        const f = files.find((x) => x.path === active);
        if (f && f.stat.size > maxFile) {
          this.log.warn(
            "Maximale Capture-Dateigröße erreicht; Capture wird gestoppt",
          );
          await this.capture?.stop();
        }
      }
      const cutoff =
          Date.now() - (Number(this.config.retentionDays) || 7) * 86400000,
        maxTotal =
          (Number(this.config.maxTotalStorageMb) || 5120) * 1024 * 1024;
      let total = files.reduce((s, x) => s + x.stat.size, 0);
      for (const f of files) {
        if (f.path === active) {
          continue;
        }
        if (f.stat.mtimeMs < cutoff || total > maxTotal) {
          await fs.unlink(f.path);
          total -= f.stat.size;
        }
      }
    } catch (e) {
      this.log.warn(
        `Speicherbereinigung fehlgeschlagen: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
  }
  private async onMessage(obj: ioBroker.Message): Promise<void> {
    if (!obj.callback || !this.capture) {
      return;
    }
    try {
      let result: unknown;
      switch (obj.command) {
        case "getInterfaces":
          result = await listInterfaces();
          break;
        case "start":
          result = await this.capture.start(
            String(obj.message?.interface || this.config.captureInterface),
          );
          break;
        case "stop":
          result = await this.capture.stop();
          break;
        default:
          throw new Error("Unbekannter Befehl");
      }
      this.sendTo(obj.from, obj.command, { result }, obj.callback);
    } catch (e) {
      this.sendTo(
        obj.from,
        obj.command,
        { error: e instanceof Error ? e.message : String(e) },
        obj.callback,
      );
    }
  }
  private async onUnload(callback: () => void): Promise<void> {
    if (this.shuttingDown) {
      return;
    }
    this.shuttingDown = true;
    try {
      if (this.stateTimer) {
        clearInterval(this.stateTimer);
      }
      if (this.fileTimer) {
        clearInterval(this.fileTimer);
      }
      await this.api?.stop();
      await this.capture?.shutdown();
      await this.setStateAsync("info.connection", false, true);
    } catch (e) {
      this.log.warn(`Shutdown: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      callback();
    }
  }
}
if (require.main === module) {
  new Netwatch();
}
