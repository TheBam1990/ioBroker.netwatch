import http from "node:http";
import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import { WebSocketServer, WebSocket } from "ws";
import fs from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { timingSafeEqual } from "node:crypto";
import path from "node:path";
import Busboy from "busboy";
import type { NetworkPacket } from "../types";
import type { CaptureManager } from "../capture/CaptureManager";
import type { RingBuffer } from "../packets/RingBuffer";
import type { Aggregator } from "../analytics/Aggregator";
import type { TsharkService } from "../tshark/TsharkService";
import { listInterfaces } from "../system/InterfaceService";
import {
  resolveCapturePath,
  safeCaptureName,
  validateFilter,
  validateLimit,
} from "../security/InputValidator";
import { validateDisplayFilter } from "../system/DependencyService";
import { parseFieldsLine } from "../tshark/TsharkParser";
export interface ApiOptions {
  host: string;
  port: number;
  username: string;
  password: string;
  webRoot: string;
  captureDirectory: string;
  maxUploadMb: number;
}
export class ApiServer {
  private app = express();
  private server?: http.Server;
  private wss?: WebSocketServer;
  private batch: NetworkPacket[] = [];
  private batchTimer?: NodeJS.Timeout;
  constructor(
    private options: ApiOptions,
    private capture: CaptureManager,
    private packets: RingBuffer<NetworkPacket>,
    private aggregator: Aggregator,
    private tshark: TsharkService,
    private dependencies: () => unknown,
    private recheckDependencies: () => Promise<unknown>,
  ) {
    this.configure();
  }
  private authorized(req: Request): boolean {
    if (this.options.host === "127.0.0.1" && !this.options.password) {
      return true;
    }
    const value = req.headers.authorization || "",
      expected = `Basic ${Buffer.from(
        `${this.options.username}:${this.options.password}`,
      ).toString("base64")}`;
    return (
      value.length === expected.length &&
      timingSafeEqual(Buffer.from(value), Buffer.from(expected))
    );
  }
  private auth = (req: Request, res: Response, next: NextFunction): void => {
    if (this.authorized(req)) {
      next();
      return;
    }
    res.setHeader("WWW-Authenticate", 'Basic realm="ioBroker netwatch"');
    res.status(401).send("Anmeldung erforderlich");
  };
  private configure(): void {
    this.app.disable("x-powered-by");
    this.app.use(this.auth);
    this.app.use(express.json({ limit: "64kb" }));
    this.app.use(
      express.static(this.options.webRoot, {
        index: "index.html",
        fallthrough: true,
        dotfiles: "deny",
      }),
    );
    const asyncRoute =
      (fn: (req: Request, res: Response) => Promise<unknown>) =>
      (req: Request, res: Response) =>
        void fn(req, res).catch((e) =>
          res
            .status(400)
            .json({ error: e instanceof Error ? e.message : String(e) }),
        );
    this.app.get("/api/status", (_q, r) =>
      r.json({
        capture: this.capture.current(),
        dependencies: this.dependencies(),
        bufferedPackets: this.packets.size,
      }),
    );
    this.app.post(
      "/api/system/recheck",
      asyncRoute(async (_q, r) => r.json(await this.recheckDependencies())),
    );
    this.app.get(
      "/api/interfaces",
      asyncRoute(async (_q, r) => r.json(await listInterfaces())),
    );
    this.app.get("/api/capture", (_q, r) =>
      r.json(this.capture.current() || null),
    );
    this.app.post(
      "/api/capture/start",
      asyncRoute(async (q, r) => {
        const b = q.body || {},
          filter = validateFilter(b.displayFilter || "");
        const valid = await validateDisplayFilter(filter);
        if (!valid.valid) {
          return r.status(422).json(valid);
        }
        this.packets.clear();
        this.aggregator.clear();
        r.json(
          await this.capture.start(
            String(b.interface || ""),
            validateFilter(b.captureFilter || ""),
            filter,
          ),
        );
      }),
    );
    this.app.post("/api/capture/pause", (_q, r) => {
      this.capture.pause();
      r.json(this.capture.current());
    });
    this.app.post("/api/capture/resume", (_q, r) => {
      this.capture.resume();
      r.json(this.capture.current());
    });
    this.app.post(
      "/api/capture/stop",
      asyncRoute(async (_q, r) => r.json(await this.capture.stop())),
    );
    this.app.delete("/api/capture/current", (_q, r) => {
      this.packets.clear();
      this.aggregator.clear();
      this.broadcast("capture.cleared", {});
      r.status(204).end();
    });
    this.app.post(
      "/api/filter/validate",
      asyncRoute(async (q, r) =>
        r.json(
          await validateDisplayFilter(validateFilter(q.body?.filter || "")),
        ),
      ),
    );
    this.app.get("/api/packets", (q, r) => {
      const limit = Math.min(Number(q.query.limit) || 1000, 10000),
        offset = Math.max(Number(q.query.offset) || 0, 0),
        all = this.packets.values();
      r.json({
        total: all.length,
        items: all.slice(
          Math.max(0, all.length - offset - limit),
          all.length - offset,
        ),
      });
    });
    this.app.get(
      "/api/packets/:id",
      asyncRoute(async (q, r) => {
        const current = this.capture.current();
        if (!current) {
          throw new Error("Kein Capture ausgewählt");
        }
        const id = validateLimit(
          q.params.id,
          1,
          Number.MAX_SAFE_INTEGER,
          "Paketnummer",
        );
        r.json({
          packet: this.packets.find((p) => p.id === id),
          details: await this.tshark.detail(current.filePath, id),
          hex: await this.tshark.hex(current.filePath, id),
        });
      }),
    );
    for (const key of [
      "conversations",
      "endpoints",
      "devices",
      "protocols",
    ] as const) {
      this.app.get(`/api/${key}`, (_q, r) =>
        r.json(this.aggregator.snapshot()[key]),
      );
    }
    this.app.get(
      "/api/captures",
      asyncRoute(async (_q, r) => {
        await fs.mkdir(this.options.captureDirectory, { recursive: true });
        const entries = await fs.readdir(this.options.captureDirectory, {
            withFileTypes: true,
          }),
          files = await Promise.all(
            entries
              .filter((e) => e.isFile() && /\.pcap(ng)?$/i.test(e.name))
              .map(async (e) => {
                const stat = await fs.stat(
                  path.join(this.options.captureDirectory, e.name),
                );
                return {
                  name: e.name,
                  size: stat.size,
                  modified: stat.mtimeMs,
                };
              }),
          );
        r.json(files.sort((a, b) => b.modified - a.modified));
      }),
    );
    this.app.get(
      "/api/captures/:name/download",
      asyncRoute(async (q, r) => {
        const name = String(q.params.name),
          file = resolveCapturePath(this.options.captureDirectory, name);
        await fs.access(file);
        r.download(file, safeCaptureName(name));
      }),
    );
    this.app.delete(
      "/api/captures/:name",
      asyncRoute(async (q, r) => {
        const file = resolveCapturePath(
          this.options.captureDirectory,
          String(q.params.name),
        );
        if (
          this.capture.current()?.filePath === file &&
          this.capture.current()?.status !== "stopped"
        ) {
          throw new Error("Laufenden Capture zuerst stoppen");
        }
        await fs.unlink(file);
        r.status(204).end();
      }),
    );
    this.app.post("/api/captures/import", (req, res) => {
      let name = "",
        written = 0,
        failed = false,
        completion: Promise<void> | undefined;
      try {
        const bb = Busboy({
          headers: req.headers,
          limits: {
            files: 1,
            fileSize: this.options.maxUploadMb * 1024 * 1024,
            fields: 3,
          },
        });
        bb.on("file", (_field, file, info) => {
          try {
            name = safeCaptureName(info.filename);
            const stream = createWriteStream(
              resolveCapturePath(this.options.captureDirectory, name),
              { flags: "wx", mode: 0o640 },
            );
            completion = new Promise((resolve, reject) => {
              stream.once("close", resolve);
              stream.once("error", reject);
            });
            file.on("data", (d: Buffer) => (written += d.length));
            file.on("limit", () => {
              failed = true;
              stream.destroy();
            });
            file.pipe(stream);
          } catch {
            failed = true;
            file.resume();
          }
        });
        bb.on("close", () => {
          if (failed || !completion) {
            return res.status(400).json({
              error:
                "Ungültige, zu große oder bereits vorhandene Capture-Datei",
            });
          }
          void completion
            .then(() => res.status(201).json({ name, size: written }))
            .catch((e) => res.status(400).json({ error: String(e) }));
        });
        req.pipe(bb);
      } catch (e) {
        res.status(400).json({ error: String(e) });
      }
    });
    this.app.post(
      "/api/captures/:name/analyze",
      asyncRoute(async (q, r) => {
        const file = resolveCapturePath(
            this.options.captureDirectory,
            String(q.params.name),
          ),
          filter = validateFilter(q.body?.displayFilter || ""),
          valid = await validateDisplayFilter(filter);
        if (!valid.valid) {
          return r.status(422).json(valid);
        }
        const output = await this.tshark.analyze(
          file,
          filter,
          validateLimit(q.body?.limit || 10000, 1, 100000, "Limit"),
        );
        this.packets.clear();
        this.aggregator.clear();
        for (const line of output.split("\n")) {
          const p = parseFieldsLine(line);
          if (p) {
            this.packets.push(p);
            this.aggregator.add(p);
          }
        }
        r.json({ packets: this.packets.size });
      }),
    );
  }
  async start(): Promise<void> {
    await fs.mkdir(this.options.captureDirectory, {
      recursive: true,
      mode: 0o750,
    });
    this.server = http.createServer(this.app);
    this.wss = new WebSocketServer({ noServer: true, maxPayload: 128 * 1024 });
    this.server.on("upgrade", (req, socket, head) => {
      const fake = { headers: req.headers } as Request;
      if (!this.authorized(fake)) {
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        return socket.destroy();
      }
      this.wss!.handleUpgrade(req, socket, head, (ws) =>
        this.wss!.emit("connection", ws, req),
      );
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.port, this.options.host, resolve);
    });
    this.capture.on("packet", (p: NetworkPacket) => {
      this.batch.push(p);
      if (!this.batchTimer) {
        this.batchTimer = setTimeout(() => this.flush(), 100);
      }
    });
    this.capture.on("status", (s) => this.broadcast("status", s));
    this.capture.on("captureError", (e) =>
      this.broadcast("error", { message: e.message }),
    );
  }
  private flush(): void {
    const packets = this.batch.splice(0);
    this.batchTimer = undefined;
    if (packets.length) {
      this.broadcast("packet.batch", packets);
    }
  }
  private broadcast(type: string, data: unknown): void {
    const payload = JSON.stringify({ type, data });
    this.wss?.clients.forEach((c) => {
      if (c.readyState === WebSocket.OPEN && c.bufferedAmount < 2_000_000) {
        c.send(payload);
      }
    });
  }
  async stop(): Promise<void> {
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
    }
    for (const client of this.wss?.clients || []) {
      client.close(1001, "Adapter stoppt");
    }
    this.wss?.close();
    if (this.server) {
      await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    }
  }
}
