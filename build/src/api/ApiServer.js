"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ApiServer = void 0;
const node_http_1 = __importDefault(require("node:http"));
const express_1 = __importDefault(require("express"));
const ws_1 = require("ws");
const promises_1 = __importDefault(require("node:fs/promises"));
const node_fs_1 = require("node:fs");
const node_crypto_1 = require("node:crypto");
const node_path_1 = __importDefault(require("node:path"));
const busboy_1 = __importDefault(require("busboy"));
const InterfaceService_1 = require("../system/InterfaceService");
const InputValidator_1 = require("../security/InputValidator");
const DependencyService_1 = require("../system/DependencyService");
const TsharkParser_1 = require("../tshark/TsharkParser");
class ApiServer {
    options;
    capture;
    packets;
    aggregator;
    tshark;
    dependencies;
    recheckDependencies;
    app = (0, express_1.default)();
    server;
    wss;
    batch = [];
    batchTimer;
    constructor(options, capture, packets, aggregator, tshark, dependencies, recheckDependencies) {
        this.options = options;
        this.capture = capture;
        this.packets = packets;
        this.aggregator = aggregator;
        this.tshark = tshark;
        this.dependencies = dependencies;
        this.recheckDependencies = recheckDependencies;
        this.configure();
    }
    authorized(req) {
        if (this.options.host === "127.0.0.1" && !this.options.password) {
            return true;
        }
        const value = req.headers.authorization || "", expected = `Basic ${Buffer.from(`${this.options.username}:${this.options.password}`).toString("base64")}`;
        return (value.length === expected.length &&
            (0, node_crypto_1.timingSafeEqual)(Buffer.from(value), Buffer.from(expected)));
    }
    auth = (req, res, next) => {
        if (this.authorized(req)) {
            next();
            return;
        }
        res.setHeader("WWW-Authenticate", 'Basic realm="ioBroker netwatch"');
        res.status(401).send("Anmeldung erforderlich");
    };
    configure() {
        this.app.disable("x-powered-by");
        this.app.use(this.auth);
        this.app.use(express_1.default.json({ limit: "64kb" }));
        this.app.use(express_1.default.static(this.options.webRoot, {
            index: "index.html",
            fallthrough: true,
            dotfiles: "deny",
        }));
        const asyncRoute = (fn) => (req, res) => void fn(req, res).catch((e) => res
            .status(400)
            .json({ error: e instanceof Error ? e.message : String(e) }));
        this.app.get("/api/status", (_q, r) => r.json({
            capture: this.capture.current(),
            dependencies: this.dependencies(),
            bufferedPackets: this.packets.size,
        }));
        this.app.post("/api/system/recheck", asyncRoute(async (_q, r) => r.json(await this.recheckDependencies())));
        this.app.get("/api/interfaces", asyncRoute(async (_q, r) => r.json(await (0, InterfaceService_1.listInterfaces)())));
        this.app.get("/api/capture", (_q, r) => r.json(this.capture.current() || null));
        this.app.post("/api/capture/start", asyncRoute(async (q, r) => {
            const b = q.body || {}, filter = (0, InputValidator_1.validateFilter)(b.displayFilter || "");
            const valid = await (0, DependencyService_1.validateDisplayFilter)(filter);
            if (!valid.valid) {
                return r.status(422).json(valid);
            }
            this.packets.clear();
            this.aggregator.clear();
            r.json(await this.capture.start(String(b.interface || ""), (0, InputValidator_1.validateFilter)(b.captureFilter || ""), filter));
        }));
        this.app.post("/api/capture/pause", (_q, r) => {
            this.capture.pause();
            r.json(this.capture.current());
        });
        this.app.post("/api/capture/resume", (_q, r) => {
            this.capture.resume();
            r.json(this.capture.current());
        });
        this.app.post("/api/capture/stop", asyncRoute(async (_q, r) => r.json(await this.capture.stop())));
        this.app.delete("/api/capture/current", (_q, r) => {
            this.packets.clear();
            this.aggregator.clear();
            this.broadcast("capture.cleared", {});
            r.status(204).end();
        });
        this.app.post("/api/filter/validate", asyncRoute(async (q, r) => r.json(await (0, DependencyService_1.validateDisplayFilter)((0, InputValidator_1.validateFilter)(q.body?.filter || "")))));
        this.app.get("/api/packets", (q, r) => {
            const limit = Math.min(Number(q.query.limit) || 1000, 10000), offset = Math.max(Number(q.query.offset) || 0, 0), all = this.packets.values();
            r.json({
                total: all.length,
                items: all.slice(Math.max(0, all.length - offset - limit), all.length - offset),
            });
        });
        this.app.get("/api/packets/:id", asyncRoute(async (q, r) => {
            const current = this.capture.current();
            if (!current) {
                throw new Error("Kein Capture ausgewählt");
            }
            const id = (0, InputValidator_1.validateLimit)(q.params.id, 1, Number.MAX_SAFE_INTEGER, "Paketnummer");
            r.json({
                packet: this.packets.find((p) => p.id === id),
                details: await this.tshark.detail(current.filePath, id),
                hex: await this.tshark.hex(current.filePath, id),
            });
        }));
        for (const key of [
            "conversations",
            "endpoints",
            "devices",
            "protocols",
        ]) {
            this.app.get(`/api/${key}`, (_q, r) => r.json(this.aggregator.snapshot()[key]));
        }
        this.app.get("/api/captures", asyncRoute(async (_q, r) => {
            await promises_1.default.mkdir(this.options.captureDirectory, { recursive: true });
            const entries = await promises_1.default.readdir(this.options.captureDirectory, {
                withFileTypes: true,
            }), files = await Promise.all(entries
                .filter((e) => e.isFile() && /\.pcap(ng)?$/i.test(e.name))
                .map(async (e) => {
                const stat = await promises_1.default.stat(node_path_1.default.join(this.options.captureDirectory, e.name));
                return {
                    name: e.name,
                    size: stat.size,
                    modified: stat.mtimeMs,
                };
            }));
            r.json(files.sort((a, b) => b.modified - a.modified));
        }));
        this.app.get("/api/captures/:name/download", asyncRoute(async (q, r) => {
            const name = String(q.params.name), file = (0, InputValidator_1.resolveCapturePath)(this.options.captureDirectory, name);
            await promises_1.default.access(file);
            r.download(file, (0, InputValidator_1.safeCaptureName)(name));
        }));
        this.app.delete("/api/captures/:name", asyncRoute(async (q, r) => {
            const file = (0, InputValidator_1.resolveCapturePath)(this.options.captureDirectory, String(q.params.name));
            if (this.capture.current()?.filePath === file &&
                this.capture.current()?.status !== "stopped") {
                throw new Error("Laufenden Capture zuerst stoppen");
            }
            await promises_1.default.unlink(file);
            r.status(204).end();
        }));
        this.app.post("/api/captures/import", (req, res) => {
            let name = "", written = 0, failed = false, completion;
            try {
                const bb = (0, busboy_1.default)({
                    headers: req.headers,
                    limits: {
                        files: 1,
                        fileSize: this.options.maxUploadMb * 1024 * 1024,
                        fields: 3,
                    },
                });
                bb.on("file", (_field, file, info) => {
                    try {
                        name = (0, InputValidator_1.safeCaptureName)(info.filename);
                        const stream = (0, node_fs_1.createWriteStream)((0, InputValidator_1.resolveCapturePath)(this.options.captureDirectory, name), { flags: "wx", mode: 0o640 });
                        completion = new Promise((resolve, reject) => {
                            stream.once("close", resolve);
                            stream.once("error", reject);
                        });
                        file.on("data", (d) => (written += d.length));
                        file.on("limit", () => {
                            failed = true;
                            stream.destroy();
                        });
                        file.pipe(stream);
                    }
                    catch {
                        failed = true;
                        file.resume();
                    }
                });
                bb.on("close", () => {
                    if (failed || !completion) {
                        return res.status(400).json({
                            error: "Ungültige, zu große oder bereits vorhandene Capture-Datei",
                        });
                    }
                    void completion
                        .then(() => res.status(201).json({ name, size: written }))
                        .catch((e) => res.status(400).json({ error: String(e) }));
                });
                req.pipe(bb);
            }
            catch (e) {
                res.status(400).json({ error: String(e) });
            }
        });
        this.app.post("/api/captures/:name/analyze", asyncRoute(async (q, r) => {
            const file = (0, InputValidator_1.resolveCapturePath)(this.options.captureDirectory, String(q.params.name)), filter = (0, InputValidator_1.validateFilter)(q.body?.displayFilter || ""), valid = await (0, DependencyService_1.validateDisplayFilter)(filter);
            if (!valid.valid) {
                return r.status(422).json(valid);
            }
            const output = await this.tshark.analyze(file, filter, (0, InputValidator_1.validateLimit)(q.body?.limit || 10000, 1, 100000, "Limit"));
            this.packets.clear();
            this.aggregator.clear();
            for (const line of output.split("\n")) {
                const p = (0, TsharkParser_1.parseFieldsLine)(line);
                if (p) {
                    this.packets.push(p);
                    this.aggregator.add(p);
                }
            }
            r.json({ packets: this.packets.size });
        }));
    }
    async start() {
        await promises_1.default.mkdir(this.options.captureDirectory, {
            recursive: true,
            mode: 0o750,
        });
        this.server = node_http_1.default.createServer(this.app);
        this.wss = new ws_1.WebSocketServer({ noServer: true, maxPayload: 128 * 1024 });
        this.server.on("upgrade", (req, socket, head) => {
            const fake = { headers: req.headers };
            if (!this.authorized(fake)) {
                socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
                return socket.destroy();
            }
            this.wss.handleUpgrade(req, socket, head, (ws) => this.wss.emit("connection", ws, req));
        });
        await new Promise((resolve, reject) => {
            this.server.once("error", reject);
            this.server.listen(this.options.port, this.options.host, resolve);
        });
        this.capture.on("packet", (p) => {
            this.batch.push(p);
            if (!this.batchTimer) {
                this.batchTimer = setTimeout(() => this.flush(), 100);
            }
        });
        this.capture.on("status", (s) => this.broadcast("status", s));
        this.capture.on("captureError", (e) => this.broadcast("error", { message: e.message }));
    }
    flush() {
        const packets = this.batch.splice(0);
        this.batchTimer = undefined;
        if (packets.length) {
            this.broadcast("packet.batch", packets);
        }
    }
    broadcast(type, data) {
        const payload = JSON.stringify({ type, data });
        this.wss?.clients.forEach((c) => {
            if (c.readyState === ws_1.WebSocket.OPEN && c.bufferedAmount < 2_000_000) {
                c.send(payload);
            }
        });
    }
    async stop() {
        if (this.batchTimer) {
            clearTimeout(this.batchTimer);
        }
        for (const client of this.wss?.clients || []) {
            client.close(1001, "Adapter stoppt");
        }
        this.wss?.close();
        if (this.server) {
            await new Promise((resolve) => this.server.close(() => resolve()));
        }
    }
}
exports.ApiServer = ApiServer;
//# sourceMappingURL=ApiServer.js.map