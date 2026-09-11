"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Netwatch = void 0;
const utils = __importStar(require("@iobroker/adapter-core"));
const node_path_1 = __importDefault(require("node:path"));
const promises_1 = __importDefault(require("node:fs/promises"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const RingBuffer_1 = require("./packets/RingBuffer");
const Aggregator_1 = require("./analytics/Aggregator");
const TsharkService_1 = require("./tshark/TsharkService");
const CaptureManager_1 = require("./capture/CaptureManager");
const ApiServer_1 = require("./api/ApiServer");
const DependencyService_1 = require("./system/DependencyService");
const InterfaceService_1 = require("./system/InterfaceService");
class Netwatch extends utils.Adapter {
    packets;
    aggregator = new Aggregator_1.Aggregator();
    tshark = new TsharkService_1.TsharkService();
    capture;
    api;
    stateTimer;
    fileTimer;
    deps;
    shuttingDown = false;
    constructor(options = {}) {
        super({ ...options, name: "netwatch" });
        this.on("ready", () => void this.onReady());
        this.on("unload", (cb) => void this.onUnload(cb));
        this.on("message", (obj) => void this.onMessage(obj));
    }
    async onReady() {
        try {
            await this.setStateAsync("info.connection", false, true);
            this.packets = new RingBuffer_1.RingBuffer(Math.max(1000, Math.min(Number(this.config.memoryPacketLimit) || 50000, 100000)));
            this.deps = await (0, DependencyService_1.checkDependencies)();
            await this.setStateAsync("info.tsharkAvailable", this.deps.tshark.available, true);
            await this.setStateAsync("info.dumpcapAvailable", this.deps.dumpcap.available, true);
            await this.setStateAsync("info.capturePermission", this.deps.capturePermission.available, true);
            await this.setStateAsync("info.setupRequired", !this.deps.ready, true);
            await this.setStateAsync("info.setupHint", this.deps.ready
                ? "System ist für Paketmitschnitte bereit"
                : [
                    ...this.deps.instructions.install,
                    ...this.deps.instructions.permissions,
                ].join(" && "), true);
            const captureDir = this.captureDirectory();
            await promises_1.default.mkdir(captureDir, { recursive: true, mode: 0o750 });
            this.capture = new CaptureManager_1.CaptureManager(captureDir, this.tshark);
            this.capture.on("packet", (packet) => {
                this.packets.push(packet);
                this.aggregator.add(packet);
            });
            this.capture.on("log", (line) => {
                if (line) {
                    this.log.debug(line);
                }
            });
            this.capture.on("captureError", (error) => {
                this.log.error(`Capture: ${error.message}`);
                void this.setStateAsync("info.lastError", error.message, true);
            });
            this.capture.on("status", () => void this.syncStates());
            if (this.config.webEnabled !== false) {
                const password = this.webPassword();
                this.api = new ApiServer_1.ApiServer({
                    host: this.config.webBind || "127.0.0.1",
                    port: Number(this.config.webPort) || 8110,
                    username: this.config.webUsername || "admin",
                    password,
                    webRoot: node_path_1.default.join(__dirname, "../../web"),
                    captureDirectory: captureDir,
                    maxUploadMb: Math.min(Number(this.config.maxCaptureSizeMb) || 500, 2048),
                }, this.capture, this.packets, this.aggregator, this.tshark, () => this.deps, () => this.refreshDependencies());
                await this.api.start();
                this.log.info(`Web UI: http://${this.config.webBind || "127.0.0.1"}:${Number(this.config.webPort) || 8110}`);
            }
            this.stateTimer = setInterval(() => void this.syncStates(), Math.max(1, Number(this.config.statisticsIntervalSec) || 2) * 1000);
            this.fileTimer = setInterval(() => void this.enforceStorageLimits(), 30000);
            await this.syncStates();
            await this.setStateAsync("info.connection", true, true);
            await this.setStateAsync("info.lastError", "", true);
            if (!this.deps.ready) {
                const msg = "Systemeinrichtung unvollständig. Details: Weboberfläche → Einstellungen.";
                this.log.warn(msg);
                await this.setStateAsync("info.lastError", msg, true);
            }
            else if (this.config.autoStart && this.config.captureInterface) {
                await this.capture
                    .start(this.config.captureInterface)
                    .catch((e) => this.log.error(e.message));
            }
        }
        catch (error) {
            this.log.error(`Start fehlgeschlagen: ${error instanceof Error ? error.stack || error.message : String(error)}`);
            await this.setStateAsync("info.lastError", String(error), true).catch(() => undefined);
        }
    }
    async refreshDependencies() {
        this.deps = await (0, DependencyService_1.checkDependencies)();
        await Promise.all([
            this.setStateAsync("info.tsharkAvailable", this.deps.tshark.available, true),
            this.setStateAsync("info.dumpcapAvailable", this.deps.dumpcap.available, true),
            this.setStateAsync("info.capturePermission", this.deps.capturePermission.available, true),
            this.setStateAsync("info.setupRequired", !this.deps.ready, true),
            this.setStateAsync("info.setupHint", this.deps.ready
                ? "System ist für Paketmitschnitte bereit"
                : [
                    ...this.deps.instructions.install,
                    ...this.deps.instructions.permissions,
                ].join(" && "), true),
        ]);
        return this.deps;
    }
    captureDirectory() {
        const configured = String(this.config.captureDirectory || "").trim();
        const base = utils.getAbsoluteDefaultDataDir();
        return configured
            ? node_path_1.default.resolve(configured)
            : node_path_1.default.join(base, "netwatch.0", "captures");
    }
    webPassword() {
        const configured = String(this.config.webPassword || "");
        if (configured) {
            return this.decrypt(this.config.webPassword);
        }
        const token = node_crypto_1.default.randomBytes(15).toString("base64url");
        this.log.warn(`Kein Web-Passwort konfiguriert. Ein temporäres Passwort wurde erzeugt: ${token}`);
        return token;
    }
    async syncStates() {
        const current = this.capture?.current(), analytics = this.aggregator.snapshot(), runtime = current ? (Date.now() - current.startedAt) / 1000 : 0;
        await Promise.all([
            this.setStateAsync("capture.running", current?.status === "running", true),
            this.setStateAsync("capture.paused", current?.status === "paused", true),
            this.setStateAsync("capture.interface", current?.interface || "", true),
            this.setStateAsync("capture.packetCount", current?.packetCount || 0, true),
            this.setStateAsync("capture.byteCount", current?.byteCount || 0, true),
            this.setStateAsync("capture.packetsPerSecond", runtime
                ? Math.round(((current?.packetCount || 0) / runtime) * 100) / 100
                : 0, true),
            this.setStateAsync("capture.bytesPerSecond", runtime ? Math.round((current?.byteCount || 0) / runtime) : 0, true),
            this.setStateAsync("statistics.devices", analytics.devices.length, true),
            this.setStateAsync("statistics.conversations", analytics.conversations.length, true),
            ...["TCP", "UDP", "ICMP", "DNS", "MQTT", "TLS"].map((p) => this.setStateAsync(`protocols.${p.toLowerCase()}.packets`, analytics.protocols[p] || 0, true)),
        ]);
    }
    async enforceStorageLimits() {
        try {
            const dir = this.captureDirectory(), entries = await promises_1.default.readdir(dir), files = (await Promise.all(entries
                .filter((x) => /\.pcap(ng)?$/i.test(x))
                .map(async (name) => ({
                name,
                path: node_path_1.default.join(dir, name),
                stat: await promises_1.default.stat(node_path_1.default.join(dir, name)),
            })))).sort((a, b) => a.stat.mtimeMs - b.stat.mtimeMs), active = this.capture?.current()?.filePath, maxFile = (Number(this.config.maxCaptureSizeMb) || 500) * 1024 * 1024;
            if (active) {
                const f = files.find((x) => x.path === active);
                if (f && f.stat.size > maxFile) {
                    this.log.warn("Maximale Capture-Dateigröße erreicht; Capture wird gestoppt");
                    await this.capture?.stop();
                }
            }
            const cutoff = Date.now() - (Number(this.config.retentionDays) || 7) * 86400000, maxTotal = (Number(this.config.maxTotalStorageMb) || 5120) * 1024 * 1024;
            let total = files.reduce((s, x) => s + x.stat.size, 0);
            for (const f of files) {
                if (f.path === active) {
                    continue;
                }
                if (f.stat.mtimeMs < cutoff || total > maxTotal) {
                    await promises_1.default.unlink(f.path);
                    total -= f.stat.size;
                }
            }
        }
        catch (e) {
            this.log.warn(`Speicherbereinigung fehlgeschlagen: ${e instanceof Error ? e.message : String(e)}`);
        }
    }
    async onMessage(obj) {
        if (!obj.callback || !this.capture) {
            return;
        }
        try {
            let result;
            switch (obj.command) {
                case "getInterfaces":
                    result = await (0, InterfaceService_1.listInterfaces)();
                    break;
                case "start":
                    result = await this.capture.start(String(obj.message?.interface || this.config.captureInterface));
                    break;
                case "stop":
                    result = await this.capture.stop();
                    break;
                default:
                    throw new Error("Unbekannter Befehl");
            }
            this.sendTo(obj.from, obj.command, { result }, obj.callback);
        }
        catch (e) {
            this.sendTo(obj.from, obj.command, { error: e instanceof Error ? e.message : String(e) }, obj.callback);
        }
    }
    async onUnload(callback) {
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
        }
        catch (e) {
            this.log.warn(`Shutdown: ${e instanceof Error ? e.message : String(e)}`);
        }
        finally {
            callback();
        }
    }
}
exports.Netwatch = Netwatch;
if (require.main === module) {
    new Netwatch();
}
//# sourceMappingURL=main.js.map