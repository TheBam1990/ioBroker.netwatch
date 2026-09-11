"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CaptureManager = void 0;
const node_events_1 = require("node:events");
const node_child_process_1 = require("node:child_process");
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const node_os_1 = __importDefault(require("node:os"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const InputValidator_1 = require("../security/InputValidator");
const TsharkParser_1 = require("../tshark/TsharkParser");
class CaptureManager extends node_events_1.EventEmitter {
    directory;
    tsharkService;
    capture;
    eventPath;
    eventTimer;
    eventOffset = 0;
    eventRemainder = "";
    draining = false;
    lastPacketId = 0;
    session;
    stopping = false;
    processError = "";
    constructor(directory, tsharkService) {
        super();
        this.directory = directory;
        this.tsharkService = tsharkService;
    }
    current() {
        return this.session ? { ...this.session } : undefined;
    }
    async start(iface, captureFilter = "", displayFilter = "") {
        if (this.capture) {
            throw new Error("Capture läuft bereits");
        }
        (0, InputValidator_1.validateInterface)(iface);
        (0, InputValidator_1.validateFilter)(captureFilter);
        (0, InputValidator_1.validateFilter)(displayFilter);
        await node_fs_1.default.promises.mkdir(this.directory, { recursive: true, mode: 0o750 });
        const id = `${new Date().toISOString().replace(/[:.]/g, "-")}-${node_crypto_1.default.randomBytes(3).toString("hex")}`;
        const filePath = node_path_1.default.join(this.directory, `${id}.pcapng`);
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
        this.eventPath = node_path_1.default.join(this.directory, `.${id}.events`);
        await node_fs_1.default.promises.writeFile(this.eventPath, "", { mode: 0o600 });
        this.eventOffset = 0;
        this.eventRemainder = "";
        this.lastPacketId = 0;
        const args = ["-q", "-i", iface, "-w", filePath];
        if (captureFilter) {
            args.push("-f", captureFilter);
        }
        this.capture = (0, node_child_process_1.spawn)("dumpcap", args, {
            stdio: ["ignore", "ignore", "pipe"],
            detached: true,
        });
        const child = this.capture;
        this.eventTimer = setInterval(() => void this.analyzeSnapshot(iface, displayFilter), 500);
        child.stderr.on("data", (data) => {
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
                this.fail(new Error(this.processError.trim() ||
                    `Capture-Pipeline unerwartet beendet (${code ?? signal})`));
            }
        });
        this.emit("status", this.current());
        return this.current();
    }
    pause() {
        if (!this.capture || this.session?.status !== "running") {
            throw new Error("Kein laufender Capture");
        }
        this.signalGroup("SIGSTOP");
        this.session.status = "paused";
        this.emit("status", this.current());
    }
    resume() {
        if (!this.capture || this.session?.status !== "paused") {
            throw new Error("Capture ist nicht pausiert");
        }
        this.signalGroup("SIGCONT");
        this.session.status = "running";
        this.emit("status", this.current());
    }
    async stop() {
        if (!this.session) {
            return undefined;
        }
        this.stopping = true;
        if (this.session.status === "paused") {
            this.signalGroup("SIGCONT");
        }
        const child = this.capture;
        if (child) {
            const exited = new Promise((resolve) => child.once("exit", () => resolve()));
            this.signalGroup("SIGINT");
            await Promise.race([
                exited,
                new Promise((resolve) => setTimeout(resolve, 3000)),
            ]);
            if (this.capture) {
                this.signalGroup("SIGTERM");
            }
        }
        this.capture = undefined;
        this.clearEventTimer();
        await this.analyzeSnapshot(this.session.interface, this.session.displayFilter || "");
        await this.removeEventFile();
        this.session.status = "stopped";
        this.session.stoppedAt = Date.now();
        this.emit("status", this.current());
        return this.current();
    }
    async shutdown() {
        await this.stop().catch(() => undefined);
        this.removeAllListeners();
    }
    signalGroup(signal) {
        if (!this.capture?.pid) {
            return;
        }
        try {
            process.kill(-this.capture.pid, signal);
        }
        catch {
            this.capture.kill(signal);
        }
    }
    fail(error) {
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
    clearEventTimer() {
        if (this.eventTimer) {
            clearInterval(this.eventTimer);
            this.eventTimer = undefined;
        }
    }
    async drainEvents(iface) {
        if (!this.eventPath || this.draining) {
            return;
        }
        this.draining = true;
        try {
            const file = await node_fs_1.default.promises.open(this.eventPath, "r");
            try {
                const size = (await file.stat()).size;
                const length = Math.min(Math.max(0, size - this.eventOffset), 1024 * 1024);
                if (length === 0) {
                    return;
                }
                const buffer = Buffer.allocUnsafe(length);
                const { bytesRead } = await file.read(buffer, 0, length, this.eventOffset);
                this.eventOffset += bytesRead;
                const text = this.eventRemainder + buffer.subarray(0, bytesRead).toString("utf8");
                const lines = text.split(/\r?\n/);
                this.eventRemainder = lines.pop() || "";
                for (const line of lines) {
                    const packet = (0, TsharkParser_1.parseFieldsLine)(line, iface);
                    if (packet && this.session) {
                        this.session.packetCount++;
                        this.session.byteCount += packet.length;
                        this.emit("packet", packet);
                    }
                }
            }
            finally {
                await file.close();
            }
        }
        catch (error) {
            if (error.code !== "ENOENT") {
                this.emit("log", `Ereignisdatei: ${String(error)}`);
            }
        }
        finally {
            this.draining = false;
        }
    }
    async analyzeSnapshot(iface, displayFilter) {
        if (!this.session?.filePath || this.draining) {
            return;
        }
        this.draining = true;
        const snapshot = node_path_1.default.join(node_os_1.default.tmpdir(), `netwatch-${this.session.id}.pcapng`);
        try {
            await node_fs_1.default.promises.copyFile(this.session.filePath, snapshot);
            const output = await this.tsharkService.analyze(snapshot, displayFilter, 100000);
            for (const line of output.split(/\r?\n/)) {
                const packet = (0, TsharkParser_1.parseFieldsLine)(line, iface);
                if (packet && packet.id > this.lastPacketId && this.session) {
                    this.lastPacketId = packet.id;
                    this.session.packetCount++;
                    this.session.byteCount += packet.length;
                    this.emit("packet", packet);
                }
            }
        }
        catch (error) {
            this.emit("log", `Snapshot-Analyse: ${String(error)}`);
        }
        finally {
            await node_fs_1.default.promises.unlink(snapshot).catch(() => undefined);
            this.draining = false;
        }
    }
    async removeEventFile() {
        const eventPath = this.eventPath;
        this.eventPath = undefined;
        if (eventPath) {
            await node_fs_1.default.promises.unlink(eventPath).catch(() => undefined);
        }
    }
}
exports.CaptureManager = CaptureManager;
//# sourceMappingURL=CaptureManager.js.map