"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TsharkService = void 0;
const node_child_process_1 = require("node:child_process");
const node_fs_1 = __importDefault(require("node:fs"));
const node_os_1 = __importDefault(require("node:os"));
const node_path_1 = __importDefault(require("node:path"));
const node_crypto_1 = __importDefault(require("node:crypto"));
class TsharkService {
    async detail(file, id) {
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
    async hex(file, id) {
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
    async analyze(file, filter = "", limit = 10000) {
        const args = ["-n", "-r", file];
        if (filter) {
            args.push("-Y", filter);
        }
        args.push("-c", String(limit), ...this.fastArgs());
        return this.run(args);
    }
    async run(args) {
        const output = node_path_1.default.join(node_os_1.default.tmpdir(), `netwatch-tshark-${node_crypto_1.default.randomBytes(8).toString("hex")}.out`);
        const fd = node_fs_1.default.openSync(output, "wx", 0o600);
        let stderr = "";
        try {
            await new Promise((resolve, reject) => {
                const child = (0, node_child_process_1.spawn)("tshark", args, {
                    stdio: ["ignore", fd, "pipe"],
                });
                child.stderr.on("data", (data) => {
                    stderr = `${stderr}${String(data)}`.slice(-8000);
                });
                child.once("error", reject);
                child.once("exit", (code, signal) => {
                    if (code === 0)
                        resolve();
                    else
                        reject(new Error(stderr.trim() || `tshark beendet (${code ?? signal})`));
                });
            });
            return await node_fs_1.default.promises.readFile(output, "utf8");
        }
        finally {
            node_fs_1.default.closeSync(fd);
            await node_fs_1.default.promises.unlink(output).catch(() => undefined);
        }
    }
    fastArgs() {
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
exports.TsharkService = TsharkService;
//# sourceMappingURL=TsharkService.js.map