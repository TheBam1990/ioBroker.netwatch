"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkBinary = checkBinary;
exports.checkDependencies = checkDependencies;
exports.validateDisplayFilter = validateDisplayFilter;
const node_child_process_1 = require("node:child_process");
const node_util_1 = require("node:util");
const promises_1 = __importDefault(require("node:fs/promises"));
const node_os_1 = __importDefault(require("node:os"));
const node_path_1 = __importDefault(require("node:path"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const execFileAsync = (0, node_util_1.promisify)(node_child_process_1.execFile);
async function checkBinary(binary) {
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
    }
    catch (error) {
        return {
            available: false,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
async function checkCapturePermission() {
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
    }
    catch (error) {
        return {
            available: false,
            error: String(error?.stderr || error?.message || error).trim(),
        };
    }
}
async function checkDependencies() {
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
        platform: `${node_os_1.default.platform()} ${node_os_1.default.release()} (${node_os_1.default.arch()})`,
        tshark,
        dumpcap,
        capturePermission,
        instructions,
    };
}
async function validateDisplayFilter(filter) {
    if (!filter) {
        return { valid: true };
    }
    const testFile = node_path_1.default.join(node_os_1.default.tmpdir(), `netwatch-filter-${process.pid}-${node_crypto_1.default.randomBytes(4).toString("hex")}.pcap`);
    try {
        // A valid, empty classic-PCAP header. /dev/null is unsuitable because
        // tshark reports an invalid capture before it can validate the filter.
        await promises_1.default.writeFile(testFile, Buffer.from("d4c3b2a1020004000000000000000000ffff000001000000", "hex"), { mode: 0o600 });
        await execFileAsync("tshark", ["-Y", filter, "-r", testFile], {
            timeout: 8000,
            maxBuffer: 256_000,
        });
        return { valid: true };
    }
    catch (error) {
        const message = String(error?.stderr || error?.message || error)
            .replace(/^tshark:\s*/, "")
            .trim();
        return {
            valid: false,
            error: message || "Ungültiger Wireshark-Display-Filter",
        };
    }
    finally {
        await promises_1.default.unlink(testFile).catch(() => undefined);
    }
}
//# sourceMappingURL=DependencyService.js.map