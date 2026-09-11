"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.listInterfaces = listInterfaces;
const node_os_1 = __importDefault(require("node:os"));
const promises_1 = __importDefault(require("node:fs/promises"));
async function readNumber(file) {
    try {
        return Number((await promises_1.default.readFile(file, "utf8")).trim()) || 0;
    }
    catch {
        return 0;
    }
}
async function listInterfaces() {
    const all = node_os_1.default.networkInterfaces();
    return Promise.all(Object.entries(all).map(async ([name, addresses]) => ({
        name,
        ipv4: (addresses || [])
            .filter((a) => a.family === "IPv4")
            .map((a) => a.address),
        ipv6: (addresses || [])
            .filter((a) => a.family === "IPv6")
            .map((a) => a.address),
        mac: (addresses || []).find((a) => a.mac && a.mac !== "00:00:00:00:00:00")
            ?.mac,
        status: await promises_1.default
            .readFile(`/sys/class/net/${name}/operstate`, "utf8")
            .then((x) => x.trim())
            .catch(() => "unknown"),
        rxBytes: await readNumber(`/sys/class/net/${name}/statistics/rx_bytes`),
        txBytes: await readNumber(`/sys/class/net/${name}/statistics/tx_bytes`),
    })));
}
//# sourceMappingURL=InterfaceService.js.map