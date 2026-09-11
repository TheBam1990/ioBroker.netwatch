"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.INTERFACE_PATTERN = void 0;
exports.validateInterface = validateInterface;
exports.validateLimit = validateLimit;
exports.safeCaptureName = safeCaptureName;
exports.resolveCapturePath = resolveCapturePath;
exports.validateFilter = validateFilter;
const node_path_1 = __importDefault(require("node:path"));
exports.INTERFACE_PATTERN = /^[a-zA-Z0-9_.:@-]{1,64}$/;
function validateInterface(value) {
    if (!exports.INTERFACE_PATTERN.test(value)) {
        throw new Error("Ungültiger Interface-Name");
    }
    return value;
}
function validateLimit(value, min, max, name) {
    const n = Number(value);
    if (!Number.isInteger(n) || n < min || n > max) {
        throw new Error(`${name} muss zwischen ${min} und ${max} liegen`);
    }
    return n;
}
function safeCaptureName(value) {
    const name = node_path_1.default.basename(String(value));
    if (name !== value ||
        !/^[-a-zA-Z0-9_. ]{1,120}\.(pcap|pcapng)$/i.test(name)) {
        throw new Error("Ungültiger Capture-Dateiname");
    }
    return name;
}
function resolveCapturePath(root, name) {
    const safe = safeCaptureName(name), resolved = node_path_1.default.resolve(root, safe), base = node_path_1.default.resolve(root) + node_path_1.default.sep;
    if (!resolved.startsWith(base)) {
        throw new Error("Pfad außerhalb des Capture-Verzeichnisses");
    }
    return resolved;
}
function validateFilter(value, max = 2048) {
    const filter = String(value || "").trim();
    if (filter.length > max || filter.includes("\0") || /[\r\n]/.test(filter)) {
        throw new Error("Filter enthält ungültige Zeichen oder ist zu lang");
    }
    return filter;
}
//# sourceMappingURL=InputValidator.js.map