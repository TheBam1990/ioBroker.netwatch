"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RingBuffer = void 0;
class RingBuffer {
    capacity;
    items = [];
    constructor(capacity) {
        this.capacity = capacity;
        if (!Number.isInteger(capacity) || capacity < 1) {
            throw new Error("capacity must be positive");
        }
    }
    push(item) {
        this.items.push(item);
        if (this.items.length > this.capacity) {
            this.items.splice(0, this.items.length - this.capacity);
        }
    }
    clear() {
        this.items = [];
    }
    values() {
        return [...this.items];
    }
    find(predicate) {
        return this.items.find(predicate);
    }
    setCapacity(capacity) {
        if (!Number.isInteger(capacity) || capacity < 1) {
            throw new Error("capacity must be positive");
        }
        this.capacity = capacity;
        if (this.items.length > capacity) {
            this.items.splice(0, this.items.length - capacity);
        }
    }
    get size() {
        return this.items.length;
    }
}
exports.RingBuffer = RingBuffer;
//# sourceMappingURL=RingBuffer.js.map