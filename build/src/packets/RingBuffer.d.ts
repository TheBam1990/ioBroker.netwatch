export declare class RingBuffer<T> {
    private capacity;
    private items;
    constructor(capacity: number);
    push(item: T): void;
    clear(): void;
    values(): T[];
    find(predicate: (item: T) => boolean): T | undefined;
    setCapacity(capacity: number): void;
    get size(): number;
}
