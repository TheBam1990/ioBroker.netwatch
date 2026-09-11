export class RingBuffer<T> {
  private items: T[] = [];
  constructor(private capacity: number) {
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new Error("capacity must be positive");
    }
  }
  push(item: T): void {
    this.items.push(item);
    if (this.items.length > this.capacity) {
      this.items.splice(0, this.items.length - this.capacity);
    }
  }
  clear(): void {
    this.items = [];
  }
  values(): T[] {
    return [...this.items];
  }
  find(predicate: (item: T) => boolean): T | undefined {
    return this.items.find(predicate);
  }
  setCapacity(capacity: number): void {
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new Error("capacity must be positive");
    }
    this.capacity = capacity;
    if (this.items.length > capacity) {
      this.items.splice(0, this.items.length - capacity);
    }
  }
  get size(): number {
    return this.items.length;
  }
}
