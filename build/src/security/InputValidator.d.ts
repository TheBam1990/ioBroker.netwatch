export declare const INTERFACE_PATTERN: RegExp;
export declare function validateInterface(value: string): string;
export declare function validateLimit(value: unknown, min: number, max: number, name: string): number;
export declare function safeCaptureName(value: string): string;
export declare function resolveCapturePath(root: string, name: string): string;
export declare function validateFilter(value: string, max?: number): string;
