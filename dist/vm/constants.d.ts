import { type ConstEntry } from "./opcodes.js";
export declare class ConstantPool {
    private entries;
    private indexMap;
    /** Returns the index of a constant in the pool, adding it if new. */
    add(entry: ConstEntry): number;
    /** Add a string constant, return its index. */
    addString(value: string): number;
    /** Add a boolean constant, return its index. */
    addBool(value: boolean): number;
    /** Add a number constant, return its index. */
    addNumber(value: number): number;
    /** Get all entries in order. */
    getAll(): ConstEntry[];
    /** Number of constants. */
    size(): number;
    /** Get the type tag for the bytecode reader (0=string, 1=bool, 2=number). */
    static typeTag(entry: ConstEntry): number;
}
