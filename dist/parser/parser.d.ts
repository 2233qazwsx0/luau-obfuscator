import { type Token } from "./tokens.js";
export type Node = {
    t: "Block";
    body: Node[];
    line: number;
} | {
    t: "Local";
    names: string[];
    types: (string | null)[];
    values: Node[] | null;
    line: number;
} | {
    t: "Assign";
    targets: Node[];
    values: Node[];
    line: number;
} | {
    t: "If";
    branches: {
        cond: Node;
        block: Node;
    }[];
    else?: Node;
    line: number;
} | {
    t: "While";
    cond: Node;
    block: Node;
    line: number;
} | {
    t: "Repeat";
    block: Node;
    cond: Node;
    line: number;
} | {
    t: "For";
    varName: string;
    varType: string | null;
    start: Node;
    stop: Node;
    step: Node | null;
    block: Node;
    line: number;
} | {
    t: "ForIn";
    names: string[];
    types: (string | null)[];
    iter: Node[];
    block: Node;
    line: number;
} | {
    t: "Function";
    name: {
        parts: string[];
        method?: string;
    };
    params: string[];
    paramTypes: (string | null)[];
    retType: string | null;
    body: Node;
    isLocal?: boolean;
    line: number;
} | {
    t: "Return";
    values: Node[];
    line: number;
} | {
    t: "Call";
    callee: Node;
    args: Node[];
    line: number;
} | {
    t: "Method";
    name: string;
    callee: Node;
    args: Node[];
    line: number;
} | {
    t: "Do";
    block: Node;
    line: number;
} | {
    t: "Break";
    line: number;
} | {
    t: "Continue";
    line: number;
} | {
    t: "Goto";
    label: string;
    line: number;
} | {
    t: "Label";
    name: string;
    line: number;
} | {
    t: "TypeDecl";
    name: string;
    exported: boolean;
    body: string;
    line: number;
} | {
    t: "Empty";
    line: number;
} | {
    t: "Nil";
    line: number;
} | {
    t: "Bool";
    value: boolean;
    line: number;
} | {
    t: "Number";
    value: string;
    line: number;
} | {
    t: "String";
    value: string;
    line: number;
} | {
    t: "Interp";
    parts: Node[];
    line: number;
} | {
    t: "IfExpr";
    cond: Node;
    then: Node;
    else: Node;
    line: number;
} | {
    t: "Ident";
    name: string;
    line: number;
} | {
    t: "Vararg";
    line: number;
} | {
    t: "Index";
    obj: Node;
    index: Node;
    line: number;
} | {
    t: "Unop";
    op: string;
    arg: Node;
    line: number;
} | {
    t: "Binop";
    op: string;
    lhs: Node;
    rhs: Node;
    line: number;
} | {
    t: "Concat";
    parts: Node[];
    line: number;
} | {
    t: "Table";
    fields: {
        key: Node | null;
        value: Node;
    }[];
    line: number;
} | {
    t: "Function";
    params: string[];
    paramTypes: (string | null)[];
    retType: string | null;
    body: Node;
    vararg: boolean;
    line: number;
};
export declare function parse(tokens: Token[]): Node;
