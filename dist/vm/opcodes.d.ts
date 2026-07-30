export declare enum Op {
    ADD_RC = "ADD_RC",// R[A] = R[B] + K[C]
    ADD_RR = "ADD_RR",// R[A] = R[B] + R[C]
    SUB_RR = "SUB_RR",// R[A] = R[B] - R[C]
    MOD_RR = "MOD_RR",// R[A] = R[B] % R[C]
    MOD_RC = "MOD_RC",// R[A] = R[B] % K[C]
    MUL_RR = "MUL_RR",// R[A] = R[B] * R[C]
    DIV_RR = "DIV_RR",// R[A] = R[B] / R[C]
    MOVE = "MOVE",// R[A] = R[B]
    LOADK = "LOADK",// R[A] = K[B]
    LOADBOOL = "LOADBOOL",// R[A] = (C ~= 0)
    LEN = "LEN",// R[A] = #R[B]
    CONCAT = "CONCAT",// R[A] = R[B] .. R[B+1] .. ... .. R[D]
    GETFIELD_K = "GETFIELD_K",// R[A+1] = R[B]; R[A] = R[B][K[C]]  (also SELF-like)
    GETFIELD_K2 = "GETFIELD_K2",// R[A] = R[B][K[C]]  (simple field access)
    SETTABLE = "SETTABLE",// R[A][K[B]] = R[C]  (table field store)
    GETUPVAL = "GETUPVAL",// R[A] = Upvalues[B]
    SETGLOBAL = "SETGLOBAL",// G[K[B]] = R[A]
    CLOSURE = "CLOSURE",// R[A] = new closure from prototype[B] with upvalue captures
    CLOSURE_SIMPLE = "CLOSURE_SIMPLE",// R[A] = createClosure(prototype[B], nil, env)
    CALL_RET_N = "CALL_RET_N",// call R[A](R[A+1]..R[A+C-1]), return N results to R[A..]
    CALL_VA = "CALL_VA",// call R[A](R[A+1]..bp), variable results from aO
    CALL_1RET = "CALL_1RET",// call R[A](R[A+1]..R[A+C-1]), return 1 result (tailcall-like)
    CALL_TAILCALL = "CALL_TAILCALL",// tailcall R[A](R[A+1]..bp)
    RETURN0 = "RETURN0",// return (no values)
    RETURN_N = "RETURN_N",// return R[A], R[A+1], ..., R[A+C-2]
    RETURN_VA = "RETURN_VA",// return R[A], R[A+1], ..., R[bp] (variable)
    JUMP = "JUMP",// pc = pc + C
    TEST_EQ_K = "TEST_EQ_K",// if R[A] == K[C] then pc++ else pc += C
    TEST_LT_RR = "TEST_LT_RR",// if R[A] < R[B] then pc++ else pc += C
    TEST_LE_RR = "TEST_LE_RR",// if R[A] <= R[B] then pc++ else pc += C
    TEST_GT = "TEST_GT",// if R[A] > R[C] then pc++ else pc += C  (reg compare)
    TEST_FALSE = "TEST_FALSE",// if not R[A] then pc++ else pc += C
    TEST_NIL = "TEST_NIL",// if not R[B] then pc++ else R[A]=R[B]; pc += next[3]+1
    FORPREP = "FORPREP",// R[A] = R[A] - R[A+2]; pc += C  (numeric for prep)
    FORLOOP = "FORLOOP",// R[A] = R[A] - R[A+2]; if cond then pc += C; R[A+3] = R[A]
    EQ_RR = "EQ_RR",// R[A] = (R[B] == R[C])
    NEQ_RR = "NEQ_RR",// R[A] = (R[B] ~= R[C])
    LT_RR_SET = "LT_RR_SET",// R[A] = (R[B] <  R[C])
    LE_RR_SET = "LE_RR_SET",// R[A] = (R[B] <= R[C])
    GT_RR_SET = "GT_RR_SET",// R[A] = (R[B] >  R[C])
    GE_RR_SET = "GE_RR_SET",// R[A] = (R[B] >= R[C])
    POW_RR = "POW_RR",// R[A] = R[B] ^ R[C]
    GETTABLE_RR = "GETTABLE_RR",// R[A] = R[B][R[C]]
    SETTABLE_RR = "SETTABLE_RR",// R[A][R[B]] = R[C]
    GETUPVAL_REAL = "GETUPVAL_REAL",// R[A] = upvals[B]
    SETUPVAL_REAL = "SETUPVAL_REAL",// upvals[B] = R[A]
    FUSED_CALL_LOADK_LEN_SUB = "FUSED_CALL_LOADK_LEN_SUB",// op 4: call+noret+len+loadk+...+sub+jump
    FUSED_TAILCALL_VA = "FUSED_TAILCALL_VA",// op 5: load global+call+tailcall+return values+return
    FUSED_CALL_5RET = "FUSED_CALL_5RET",// op 9: call+add+mod+getfield+call+cmp
    FUSED_TAILCALL_RET = "FUSED_TAILCALL_RET",// op 11: call+tailcall+return
    FUSED_GETFIELD_CALL_CONCAT = "FUSED_GETFIELD_CALL_CONCAT",// op 19/63: getupval+getfield+call+concat+...
    FUSED_CALL_VA_RET = "FUSED_CALL_VA_RET"
}
export declare const OP_ALIASES: Record<number, Op>;
export declare function getAliases(op: Op): number[];
export type EncodeMode = 0 | 1 | 2 | 3;
export type Instruction = {
    op: number;
    A: number;
    B: number;
    C: number;
    D: number;
    mode: EncodeMode;
};
export interface FuncPrototype {
    instructions: Instruction[];
    constants: ConstEntry[];
    subFunctions: FuncPrototype[];
    paramCount: number;
    isVararg: boolean;
    upvalues: {
        fromStack: boolean;
        index: number;
    }[];
}
export type ConstEntry = {
    type: "string";
    value: string;
} | {
    type: "bool";
    value: boolean;
} | {
    type: "number";
    value: number;
};
export declare function pickAlias(rng: () => number, op: Op): number;
