-- runtime/vm-runtime.template.lua — LVM2 runtime template (v0.4)
--
-- Decodes the packed bytecode produced by src/vm/pipeline.ts and executes it
-- on a register-based interpreter. Pure Luau, no loadstring/debug/os — runs
-- on both standalone Luau and Roblox.
--
-- Placeholders (substituted by src/vm/runtime-template.ts):
--   __HEX_BLOB__     → packed hex string (LZW + stream-cipher)
--   214   → stream cipher key (number 0-255)
--
-- NOTE: the _B (bitxor) polyfill is intentionally NOT defined here. When this
-- template is self-obfuscated through the D1-D5 pipeline, the emitter prepends
-- its own _B polyfill (src/emit/bit32_polyfill.ts) which D2/D3 rely on.



-- Extract `width` bits from `value` starting at 1-indexed bit `start`.
-- Matches encoder.ts extractBits() exactly.
local function extract_bits(value, start, width)
  local shifted = value / (2 ^ (start - 1))
  local mask = 2 ^ width - 1
  return math.floor(shifted) % (mask + 1)
end

-- --------------------------------------------------------------------------
-- Hex → binary string  (mirrors packer.bytesToHex in reverse)
-- --------------------------------------------------------------------------
local function hex_to_bytes(hex)
  local out = {}
  for i = 1, #hex, 2 do
    out[#out + 1] = string.char(tonumber(string.sub(hex, i, i + 1), 16))
  end
  return table.concat(out)
end

-- --------------------------------------------------------------------------
-- Position-dependent stream decrypt  (mirrors packer.streamDecrypt)
--   decrypt[i] = cipher[i] - (key + i) % 256     (1-indexed)
-- --------------------------------------------------------------------------
local function stream_decrypt(data, key)
  local len = #data
  local out = {}
  for i = 1, len do
    local b = string.byte(data, i)
    local p = b - ((key + i) % 256)
    if p < 0 then p = p + 256 end
    out[i] = string.char(p)
  end
  return table.concat(out)
end

-- --------------------------------------------------------------------------
-- LZW decompress  (mirrors packer.lzwDecompress — base-36 variable-length)
-- --------------------------------------------------------------------------
local function lzw_decode(s)
  if #s == 0 then return "" end
  local dict = {}
  for i = 0, 255 do dict[i] = string.char(i) end
  local next_code = 256
  local pos = 1

  local function read_code()
    local len = tonumber(string.sub(s, pos, pos), 36)
    pos = pos + 1
    local code = tonumber(string.sub(s, pos, pos + len - 1), 36)
    pos = pos + len
    return code
  end

  local first = read_code()
  local prev = string.char(first)
  local result = { prev }

  while pos <= #s do
    local code = read_code()
    local entry
    if code < next_code then
      entry = dict[code]
    elseif code == next_code then
      entry = prev .. string.sub(prev, 1, 1)
    else
      error("LZW: invalid code " .. tostring(code) .. " at dict " .. tostring(next_code))
    end
    result[#result + 1] = entry
    dict[next_code] = prev .. string.sub(entry, 1, 1)
    next_code = next_code + 1
    prev = entry
  end

  return table.concat(result)
end

-- --------------------------------------------------------------------------
-- Byte reader over a binary string
-- --------------------------------------------------------------------------
local function make_reader(data)
  local state = { pos = 1 }
  local function u8()
    local b = string.byte(data, state.pos)
    state.pos = state.pos + 1
    return b
  end
  local function u32()
    local b0, b1, b2, b3 = string.byte(data, state.pos, state.pos + 3)
    state.pos = state.pos + 4
    return (b0 or 0) + (b1 or 0) * 256 + (b2 or 0) * 65536 + (b3 or 0) * 16777216
  end
  local function f64()
    local b0, b1, b2, b3, b4, b5, b6, b7 = string.byte(data, state.pos, state.pos + 7)
    state.pos = state.pos + 8
    local lo = (b0 or 0) + (b1 or 0) * 256 + (b2 or 0) * 65536 + (b3 or 0) * 16777216
    local hi = (b4 or 0) + (b5 or 0) * 256 + (b6 or 0) * 65536 + (b7 or 0) * 16777216
    local sign = (hi >= 0x80000000) and -1 or 1
    local hi_no_sign = hi % 0x80000000
    local exp_raw = math.floor(hi_no_sign / 0x100000)
    local mant_hi = hi_no_sign % 0x100000
    local mant = mant_hi * 0x100000000 + lo
    if exp_raw == 0 then
      if mant == 0 then return sign * 0 end
      return sign * mant * (2 ^ -1074)
    elseif exp_raw == 0x7FF then
      if mant == 0 then return sign * math.huge end
      return 0 / 0
    else
      return sign * (1 + mant * (2 ^ -52)) * (2 ^ (exp_raw - 1023))
    end
  end
  local function str()
    local len = u8()
    if len == 0xFF then len = u32() end
    local s = string.sub(data, state.pos, state.pos + len - 1)
    state.pos = state.pos + len
    return s
  end
  return {
    u8 = u8,
    u32 = u32,
    f64 = f64,
    str = str,
    pos = function() return state.pos end,
    seek = function(p) state.pos = p end,
    sub = function(off, len) return string.sub(data, off, off + len - 1) end,
  }
end

-- --------------------------------------------------------------------------
-- Instruction decoder  (inverse of encoder.encodeInstruction)
-- --------------------------------------------------------------------------
local function decode_insn(b8, b9)
  local mode = extract_bits(b8, 1, 2)
  local op = extract_bits(b9, 1, 11)
  local A = extract_bits(b8, 3, 9)
  local B, C, D = 0, 0, 0
  if mode == 0 then
    B = extract_bits(b9, 12, 9)
    C = extract_bits(b8, 12, 9)
    D = extract_bits(b8, 21, 9)
  elseif mode == 1 then
    B = extract_bits(b8, 12, 9)
    C = extract_bits(b9, 12, 22)
  elseif mode == 2 then
    B = extract_bits(b8, 12, 9)
    C = extract_bits(b9, 12, 21) - 1048575
  elseif mode == 3 then
    B = extract_bits(b8, 12, 9)
    C = extract_bits(b9, 12, 21) - 1048575
    D = extract_bits(b8, 21, 9)
  end
  return { op = op, A = A, B = B, C = C, D = D, mode = mode }
end

-- --------------------------------------------------------------------------
-- Function prototype deserializer  (inverse of encoder.serializeFunction)
-- --------------------------------------------------------------------------
local function deserialize_proto(reader)
  local num_insns = reader.u32()
  local instructions = {}
  for i = 1, num_insns do
    local b8 = reader.u32()
    local b9 = reader.u32()
    instructions[i] = decode_insn(b8, b9)
  end

  local num_consts = reader.u32()
  local constants = {}
  for i = 1, num_consts do
    local tag = reader.u8()
    if tag == 0 then
      constants[i] = reader.str()
    elseif tag == 1 then
      constants[i] = reader.u8() ~= 0
    else
      constants[i] = reader.f64()
    end
  end

  local param_count = reader.u8()
  local is_vararg = reader.u8() ~= 0

  local num_subs = reader.u32()
  local sub_functions = {}
  for i = 1, num_subs do
    local sub_len = reader.u32()
    local sub_start = reader.pos()
    local sub_data = reader.sub(sub_start, sub_len)
    local sub_reader = make_reader(sub_data)
    sub_functions[i] = deserialize_proto(sub_reader)
    reader.seek(sub_start + sub_len)
  end

  local num_upvals = reader.u8()
  local upvalues = {}
  for i = 1, num_upvals do
    local from_stack = reader.u8() ~= 0
    local idx = reader.u8()
    upvalues[i] = { from_stack = from_stack, index = idx }
  end

  -- v0.8 多 VM：函数默认 VM 编号（0/1/2）。旧字节码没有该字段时默认 0。
  local vm_id = reader.u8() or 0

  return {
    instructions = instructions,
    constants = constants,
    sub_functions = sub_functions,
    param_count = param_count,
    is_vararg = is_vararg,
    upvalues = upvalues,
    vm_id = vm_id,
  }
end

-- --------------------------------------------------------------------------
-- v0.8 多 VM：opcode 映射表构建
-- --------------------------------------------------------------------------
-- 与 src/vm/opcodes.ts 的 buildVmOpMap 完全对齐：VM0 复用标准 OP_ALIASES；
-- VM1/VM2 用 seed 派生的 Fisher-Yates 置换重新分配 op 号 → 语义。运行时
-- vm_execute 用 vm_maps[current_vm][op] 把字节码里的 op 号翻译成语义字符串，
-- 再按语义 dispatch。同一语义在 3 个 VM 下对应不同 op 号 → 攻击者必须同时
-- 逆向 3 套映射表。
local VM_SEED = 12345
local VM_COUNT = 3
local OP_SWITCH_VM = 200
local OP_DEAD_VM = 201

-- 标准 op→sem 表（VM0），与 OP_ALIASES 完全一致（84 条，键 0..83）。
local OP_ALIASES = {
  [0]="ADD_RC", [1]="FUSED_TAILCALL_VA", [2]="CLOSURE", [3]="GETFIELD_K",
  [4]="FUSED_CALL_LOADK_LEN_SUB", [5]="FUSED_TAILCALL_VA", [6]="MOVE",
  [7]="JUMP", [8]="GETUPVAL", [9]="FUSED_CALL_5RET", [10]="TEST_NIL",
  [11]="FUSED_TAILCALL_RET", [12]="LOADBOOL", [13]="CALL_TAILCALL",
  [14]="CALL_RET_N", [15]="MOD_RR", [16]="FUSED_CALL_VA_RET",
  [17]="CALL_TAILCALL", [18]="ADD_RC", [19]="FUSED_GETFIELD_CALL_CONCAT",
  [20]="GETUPVAL", [21]="FORLOOP", [22]="CLOSURE", [23]="GETUPVAL",
  [24]="MOD_RR", [25]="GETFIELD_K2", [26]="CONCAT", [27]="ADD_RR",
  [28]="CLOSURE_SIMPLE", [29]="CALL_1RET", [30]="MOVE", [31]="MOD_RC",
  [32]="FORPREP", [33]="LEN", [34]="TEST_EQ_K", [35]="FUSED_CALL_VA_RET",
  [36]="RETURN_VA", [37]="CLOSURE_SIMPLE", [38]="LOADK",
  [39]="FUSED_CALL_VA_RET", [40]="SUB_RR", [41]="FORPREP", [42]="TEST_EQ_K",
  [43]="LOADBOOL", [44]="RETURN_N", [45]="RETURN_N", [46]="MOD_RC",
  [47]="GETFIELD_K", [48]="CALL_1RET", [49]="SUB_RR", [50]="FUSED_CALL_VA_RET",
  [51]="RETURN_VA", [52]="LEN", [53]="SETGLOBAL", [54]="CONCAT",
  [55]="RETURN0", [56]="LOADK", [57]="JUMP", [58]="ADD_RR", [59]="MUL_RR",
  [60]="SETGLOBAL", [61]="TEST_NIL", [62]="TEST_FALSE",
  [63]="FUSED_GETFIELD_CALL_CONCAT", [64]="GETUPVAL", [65]="FORLOOP",
  [66]="DIV_RR", [67]="GETFIELD_K2", [68]="RETURN0", [69]="SETTABLE",
  [70]="TEST_LT_RR", [71]="TEST_LE_RR", [72]="EQ_RR", [73]="NEQ_RR",
  [74]="LT_RR_SET", [75]="LE_RR_SET", [76]="GT_RR_SET", [77]="GE_RR_SET",
  [78]="POW_RR", [79]="GETTABLE_RR", [80]="EQ_RR", [81]="SETTABLE_RR",
  [82]="GETUPVAL_REAL", [83]="SETUPVAL_REAL",
}

-- 把任意整数规范化到 [0, 2^32)（按位运算结果归一为无符号）。
local function b32(x) return x % 4294967296 end

-- 32 位逻辑右移（x 视为无符号）。用纯算术实现，避免 Luau 按位运算符
-- （混淆器自解析阶段词法器不识别 | / &，这里统一用算术风格，与 extract_bits 一致）。
local function bshr(x, n) return math.floor(x / (2 ^ n)) end

-- 32 位按位异或（逐位算术）。a, b ∈ [0, 2^32)。
local function bxor32(a, b)
  local r, p = 0, 1
  for _ = 0, 31 do
    if (math.floor(a / p) % 2) ~= (math.floor(b / p) % 2) then r = r + p end
    p = p * 2
  end
  return r
end

-- 32 位按位或。
local function bor32(a, b)
  local r, p = 0, 1
  for _ = 0, 31 do
    if (math.floor(a / p) % 2) == 1 or (math.floor(b / p) % 2) == 1 then r = r + p end
    p = p * 2
  end
  return r
end

-- 32 位无符号乘法（低 32 位）。拆 16 位半字避开 double 精度丢失，
-- 等价于 TS 端 Math.imul 的低 32 位比特模式。
local function imul32(a, b)
  local al = a % 65536
  local ah = (a - al) / 65536
  local bl = b % 65536
  local bh = (b - bl) / 65536
  local p = al * bl + ((al * bh + ah * bl) % 65536) * 65536
  return p % 4294967296
end

-- mulberry32，与 src/util/prng.ts 完全一致（用上面的算术按位助手复刻）。
local function mulberry32(seed)
  local s = b32(seed)
  return function()
    s = b32(s + 0x6D2B79F5)
    local t = s
    t = imul32(bxor32(t, bshr(t, 15)), bor32(t, 1))
    t = bxor32(t, b32(t + imul32(bxor32(t, bshr(t, 7)), bor32(t, 61))))
    return b32(bxor32(t, bshr(t, 14))) / 4294967296
  end
end

-- 构建指定 VM 的 op→sem 反查表。与 buildVmOpMap 对齐。
local function build_vm_map(seed, vmId)
  if vmId == 0 then
    local m = {}
    for k, v in pairs(OP_ALIASES) do m[k] = v end
    return m
  end
  -- 收集 OP_ALIASES 的键并升序排列（与 TS Object.entries sort 一致）。
  local keys = {}
  for k in pairs(OP_ALIASES) do keys[#keys + 1] = k end
  table.sort(keys)
  local n = #keys
  -- order[i] = 第 i 个 op 号（升序）。Fisher-Yates 打乱后赋值语义。
  local order = {}
  for i = 1, n do order[i] = keys[i] end
  local rng = mulberry32(b32(bxor32(seed, 0x5AA00000) + vmId * 0x9E3779B1))
  for i = n, 2, -1 do
    local j = math.floor(rng() * i) + 1
    order[i], order[j] = order[j], order[i]
  end
  local m = {}
  for i = 1, n do
    m[order[i]] = OP_ALIASES[keys[i]]
  end
  return m
end

-- vm_maps[vmId] = op→sem 表。在 vm_boot 里赋值，vm_execute 作为 upvalue 引用。
local vm_maps

local function build_vm_maps(seed)
  local maps = {}
  for vm = 0, VM_COUNT - 1 do
    maps[vm] = build_vm_map(seed, vm)
  end
  return maps
end

-- --------------------------------------------------------------------------
-- VM execution engine — 70+ opcode dispatch
-- --------------------------------------------------------------------------
-- Forward declare vm_execute so make_closure can reference it (Lua locals
-- are not in scope before their declaration line).
local vm_execute

-- Builds a closure for a sub-prototype, capturing its upvalues. Stack
-- upvalues are boxed (1-slot tables) so SETUPVAL_REAL writes are visible.
-- After binding, we sync any upvalue that referenced the closure's OWN
-- destination register — this makes `local function f()` recursion work
-- (the box sees the just-assigned closure).
local function make_closure(sub, env, regs, upvals, destReg)
  local captured = {}
  for i, uv in ipairs(sub.upvalues) do
    if uv.from_stack then
      captured[i] = { v = regs[uv.index] }
    else
      captured[i] = upvals[uv.index + 1]
    end
  end
  local cl = function(...)
    return vm_execute(sub, env, captured, { ... })
  end
  for i, uv in ipairs(sub.upvalues) do
    if uv.from_stack and uv.index == destReg then
      captured[i].v = cl
    end
  end
  return cl
end

function vm_execute(proto, env, upvals, args)
  local regs = {}
  local ip = 1
  local code = proto.instructions
  local consts = proto.constants
  local ncode = #code
  -- v0.8：当前 VM 编号。从 proto.vm_id 起步，遇到 SWITCH_VM (op 200) 切换。
  local current_vm = proto.vm_id or 0
  local maps = vm_maps

  -- Set up parameters (0-indexed registers, 1-indexed args)
  if args then
    for i = 1, proto.param_count do
      regs[i - 1] = args[i]
    end
  end

  while ip <= ncode do
    local inst = code[ip]
    local op = inst.op

    -- v0.8：保留 op 号优先 dispatch（不参与各 VM 的 op 映射）。
    if op == OP_SWITCH_VM then             -- SWITCH_VM: current_vm = C
      current_vm = inst.C
    elseif op == OP_DEAD_VM then           -- DEAD_VM：诱饵，真执行到即报错
      error("VM: reached DEAD_VM decoy at ip=" .. tostring(ip))
    else
      -- 用当前 VM 的 op→sem 反查表把 op 号翻译成语义字符串再 dispatch。
      local sem = maps[current_vm][op]
      local A, B, C, D = inst.A, inst.B, inst.C, inst.D

      -- ---- Arithmetic ----
      if sem == "ADD_RC" then              -- R[A] = R[B] + K[C]
        regs[A] = (regs[B] or 0) + (consts[C + 1] or 0)
      elseif sem == "ADD_RR" then          -- R[A] = R[B] + R[C]
        regs[A] = (regs[B] or 0) + (regs[C] or 0)
      elseif sem == "SUB_RR" then
        regs[A] = (regs[B] or 0) - (regs[C] or 0)
      elseif sem == "MUL_RR" then
        regs[A] = (regs[B] or 0) * (regs[C] or 0)
      elseif sem == "DIV_RR" then
        regs[A] = (regs[B] or 0) / (regs[C] or 0)
      elseif sem == "MOD_RR" then
        regs[A] = (regs[B] or 0) % (regs[C] or 0)
      elseif sem == "MOD_RC" then          -- R[A] = R[B] % K[C]
        regs[A] = (regs[B] or 0) % (consts[C + 1] or 0)
      elseif sem == "POW_RR" then
        regs[A] = (regs[B] or 0) ^ (regs[C] or 0)

      -- ---- Direct comparison (v0.4) ----
      elseif sem == "EQ_RR" then
        regs[A] = (regs[B] == regs[C])
      elseif sem == "NEQ_RR" then
        regs[A] = (regs[B] ~= regs[C])
      elseif sem == "LT_RR_SET" then
        regs[A] = (regs[B] < regs[C])
      elseif sem == "LE_RR_SET" then
        regs[A] = (regs[B] <= regs[C])
      elseif sem == "GT_RR_SET" then
        regs[A] = (regs[B] > regs[C])
      elseif sem == "GE_RR_SET" then
        regs[A] = (regs[B] >= regs[C])

      -- ---- Data movement ----
      elseif sem == "MOVE" then
        regs[A] = regs[B]
      elseif sem == "LOADK" then
        regs[A] = consts[B + 1]
      elseif sem == "LOADBOOL" then        -- C=2 sentinel → new table
        if C == 2 then
          regs[A] = {}
        else
          regs[A] = (C ~= 0)
        end
      elseif sem == "LEN" then
        regs[A] = #regs[B]
      elseif sem == "CONCAT" then          -- R[A] = R[B]....R[D]
        local s = regs[B]
        for i = B + 1, D do
          s = s .. regs[i]
        end
        regs[A] = s

      -- ---- Table access ----
      elseif sem == "GETFIELD_K" then      -- R[A+1]=R[B]; R[A]=R[B][K[C]]
        regs[A + 1] = regs[B]
        regs[A] = regs[B][consts[C + 1]]
      elseif sem == "GETFIELD_K2" then     -- R[A] = R[B][K[C]]
        regs[A] = regs[B][consts[C + 1]]
      elseif sem == "GETTABLE_RR" then     -- R[A] = R[B][R[C]]
        regs[A] = regs[B][regs[C]]
      elseif sem == "SETTABLE" then        -- R[A][K[B]] = R[C]
        regs[A][consts[B + 1]] = regs[C]
      elseif sem == "SETTABLE_RR" then     -- R[A][R[B]] = R[C]
        regs[A][regs[B]] = regs[C]

      -- ---- Upvalues / Globals ----
      -- GETUPVAL 被编译器复用为全局访问：R[A] = env[K[B]]
      elseif sem == "GETUPVAL" then
        regs[A] = env[consts[B + 1]]
      elseif sem == "SETGLOBAL" then       -- env[K[B]] = R[A]
        env[consts[B + 1]] = regs[A]
      elseif sem == "GETUPVAL_REAL" then   -- R[A] = upvals[B+1].v
        regs[A] = upvals[B + 1].v
      elseif sem == "SETUPVAL_REAL" then   -- upvals[B+1].v = R[A]
        upvals[B + 1].v = regs[A]

      -- ---- Closures ----
      elseif sem == "CLOSURE" or sem == "CLOSURE_SIMPLE" then
        local sub = proto.sub_functions[B + 1]
        regs[A] = make_closure(sub, env, regs, upvals, A)

      -- ---- Calls ----
      -- A=callee, B=arg count, C=result count (0=discard, N=put N results in R[A..])
      elseif sem == "CALL_RET_N" then
        local callee = regs[A]
        local results
        if B == 0 then
          results = { callee() }
        else
          local call_args = {}
          for i = 1, B do call_args[i] = regs[A + i] end
          results = { callee(unpack(call_args)) }
        end
        if C >= 1 then
          for i = 1, C do
            regs[A + i - 1] = results[i]
          end
        end
      elseif sem == "CALL_1RET" then       -- 1 result
        local callee = regs[A]
        local call_args = {}
        for i = 1, B do call_args[i] = regs[A + i] end
        regs[A] = callee(unpack(call_args))
      elseif sem == "CALL_TAILCALL" then
        local callee = regs[A]
        local call_args = {}
        for i = 1, B do call_args[i] = regs[A + i] end
        return callee(unpack(call_args))

      -- ---- Returns ----
      elseif sem == "RETURN0" then
        return
      elseif sem == "RETURN_N" then        -- C = count + 1
        local ret_vals = {}
        for i = 1, C - 1 do
          ret_vals[i] = regs[A + i - 1]
        end
        return unpack(ret_vals)
      elseif sem == "RETURN_VA" then       -- treat like RETURN_N
        local ret_vals = {}
        for i = 1, C - 1 do
          ret_vals[i] = regs[A + i - 1]
        end
        return unpack(ret_vals)

      -- ---- Control flow ----
      elseif sem == "JUMP" then            -- ip += C
        ip = ip + C - 1
      elseif sem == "TEST_FALSE" then      -- if not R[A] → ip += C
        if not regs[A] then
          ip = ip + C - 1
        end
      elseif sem == "TEST_EQ_K" then       -- if R[A]==K[C] → pc++ else pc+=C
        if regs[A] == consts[C + 1] then
          -- fall through (ip += 1)
        else
          ip = ip + C - 1
        end
      elseif sem == "TEST_LT_RR" then      -- if R[A]<R[B] → pc++ else pc+=C
        if regs[A] < regs[B] then
          -- fall through
        else
          ip = ip + C - 1
        end
      elseif sem == "TEST_LE_RR" then
        if regs[A] <= regs[B] then
          -- fall through
        else
          ip = ip + C - 1
        end
      elseif sem == "TEST_NIL" then
        if not regs[B] then
          -- fall through
        else
          regs[A] = regs[B]
          ip = ip + C - 1
        end

      -- ---- Loops ----
      elseif sem == "FORPREP" then         -- R[A]-=R[A+2]; ip += C
        regs[A] = (regs[A] or 0) - (regs[A + 2] or 0)
        ip = ip + C - 1
      elseif sem == "FORLOOP" then         -- R[A]+=R[A+2]; if bounds → R[A+3]=R[A]; ip+=C
        regs[A] = (regs[A] or 0) + (regs[A + 2] or 0)
        local step = regs[A + 2] or 0
        local limit = regs[A + 1] or 0
        local cont = (step >= 0 and regs[A] <= limit) or (step < 0 and regs[A] >= limit)
        if cont then
          regs[A + 3] = regs[A]
          ip = ip + C - 1
        end

      -- ---- Fused compound ops（编译器不发射，运行时不支持） ----
      elseif sem == "FUSED_TAILCALL_VA"
          or sem == "FUSED_CALL_LOADK_LEN_SUB"
          or sem == "FUSED_CALL_5RET"
          or sem == "FUSED_TAILCALL_RET"
          or sem == "FUSED_CALL_VA_RET"
          or sem == "FUSED_GETFIELD_CALL_CONCAT" then
        error("VM: fused op " .. tostring(sem) .. " not supported")

      else
        error("VM: unknown semantic " .. tostring(sem) .. " (op=" .. tostring(op)
            .. " vm=" .. tostring(current_vm) .. ") at ip=" .. tostring(ip))
      end
    end

    ip = ip + 1
  end
end

-- --------------------------------------------------------------------------
-- Boot
-- --------------------------------------------------------------------------
local HEX_BLOB = "090C0D0B0C0D0D10161613191A16171F191F201C1C4F1E26212727235A262C2D29295E2C32332E3331336C33663638713939703C42433F3F7B424849454580484E504B517C4E505251575754555457589E5A60605D6394606666626764A36666696BA46C6C9F6F757671A7747A7B777E7E7A7B837D83B07F7F8183848A8B8787BB8A90908D8FC89096D1939999969CD5999F9F9C9CDB9FA5A7A2A9D3A5A5DCA8AADBABB1F0AEB4F2B0B0B3B3ECB6BCEEB9C0BABCC2F8BFC6C4C2C9F3C5CCCDC8CEFDCBD2FDCED502D1D807D4DB10D7DE10DAE0E1DDDD20E0E6E8E3EBE3E6E621E9EB24ECF231EFF62FF1F1F4F431F7FD2FFA003BFDFF3800004703090B060D0708080B0C0B0E14161057131A4E161916191F1F1C1C561F2162222828252D2C282E2E2B2C342E2E32313737343C65373D3D3A41793D4444404888434A47464E47494F4F4C53814F5651525A995454575E915A608E5D636360649B63696A666EA0696F6F6BA56E9E747171B0747CB9767678AC7B83AD7D7D8080C183898A86878B8990CF8C94908E8E9192C3949C94979E9E99D39CA3D49FA6D2A2A8A8A4E1A7AEDDAADAE3ACACAFB0B5B2E2B6B5E5EBB8BEBFBBC3F9BEC4C4C1C1C3C4CBFCC7C70ACAD20CCCCCCFD0D7D20210D5D51AD8DEDFDBDB1CDEE61CE1E31CE41416E619E9EFF0EC1D29EFF5F5F2F233F5FB2AF82939FB0102FEFE0001094804350707373A0A11400D14141010121344471648181919551C4D641E1E2129612323262A622930302C5E5F2F616432383835673D383F6E3B6C6F3D3D3F844248494546494879924B7C7F4E4E95515459545A5A57585F5A8B935D5DA660919E636BA36668A16970B26BB06E76A27078737AA475AA78A9A97A7A7D7D7F80818883B5BC868CC489BBC48C92938FC1CD92989895C7D598C9CD9BCECC9D9DA0D2E3A3D5E8A6D8EDA9DAE7ACB4B3AFB1EAB2E5ECB5E8BDB8B9EFBBC1C1BEBFF1C1F20BC4C503C7CDCECAD2CACDFD04D0D615D3D612D6DCDCD9D90FDCDF13DF1216E2E8E9E41EE7ED2EEA1D25ED1F31F0F733F3242CF627F6F9003BFC2EFEFF300402090405383D0839100B11120E4150104A131A55161716194D1E1C4C5B1F5351222324255569282E6C2B2D662E606A3033333B67366A7038723B6B7C3E718441474744454A474F474A4B7D4D547E50508153878F565C5D595A5F5C905E5E5E6194A5649968676F676A6BA16DA27570767773A87676A77E797CC07C82827F80BA82B7B4858D858889C38BC0C58E949491C6C794C59C979B9B9AA0DF9DA3A4A0A0D1A3D5D6A6D7A6A9D9E7ACE0E3AFB6E5B2B3F5B5EAE7B8BEBFBBEFC4BDBDBFF9C2F200C5C604C8CC0BCBD1D1CD01D004D0D3070AD60807D9E115DC0E14DFE5E5E2181DE5EBECE8E929EB1B2FEE2132F1F32CF4273CF7FDFDFA2E43FD030300360603333D06373F090B090C413E0F4553121954154B46184C4A1B1D231E5225215562242624275C2F2A322A2D6336303136333833363C3C396F7D3B3B3E3E6F41718B44784B477C7B4A51514D814D508057538556565D58595B905C8F915F65666292A365986D689D9C6B72AB6E74737172797479BB777D7D7A7CAF7DAEBB80B1C0838BB78585878F8A92BE8DC4CF90C1C593C8D19595989AD79BCED09ED2A7A1D1DFA4D7ACA7DCEFAAE2DDADE0B2B0B7E1B3EAF8B5FAB7BFBAC0BFBDF5C2BFF4C2F9FCC5F6FAC8CCFBCBFEFDCED6D3D1D8D3D4D61BD70E1ADAE0E0DD1111E0E0E2E31B28E5E5E8EA2BEA31ED2436EF2EF2F8F7F5F73AF82936FB2E2CFE0039013938043547070D0D0A433B0D3E53101714131B45164960191F201C54531E58215521245C6D275C5E2A302F2D61612F69326867356E3938713E3B71783E4443417745444B464778474A817F4D848C50848853558E568A8A598A625C62625F6263629669659F68686AAF6B6B6F6E747370A473ACBB7678BF79A9BD7C83C27FB8B582B8B3858A8D88B9B98AC48D92C490C8D6929295CF9A98D29F9BA1A29ED8CFA1D1DBA4DEE5A6A6A9E3DDACE6E2AFE9E7B2ECECB5EDFDB8ECBFBBC0FABEF8FDC1F9C1C4FEC8C7CEFDCA0411CD0108D0D6D6D30705D60C07D914E1DCDFDCDFDF12E21C18E51F1AE7E7EAEDECED1D31F02338F32DF9F62AFDF8F8FB0100FE3930003A033B3C06413B08420B464D0E494A111718131B161E6019505E1B1B1E555C21245424575927606F2A5E6B2D5F6A30386C33366E36696B3939743C42413E71414241444A494747844A4A8D4D5352508B8D5359595591585C9B5B615E5E6098619366649CA3679EA66A71A46D6FA870ABA273A6A9757578B3AD7B7B7D7EBAC281BCB984BBCD87C2C28AC6C78DBDCF90C9C393CF9996C7CB98CF9BA1A09EDAA7A1A1A3A4DDACA6A6A9ACADACE8E7AEAEB1B1EFB4F0E9B7F301BAEB04BDF605C0FDC3C2C2C5C5F9C80303CBFDD0CE0909D103D9D40605D7DF21DA0C0EDDE4E4E01D28E3191FE61820E9F0EBEC2721EF2B38F22FFBF528FDF83333FBFEFFFE3B3A010209043F3D0606090C0F0C3D4A0F1747124D44154D1C18534C1B4C651E5C51215F272368262E6229645B2C646E2F6B2F3263643566663839413B78773E704041714A44467F47837A4A82914C4C4F868B5290975592885859605B61605E5F5E619D99636366699F6970AE6C736E6EA971797174ACB7777FBF7AB7B37DBBC48087B683C1CD86BDC689C88A8C92948FCCC89295C995D49A98A0D59BDAA39EDDCFA1A7EBA4ABE4A7A9E2AAE6B3ADB3B6B0B6B5B3F2EEB6B7BFB9F8C1BBBBBEF7FAC1C7C7C4FB00C7020FCAD0CFCD0C11D008D6D3DB0BD6D919D90E0BDC1915DF1711E213EAE5222DE82021EB1CF3EEEF25F1F7F6F4F8FCF72C29FA3A35FCFCFF03FF020435050B0A08083E0B0D0F0E141311514A14151A1757561A1D611D1E6420262523242C26666B2968322C32332F2F353236653571763869383B7A7C3E783E417F8A447A4B47874C4A7E514D8C8E508F90538D8956959959899D5C8EA65F976562A0A56464676FA369696C6D756FA9AD72A27675767E78B8B77BBAB47E858081C0BC84B4B887C6898ACAC98DCEC590CFD293D39B96D5C899D8E09CA2A49FA0DEA2A8A7A5ACADA8E9A8ABE2EAAEECF6B1E8EDB4E4E8B7F7EABAC202BDFFEFC0C3FBC30302C6C7C6C9080ACCCF09CFD507D2DA17D51608D8DEDEDBDCE0DE1FE1E12316E4212CE7EA22EAF226EC2FEFF620F23228F5F531F838FAFB0102FE353C0105010437390746480A4A430C510F4F58121A1215535617171A1D631D4E5B20595A23655A265863296B312B2B2E6E6B313737337836663C39793C3C7D7A3F784242734A45877747864A4C854D8F56509092538D5756598D599A615C90635FA2A762A394659CA168A2706A6A6DB0A56FA972B5BA75B7AF78B2AE7BBDB87EAEC28189B984C3BF87BDCD8AC9C78DBDC790D3D693D79996CBC899C99F9CDBD79FD6D8A2D3D3A5DCE3A8DAADABADEEAEE7F8B1E4E4B4BBB6B7FABCBAFDF7BDC3C4C000F9C3C3C5C60A09C8C8CBCE12CE0FD1D1D2D9D41606D71A0CDA1313DD2123E0112AE3E6E3E6262CE91A33ECEFF4EF31F8F232F6F53AF7F839FBFAFAFD3F2F00310003063A064A4A093A0D0C13420F4F56121819155851184E491B60581E5E5E2164692357266B5F296C2C2C32332F3331327068357A3E38696D3B3E7A3E7E7A41728B44478B474D4C4A8D8C4D4D4F505454539399565C8B585B5B5B945EA1A6616161639A666B6E686A6B6BA46EB3A971A2BB7478A777BCB57AB1BA7D7FB880B7BE83BFCC868AC589CFC88C92918F93C692D7C795C6CF98DDCA9A9A9DA1D6A0E3D6A3AAA5A6AADDA9AFB0ACE6E8AFF6B2B2E3F8B5E6FDB8FFBEBBECF0BEC2F9C10702C4000AC7F9CCCACE0DCD1403D0D706D31019D610D7D90B10DC0E12DFE5E5E2181EE52B2BE82C30EBF1F1EE2734F124F9F43B2DF733FBFA3F3FFDFE0500464A030740064D0A094F4C0C480C0F174312595415481D181D181B21201E65632065235457265D64296C5C2C5E312F343732796C353C3738723B3B6D783E444541464544758E478F7E49494C50934F958252838C559B5D57575A5EA35DA35F60629B63A4A666996E696EA06C72716F74A272A3BC757AB4787E7D7B807B7EC5B381BEBB84CAC4868689D1C68CBDC18F94D692989795DDD6989E9D9B9BCF9EE6E2A1D3A6A4ACA5A7E5A9AAACE5ADF6DFB0F8EBB3B9B9B6FEFFB9B9BBBCC4BDBFC4BFC20BCBC5C6CDC8100ACBD0CDCE010DD1190AD41CD8D7DDDDDA2318DD1ADEE0E713E32CE5E62923E91A1DEC3435EFEF26F23BF9F53D2FF8402DFB4032FE2FFE0037030A360647380943520C473F0E0E11164C14481B1817174E1A1A1D2250206828235362266D6D292E5E2C70602F3631326D3835656F37763A416D3D42804074474289454C78484D7F4B944B4D4D505086539B92575656935A8A945D5D6161606065656464A66868A16BB2B26E9F6E7171A4757474AC787E7F7BB5807F7E7F88838282BD878686CE8AC0BB8E8D8EC690909398CA96DED598CC9C9B9BDD9FA4D8A2DDA5A5A7E0A8E5F0ABE1DCAEEEE7B1E5B8B4B4EFB8B7B8F1BB00FABEC5C0C2C1C2FEC509CAC9C8C907CCFDCDD0CFD0D3D4D3D417D8D7D81DDB0F20DFDEE0E4E21714E5181FE9E8EAF1EC2BF4F0EFF032F3F9F8F53EF9F8FA2CFC3E3EFF3B0102393F050B0C090808420C4A45100F0F4B13445D1616591A191A1D1D23241F5422295325572D282F6E2C2B2D6E2F37633332336F36683C3A393B813D43434140428A447575477A504B4A4C4E4E94905251528E55919E595859975D5C5F8E616061A264ACA367686F6B6A6CA86E9EB072717473757B7C7878797BBCBB7EAFC88182B8858487B788C4CE8C8B8CCA8FCBD89392939396C7CB9A999CDC9E9D9DD9A2A1A2A7A5A6ADA8F0E7ABEEEBAEEAB2B1B7B8B4B9F1B7E7FBBAEBFABEBDBEFAC105F8C5C4C6CDC8C907CBD2FECE09D6D102D9D41B1BD7DDD7DA0EE1DD1CE5E0E527E318EBE6ED17EAE9EC31ED1EF5F039F4F4F3F538F7FDFDFA3E39FD2D010034080403063607410C0A45530E0D0D48101413551C17161A5C19191C221C1E262128542357262E27292F2B2C5C702F6B313332366B366C7B39713E3D3C413D404244434A7647464B794A81824D54965094515453579A57895B5A9C635DA162616064AB64949E67699A6B6A6FA26F6E737372A2B176757A7D7A797AC17E7D7FBE81BBC384B68D878E898AD3C68DBF959092949398D596D2D8999FA09C9CD69FD4D0A2DCE4A5ABABA7EEAAACABAEADAFF4B1E1B5B4B5F3B7B9BEBBBAC0EFBEC5C5C1C5F4C4C6C7C8C7CD00CBD1D2CDD0D0D404D4D3D910D71919DADE0CDEDDE31EE0E0E3E425E6EA1BEAE9EF2DEC33EFF034F3F2F836F6F92DF9FBFEFDFC023D00023B024206050B4C093B0B0C554C0F105513121856161755191A5C1D1C226020215424232A2927572B2A2B742D30743130367434353538373E6D3B42423D74404246434B4A454A484A4C4B4D514E4F96515353548B5A565E595A9B5C5E5F5F6168636269A76667AA696B6F6C6CA9706F76767379797677AE7981807B7F7E7FBE8182C48485C788878F8A8BBCBC8D95919096D494D49798979DDB9B9EE29EA0A6A1A9A8A3ABA6A7EBA9AAF1ACADEDAFAFB3B2B2E6B5B5E8B8B8BDBCBBC3EEBFEFC3C2C2C2C6C5CB09C9CD0CCDCCD204D1D0D8D4D4D5DCD7D914DBDAE01EDEE326E1E42AE5E4EA28E8EDF0EBEDEDEFEEF624F3F2F8FCF5F5F8F83BFBFC38FE06050006030537060808090A4B0C0E110F11411312174916461A191D4C1C1D63201F27552328622626682A29312D2D2E6C30317A3433397737386A3A3E413E3D4381407F43458C47464C8A4A4F4E4D51505150569454568F5758A05A62615C8D5F616662646B65676667AE6A6A9E6D6D9E7070A174737BB478777FBB7B81AC7F7E858083828A868686C98A8991C38E8D9591909092CD96959BD9999AA19C9EA0A09FA5E3A3A3E6A6A8A6A9B1B0ABB2AEB0E1B1B2F8B4B6E5B7B8F8BABB00BDBEFDC0C10AC4C3CBC7C7C902CACB05CECDD601D1D219D4D6D8D7D817DADB22DDDFE3E0E2E7E4E3EBE7E7EC26EBEAF129EDEDEF20F2F4FAF5F635F8F939FBFDFBFEFF4200470403340B0709080B0A3B410E141411144814155518171D5B1B1C541F1E25572322535C27262D2F2B2A322E2E333631327035343B7438397F3B3C7F3E403E4143414446474782894A528A4C514F518152545555575B585A585B5C9E5F5E8F9B636294AC66966A696CAE6D6C72AC7170A2747475B67877A8BD7C7B82C3807F88B68384C386888E8A89BBCB8E8D96979192D595949AD89898989B9ECC9F9EA4E2A2A5E3A5A8E9A9A8D9EBACB0ACB0AFB7E5B4B3BCBAB6B6B8BCBCBBEDF8BFC1C1C3C2F506C5C5C9C8FBCACDCCD4D0D0D507D4D3060FD707DBDADBDCDDE023E1E0E624E4E817E7EA23EBEA1BEDEFEEF52DF3F2FAF6F6F92DF9FA41FC0403FE0101024204054C07084D09090B100E101511131214155418174A1D1C1B231F1F235222235B2625595F2A295A6B2C2C2E31313169337B3736697A3A3E6D3D3E7D4140484744458747494A4A4C4C4D4E915150818D545993575B895A959C5C605F659F62689A65AC6C68ACAD6C6B6F6F6F9FA27279A3747C77A9AA7A7AB57D85B97F87828A8286858A8C89BABA8BD58EC1959291C2CE949597DF9D99D59CDADE9FDE9FA2DCDEA5ABAEA8AEAEAAAEADB5E9B0B0EDB3BBB3B5BBB8FABDBCBBF0F9BFFEBFC1C5C5C4F90FC8CECFCB0C12CED408D1D7D8D4D4D7D7DDDEDA1B1ADD0D11DF22E2E91FE5EBEBE722EAF122EDED24F020F6F225F5FC26F83A41FCFB314400FF354103090A07063C4D0A490A0D430E11104643145553171F5E1A1A511D24551F5A23225926262D572959732C2C682F6C77333267783666363A396E823E3D737B4241774346457B844A49808C4D7E7E5150598F5454965799605A60615C5D5E5F60946263659D9C69689EA36D6C70B17076777473AB777778A97B7AB2807E867E80C883B68A8786BE8A8B8AC1D28F8EBFCB9299999695CCDD999A9C9CA2A3A09FD5D8A3D4D4A6A7D7AAA9E1AFADDEF7B0B7B7B3BAE4B6BEECBAB9F1F5BEBDC4FAC1C7C7C4C4CDC7FACECBCAD0D2CED4D4D2D10906D50606D9D8E118DC0D0DE0DF1629E4E31922E7201FEBEAEF30EFEE2422F2F834F5FBFBF8FF41FB0204FE0404013B3D0434380737510B0A413D0D3E10161713131B16486018531B21591E261E2221576626255C29292F672C69742E3231386934346E37673D3B3A73723E44444141814449444783884A51934D4D895150859555548B9558885C5C5B915E5F99A16362979C67666FA76A9D716DAAA670A0747379787576"
local FAKE_BLOB = ""
local CIPHER_KEY = 214

local function vm_boot()
  local blob = HEX_BLOB

  local cipher_data = hex_to_bytes(blob)
  local decrypted = stream_decrypt(cipher_data, CIPHER_KEY)
  local serialized = lzw_decode(decrypted)
  local reader = make_reader(serialized)
  local proto = deserialize_proto(reader)
  -- Environment: a WRITABLE table that falls through to _G for reads.
  -- Luau's _G is read-only, so SETGLOBAL (env[k]=v) would crash if env were
  -- _G directly. The __index proxy keeps globals like print/tostring/game
  -- visible while letting the script declare its own globals.
  local env = setmetatable({}, { __index = _G })

  -- v0.8：构建 3 套 VM 的 op→sem 反查表。vm_execute 通过 upvalue 引用 vm_maps。
  vm_maps = build_vm_maps(VM_SEED)


  vm_execute(proto, env, {}, {})

end

vm_boot()
