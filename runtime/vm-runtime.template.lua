-- runtime/vm-runtime.template.lua — LVM2 runtime template (v0.4)
--
-- Decodes the packed bytecode produced by src/vm/pipeline.ts and executes it
-- on a register-based interpreter. Pure Luau, no loadstring/debug/os — runs
-- on both standalone Luau and Roblox.
--
-- Placeholders (substituted by src/vm/runtime-template.ts):
--   __HEX_BLOB__     → packed hex string (LZW + stream-cipher)
--   __CIPHER_KEY__   → stream cipher key (number 0-255)
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

  return {
    instructions = instructions,
    constants = constants,
    sub_functions = sub_functions,
    param_count = param_count,
    is_vararg = is_vararg,
    upvalues = upvalues,
  }
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

  -- Set up parameters (0-indexed registers, 1-indexed args)
  if args then
    for i = 1, proto.param_count do
      regs[i - 1] = args[i]
    end
  end

  while ip <= ncode do
    local inst = code[ip]
    local op = inst.op
    local A, B, C, D = inst.A, inst.B, inst.C, inst.D

    -- ---- Arithmetic ----
    if op == 0 or op == 18 then            -- ADD_RC: R[A] = R[B] + K[C]
      regs[A] = (regs[B] or 0) + (consts[C + 1] or 0)
    elseif op == 27 or op == 58 then       -- ADD_RR: R[A] = R[B] + R[C]
      regs[A] = (regs[B] or 0) + (regs[C] or 0)
    elseif op == 40 or op == 49 then       -- SUB_RR
      regs[A] = (regs[B] or 0) - (regs[C] or 0)
    elseif op == 59 then                   -- MUL_RR
      regs[A] = (regs[B] or 0) * (regs[C] or 0)
    elseif op == 66 then                   -- DIV_RR
      regs[A] = (regs[B] or 0) / (regs[C] or 0)
    elseif op == 15 or op == 24 then       -- MOD_RR
      regs[A] = (regs[B] or 0) % (regs[C] or 0)
    elseif op == 31 or op == 46 then       -- MOD_RC: R[A] = R[B] % K[C]
      regs[A] = (regs[B] or 0) % (consts[C + 1] or 0)
    elseif op == 78 then                   -- POW_RR
      regs[A] = (regs[B] or 0) ^ (regs[C] or 0)

    -- ---- Direct comparison (v0.4) ----
    elseif op == 72 or op == 80 then       -- EQ_RR
      regs[A] = (regs[B] == regs[C])
    elseif op == 73 then                   -- NEQ_RR
      regs[A] = (regs[B] ~= regs[C])
    elseif op == 74 then                   -- LT_RR_SET
      regs[A] = (regs[B] < regs[C])
    elseif op == 75 then                   -- LE_RR_SET
      regs[A] = (regs[B] <= regs[C])
    elseif op == 76 then                   -- GT_RR_SET
      regs[A] = (regs[B] > regs[C])
    elseif op == 77 then                   -- GE_RR_SET
      regs[A] = (regs[B] >= regs[C])

    -- ---- Data movement ----
    elseif op == 6 or op == 30 then        -- MOVE
      regs[A] = regs[B]
    elseif op == 38 or op == 56 then       -- LOADK
      regs[A] = consts[B + 1]
    elseif op == 12 or op == 43 then       -- LOADBOOL (C=2 sentinel → new table)
      if C == 2 then
        regs[A] = {}
      else
        regs[A] = (C ~= 0)
      end
    elseif op == 33 or op == 52 then       -- LEN
      regs[A] = #regs[B]
    elseif op == 26 or op == 54 then       -- CONCAT: R[A] = R[B]....R[D]
      local s = regs[B]
      for i = B + 1, D do
        s = s .. regs[i]
      end
      regs[A] = s

    -- ---- Table access ----
    elseif op == 3 or op == 47 then        -- GETFIELD_K: R[A+1]=R[B]; R[A]=R[B][K[C]]
      regs[A + 1] = regs[B]
      regs[A] = regs[B][consts[C + 1]]
    elseif op == 25 or op == 67 then       -- GETFIELD_K2: R[A] = R[B][K[C]]
      regs[A] = regs[B][consts[C + 1]]
    elseif op == 79 then                   -- GETTABLE_RR: R[A] = R[B][R[C]]
      regs[A] = regs[B][regs[C]]
    elseif op == 69 then                   -- SETTABLE: R[A][K[B]] = R[C]
      regs[A][consts[B + 1]] = regs[C]
    elseif op == 81 then                   -- SETTABLE_RR: R[A][R[B]] = R[C]
      regs[A][regs[B]] = regs[C]

    -- ---- Upvalues / Globals ----
    -- In v0.3 compiler, GETUPVAL was repurposed for global access:
    -- R[A] = env[K[B]]  (look up global by name in env table)
    elseif op == 8 or op == 20 or op == 23 or op == 64 then  -- GETUPVAL (global)
      regs[A] = env[consts[B + 1]]
    elseif op == 53 or op == 60 then       -- SETGLOBAL: env[K[B]] = R[A]
      env[consts[B + 1]] = regs[A]

    -- ---- Closures ----
    elseif op == 2 or op == 22 then        -- CLOSURE
      local sub = proto.sub_functions[B + 1]
      regs[A] = make_closure(sub, env, regs, upvals, A)
    elseif op == 28 or op == 37 then       -- CLOSURE_SIMPLE
      local sub = proto.sub_functions[B + 1]
      regs[A] = make_closure(sub, env, regs, upvals, A)
    elseif op == 82 then                   -- GETUPVAL_REAL: R[A] = upvals[B+1].v
      regs[A] = upvals[B + 1].v
    elseif op == 83 then                   -- SETUPVAL_REAL: upvals[B+1].v = R[A]
      upvals[B + 1].v = regs[A]

    -- ---- Calls ----
    -- A=callee, B=arg count, C=result count (0=discard, N=put N results in R[A..])
    elseif op == 14 then                   -- CALL_RET_N
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
    elseif op == 29 or op == 48 then       -- CALL_1RET (1 result)
      local callee = regs[A]
      local call_args = {}
      for i = 1, B do call_args[i] = regs[A + i] end
      regs[A] = callee(unpack(call_args))
    elseif op == 13 or op == 17 then       -- CALL_TAILCALL
      local callee = regs[A]
      local call_args = {}
      for i = 1, B do call_args[i] = regs[A + i] end
      return callee(unpack(call_args))

    -- ---- Returns ----
    elseif op == 55 or op == 68 then       -- RETURN0
      return
    elseif op == 44 or op == 45 then       -- RETURN_N (C = count + 1)
      local ret_vals = {}
      for i = 1, C - 1 do
        ret_vals[i] = regs[A + i - 1]
      end
      return unpack(ret_vals)
    elseif op == 36 or op == 51 then       -- RETURN_VA (treat like RETURN_N)
      local ret_vals = {}
      for i = 1, C - 1 do
        ret_vals[i] = regs[A + i - 1]
      end
      return unpack(ret_vals)

    -- ---- Control flow ----
    elseif op == 7 or op == 57 then        -- JUMP: ip += C
      ip = ip + C - 1
    elseif op == 62 then                   -- TEST_FALSE: if not R[A] → ip += C
      if not regs[A] then
        ip = ip + C - 1
      end
    elseif op == 34 or op == 42 then       -- TEST_EQ_K: if R[A]==K[C] → pc++ else pc+=C
      if regs[A] == consts[C + 1] then
        -- fall through (ip += 1)
      else
        ip = ip + C - 1
      end
    elseif op == 70 then                   -- TEST_LT_RR: if R[A]<R[B] → pc++ else pc+=C
      if regs[A] < regs[B] then
        -- fall through
      else
        ip = ip + C - 1
      end
    elseif op == 71 then                   -- TEST_LE_RR
      if regs[A] <= regs[B] then
        -- fall through
      else
        ip = ip + C - 1
      end
    elseif op == 10 or op == 61 then       -- TEST_NIL
      if not regs[B] then
        -- fall through
      else
        regs[A] = regs[B]
        ip = ip + C - 1
      end

    -- ---- Loops ----
    elseif op == 32 or op == 41 then       -- FORPREP: R[A]-=R[A+2]; ip += C
      regs[A] = (regs[A] or 0) - (regs[A + 2] or 0)
      ip = ip + C - 1
    elseif op == 21 or op == 65 then       -- FORLOOP: R[A]+=R[A+2]; if bounds → R[A+3]=R[A]; ip+=C
      regs[A] = (regs[A] or 0) + (regs[A + 2] or 0)
      local step = regs[A + 2] or 0
      local limit = regs[A + 1] or 0
      local cont = (step >= 0 and regs[A] <= limit) or (step < 0 and regs[A] >= limit)
      if cont then
        regs[A + 3] = regs[A]
        ip = ip + C - 1
      end

    -- ---- Fused compound ops (not yet implemented; compiler doesn't emit them) ----
    elseif op == 1 or op == 5 then
      error("FUSED_TAILCALL_VA not supported in v0.4 runtime")
    elseif op == 4 then
      error("FUSED_CALL_LOADK_LEN_SUB not supported in v0.4 runtime")
    elseif op == 9 then
      error("FUSED_CALL_5RET not supported in v0.4 runtime")
    elseif op == 11 then
      error("FUSED_TAILCALL_RET not supported in v0.4 runtime")
    elseif op == 16 or op == 35 or op == 39 or op == 50 then
      error("FUSED_CALL_VA_RET not supported in v0.4 runtime")
    elseif op == 19 or op == 63 then
      error("FUSED_GETFIELD_CALL_CONCAT not supported in v0.4 runtime")

    else
      error("VM: unknown opcode " .. tostring(op) .. " at ip=" .. tostring(ip))
    end

    ip = ip + 1
  end
end

-- --------------------------------------------------------------------------
-- Boot
-- --------------------------------------------------------------------------
local HEX_BLOB = "__HEX_BLOB__"
local CIPHER_KEY = __CIPHER_KEY__

local function vm_boot()
  local cipher_data = hex_to_bytes(HEX_BLOB)
  local decrypted = stream_decrypt(cipher_data, CIPHER_KEY)
  local serialized = lzw_decode(decrypted)
  local reader = make_reader(serialized)
  local proto = deserialize_proto(reader)
  -- Environment: a WRITABLE table that falls through to _G for reads.
  -- Luau's _G is read-only, so SETGLOBAL (env[k]=v) would crash if env were
  -- _G directly. The __index proxy keeps globals like print/tostring/game
  -- visible while letting the script declare its own globals.
  local env = setmetatable({}, { __index = _G })
  vm_execute(proto, env, {}, {})
end

vm_boot()
