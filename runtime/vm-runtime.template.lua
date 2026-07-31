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

-- Lua 5.4 compat: unpack moved to table.unpack. Luau has both, standard Lua 5.4
-- only has table.unpack. Use whichever is available.
local unpack = table.unpack or unpack

--[[__MEMWIPE_BEGIN__]]
-- ---- v0.5 内存清理辅助函数 ----
-- 安全置空：先用全零/空值覆写，再解除引用，防止内存 dump 拿到明文残片。
-- string 不可变，但用同长全零串覆盖局部槽后原串引用计数下降，配合 GC 回收。
local function secure_nil(var)
  if type(var) == "string" then
    return string.rep("\x00", #var)
  elseif type(var) == "table" then
    local k = next(var)
    while k ~= nil do
      var[k] = nil
      k = next(var, k)
    end
    return nil
  end
  return nil
end

-- 安全触发 GC：独立 Luau 有 collectgarbage，Roblox 没有 → pcall 降级。
local function gc_trigger()
  pcall(function() collectgarbage("collect") end)
end
--[[__MEMWIPE_END__]]

--[[__ANTIDUMP_HELPERS_BEGIN__]]
-- ---- v0.5 反 dump 环境检测 + v0.10 动态检测 ----
-- 返回 true 表示疑似调试/dump/exploit 环境，应使用假数据诱饵。
-- 设计原则：误杀优先于漏杀 —— 正常 Luau/Roblox 环境绝不触发。
-- 只检测明确的 exploit/dump 工具特征，不因 debug/getfenv 存在就触发。
local function anti_dump_check()
  local detected = false

  -- 1) 已知 exploit/dump 环境的全局函数（Roblox exploit 注入、dump 工具等）
  --    这些在原生 Luau/Roblox 中不存在，只有注入工具才有。
  --    注意：loadstring/getfenv/setfenv 在原生 Luau 中存在，不能作为判据。
  pcall(function()
    local exploit_signs = {
      "hookfunction", "getrawmetatable", "setrawmetatable", "syn",
      "getgenv", "getrenv", "getreg", "getidentity",
      "dumpstring", "bytecode",
    }
    local g = getfenv and getfenv(0) or _G
    for _, name in ipairs(exploit_signs) do
      if g[name] ~= nil then
        detected = true
        break
      end
    end
  end)
  if detected then return true end

  -- 2) 活跃的 debug hook（调试器附加时 sethook 会设置钩子）
  --    原生 Luau 的 debug.gethook 返回 nil（无钩子），调试器返回非 nil。
  pcall(function()
    if type(debug) == "table" and type(debug.gethook) == "function" then
      local hook = debug.gethook()
      if hook ~= nil then
        detected = true
      end
    end
  end)
  if detected then return true end

  --[[__ANTIDUMP_DYNAMIC_CHECKS_BEGIN__]]
  -- v0.10 动态检测（3 项）：时间差 / debug hook 完整性 / 环境干净性。
  -- 任一命中即视为被调试，走 FAKE_BLOB 假路径。
  -- 3a) 时间差检测：测量 os.clock() 在固定计算循环上的耗时。
  --     正常环境 << 0.5s；调试器单步插桩会显著拉长。os.clock 不可用时跳过。
  pcall(function()
    if type(os) == "table" and type(os.clock) == "function" then
      local t0 = os.clock()
      local acc = 0
      for i = 1, 2000 do acc = acc + i end
      local dt = os.clock() - t0
      if dt > 0.5 then detected = true end
    end
  end)
  if detected then return true end

  -- 3b) debug hook 完整性：gethook/sethook 必须都是 function 且 gethook() == nil。
  --     调试器替换 debug 表或设置 hook 都会触发。
  pcall(function()
    if type(debug) ~= "table"
      or type(debug.gethook) ~= "function"
      or type(debug.sethook) ~= "function"
    then
      detected = true
    else
      local h1 = debug.gethook()
      local h2 = debug.gethook()
      if h1 ~= nil or h2 ~= nil or h1 ~= h2 then detected = true end
    end
  end)
  if detected then return true end

  -- 3c) 环境干净性：getfenv(0) 必须是 table，标准库 (string/math/pairs) 必须存在。
  --     代理/沙箱替换 _G 会破坏这些不变量。
  pcall(function()
    local g = getfenv and getfenv(0) or _G
    if type(g) ~= "table"
      or type(g.string) ~= "table"
      or type(g.math) ~= "table"
      or type(g.pairs) ~= "function"
    then
      detected = true
    end
  end)
  if detected then return true end
  --[[__ANTIDUMP_DYNAMIC_CHECKS_END__]]

  return false
end

-- v0.10 周期性轻量检测：在 vm_execute 主循环每 N 条指令调用一次。
-- 只做廉价的 hook 完整性 + 环境干净性检查（跳过耗时的时间差检测）。
-- 命中即 error() 崩溃（执行中无法替换 blob，直接终止防泄漏）。
--[[__ANTIDUMP_DYNAMIC_HELPER_BEGIN__]]
local function anti_dump_dynamic()
  local detected = false
  pcall(function()
    if type(debug) ~= "table"
      or type(debug.gethook) ~= "function"
      or type(debug.sethook) ~= "function"
    then
      detected = true
    else
      if debug.gethook() ~= nil then detected = true end
    end
  end)
  if not detected then
    pcall(function()
      local g = getfenv and getfenv(0) or _G
      if type(g) ~= "table"
        or type(g.string) ~= "table"
        or type(g.math) ~= "table"
        or type(g.pairs) ~= "function"
      then
        detected = true
      end
    end)
  end
  return detected
end
--[[__ANTIDUMP_DYNAMIC_HELPER_END__]]
--[[__ANTIDUMP_HELPERS_END__]]

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
    peek_u32 = function()
      local b0, b1, b2, b3 = string.byte(data, state.pos, state.pos + 3)
      return (b0 or 0) + (b1 or 0) * 256 + (b2 or 0) * 65536 + (b3 or 0) * 16777216
    end,
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
-- v0.6 F4 / v0.11 F6: bit 助手 + mulberry32 + 指令层加密助手
-- --------------------------------------------------------------------------
-- 必须在 deserialize_proto 之前定义：Lua 词法作用域对 local function 的前向
-- 引用会解析到 nil（global），deserialize_proto 在 F4/F6 解密路径中调用这些
-- 助手，所以它们必须先声明。
-- 与 src/vm/insncrypt.ts (rol32/ror32/f6Encrypt/f6Decrypt) 严格对齐。

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

-- v0.11 F6: 32 位循环左移 / 右移（纯算术实现，与 src/vm/insncrypt.ts rol32/ror32 对齐）。
-- n ∈ [0, 31]。ROL(x, n) = ((x << n) | (x >> (32-n))) & 0xFFFFFFFF。
local function rol32(x, n)
  x = b32(x)
  n = n % 32
  if n == 0 then return x end
  local lo = bshr(x, 32 - n)
  local hi = (x * (2 ^ n)) % 4294967296
  return bor32(hi, lo)
end

local function ror32(x, n)
  return rol32(x, 32 - (n % 32))
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

-- v0.11 F6: 派生第 i 条指令的 (k8, k9, rotB8, rotB9)。
-- 与 src/vm/insncrypt.ts perIpParams 严格对齐：
--   perIpSeed = insnSeed ^ imul(i + 1, 0x9E3779B1)
--   rng = mulberry32(perIpSeed)
--   k8 = floor(rng() * 2^32); k9 = floor(rng() * 2^32)
--   rotB8 = 1 + floor(rng() * 31); rotB9 = 1 + floor(rng() * 31)   (强制 [1,31])
local function f6_per_ip_params(insn_seed, i)
  local per_ip_seed = b32(bxor32(insn_seed, imul32(i + 1, 0x9E3779B1)))
  local rng = mulberry32(per_ip_seed)
  local k8 = math.floor(rng() * 4294967296) % 4294967296
  local k9 = math.floor(rng() * 4294967296) % 4294967296
  local rot_b8 = 1 + math.floor(rng() * 31)
  local rot_b9 = 1 + math.floor(rng() * 31)
  return k8, k9, rot_b8, rot_b9
end

-- v0.11 F6: CBC + per-IP ROL + per-IP keystream 解密。
--   plain_i = ROR(enc_i, rot_i) ^ enc_{i-1} ^ key_i
--   enc_{-1} = (iv_b8, iv_b9)
-- 与 src/vm/insncrypt.ts f6Decrypt 对齐。返回明文 (b8, b9) 数组。
local function f6_decrypt(enc_b8, enc_b9, insn_seed, iv_b8, iv_b9, num_insns)
  local plain_b8 = {}
  local plain_b9 = {}
  local prev_b8 = b32(iv_b8)
  local prev_b9 = b32(iv_b9)
  for i = 1, num_insns do
    local k8, k9, rot_b8, rot_b9 = f6_per_ip_params(insn_seed, i - 1)
    local x_b8 = bxor32(ror32(enc_b8[i], rot_b8), prev_b8)
    local x_b9 = bxor32(ror32(enc_b9[i], rot_b9), prev_b9)
    plain_b8[i] = bxor32(x_b8, k8)
    plain_b9[i] = bxor32(x_b9, k9)
    prev_b8 = b32(enc_b8[i])
    prev_b9 = b32(enc_b9[i])
  end
  return plain_b8, plain_b9
end

-- --------------------------------------------------------------------------
-- Function prototype deserializer  (inverse of encoder.serializeFunction)
-- --------------------------------------------------------------------------
-- v0.6 扩展：
--   F3: 常量盲化（num_split / str_xor），存储时 + 运行时首次访问解密并缓存
--   F4: 指令字段 XOR 加密，每 proto 独立 seed，执行时按 IP 解密
--   F5: vm_id 扩展到 0..4 (5 VM)，末尾新增 has_insn_seed/insn_seed
--   F6 (v0.11): per-IP keystream + per-IP ROL + CBC chaining + IV。
--               insn_crypt_mode 字节选择 F4 (0) / F6 (1)。F6 模式额外读 8 字节 IV。
--
-- 检测方式：读完 constants 之后，下一个 u32 == num_consts 且 num_consts >= 1 → v0.6。
local function deserialize_proto(reader)
  local num_insns = reader.u32()
  -- F4: 存加密的 (b8, b9) 对，以及（若无 seed）预解码 instructions[]
  local enc_b8 = {}
  local enc_b9 = {}
  local instructions = {}
  for i = 1, num_insns do
    local b8 = reader.u32()
    local b9 = reader.u32()
    enc_b8[i] = b8
    enc_b9[i] = b9
    instructions[i] = decode_insn(b8, b9)  -- 会在 insn_seed 存在时被覆写
  end

  local num_consts = reader.u32()
  local raw_constants = {}  -- 存储的（盲化后）原始常量
  for i = 1, num_consts do
    local tag = reader.u8()
    if tag == 0 then
      raw_constants[i] = reader.str()
    elseif tag == 1 then
      raw_constants[i] = reader.u8() ~= 0
    else
      raw_constants[i] = reader.f64()
    end
  end

  -- v0.6 格式检测
  local before_blind = reader.pos()
  local peek = reader.peek_u32()
  local is_v06 = (peek == num_consts and num_consts >= 1)
  if num_consts == 0 and peek == 0 then
    -- 边界保守判断：num_consts=0 时仍按 v0.6 解析
    is_v06 = true
  end

  local blind_descs = nil
  local constants = nil
  if is_v06 then
    -- 跳过 num_blind u32
    reader.u32()
    blind_descs = {}
    for i = 1, num_consts do
      local t = reader.u8()
      if t == 0 then
        blind_descs[i] = false
      elseif t == 1 then
        blind_descs[i] = { "num_split", reader.f64() }
      elseif t == 2 then
        local klen = reader.u8()
        local k = {}
        for j = 1, klen do k[j] = reader.u8() end
        blind_descs[i] = { "str_xor", k }
      else
        blind_descs[i] = false
      end
    end
    -- F3: 常量数组延迟解密初始化：consts[i] = nil 表示尚未解密
    constants = {}
    for i = 1, num_consts do constants[i] = nil end
  else
    -- 旧格式：无盲化
    blind_descs = nil
    constants = raw_constants
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

  -- vm_id
  local vm_id = reader.u8() or 0

  -- F4 / F6: has_insn_seed + insn_seed + (v0.11) insn_crypt_mode + IV
  local insn_seed = nil
  local insn_crypt_mode = 0  -- 0 = F4 (legacy), 1 = F6 (v0.11)
  local iv_b8, iv_b9 = 0, 0
  if is_v06 then
    local has_seed = reader.u8()
    if has_seed and has_seed ~= 0 then
      insn_seed = reader.u32()
      -- v0.11 F6: 检测 mode 字节。旧 v0.6 proto 此处已是 end-of-buffer
      -- → 默认 F4。新 v0.11 proto 此处是 0 (F4) 或 1 (F6)。
      local mode = reader.u8()
      if mode then
        insn_crypt_mode = mode
        if mode == 1 then
          -- F6 模式必读 IV (b8, b9)。
          iv_b8 = reader.u32()
          iv_b9 = reader.u32()
          if iv_b8 == nil or iv_b9 == nil then
            -- 数据不完整（被截断）→ 回退到 F4。
            insn_crypt_mode = 0
          end
        end
      end
    end
  end

  -- 指令解密：根据 insn_crypt_mode 选择 F6 或 F4。
  if insn_seed ~= nil then
    if insn_crypt_mode == 1 and iv_b8 ~= nil and iv_b9 ~= nil then
      -- F6: per-IP keystream + per-IP ROL + CBC chaining + IV。
      local plain_b8, plain_b9 = f6_decrypt(enc_b8, enc_b9, insn_seed, iv_b8, iv_b9, num_insns)
      for i = 1, num_insns do
        instructions[i] = decode_insn(plain_b8[i], plain_b9[i])
      end
    else
      -- F4: 单 mulberry32(insn_seed) 流 XOR（v0.6 legacy）。
      local rng = mulberry32(insn_seed)
      for i = 1, num_insns do
        local k8 = math.floor(rng() * 4294967296) % 4294967296
        local k9 = math.floor(rng() * 4294967296) % 4294967296
        local b8 = bxor32(enc_b8[i], k8)
        local b9 = bxor32(enc_b9[i], k9)
        instructions[i] = decode_insn(b8, b9)
      end
    end
  end

  return {
    instructions = instructions,
    constants = constants,
    _raw_constants = raw_constants,  -- F3 专用
    _blind_descs = blind_descs,     -- F3 专用 (false 表示无盲化)
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
local VM_SEED = __VM_SEED__
local VM_COUNT = 5   -- v0.6 F5: VM0-2 real, VM3-4 fake (full dispatch, inert writes)
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
-- v0.11 F6: bit 助手 + mulberry32 + f6 助手已前移到 deserialize_proto 之前，
-- 避免 Lua 词法作用域对前向 local 引用的解析问题（local function 必须先声明后使用）。

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
-- v0.6 F3: 常量盲化运行时支持
-- --------------------------------------------------------------------------
-- 对单个字符串字节逐位 XOR（单字节 key 循环）。
local function str_xor(s, key)
  local klen = #key
  if klen == 0 then return s end
  local parts = {}
  for i = 1, #s do
    local c = string.byte(s, i)
    local k = key[((i - 1) % klen) + 1] or 0
    parts[i] = string.char(bxor32(c, k) % 256)
  end
  return table.concat(parts)
end

--[[__KEYFUSE_HELPERS_BEGIN__]]
-- v0.9 keyfuse: 512 位循环 XOR（与 src/vm/keyfuse.ts xor512 对齐）。
-- data 逐字节 XOR keyBytes[i % 64]；XOR 对称，加密解密同函数。
-- keyHex 是 128 hex 字符串（512 位），运行时 hex 解析为 64 字节密钥。
local function xor_bytes_512(data, keyHex)
  local klen = #keyHex / 2
  local key = {}
  for i = 1, klen do
    key[i] = tonumber(string.sub(keyHex, (i - 1) * 2 + 1, i * 2), 16)
  end
  local out = {}
  for i = 1, #data do
    local b = string.byte(data, i)
    local k = key[((i - 1) % klen) + 1] or 0
    out[i] = string.char(bxor32(b, k) % 256)
  end
  return table.concat(out)
end
--[[__KEYFUSE_HELPERS_END__]]

--[[__RT_MIX_HELPERS_BEGIN__]]
-- v0.10 rt_deps: position-dependent ADD/SUB 层（解密链最外层）。
-- 密钥流 (token + i*31 + 7) % 256 与 stream cipher (key + i + 1) % 256 不同公式，
-- 不可折叠。token 由 #HEX_BLOB / #_kh 派生（运行时才知道），纯静态模拟无法还原。
-- 与 src/vm/rtdeps.ts rtMixDecrypt 完全对齐。
local function rt_mix_decrypt(data, token)
  local len = #data
  local out = {}
  for i = 1, len do
    local k = (token + i * 31 + 7) % 256
    local b = string.byte(data, i)
    local p = b - k
    if p < 0 then p = p + 256 end
    out[i] = string.char(p)
  end
  return table.concat(out)
end
--[[__RT_MIX_HELPERS_END__]]

-- 返回常量 i（1-indexed），首次访问时若存在 blind_desc 则解密并缓存。
-- proto.constants[i] == nil 表示首次访问（已盲化）。
local function make_const_access(proto)
  local raw = proto._raw_constants
  local descs = proto._blind_descs
  local consts = proto.constants
  if not descs then
    return function(i) return consts[i] end
  end
  return function(i)
    local v = consts[i]
    if v ~= nil then return v end
    local r = raw[i]
    local d = descs[i]
    if not d then
      consts[i] = r
      return r
    end
    if d[1] == "num_split" then
      local dec = r - d[2]
      consts[i] = dec
      return dec
    elseif d[1] == "str_xor" then
      local dec = str_xor(r, d[2])
      consts[i] = dec
      return dec
    end
    consts[i] = r
    return r
  end
end

--[[__KEYFUSE_REAL_BEGIN__]]
-- v0.9 keyfuse: 真实融合宿主定义（早期段，vm_execute 之前）。
-- _rf1/_rf2 被假 VM 分支的 junk 计算引用（作为 upvalue），同时其低 nibble
-- 承载密钥碎片。值 = magic_base + key_nibble（magic_base 为 16 的倍数）。
-- 修改 _rf1/_rf2 → junk 变更（惰性）+ 密钥碎片损坏 → 解密失败崩溃。
-- 整段由 src/vm/runtime-template.ts 用 genKeyfuseAssembly().realFusedCode 替换。
--[[__KEYFUSE_REAL_END__]]

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
  -- F3: 常量访问器（首次访问盲化常量时解密并缓存）
  local K = make_const_access(proto)
  local ncode = #code
  -- v0.8：当前 VM 编号。从 proto.vm_id 起步，遇到 SWITCH_VM (op 200) 切换。
  -- v0.6 F5：VM3/4 为假 VM（仅写入高寄存器区，真实语义保持）。
  local current_vm = proto.vm_id or 0
  local last_real_vm = (current_vm <= 2) and current_vm or 0
  local maps = vm_maps

  -- Set up parameters (0-indexed registers, 1-indexed args)
  if args then
    for i = 1, proto.param_count do
      regs[i - 1] = args[i]
    end
  end

  --[[__ANTIDUMP_DYNAMIC_RUNTIME_BEGIN__]]
  -- v0.10 周期性反调试：每 N 条指令调用 anti_dump_dynamic()，命中即 error() 崩溃。
  local __ad_cnt = 0
  --[[__ANTIDUMP_DYNAMIC_RUNTIME_END__]]

  while ip <= ncode do
    --[[__ANTIDUMP_DYNAMIC_RUNTIME_BEGIN__]]
    __ad_cnt = __ad_cnt + 1
    if __ad_cnt >= 4096 then
      __ad_cnt = 0
      if anti_dump_dynamic() then error("__ad") end
    end
    --[[__ANTIDUMP_DYNAMIC_RUNTIME_END__]]
    -- v0.6 F5：假 VM 分支 → 写入高寄存器(200..255)惰性垃圾并立即退回最近真VM。
    -- 真执行永远不会走这里；假 VM 只在不透明谓词的永假分支里 SWITCH_VM 到。
    if current_vm == 3 or current_vm == 4 then
      -- v0.9 keyfuse: junk 魔数由 __KF_JUNK1__/__KF_JUNK2__ 占位符替换。
      --   keyfuse 开启 → 替换为 _rf1/_rf2（真实融合宿主，承载密钥碎片）。
      --   keyfuse 关闭 → 替换为原始字面量 1315423911 / 2654435761。
      local junk = (ip * __KF_JUNK1__ + current_vm * __KF_JUNK2__) % 4294967296
      local iter = 3 + (junk % 5)
      for f = 1, iter do
        local ridx = 200 + ((junk + f * 17) % 56)
        regs[ridx] = ((junk * (f + 3)) % 999991) * 0.0037
      end
      current_vm = last_real_vm
    end

    local inst = code[ip]
    local op = inst.op

    -- v0.8：保留 op 号优先 dispatch（不参与各 VM 的 op 映射）。
    if op == OP_SWITCH_VM then             -- SWITCH_VM: current_vm = C
      current_vm = inst.C
      if current_vm <= 2 then last_real_vm = current_vm end
    elseif op == OP_DEAD_VM then           -- DEAD_VM：诱饵，真执行到即报错
      error("VM: reached DEAD_VM decoy at ip=" .. tostring(ip))
    else
      -- 用当前 VM 的 op→sem 反查表把 op 号翻译成语义字符串再 dispatch。
      local sem = maps[current_vm][op]
      local A, B, C, D = inst.A, inst.B, inst.C, inst.D

      -- ---- Arithmetic ----
      if sem == "ADD_RC" then              -- R[A] = R[B] + K[C]
        regs[A] = (regs[B] or 0) + (K(C + 1) or 0)
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
        regs[A] = (regs[B] or 0) % (K(C + 1) or 0)
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
        regs[A] = K(B + 1)
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
        regs[A] = regs[B][K(C + 1)]
      elseif sem == "GETFIELD_K2" then     -- R[A] = R[B][K[C]]
        regs[A] = regs[B][K(C + 1)]
      elseif sem == "GETTABLE_RR" then     -- R[A] = R[B][R[C]]
        regs[A] = regs[B][regs[C]]
      elseif sem == "SETTABLE" then        -- R[A][K[B]] = R[C]
        regs[A][K(B + 1)] = regs[C]
      elseif sem == "SETTABLE_RR" then     -- R[A][R[B]] = R[C]
        regs[A][regs[B]] = regs[C]

      -- ---- Upvalues / Globals ----
      -- GETUPVAL 被编译器复用为全局访问：R[A] = env[K[B]]
      elseif sem == "GETUPVAL" then
        regs[A] = env[K(B + 1)]
      elseif sem == "SETGLOBAL" then       -- env[K[B]] = R[A]
        env[K(B + 1)] = regs[A]
      elseif sem == "GETUPVAL_REAL" then   -- R[A] = upvals[B+1].v
        regs[A] = upvals[B + 1].v
      elseif sem == "SETUPVAL_REAL" then   -- upvals[B+1].v = R[A]
        upvals[B + 1].v = regs[A]

      -- ---- Closures ----
      elseif sem == "CLOSURE" or sem == "CLOSURE_SIMPLE" then
        local sub = proto.sub_functions[B + 1]
        if sub == nil then
          error("VM: CLOSURE sub nil! B=" .. tostring(B) .. " nsubs=" .. tostring(#proto.sub_functions) .. " ip=" .. tostring(ip) .. " vm=" .. tostring(current_vm))
        end
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
        if regs[A] == K(C + 1) then
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
--[[__BLOB_DEFS_BEGIN__]]
-- v0.7: HEX_BLOB/FAKE_BLOB 定义由 runtime-template.ts 替换。
--   碎片化开启：替换为一串顶层赋值（碎片表 + 顺序拼接 + 清空）。
--   碎片化关闭：替换为单串 local 定义。
local HEX_BLOB = "__HEX_BLOB__"
local FAKE_BLOB = "__FAKE_BLOB__"
--[[__BLOB_DEFS_END__]]
local CIPHER_KEY = __CIPHER_KEY__

--[[__KEYFUSE_BEGIN__]]
-- v0.9 keyfuse: 512 位密钥深度融合装配（晚期段，vm_boot 之前）。
-- 由 src/vm/runtime-template.ts 用 genKeyfuseAssembly().assemblyCode 替换：
--   _kh 表混存真实+假碎片宿主；D4 风格 dispatch loop 按 _B() 动态索引打散装配；
--   D5 风格死分支 case 结构与真碎片完全相同。装配出 128 hex 字符的 KEY。
-- KEY 在 vm_boot 内 xor_bytes_512 解密后立即 secure_nil 销毁。
--[[__KEYFUSE_END__]]

local function vm_boot()
  local blob = HEX_BLOB
  --[[__ANTIDUMP_BOOT_BEGIN__]]
  -- 反 dump：检测到调试环境时把真实 blob 替换为假数据诱饵。
  -- dump 出来的字节码是伪随机垃圾，无法还原程序逻辑。
  if anti_dump_check() then blob = FAKE_BLOB end
  --[[__ANTIDUMP_BOOT_END__]]

  local cipher_data = hex_to_bytes(blob)
  -- keyfuse 关闭时 dec_input = cipher_data；开启时先做 512 位 XOR 解密。
  local dec_input = cipher_data
  --[[__RT_MIX_STEP_BEGIN__]]
  -- v0.10 rt_deps: rt_mix 解密层（最外层）。token 来自 keyfuse 装配段的 _rt_tok。
  -- 必须在 xor_bytes_512 之前执行（加密顺序：xor512 → rt_mix，解密逆序）。
  dec_input = rt_mix_decrypt(dec_input, _rt_tok)
  --[[__RT_MIX_STEP_END__]]
  --[[__KEYFUSE_XOR_STEP_BEGIN__]]
  -- v0.9 keyfuse: 512 位 XOR 外层解密。KEY 由晚期装配段生成（128 hex 字符）。
  -- 解密后立即销毁 KEY，完整密钥在内存中存活时间极短。
  dec_input = xor_bytes_512(dec_input, KEY)
  --[[__KEYFUSE_XOR_STEP_END__]]
  local decrypted = stream_decrypt(dec_input, CIPHER_KEY)
  local serialized = lzw_decode(decrypted)
  local reader = make_reader(serialized)
  local proto = deserialize_proto(reader)
  -- Environment: a WRITABLE table that falls through to _G for reads.
  -- Luau's _G is read-only, so SETGLOBAL (env[k]=v) would crash if env were
  -- _G directly. The __index proxy keeps globals like print/tostring/game
  -- visible while letting the script declare its own globals.
  local env = setmetatable({}, { __index = _G })

  -- v0.6：构建 5 套 VM 的 op→sem 反查表（0/1/2 真，3/4 假）。vm_execute 通过 upvalue 引用。
  vm_maps = build_vm_maps(VM_SEED)

  --[[__MEMWIPE_BEGIN__]]
  -- 解码完成、执行前：立即清空所有中间解码数据 + 强制 GC。
  -- 此时 proto.instructions 已独立存在于内存，原始密文/明文/序列化串不再需要。
  -- dump 只能拿到反序列化后的指令数组，拿不到 LZW 解压后的完整二进制。
  -- v0.9 keyfuse: 一并销毁 KEY 与 XOR 中间结果。
  secure_nil(cipher_data)
  secure_nil(dec_input)
  secure_nil(decrypted)
  secure_nil(serialized)
  -- reader 内部持有 serialized 的引用（state.pos + data），一并清空。
  pcall(function() reader.state = nil end)
  secure_nil(reader)
  --[[__KEYFUSE_MEMWIPE_BEGIN__]]
  secure_nil(KEY)
  --[[__KEYFUSE_MEMWIPE_END__]]
  --[[__RT_MIX_MEMWIPE_BEGIN__]]
  secure_nil(_rt_tok)
  --[[__RT_MIX_MEMWIPE_END__]]
  gc_trigger()
  --[[__MEMWIPE_END__]]

  vm_execute(proto, env, {}, {})

  --[[__MEMWIPE_BEGIN__]]
  -- 执行完毕：清空指令数组 + 常量池 + 环境，再触发 GC。
  -- 此时程序已输出完毕，所有解码数据从内存消失。
  secure_nil(proto)
  secure_nil(env)
  gc_trigger()
  --[[__MEMWIPE_END__]]
end

vm_boot()
