-- Compare VM maps: dump the runtime's maps and compare with compiler output.
local seed = 12345
local VM_COUNT = 3

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

local function b32(x) return x % 4294967296 end
local function bshr(x, n) return math.floor(x / (2 ^ n)) end
local function bxor32(a, b)
  local r, p = 0, 1
  for _ = 0, 31 do
    if (math.floor(a / p) % 2) ~= (math.floor(b / p) % 2) then r = r + p end
    p = p * 2
  end
  return r
end
local function bor32(a, b)
  local r, p = 0, 1
  for _ = 0, 31 do
    if (math.floor(a / p) % 2) == 1 or (math.floor(b / p) % 2) == 1 then r = r + p end
    p = p * 2
  end
  return r
end
local function imul32(a, b)
  local al = a % 65536
  local ah = (a - al) / 65536
  local bl = b % 65536
  local bh = (b - bl) / 65536
  local p = al * bl + ((al * bh + ah * bl) % 65536) * 65536
  return p % 4294967296
end
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

local function build_vm_map(seed, vmId)
  if vmId == 0 then
    local m = {}
    for k, v in pairs(OP_ALIASES) do m[k] = v end
    return m
  end
  local keys = {}
  for k in pairs(OP_ALIASES) do keys[#keys + 1] = k end
  table.sort(keys)
  local n = #keys
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

for vm = 0, VM_COUNT - 1 do
  local m = build_vm_map(seed, vm)
  print("== VM" .. vm .. " map (op -> sem) ==")
  -- Print first 10 entries sorted by op number
  local keys = {}
  for k in pairs(m) do keys[#keys + 1] = k end
  table.sort(keys)
  for i = 1, math.min(10, #keys) do
    print(string.format("  [%d]=%s", keys[i], m[keys[i]]))
  end
end
