// src/emit/bit32_polyfill.ts — Pure-Lua bit32.bxor replacement for Roblox Luau.
//
// Roblox Luau does not ship the `bit32` library. This polyfill provides a
// drop-in `_B(a, b)` function that computes `a XOR b` using only integer
// math, so the obfuscated output runs on Roblox without modification.
export const BIT32_POLYFILL = [
  "local _B=(function()",
  "local function bx(_a,_b)",
  "  _a,_b=math.floor(_a),math.floor(_b)",
  "  local _r=0",
  "  local _s=1",
  "  while _a>0 or _b>0 do",
  "    if (_a%2)~=(_b%2) then _r=_r+_s end",
  "    _a=math.floor(_a/2)",
  "    _b=math.floor(_b/2)",
  "    _s=_s*2",
  "  end",
  "  return _r",
  "end",
  "return{bx=bx}",
  "end)().bx",
].join("\n");
