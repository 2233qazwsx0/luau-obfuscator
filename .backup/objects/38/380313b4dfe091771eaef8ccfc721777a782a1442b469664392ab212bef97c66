-- examples/reference-slice.lua
--
-- A small slice that mirrors the construction style of the
-- `[混淆加密]猫猫脚本 114514.txt` reference: 32-entry dispatch table,
-- XOR-encrypted strings, bitxor'd numbers, indirect calls.
--
-- This file is the local "ground truth" that the obfuscator should NOT
-- be able to parse naively — it lets us confirm that the parser/lexer
-- at least *tries* to handle obfuscated-style input even though most of
-- the runtime machinery (the recursive VM) is out of scope for v0.1.

local dispatch = { "6", "x", "C", "2", "5", "A", "8", _G, "1", "F",
                   "4", "E", "0", "9", "7", "_", "B", "D", "3", 37 }

dispatch[10] = "gotcha"

local function dec(key)
    return function(hex)
        local out = ""
        for i = 1, #hex, 2 do
            out = out .. string.char(bit32.bxor(
                tonumber(hex:sub(i, i + 1), 16),
                (key:byte((i - 1) % 4 + 1) + (i - 1)) % 256))
        end
        return out
    end
end

local k = "ABCD"
local s = dec(k)("6E6F6368756E")

print(s)
print(dispatch[10])
