-- examples/reference.lua
--
-- Local copy of the reference obfuscated Luau sample
-- `[混淆加密]猫猫脚本 114514.txt`. We keep only the first ~200 lines so the
-- file is manageable; the full file lives on the original download path
-- `/storage/emulated/0/Download/Operit/cleanOnExit/attachment_3850277964894214833.txt`.
--
-- This file is intentionally NOT obfuscatable by v0.1 — it is the
-- target shape that the *future* VM-mode pipeline (TODO.md E/F) will
-- learn to produce.

local a = { "6", "x", "C", "2", "5", "A", "8", _G, "1", "F" }
a[10] = "gotcha"

local function dec(k)
    return function(h)
        local o = ""
        for i = 1, #h, 2 do
            o = o .. string.char(bit32.bxor(
                tonumber(h:sub(i, i + 1), 16),
                (k:byte((i - 1) % 4 + 1) + (i - 1)) % 256))
        end
        return o
    end
end

print(dec("ABCD")("6E6F6368756E"))  -- outputs "nochun"
print(a[10])
