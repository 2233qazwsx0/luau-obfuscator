-- examples/hello.lua
-- Minimal smoke test for the basic obfuscator.

local greeting = "hello world"
local repeat_count = 3

for i = 1, repeat_count do
    print(greeting .. " #" .. tostring(i))
end

local function add(a, b)
    return a + b
end

print("1 + 2 = " .. tostring(add(1, 2)))

if greeting:sub(1, 1) == "h" then
    print("starts with h")
end
