-- examples/luau-features.lua
-- Tests all v0.1.1 Luau syntax additions

-- Type annotations
local x: number = 42
local s: string = "hello"

-- Type declaration
type Point = { x: number, y: number }

-- Export type
export type Color = { r: number, g: number, b: number }

-- Function with typed params and return type
local function add(a: number, b: number): number
    return a + b
end

-- Anonymous function with body (Bug #7 test)
local mul = function(a: number, b: number): number
    return a * b
end

-- If expression (Luau-specific)
local result = if x > 40 then "big" else "small"

-- Interp string (Luau backtick) — disabled for luau 0.601 compat
-- local name = "world"
-- local greeting = `hello {name}!`

-- Compound assignment
local count = 0
count += 1
count += 10

-- Generic for with type annotations
local total = 0
for k: string, v: number in pairs({ a = 1, b = 2 }) do
    total += v
end

-- Numeric for with type annotation
for i: number = 1, 3 do
    print("i = " .. tostring(i))
end

-- Goto and label (disabled for luau 0.601 compat test)
-- do
--     goto skip
--     print("this is skipped")
--     ::skip::
--     print("after goto")
-- end

print("add(1, 2) = " .. tostring(add(1, 2)))
print("mul(3, 4) = " .. tostring(mul(3, 4)))
print("result = " .. result)
-- print(greeting)
print("count = " .. tostring(count))
print("total = " .. tostring(total))