-- Comprehensive VM runtime test: globals, while, repeat, functions, concat
local function fact(n)
    if n <= 1 then return 1 end
    return n * fact(n - 1)
end

print("fact(5) = " .. tostring(fact(5)))

local i = 1
local sum = 0
while i <= 4 do
    sum = sum + i
    i = i + 1
end
print("while sum = " .. tostring(sum))

local j = 0
repeat
    j = j + 1
until j >= 3
print("repeat j = " .. tostring(j))

-- global write
counter = 42
print("counter = " .. tostring(counter))

-- table
local t = { 10, 20, 30 }
print("t[2] = " .. tostring(t[2]))
t[4] = 99
print("t[4] = " .. tostring(t[4]))
