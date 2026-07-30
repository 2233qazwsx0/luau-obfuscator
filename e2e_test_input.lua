-- e2e test: exercises arithmetic, loops, functions, closures, conditionals, strings, tables
local function add(a, b) return a + b end
local function fib(n)
  if n < 2 then return n end
  return fib(n - 1) + fib(n - 2)
end

local function makeCounter()
  local count = 0
  return function()
    count = count + 1
    return count
  end
end

local counter = makeCounter()
print("counter:", counter(), counter(), counter())

print("add:", add(3, 4))
print("fib(10):", fib(10))

local sum = 0
for i = 1, 10 do
  sum = sum + i
end
print("sum 1..10:", sum)

local t = {}
for i = 1, 5 do
  t[i] = i * i
end
local tsum = 0
for _, v in ipairs(t) do
  tsum = tsum + v
end
print("table sum:", tsum)

local s = "hello" .. " " .. "world"
print("concat:", s)
print("len:", #s)

local x = 10
if x > 5 then
  print("big")
else
  print("small")
end

local function factorial(n)
  local result = 1
  for i = 2, n do
    result = result * i
  end
  return result
end
print("5!:", factorial(5))

print("done")
