-- v0.6 comprehensive test script
-- Covers: functions (nested), arithmetic, strings, tables, closures, loops, if/else, upvalues
-- Outputs a single line with a deterministic checksum of all test results

local results = {}

-- 1. Basic arithmetic (exercises numbers, constants)
local function arith_test()
    local a = 42
    local b = 17
    local c = a + b * 3
    local d = (a % b) ^ 2
    local e = 100 / 8
    return c + d + e
end
results[#results + 1] = arith_test()

-- 2. String operations (exercises string constants, concat, len)
local function string_test()
    local s1 = "HelloWorld"
    local s2 = "TestSuffix"
    local s3 = s1 .. "_" .. s2
    local n = 123
    local combined = s3 .. tostring(n)
    return #combined
end
results[#results + 1] = string_test()

-- 3. Nested functions (exercises F1: recursive flattening)
local function outer()
    local x = 10
    local function inner1()
        x = x + 5
        return x
    end
    local function inner2()
        local y = x * 2
        local function inner_deep()
            return y + 3
        end
        return inner_deep()
    end
    inner1()
    inner1()
    return inner1() + inner2()
end
results[#results + 1] = outer()

-- 4. Closure with upvalues
local function make_counter(step)
    local count = 0
    return function()
        count = count + step
        return count
    end
end
do
    local c1 = make_counter(3)
    c1()
    c1()
    results[#results + 1] = c1()
    local c2 = make_counter(7)
    c2()
    results[#results + 1] = c2()
end

-- 5. Tables and loops (exercises for/while/repeat/if)
local function table_test()
    local t = {}
    for i = 1, 10 do
        t[i] = i * i
    end
    local sum = 0
    for k, v in pairs(t) do
        sum = sum + v
    end
    local product = 1
    local i = 1
    while i <= 5 do
        product = product * t[i]
        i = i + 1
    end
    return sum + product
end
results[#results + 1] = table_test()

-- 6. If/else branching
local function branch_test(x)
    if x < 0 then
        return "neg"
    elseif x == 0 then
        return "zero"
    elseif x < 10 then
        return "small"
    elseif x < 100 then
        return "medium"
    else
        return "large"
    end
end
results[#results + 1] = #branch_test(-5)
results[#results + 1] = #branch_test(0)
results[#results + 1] = #branch_test(7)
results[#results + 1] = #branch_test(50)
results[#results + 1] = #branch_test(500)

-- 7. Recursive function
local function fib(n)
    if n <= 1 then
        return n
    end
    return fib(n - 1) + fib(n - 2)
end
results[#results + 1] = fib(10)

-- 8. Table field access (settable/gettable)
local function field_test()
    local t = { name = "test_table", value = 99, nested = { depth = 2 } }
    t.newfield = 77
    t["index_key"] = t.value + t.newfield
    return t.nested.depth * 1000 + t["index_key"]
end
results[#results + 1] = field_test()

-- 9. Repeat-until loop
local function repeat_test()
    local sum = 0
    local i = 1
    repeat
        sum = sum + i
        i = i + 1
    until i > 7
    return sum
end
results[#results + 1] = repeat_test()

-- 10. Vararg function
local function vararg_sum(...)
    local args = {...}
    local s = 0
    for _, v in ipairs(args) do
        s = s + v
    end
    return s
end
results[#results + 1] = vararg_sum(10, 20, 30, 40, 50)

-- 11. Break/continue inside loop
local function loop_break_test()
    local sum = 0
    for i = 1, 100 do
        if i > 10 then break end
        if i % 2 == 0 then goto skip end
        sum = sum + i
        ::skip::
    end
    return sum
end
results[#results + 1] = loop_break_test()

-- 12. Nested if + string concat (tests F3: constant blinding on long strings)
local function secret_test()
    local api_key = "sk-12345-ABCDEFGHIJKLMNOP-secret-token"
    local url_base = "https://api.example.com/v2/service/endpoint"
    local full_url = url_base .. "/key=" .. api_key
    if #full_url > 30 then
        local hash = 0
        for i = 1, #full_url do
            local c = string.byte(full_url, i)
            hash = (hash + c * i) % 1000000
        end
        return hash
    end
    return 0
end
results[#results + 1] = secret_test()

-- 13. Higher-order function + multiple return
local function apply_twice(f, x)
    local a = f(x)
    local b = f(a)
    return a, b
end
do
    local r1, r2 = apply_twice(function(n) return n * 2 + 1 end, 5)
    results[#results + 1] = r1
    results[#results + 1] = r2
end

-- 14. do-end scoping + shadowing
local function scope_test()
    local x = 100
    do
        local x = 5
        x = x + 1
    end
    return x
end
results[#results + 1] = scope_test()

-- 15. Boolean + comparison operators
local function bool_test()
    local a = 10
    local b = 20
    local c = (a < b) and 1 or 0
    local d = (a == b) and 1 or 0
    local e = (a ~= b) and 1 or 0
    return c * 100 + d * 10 + e
end
results[#results + 1] = bool_test()

-- Compute final checksum
local total = 0
for i, v in ipairs(results) do
    total = total + v * i
end
local total_int = math.floor(total + 0.5)
local checksum_str = string.format("V06_TEST_OK|count=%d|total=%d", #results, total_int)
print(checksum_str)
