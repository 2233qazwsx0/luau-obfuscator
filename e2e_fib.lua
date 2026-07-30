local function fib(n)
  if n < 2 then return n end
  return fib(n - 1) + fib(n - 2)
end
print("fib(5):", fib(5))
print("fib(10):", fib(10))
