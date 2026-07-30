local function makeCounter()
  local count = 0
  return function()
    count = count + 1
    return count
  end
end
local c = makeCounter()
print(c(), c(), c())
