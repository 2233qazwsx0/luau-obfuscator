local a = ((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((bit32.bxor(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({172,114,49,96}))("1A570EC3191611DC08560E")

local b = (bit32.bxor(1033618434, 1033618433) + (0))
for c = (bit32.bxor(1033618432, 1033618433) + (0)), b do
    print((a .. (" #" .. tostring(c))))
end

function d(a, b)
    return (a + b)
end
print((((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((bit32.bxor(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({172,114,49,96}))("4312498F44165B93") .. tostring(d((bit32.bxor(1033618432, 1033618433) + (0)), (bit32.bxor(1033618435, 1033618433) + (0))))))

if (a:sub((bit32.bxor(1033618432, 1033618433) + (0)), (bit32.bxor(1033618432, 1033618433) + (0))) == "h") then
    print(((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((bit32.bxor(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({172,114,49,96}))("014603DD024546C4134E029716"))
end