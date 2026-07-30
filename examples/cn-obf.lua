local _B=(function()
local function bx(_a,_b)
  _a,_b=math.floor(_a),math.floor(_b)
  local _r=0
  local _s=1
  while _a>0 or _b>0 do
    if (_a%2)~=(_b%2) then _r=_r+_s end
    _a=math.floor(_a/2)
    _b=math.floor(_b/2)
    _s=_s*2
  end
  return _r
end
return{bx=bx}
end)().bx
print(((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({172,114,49,96}))("968ACF49E0B18006F1D2C522"))