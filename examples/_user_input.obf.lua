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
local __b = (_B(52612367, 52612481) + (0))

local c, d, out, i, len, b, p, h, j, k, code, m, n, o, q, t, b0, b1, b2, b3, y, z, E, F, G, H, I, J, K, L, M, s, P, op, A, B, C, D, R, S, T, U, V, W, X, Y, Z, aa, ab, ac, ad, ae, af, ag, ah, ai, aj, vm_execute, al, uv, am, an, ao, ap, aq, ar, sub, callee, as, call_args, ret_vals, at, au, av, aw, ax, az, aA, aB, aC, aD, aE
while true do
    if (__b == (_B(52612367, 52612481) + (0))) then
        function a(value, start, width)
            local c = (value / ((_B(52612483, 52612481) + (0)) ^ (start - (_B(52612480, 52612481) + (0)))))

            local d = (((_B(52612483, 52612481) + (0)) ^ width) - (_B(52612480, 52612481) + (0)))
            return (math[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("026C36A81A")](c) % (d + (_B(52612480, 52612481) + (0))))
        end

        __b = (_B(52612414, 52612481) + (0))
    end

    if (__b == (_B(52612414, 52612481) + (0))) then
        if false then
            local __d0 = (_B(52614478, 52612481) + (0))

            __d0 = (__d0 + (_B(52616019, 52612481) + (0)))
        end

        __b = (_B(52612586, 52612481) + (0))
    end

    if (__b == (_B(52612586, 52612481) + (0))) then
        function e(hex)
            local out = {  }
            for i = (_B(52612480, 52612481) + (0)), (# hex), (_B(52612483, 52612481) + (0)) do
                out[((# out) + (_B(52612480, 52612481) + (0)))] = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076838B5")](tonumber(string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")](hex, i, (i + (_B(52612480, 52612481) + (0)))), (_B(52612497, 52612481) + (0))))
            end
            return table[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076F37A40970")](out)
        end

        __b = (_B(52612437, 52612481) + (0))
    end

    if (__b == (_B(52612437, 52612481) + (0))) then
        function f(data, key)
            local len = (# data)

            local out = {  }
            for i = (_B(52612480, 52612481) + (0)), len do
                local b = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("06792DA2")](data, i)

                local p = (b - ((key + i) % (_B(52612225, 52612481) + (0))))

                if (p < (_B(52612481, 52612481) + (0))) then
                    p = (p + (_B(52612225, 52612481) + (0)))
                end

                out[i] = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076838B5")](p)
            end
            return table[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076F37A40970")](out)
        end

        __b = (_B(52612423, 52612481) + (0))
    end

    if (__b == (_B(52612423, 52612481) + (0))) then
        function g(s)
            if ((# s) == (_B(52612481, 52612481) + (0))) then
                return ""
            end

            local h = {  }
            for i = (_B(52612481, 52612481) + (0)), (_B(52612478, 52612481) + (0)) do
                h[i] = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076838B5")](i)
            end

            local j = (_B(52612225, 52612481) + (0))

            local k = (_B(52612480, 52612481) + (0))

            function l()
                local len = tonumber(string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")](s, k, k), (_B(52612517, 52612481) + (0)))

                k = (k + (_B(52612480, 52612481) + (0)))

                local code = tonumber(string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")](s, k, ((k + len) - (_B(52612480, 52612481) + (0)))), (_B(52612517, 52612481) + (0)))

                k = (k + len)
                return code
            end

            local m = l()

            local n = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076838B5")](m)

            local o = { n }
            while (k <= (# s)) do
                local code = l()

                local q

                if (code < j) then
                    q = h[code]
                elseif (code == j) then
                    q = (n .. string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")](n, (_B(52612480, 52612481) + (0)), (_B(52612480, 52612481) + (0))))
                else
                    error((((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("285A0EFD486D33BD0D6408AB506F0AB71130") .. (tostring(code) .. (((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("44612DE70C6D3EBF4C") .. tostring(j)))))
                end

                o[((# o) + (_B(52612480, 52612481) + (0)))] = q

                h[j] = (n .. string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")](q, (_B(52612480, 52612481) + (0)), (_B(52612480, 52612481) + (0))))

                j = (j + (_B(52612480, 52612481) + (0)))

                n = q
            end
            return table[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076F37A40970")](o)
        end

        __b = (_B(52612386, 52612481) + (0))
    end

    if (__b == (_B(52612386, 52612481) + (0))) then
        function r(data)
            local t = { [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] = (_B(52612480, 52612481) + (0)) }

            function u()
                local b = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("06792DA2")](data, t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")])

                t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] = (t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] + (_B(52612480, 52612481) + (0)))
                return b
            end

            function w()
                local b0, b1, b2, b3 = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("06792DA2")](data, t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")], (t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] + (_B(52612482, 52612481) + (0))))

                t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] = (t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] + (_B(52612485, 52612481) + (0)))
                return ((((b0 or (_B(52612481, 52612481) + (0))) + ((b1 or (_B(52612481, 52612481) + (0))) * (_B(52612225, 52612481) + (0)))) + ((b2 or (_B(52612481, 52612481) + (0))) * (_B(52678017, 52612481) + (0)))) + ((b3 or (_B(52612481, 52612481) + (0))) * (_B(35835265, 52612481) + (0))))
            end

            function x()
                local b0, b1, b2, b3, y, z, E, F = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("06792DA2")](data, t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")], (t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] + (_B(52612486, 52612481) + (0))))

                t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] = (t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] + (_B(52612489, 52612481) + (0)))

                local G = ((((b0 or (_B(52612481, 52612481) + (0))) + ((b1 or (_B(52612481, 52612481) + (0))) * (_B(52612225, 52612481) + (0)))) + ((b2 or (_B(52612481, 52612481) + (0))) * (_B(52678017, 52612481) + (0)))) + ((b3 or (_B(52612481, 52612481) + (0))) * (_B(35835265, 52612481) + (0))))

                local H = ((((y or (_B(52612481, 52612481) + (0))) + ((z or (_B(52612481, 52612481) + (0))) * (_B(52612225, 52612481) + (0)))) + ((E or (_B(52612481, 52612481) + (0))) * (_B(52678017, 52612481) + (0)))) + ((F or (_B(52612481, 52612481) + (0))) * (_B(35835265, 52612481) + (0))))

                local I = (((H >= (_B(2200096129, 52612481) + (4294967296))) and (- (_B(52612480, 52612481) + (0)))) or (_B(52612480, 52612481) + (0)))

                local J = (H % (_B(2200096129, 52612481) + (4294967296)))

                local K = math[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("026C36A81A")]((J / (_B(53661057, 52612481) + (0))))

                local L = (J % (_B(53661057, 52612481) + (0)))

                local M = ((L * (_B(52612481, 52612481) + (4294967296))) + G)

                if (K == (_B(52612481, 52612481) + (0))) then
                    if (M == (_B(52612481, 52612481) + (0))) then
                        return (I * (_B(52612481, 52612481) + (0)))
                    end
                    return ((I * M) * ((_B(52612483, 52612481) + (0)) ^ (- (_B(52611507, 52612481) + (0)))))
                elseif (K == (_B(52611710, 52612481) + (0))) then
                    if (M == (_B(52612481, 52612481) + (0))) then
                        return (I * math[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0C753EA2")])
                    end
                    return ((_B(52612481, 52612481) + (0)) / (_B(52612481, 52612481) + (0)))
                else
                    return ((I * ((_B(52612480, 52612481) + (0)) + (M * ((_B(52612483, 52612481) + (0)) ^ (- (_B(52612533, 52612481) + (0))))))) * ((_B(52612483, 52612481) + (0)) ^ (K - (_B(52612734, 52612481) + (0)))))
                end
            end

            function N()
                local len = u()

                if (len == (_B(52612478, 52612481) + (0))) then
                    len = w()
                end

                local s = string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")](data, t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")], ((t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] + len) - (_B(52612480, 52612481) + (0))))

                t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] = (t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] + len)
                return s
            end
            return { [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("1138")] = u, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11336B")] = w, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("02366D")] = x, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17742B")] = N, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] = function()
                                return t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")]
            end, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17653CAC")] = function(p)
                                t[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")] = p
            end, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")] = function(aF, len)
                                return string[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")](data, aF, ((aF + len) - (_B(52612480, 52612481) + (0))))
            end }
        end

        __b = (_B(52612595, 52612481) + (0))
    end

    if (__b == (_B(52612595, 52612481) + (0))) then
        if false then
            local __d1 = (_B(52617178, 52612481) + (0))

            __d1 = (__d1 + (_B(52609251, 52612481) + (0)))
        end

        __b = (_B(52612600, 52612481) + (0))
    end

    if (__b == (_B(52612600, 52612481) + (0))) then
        function O(T, U)
            local P = a(T, (_B(52612480, 52612481) + (0)), (_B(52612483, 52612481) + (0)))

            local op = a(U, (_B(52612480, 52612481) + (0)), (_B(52612490, 52612481) + (0)))

            local A = a(T, (_B(52612482, 52612481) + (0)), (_B(52612488, 52612481) + (0)))

            local B, C, D = (_B(52612481, 52612481) + (0)), (_B(52612481, 52612481) + (0)), (_B(52612481, 52612481) + (0))

            if (P == (_B(52612481, 52612481) + (0))) then
                B = a(U, (_B(52612493, 52612481) + (0)), (_B(52612488, 52612481) + (0)))

                C = a(T, (_B(52612493, 52612481) + (0)), (_B(52612488, 52612481) + (0)))

                D = a(T, (_B(52612500, 52612481) + (0)), (_B(52612488, 52612481) + (0)))
            elseif (P == (_B(52612480, 52612481) + (0))) then
                B = a(T, (_B(52612493, 52612481) + (0)), (_B(52612488, 52612481) + (0)))

                C = a(U, (_B(52612493, 52612481) + (0)), (_B(52612503, 52612481) + (0)))
            elseif (P == (_B(52612483, 52612481) + (0))) then
                B = a(T, (_B(52612493, 52612481) + (0)), (_B(52612488, 52612481) + (0)))

                C = (a(U, (_B(52612493, 52612481) + (0)), (_B(52612500, 52612481) + (0))) - (_B(53293694, 52612481) + (0)))
            elseif (P == (_B(52612482, 52612481) + (0))) then
                B = a(T, (_B(52612493, 52612481) + (0)), (_B(52612488, 52612481) + (0)))

                C = (a(U, (_B(52612493, 52612481) + (0)), (_B(52612500, 52612481) + (0))) - (_B(53293694, 52612481) + (0)))

                D = a(T, (_B(52612500, 52612481) + (0)), (_B(52612488, 52612481) + (0)))
            end
            return { [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0B70")] = op, ["A"] = A, ["B"] = B, ["C"] = C, ["D"] = D, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("096F3DA2")] = P }
        end

        __b = (_B(52612395, 52612481) + (0))
    end

    if (__b == (_B(52612395, 52612481) + (0))) then
        function Q(aC)
            local R = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11336B")]()

            local S = {  }
            for i = (_B(52612480, 52612481) + (0)), R do
                local T = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11336B")]()

                local U = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11336B")]()

                S[i] = O(T, U)
            end

            local V = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11336B")]()

            local W = {  }
            for i = (_B(52612480, 52612481) + (0)), V do
                local X = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("1138")]()

                if (X == (_B(52612481, 52612481) + (0))) then
                    W[i] = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17742B")]()
                elseif (X == (_B(52612480, 52612481) + (0))) then
                    W[i] = (aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("1138")]() ~= (_B(52612481, 52612481) + (0)))
                else
                    W[i] = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("02366D")]()
                end
            end

            local Y = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("1138")]()

            local Z = (aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("1138")]() ~= (_B(52612481, 52612481) + (0)))

            local aa = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11336B")]()

            local ab = {  }
            for i = (_B(52612480, 52612481) + (0)), aa do
                local ac = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11336B")]()

                local ad = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("146F2A")]()

                local ae = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B")](ad, ac)

                local af = r(ae)

                ab[i] = Q(af)
                aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17653CAC")]((ad + ac))
            end

            local ag = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("1138")]()

            local ah = {  }
            for i = (_B(52612480, 52612481) + (0)), ag do
                local ai = (aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("1138")]() ~= (_B(52612481, 52612481) + (0)))

                local aj = aC[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("1138")]()

                ah[i] = { [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("027236AA377729AA0F63")] = ai, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0D6E3DA210")] = aj }
            end
            return { [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0D6E2AB31A713EBF05670FBC")] = S, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076F37B41C6533BF1F")] = W, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B980E7133A818610EA103")] = ab, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("14612BA6055B3EA4196615")] = Y, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0D7306B109763CB90B")] = Z, [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11702FA6047138B8")] = ah }
        end

        __b = (_B(52612409, 52612481) + (0))
    end

    if (__b == (_B(52612409, 52612481) + (0))) then
        local __d2 = ((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11683BAA0467")

        __b = (_B(52612381, 52612481) + (0))
    end

    if (__b == (_B(52612381, 52612481) + (0))) then

        __b = (_B(52612353, 52612481) + (0))
    end

    if (__b == (_B(52612353, 52612481) + (0))) then
        if false then
            local __d3 = (_B(52609552, 52612481) + (0))

            __d3 = (__d3 + (_B(52611342, 52612481) + (0)))
        end

        __b = (_B(52612358, 52612481) + (0))
    end

    if (__b == (_B(52612358, 52612481) + (0))) then
        function ak(sub, aE, an, upvals, destReg)
            local al = {  }
            for i, uv in ipairs(sub[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11702FA6047138B8")]) do
                if uv[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("027236AA377729AA0F63")] then
                    al[i] = { ["v"] = an[uv[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0D6E3DA210")]] }
                else
                    al[i] = upvals[(uv[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0D6E3DA210")] + (_B(52612480, 52612481) + (0)))]
                end
            end

            local am = function(...)
                                return vm_execute(sub, aE, al, { ... })
            end
            for i, uv in ipairs(sub[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("11702FA6047138B8")]) do
                if (uv[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("027236AA377729AA0F63")] and (uv[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0D6E3DA210")] == destReg)) then
                    al[i]["v"] = am
                end
            end
            return am
        end

        __b = (_B(52612442, 52612481) + (0))
    end

    if (__b == (_B(52612442, 52612481) + (0))) then
        function vm_execute(aD, aE, upvals, args)
            local an = {  }

            local ao = (_B(52612480, 52612481) + (0))

            local code = aD[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0D6E2AB31A713EBF05670FBC")]

            local ap = aD[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("076F37B41C6533BF1F")]

            local aq = (# code)

            if args then
                for i = (_B(52612480, 52612481) + (0)), aD[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("14612BA6055B3EA4196615")] do
                    an[(i - (_B(52612480, 52612481) + (0)))] = args[i]
                end
            end
            while (ao <= aq) do
                local ar = code[ao]

                local op = ar[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("0B70")]

                local A, B, C, D = ar["A"], ar["B"], ar["C"], ar["D"]

                if ((op == (_B(52612481, 52612481) + (0))) or (op == (_B(52612499, 52612481) + (0)))) then
                    an[A] = ((an[B] or (_B(52612481, 52612481) + (0))) + (ap[(C + (_B(52612480, 52612481) + (0)))] or (_B(52612481, 52612481) + (0))))
                elseif ((op == (_B(52612506, 52612481) + (0))) or (op == (_B(52612539, 52612481) + (0)))) then
                    an[A] = ((an[B] or (_B(52612481, 52612481) + (0))) + (an[C] or (_B(52612481, 52612481) + (0))))
                elseif ((op == (_B(52612521, 52612481) + (0))) or (op == (_B(52612528, 52612481) + (0)))) then
                    an[A] = ((an[B] or (_B(52612481, 52612481) + (0))) - (an[C] or (_B(52612481, 52612481) + (0))))
                elseif (op == (_B(52612538, 52612481) + (0))) then
                    an[A] = ((an[B] or (_B(52612481, 52612481) + (0))) * (an[C] or (_B(52612481, 52612481) + (0))))
                elseif (op == (_B(52612547, 52612481) + (0))) then
                    an[A] = ((an[B] or (_B(52612481, 52612481) + (0))) / (an[C] or (_B(52612481, 52612481) + (0))))
                elseif ((op == (_B(52612494, 52612481) + (0))) or (op == (_B(52612505, 52612481) + (0)))) then
                    an[A] = ((an[B] or (_B(52612481, 52612481) + (0))) % (an[C] or (_B(52612481, 52612481) + (0))))
                elseif ((op == (_B(52612510, 52612481) + (0))) or (op == (_B(52612527, 52612481) + (0)))) then
                    an[A] = ((an[B] or (_B(52612481, 52612481) + (0))) % (ap[(C + (_B(52612480, 52612481) + (0)))] or (_B(52612481, 52612481) + (0))))
                elseif (op == (_B(52612559, 52612481) + (0))) then
                    an[A] = ((an[B] or (_B(52612481, 52612481) + (0))) ^ (an[C] or (_B(52612481, 52612481) + (0))))
                elseif ((op == (_B(52612553, 52612481) + (0))) or (op == (_B(52612561, 52612481) + (0)))) then
                    an[A] = (an[B] == an[C])
                elseif (op == (_B(52612552, 52612481) + (0))) then
                    an[A] = (an[B] ~= an[C])
                elseif (op == (_B(52612555, 52612481) + (0))) then
                    an[A] = (an[B] < an[C])
                elseif (op == (_B(52612554, 52612481) + (0))) then
                    an[A] = (an[B] <= an[C])
                elseif (op == (_B(52612557, 52612481) + (0))) then
                    an[A] = (an[B] > an[C])
                elseif (op == (_B(52612556, 52612481) + (0))) then
                    an[A] = (an[B] >= an[C])
                elseif ((op == (_B(52612487, 52612481) + (0))) or (op == (_B(52612511, 52612481) + (0)))) then
                    an[A] = an[B]
                elseif ((op == (_B(52612519, 52612481) + (0))) or (op == (_B(52612537, 52612481) + (0)))) then
                    an[A] = ap[(B + (_B(52612480, 52612481) + (0)))]
                elseif ((op == (_B(52612493, 52612481) + (0))) or (op == (_B(52612522, 52612481) + (0)))) then
                    if (C == (_B(52612483, 52612481) + (0))) then
                        an[A] = {  }
                    else
                        an[A] = (C ~= (_B(52612481, 52612481) + (0)))
                    end
                elseif ((op == (_B(52612512, 52612481) + (0))) or (op == (_B(52612533, 52612481) + (0)))) then
                    an[A] = (# an[B])
                elseif ((op == (_B(52612507, 52612481) + (0))) or (op == (_B(52612535, 52612481) + (0)))) then
                    local s = an[B]
                    for i = (B + (_B(52612480, 52612481) + (0))), D do
                        s = (s .. an[i])
                    end

                    an[A] = s
                elseif ((op == (_B(52612482, 52612481) + (0))) or (op == (_B(52612526, 52612481) + (0)))) then
                    an[(A + (_B(52612480, 52612481) + (0)))] = an[B]

                    an[A] = an[B][ap[(C + (_B(52612480, 52612481) + (0)))]]
                elseif ((op == (_B(52612504, 52612481) + (0))) or (op == (_B(52612546, 52612481) + (0)))) then
                    an[A] = an[B][ap[(C + (_B(52612480, 52612481) + (0)))]]
                elseif (op == (_B(52612558, 52612481) + (0))) then
                    an[A] = an[B][an[C]]
                elseif (op == (_B(52612548, 52612481) + (0))) then
                    an[A][ap[(B + (_B(52612480, 52612481) + (0)))]] = an[C]
                elseif (op == (_B(52612560, 52612481) + (0))) then
                    an[A][an[B]] = an[C]
                elseif ((((op == (_B(52612489, 52612481) + (0))) or (op == (_B(52612501, 52612481) + (0)))) or (op == (_B(52612502, 52612481) + (0)))) or (op == (_B(52612545, 52612481) + (0)))) then
                    an[A] = aE[ap[(B + (_B(52612480, 52612481) + (0)))]]
                elseif ((op == (_B(52612532, 52612481) + (0))) or (op == (_B(52612541, 52612481) + (0)))) then
                    aE[ap[(B + (_B(52612480, 52612481) + (0)))]] = an[A]
                elseif ((op == (_B(52612483, 52612481) + (0))) or (op == (_B(52612503, 52612481) + (0)))) then
                    local sub = aD[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B980E7133A818610EA103")][(B + (_B(52612480, 52612481) + (0)))]

                    an[A] = ak(sub, aE, an, upvals, A)
                elseif ((op == (_B(52612509, 52612481) + (0))) or (op == (_B(52612516, 52612481) + (0)))) then
                    local sub = aD[((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("17753B980E7133A818610EA103")][(B + (_B(52612480, 52612481) + (0)))]

                    an[A] = ak(sub, aE, an, upvals, A)
                elseif (op == (_B(52612563, 52612481) + (0))) then
                    an[A] = upvals[(B + (_B(52612480, 52612481) + (0)))]["v"]
                elseif (op == (_B(52612562, 52612481) + (0))) then
                    upvals[(B + (_B(52612480, 52612481) + (0)))]["v"] = an[A]
                elseif (op == (_B(52612495, 52612481) + (0))) then
                    local callee = an[A]

                    local as

                    if (B == (_B(52612481, 52612481) + (0))) then
                        as = { callee() }
                    else
                        local call_args = {  }
                        for i = (_B(52612480, 52612481) + (0)), B do
                            call_args[i] = an[(A + i)]
                        end

                        as = { callee(unpack(call_args)) }
                    end

                    if (C >= (_B(52612480, 52612481) + (0))) then
                        for i = (_B(52612480, 52612481) + (0)), C do
                            an[((A + i) - (_B(52612480, 52612481) + (0)))] = as[i]
                        end
                    end
                elseif ((op == (_B(52612508, 52612481) + (0))) or (op == (_B(52612529, 52612481) + (0)))) then
                    local callee = an[A]

                    local call_args = {  }
                    for i = (_B(52612480, 52612481) + (0)), B do
                        call_args[i] = an[(A + i)]
                    end

                    an[A] = callee(unpack(call_args))
                elseif ((op == (_B(52612492, 52612481) + (0))) or (op == (_B(52612496, 52612481) + (0)))) then
                    local callee = an[A]

                    local call_args = {  }
                    for i = (_B(52612480, 52612481) + (0)), B do
                        call_args[i] = an[(A + i)]
                    end
                    return callee(unpack(call_args))
                elseif ((op == (_B(52612534, 52612481) + (0))) or (op == (_B(52612549, 52612481) + (0)))) then
                    return
                elseif ((op == (_B(52612525, 52612481) + (0))) or (op == (_B(52612524, 52612481) + (0)))) then
                    local ret_vals = {  }
                    for i = (_B(52612480, 52612481) + (0)), (C - (_B(52612480, 52612481) + (0))) do
                        ret_vals[i] = an[((A + i) - (_B(52612480, 52612481) + (0)))]
                    end
                    return unpack(ret_vals)
                elseif ((op == (_B(52612517, 52612481) + (0))) or (op == (_B(52612530, 52612481) + (0)))) then
                    local ret_vals = {  }
                    for i = (_B(52612480, 52612481) + (0)), (C - (_B(52612480, 52612481) + (0))) do
                        ret_vals[i] = an[((A + i) - (_B(52612480, 52612481) + (0)))]
                    end
                    return unpack(ret_vals)
                elseif ((op == (_B(52612486, 52612481) + (0))) or (op == (_B(52612536, 52612481) + (0)))) then
                    ao = ((ao + C) - (_B(52612480, 52612481) + (0)))
                elseif (op == (_B(52612543, 52612481) + (0))) then
                    if (not an[A]) then
                        ao = ((ao + C) - (_B(52612480, 52612481) + (0)))
                    end
                elseif ((op == (_B(52612515, 52612481) + (0))) or (op == (_B(52612523, 52612481) + (0)))) then
                    if (an[A] == ap[(C + (_B(52612480, 52612481) + (0)))]) then
                    else
                        ao = ((ao + C) - (_B(52612480, 52612481) + (0)))
                    end
                elseif (op == (_B(52612551, 52612481) + (0))) then
                    if (an[A] < an[B]) then
                    else
                        ao = ((ao + C) - (_B(52612480, 52612481) + (0)))
                    end
                elseif (op == (_B(52612550, 52612481) + (0))) then
                    if (an[A] <= an[B]) then
                    else
                        ao = ((ao + C) - (_B(52612480, 52612481) + (0)))
                    end
                elseif ((op == (_B(52612491, 52612481) + (0))) or (op == (_B(52612540, 52612481) + (0)))) then
                    if (not an[B]) then
                    else
                        an[A] = an[B]

                        ao = ((ao + C) - (_B(52612480, 52612481) + (0)))
                    end
                elseif ((op == (_B(52612513, 52612481) + (0))) or (op == (_B(52612520, 52612481) + (0)))) then
                    an[A] = ((an[A] or (_B(52612481, 52612481) + (0))) - (an[(A + (_B(52612483, 52612481) + (0)))] or (_B(52612481, 52612481) + (0))))

                    ao = ((ao + C) - (_B(52612480, 52612481) + (0)))
                elseif ((op == (_B(52612500, 52612481) + (0))) or (op == (_B(52612544, 52612481) + (0)))) then
                    an[A] = ((an[A] or (_B(52612481, 52612481) + (0))) + (an[(A + (_B(52612483, 52612481) + (0)))] or (_B(52612481, 52612481) + (0))))

                    local at = (an[(A + (_B(52612483, 52612481) + (0)))] or (_B(52612481, 52612481) + (0)))

                    local au = (an[(A + (_B(52612480, 52612481) + (0)))] or (_B(52612481, 52612481) + (0)))

                    local av = (((at >= (_B(52612481, 52612481) + (0))) and (an[A] <= au)) or ((at < (_B(52612481, 52612481) + (0))) and (an[A] >= au)))

                    if av then
                        an[(A + (_B(52612482, 52612481) + (0)))] = an[A]

                        ao = ((ao + C) - (_B(52612480, 52612481) + (0)))
                    end
                elseif ((op == (_B(52612480, 52612481) + (0))) or (op == (_B(52612484, 52612481) + (0)))) then
                    error(((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("22550A822C5B098A2544228E3C403A85353007B80C341EAE0C681EADF47911C3ED4E5991B80A49CBFE5DEF9BF941E0"))
                elseif (op == (_B(52612485, 52612481) + (0))) then
                    error(((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("22550A822C5B1E8A20443E833F4D21982B5C2C99274738995C761EABA06F0093F44F0B93ED405D82E208F7DFBE18A581E15EFD9EF551"))
                elseif (op == (_B(52612488, 52612481) + (0))) then
                    error(((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("22550A822C5B1E8A20443EFA224931F31A7F1DF70B611DAB136A05BAE43C1C8DA45649C9BC040F9EE25CE882F5"))
                elseif (op == (_B(52612490, 52612481) + (0))) then
                    error(((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("22550A822C5B098A2544228E3C403A81314449B917604DA8096801B0F2681087A44917C7FE1453DFAC5AF481E445E896"))
                elseif ((((op == (_B(52612497, 52612481) + (0))) or (op == (_B(52612514, 52612481) + (0)))) or (op == (_B(52612518, 52612481) + (0)))) or (op == (_B(52612531, 52612481) + (0)))) then
                    error(((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("22550A822C5B1E8A20443E9931533796203007B80C341EAE0C681EADF47911C3ED4E5991B80A49CBFE5DEF9BF941E0"))
                elseif ((op == (_B(52612498, 52612481) + (0))) or (op == (_B(52612542, 52612481) + (0)))) then
                    error(((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("22550A822C5B1A8E384E288A3C483A90355C25883B5B23983D4C51B1EF685590F1500988FA50188FAC41EFCFE61CABC7B442FC99EC5DE09E"))
                else
                    error((((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("324D63E71D6A36A5037F0FEF1F7C06BC107549") .. (tostring(op) .. (((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("44612DE7017460") .. tostring(ao)))))
                end

                ao = (ao + (_B(52612480, 52612481) + (0)))
            end
        end

        __b = (_B(52612372, 52612481) + (0))
    end

    if (__b == (_B(52612372, 52612481) + (0))) then
        aw = ((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("50336DFF5C3169FE5830558A4448519141215CE64C50599F485E44E8B52E40DBB1184CD3BD1C48DCB96CB4ABA56DB0B2A173BCB3AE07BBCDAA08A7C9960BA3319272AF33917DAB3C9A0C984C860D922383619F538E109B5D8A1EF029F76E821B85588E13FF508A1CFB5F831EE72DFD03EC40FE74EF32FA7DE44DE909D84DED75DCB4E171D0BCE57CD4B1D90BC8CDDD11B0A2D113C0D2D51DC5A8C86D39A4CC513D92C053319CC45C3590452C29ED3C305583303321F1493D5D88504E65FD54B165F458B2698659C96DF060CC748E64D175936CAF79916CDE7AE973AF02EC779106D37B920AA678E9")

        __b = (_B(52612581, 52612481) + (0))
    end

    if (__b == (_B(52612581, 52612481) + (0))) then
        ax = (_B(52612496, 52612481) + (0))

        __b = (_B(52612400, 52612481) + (0))
    end

    if (__b == (_B(52612400, 52612481) + (0))) then
        function ay()
            local az = e(aw)

            local aA = f(az, ax)

            local aB = g(aA)

            local aC = r(aB)

            local aD = Q(aC)

            local aE = setmetatable({  }, { [((function(K) return function(H) local O="";for i=1,#H,2 do local j=(i+1)/2-1;O=O..string.char((_B(tonumber(H:sub(i,i+1),16),(K[(j+1)%4+1]+j))%256)) end;return O end end)({196,100,255,87}))("3B5F30A90C6125")] = _G })
            vm_execute(aD, aE, {  }, {  })
        end

        __b = (_B(52612428, 52612481) + (0))
    end

    if (__b == (_B(52612428, 52612481) + (0))) then
        ay()

        __b = (_B(4242354814, 52612481) + (0))
    end

    if (__b == (_B(4242354814, 52612481) + (0))) then
        break
    end
end