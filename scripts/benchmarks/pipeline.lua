-- wrk script: send N requests per write instead of one, so a connection
-- has N requests outstanding rather than one.
--
-- Why it exists. sarm serves one process per connection and blocks in
-- read(), so an unpipelined keep-alive client costs it exactly one
-- context switch per request -- measured at 1.01 on a c6g.metal, against
-- 0.02 for HTTP/2, which multiplexes and so amortises one wakeup over
-- ~42 requests. That switch, and the cold traverse of the TCP stack
-- after it, is most of what an HTTP/1.1 request costs on that box:
-- ~50,800 cycles, of which the scheduler and the lock paths are ~28%.
--
-- src/sarm/child.S already has the code to exploit pipelining
-- (Lcheck_leftover serves a complete request out of leftover bytes
-- without another read()), and nothing in the benchmark suite exercised
-- it. This is the measurement that separates "HTTP/1.1 is expensive"
-- from "waking up is expensive": if req/s multiplies with depth, the
-- per-request work is not the bottleneck and no amount of optimising
-- the parse path will move the number.
--
--   wrk -t2 -c32 -d10s -s scripts/benchmarks/pipeline.lua http://... -- 8
--
-- The trailing argument is the depth; it defaults to 1, which is
-- byte-for-byte what wrk sends without this script.
--
-- READ THE LATENCY FIGURE WITH CARE. wrk times each response against
-- the moment its batch was written, so at depth N the reported latency
-- includes the queueing of the N-1 requests ahead of it and will climb
-- roughly linearly with depth even when the server got faster. req/s is
-- the figure this script exists to produce; latency is not comparable
-- across depths.

local req = ""

function init(args)
    local depth = tonumber(args[1]) or 1
    if depth < 1 then
        depth = 1
    end
    local parts = {}
    for i = 1, depth do
        parts[i] = wrk.format()
    end
    req = table.concat(parts)
end

function request()
    return req
end
