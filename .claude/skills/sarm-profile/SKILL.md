---
name: sarm-profile
description: How to profile sarm — where a connection's CPU time goes (profile_workload.py), which function is hot (profile_samples.py), and how often a function runs (count_calls.py). Use whenever asked to profile the server, find hot functions, or understand where time/cost is spent in a request or handshake.
---

# Profiling sarm

```bash
python3 scripts/profile_workload.py pageload handshake transfer request   # authority on where time goes
python3 scripts/profile_samples.py handshake --top 30                     # PC sampler, self-time only
python3 scripts/count_calls.py --workload pageload                        # call frequency via lldb
```

- **`profile_workload.py`** — the authority on *where a connection's cost
  is*. Runs sarm as a child, drives it with `h2_browser_sim.py`'s
  `Connection`, and reads server CPU from `getrusage(RUSAGE_CHILDREN)`. Runs
  each scenario at three workload sizes and least-squares-fits marginal vs.
  fixed cost — reading marginal cost off a single size folds the handshake
  in and misstates it by 30–60%. **Wall clock is not the measurement**: the
  Python client's own TLS decryption costs several times what sarm's
  encryption does.
- **`profile_samples.py`** — periodic PC sampler via `/usr/bin/sample`
  (`xctrace` needs a full Xcode install; CLT only here), attributed to
  functions. sarm has no frame-pointer chain, so this is self-time only.
- **`count_calls.py`** — call frequency per connection/request, via `lldb`
  with auto-continuing breakpoints. Frequency, not size, is what makes a
  function hot, and the shipped binary deliberately logs nothing.

## Related skills

- Isolated per-function runtime (not connection-level) → [sarm-benchmark](../sarm-benchmark/SKILL.md)
- Register/ABI legality before profiling a candidate → [sarm-static-analysis](../sarm-static-analysis/SKILL.md)
- End-to-end throughput → [sarm-load-test](../sarm-load-test/SKILL.md)
