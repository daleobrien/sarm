# docs/

| File | Read it when |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | You need to change the server and want the map: modules, seams, the request lifecycle, and what's dead weight. |
| [SECURITY.md](SECURITY.md) | You need the threat model, the attack-surface inventory, what the security programme found, or what is left of it. Source comments cite its section numbers. |
| [HISTORY.md](HISTORY.md) | You want to know why the code looks like this, what each change measured, what was rejected on evidence, and the working rules that came out of it. Also holds the profile table `scripts/strategy.py` reads. |
| [MULTICORE-BASELINE.md](MULTICORE-BASELINE.md) | You are about to benchmark something. §4 is the list of ways this machine has already fooled us. |
| [SCRIPTS.md](SCRIPTS.md) | You want to run the tests, profile something, benchmark something, check an ABI change, or touch the crypto. |
| [CONFIGURATION.md](CONFIGURATION.md) | You want to change a setting, add a MIME type, swap the certificate, or look up a status code. |

Also here: `COPYING` (GPL-3.0), `face.svg`.

Elsewhere in the tree:

- [`../Plan.md`](../Plan.md) — the completed performance plan. Source comments
  and tests cite its phase and step numbers.
- `src/tls/{server,record,handshake,transcript}/README.md`, `src/http1/README.md`
  — module detail.
- `tests/security/README.md` — how each security harness works.
- `certs/README.md` — certificate layout and how it's embedded.
- `.claude/skills/verified-asm-crypto/` — the mandatory workflow for changing
  assembly arithmetic.
