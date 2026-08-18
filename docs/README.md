# docs/

| File | Read it when |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | You need to change the server and want the map: modules, seams, the request lifecycle, and what's dead weight. |
| [HISTORY.md](HISTORY.md) | You want to know why the code looks like this, what each optimisation measured, what was rejected on evidence, and the working rules that came out of it. Also holds the profile table `scripts/strategy.py` reads. |
| [SCRIPTS.md](SCRIPTS.md) | You want to run the tests, profile something, benchmark something, check an ABI change, or touch the crypto. |
| [CONFIGURATION.md](CONFIGURATION.md) | You want to change a setting, add a MIME type, swap the certificate, or look up a status code. |
| [PLAN.MD](PLAN.MD) | You hit a `PLAN.MD §N` reference in the source, or want the remaining TLS work (phases 23–26). |
| [OPTIMISATION.MD](OPTIMISATION.MD) | You're working on the automated optimisation harness in `scripts/`. |

Also here: `COPYING` (GPL-3.0), `face.svg`.

Elsewhere in the tree:

- `src/tls/{server,record,handshake,transcript}/README.md` — module detail.
- `certs/README.md` — certificate layout and how it's embedded.
- `prompts/` — the archived task briefs that drove the optimisation work. Historical:
  they reference documents that have since been consolidated into `HISTORY.md`.
- `.claude/skills/verified-asm-crypto/` — the mandatory workflow for changing
  assembly arithmetic.
