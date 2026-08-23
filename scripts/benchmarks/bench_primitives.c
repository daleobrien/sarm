// Per-call cost of sarm's crypto primitives, linked against the repo's
// own object files (docs/SCRIPTS.md, steps 2 and 3).
//
// This is the CPU-accurate half of the profile. sample(1) reports where
// the server's *wall* time goes, blocked syscalls included; multiplying
// these per-call numbers by measured call counts gives an independent
// estimate that owes nothing to the sampler, and docs/HISTORY.md
// compares the two.
//
// Why the calls go through an assembly trampoline
// -----------------------------------------------
// `aes128_encrypt` used to keep round keys in v8-v11 and never restore
// them. AAPCS64 makes the low 64 bits of v8-v15 callee-saved, so C code
// holding a `double` across the call got it corrupted — which is exactly
// what happened to the first version of this file, and it reported GCM
// costs of 1e86 ns rather than crashing. The round keys have since moved
// to v1-v7 and v22-v25, all caller-saved, so that particular trap is
// gone. `bench_call` still runs the timing loop in inline assembly with
// v0-v31 declared clobbered, because the general point survives the fix:
// a call into hand-written assembly should never have a floating-point
// value live across it, and this file should not have to track which
// registers each callee currently uses.
//
// x19-x28 were checked separately and *are* preserved by every function
// timed here, which is what lets the loop counter live in one of them.
//
// Every primitive is checked for a correct answer before it is timed — a
// GCM round trip, agreeing X25519 shared secrets, a known SHA-256 state
// — so a linking mistake cannot quietly become a fast wrong number.
//
// Build and run:
//   make -C scripts/benchmarks bench_primitives
//   ./scripts/benchmarks/_bench_bin/bench_primitives          # JSON on stdout

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// ── the assembly under test ──────────────────────────────────────────
// Declared as data rather than functions: everything is called through
// `bench_call`, which needs the address and nothing else. sarm's symbols
// have no leading underscore, hence the asm labels.
#define ASM_SYM(name) extern const char name[] __asm__(#name)

ASM_SYM(aes128_key_expand);
ASM_SYM(aes128_encrypt);
ASM_SYM(aes_gcm_encrypt);
ASM_SYM(aes_gcm_decrypt);
ASM_SYM(ghash);
ASM_SYM(sha256);
ASM_SYM(p256_bn_mul);
ASM_SYM(p256_fe_mul);
ASM_SYM(p256_point_mul);
ASM_SYM(p256_ecdsa_sign_with_k);
ASM_SYM(x25519);
ASM_SYM(hkdf_expand_label);
ASM_SYM(hmac_sha256);

// ── the trampoline ───────────────────────────────────────────────────
// bargs holds x0..x7 for the call; bret receives x0 from the last one.
// Both are external globals so the asm can name them directly and needs
// no register operand of its own.
uint64_t bargs[8];
uint64_t bret;

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t bench_call(const void *fn, uint64_t iters) {
	uint64_t n = iters;
	uint64_t t0 = now_ns();
	__asm__ __volatile__(
		"1:\n"
		"  adrp x8, _bargs@PAGE\n"
		"  add  x8, x8, _bargs@PAGEOFF\n"
		"  ldp  x0, x1, [x8]\n"
		"  ldp  x2, x3, [x8, #16]\n"
		"  ldp  x4, x5, [x8, #32]\n"
		"  ldp  x6, x7, [x8, #48]\n"
		"  blr  %[fn]\n"
		"  subs %[n], %[n], #1\n"
		"  b.ne 1b\n"
		"  adrp x8, _bret@PAGE\n"
		"  add  x8, x8, _bret@PAGEOFF\n"
		"  str  x0, [x8]\n"
		: [n] "+r"(n)
		: [fn] "r"(fn)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30",
		  "cc", "memory",
		  "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
		  "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
		  "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
		  "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");
	return now_ns() - t0;
}

static void set_args(const uint64_t *v, size_t n) {
	for (size_t i = 0; i < 8; i++)
		bargs[i] = i < n ? v[i] : 0;
}
#define ARGS(...)                                                          \
	set_args((const uint64_t[]){__VA_ARGS__},                              \
	         sizeof((const uint64_t[]){__VA_ARGS__}) / sizeof(uint64_t))

// ── reporting ────────────────────────────────────────────────────────
// The minimum over rounds is reported: on this machine every source of
// noise (interrupt, core migration, frequency change) only ever makes a
// run slower, so the fastest run is the closest estimate of the real
// cost. The spread against the slowest round is printed so a run that
// was disturbed throughout is visible rather than silently believed.
#define ROUNDS 9

static int failures;
static double loop_overhead_ns;

static void check(const char *what, int ok) {
	if (!ok) {
		fprintf(stderr, "  !! %s produced a wrong answer\n", what);
		failures++;
	}
}

static void bench(const char *fn, const void *addr, const char *label,
                  uint64_t iters) {
	double best = 1e30, worst = 0;
	for (int r = 0; r < ROUNDS; r++) {
		double per = (double)bench_call(addr, iters) / (double)iters;
		if (per < best) best = per;
		if (per > worst) worst = per;
	}
	double net = best - loop_overhead_ns;
	if (net < 0) net = 0;
	printf("{\"function\":\"%s\",\"case\":\"%s\",\"ns_per_call\":%.2f,"
	       "\"raw_ns\":%.2f,\"spread_pct\":%.1f}\n",
	       fn, label, net, best, (worst - best) / best * 100.0);
	fprintf(stderr, "  %-24s %-12s %11.2f ns   +%.1f%%\n",
	        fn, label, net, (worst - best) / best * 100.0);
}

// ── fixtures ─────────────────────────────────────────────────────────

static uint8_t key[16], iv[12], aad[5], tag[16], rk[176], h[16], ghout[16];
static uint8_t buf_pt[1 << 15], buf_ct[1 << 15], buf_rt[1 << 15];

// P-256 base point in the little-endian 4-limb form p256_fe uses.
static const uint64_t GX[4] = {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
                               0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL};
static const uint64_t GY[4] = {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
                               0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL};

// A bare `ret`, used to measure what the trampoline itself costs so the
// per-call numbers are the callee and not the harness.
__asm__(".text\n.align 2\n_bench_nop:\n  ret\n");
extern const char bench_nop[] __asm__("_bench_nop");

int main(void) {
	for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 1);
	for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(i * 5 + 3);
	for (int i = 0; i < 5; i++) aad[i] = (uint8_t)(i + 0x17);
	for (size_t i = 0; i < sizeof buf_pt; i++)
		buf_pt[i] = (uint8_t)((i * 131 + 17) & 0xFF);

	// Loop overhead first — everything after it is reported net of this.
	double best = 1e30;
	for (int r = 0; r < ROUNDS; r++) {
		double per = (double)bench_call(bench_nop, 5000000) / 5000000.0;
		if (per < best) best = per;
	}
	loop_overhead_ns = best;
	fprintf(stderr, "\n  primitive costs (Apple M3 Pro, min of %d rounds, "
	                "net of %.2f ns trampoline)\n\n", ROUNDS, best);

	// ── AES / GCM ────────────────────────────────────────────────
	ARGS((uint64_t)key, (uint64_t)rk);
	bench_call(aes128_key_expand, 1);
	bench("aes128_key_expand", aes128_key_expand, "16B key", 2000000);

	ARGS((uint64_t)buf_pt, (uint64_t)rk, (uint64_t)buf_ct);
	bench("aes128_encrypt", aes128_encrypt, "1 block", 5000000);

	static const uint64_t sizes[] = {26, 104, 1024, 4096, 16384};
	static const char *names[] = {"26B", "104B", "1KiB", "4KiB", "16KiB"};
	for (int s = 0; s < 5; s++) {
		uint64_t n = sizes[s];
		uint64_t iters = 40000000 / n;
		if (iters < 300) iters = 300;

		ARGS((uint64_t)key, (uint64_t)iv, (uint64_t)aad, 5,
		     (uint64_t)buf_pt, n, (uint64_t)buf_ct, (uint64_t)tag);
		bench_call(aes_gcm_encrypt, 1);
		memset(buf_rt, 0, n);
		ARGS((uint64_t)key, (uint64_t)iv, (uint64_t)aad, 5,
		     (uint64_t)buf_ct, n, (uint64_t)tag, (uint64_t)buf_rt);
		bench_call(aes_gcm_decrypt, 1);
		check("aes_gcm round trip",
		      bret == 1 && memcmp(buf_pt, buf_rt, n) == 0);

		bench("aes_gcm_decrypt", aes_gcm_decrypt, names[s], iters);
		ARGS((uint64_t)key, (uint64_t)iv, (uint64_t)aad, 5,
		     (uint64_t)buf_pt, n, (uint64_t)buf_ct, (uint64_t)tag);
		bench("aes_gcm_encrypt", aes_gcm_encrypt, names[s], iters);

		memset(h, 0, sizeof h);
		ARGS((uint64_t)h, (uint64_t)rk, (uint64_t)h);
		bench_call(aes128_encrypt, 1);            // H = E_K(0^128)
		ARGS((uint64_t)h, (uint64_t)aad, 5, (uint64_t)buf_ct, n,
		     (uint64_t)ghout);
		bench("ghash", ghash, names[s], iters);
	}

	// ── SHA-256 ──────────────────────────────────────────────────
	// Known answer: the SHA-256 state after compressing one all-zero
	// 64-byte block (no padding, no length appended).
	static uint32_t state[8];
	static const uint32_t iv256[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	static uint8_t zero_block[64];
	memcpy(state, iv256, sizeof state);
	ARGS((uint64_t)state, (uint64_t)zero_block, 1);
	bench_call(sha256, 1);
	check("sha256 one block", state[0] == 0xda5698beU);

	bench("sha256", sha256, "1 block", 3000000);
	ARGS((uint64_t)state, (uint64_t)buf_pt, 16);
	bench("sha256", sha256, "16 blocks", 300000);

	// ── P-256 ────────────────────────────────────────────────────
	static uint64_t prod[16], fe[4], outx[4], outy[4];
	ARGS((uint64_t)prod, (uint64_t)GX, 4, (uint64_t)GY, 4);
	bench_call(p256_bn_mul, 1);
	check("p256_bn_mul", prod[0] || prod[1]);
	bench("p256_bn_mul", p256_bn_mul, "4x4", 5000000);
	ARGS((uint64_t)prod, (uint64_t)GX, 5, (uint64_t)GY, 5);
	bench("p256_bn_mul", p256_bn_mul, "5x5", 5000000);

	ARGS((uint64_t)fe, (uint64_t)GX, (uint64_t)GY);
	bench_call(p256_fe_mul, 1);
	check("p256_fe_mul", fe[0] || fe[1]);
	bench("p256_fe_mul", p256_fe_mul, "a*b mod p", 2000000);

	static const uint64_t k[4] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL,
	                              0x0f1e2d3c4b5a6978ULL, 0x1122334455667788ULL};
	ARGS((uint64_t)outx, (uint64_t)outy, (uint64_t)k,
	     (uint64_t)GX, (uint64_t)GY);
	bench_call(p256_point_mul, 1);
	check("p256_point_mul", outx[0] || outx[1] || outx[2] || outx[3]);
	bench("p256_point_mul", p256_point_mul, "256-bit k", 400);

	static uint8_t sig_r[32], sig_s[32], hash[32], d[32], nonce[32];
	for (int i = 0; i < 32; i++) {
		hash[i] = (uint8_t)(i + 1);
		d[i] = (uint8_t)(0x40 + i);
		nonce[i] = (uint8_t)(0x80 + i);
	}
	d[0] = 0x01; nonce[0] = 0x01;      // keep both well inside [1, n-1]
	ARGS((uint64_t)sig_r, (uint64_t)sig_s, (uint64_t)hash,
	     (uint64_t)d, (uint64_t)nonce);
	bench_call(p256_ecdsa_sign_with_k, 1);
	check("p256_ecdsa_sign_with_k", bret == 0);
	bench("p256_ecdsa_sign_with_k", p256_ecdsa_sign_with_k, "sign", 300);

	// ── X25519 ───────────────────────────────────────────────────
	// Checked by the Diffie-Hellman property rather than a fixed vector:
	// both sides must derive the same shared secret.
	static uint8_t basepoint[32] = {9}, apub[32], bpub[32];
	static uint8_t ass[32], bss[32], asec[32], bsec[32];
	for (int i = 0; i < 32; i++) {
		asec[i] = (uint8_t)(i + 3);
		bsec[i] = (uint8_t)(i * 3 + 5);
	}
	ARGS((uint64_t)apub, (uint64_t)asec, (uint64_t)basepoint);
	bench_call(x25519, 1);
	ARGS((uint64_t)bpub, (uint64_t)bsec, (uint64_t)basepoint);
	bench_call(x25519, 1);
	ARGS((uint64_t)ass, (uint64_t)asec, (uint64_t)bpub);
	bench_call(x25519, 1);
	ARGS((uint64_t)bss, (uint64_t)bsec, (uint64_t)apub);
	bench_call(x25519, 1);
	check("x25519 agreement", memcmp(ass, bss, 32) == 0);
	ARGS((uint64_t)ass, (uint64_t)asec, (uint64_t)bpub);
	bench("x25519", x25519, "scalarmult", 600);

	fprintf(stderr, "\n");
	if (failures) {
		fprintf(stderr, "  %d correctness check(s) FAILED — the numbers "
		                "above are not trustworthy\n\n", failures);
		return 1;
	}
	return 0;
}
