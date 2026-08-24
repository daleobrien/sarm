// Taking a symbol's address from inline asm, on both Mach-O and ELF.
//
// The two formats disagree twice, and a benchmark that spells only one of
// them builds on one host and is skipped on the other:
//
//   * relocation syntax -- Mach-O writes the high half as `sym@PAGE` and
//     the low half as `sym@PAGEOFF`; ELF writes `sym` and `:lo12:sym`.
//
//   * symbol naming -- Mach-O prefixes symbols defined in *C* with an
//     underscore, so the variable `gcm_args` is `_gcm_args` to the
//     assembler. Symbols defined in this tree's .S files are not
//     prefixed on either platform (defs.S's FUNC/OBJECT emit the bare
//     name), which is why an asm symbol and a C symbol need different
//     macros here rather than one.
//
// This is the same split src/defs.S's `adr_l` handles for assembly; C
// files cannot use that macro, so they use these.
//
// Usage -- the register is an operand string, so it works with both a
// hard-coded register and a `%0` placeholder:
//
//     asm volatile(ASM_ADDR_ASM("%0", "h2_streams") : "=r"(p));
//     asm volatile(ASM_ADDR_C("x8", "gcm_args") ::: "x8");

#ifndef SARM_ASM_SYM_H
#define SARM_ASM_SYM_H

#if defined(__APPLE__)
#define ASM_CSYM(name) "_" name
#define ASM_ADRP(reg, sym) "adrp " reg ", " sym "@PAGE\n"
#define ASM_ADDLO(reg, sym) "add " reg ", " reg ", " sym "@PAGEOFF\n"
#else
#define ASM_CSYM(name) name
#define ASM_ADRP(reg, sym) "adrp " reg ", " sym "\n"
#define ASM_ADDLO(reg, sym) "add " reg ", " reg ", :lo12:" sym "\n"
#endif

// Address of a symbol defined in a .S file (never underscore-prefixed).
#define ASM_ADDR_ASM(reg, name) ASM_ADRP(reg, name) ASM_ADDLO(reg, name)

// Address of a symbol defined in C (underscore-prefixed on Mach-O).
#define ASM_ADDR_C(reg, name) \
	ASM_ADRP(reg, ASM_CSYM(name)) ASM_ADDLO(reg, ASM_CSYM(name))

#endif // SARM_ASM_SYM_H
