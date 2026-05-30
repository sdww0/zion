/*
 * sbi_trap_exit — restore registers and mret (non-local return).
 *
 * Used by Keystone SM to return from SBI calls directly to
 * the caller (host or enclave) without normal ecall return path.
 *
 * void sbi_trap_exit(struct sbi_trap_regs *regs);
 *
 * struct sbi_trap_regs layout (64-bit):
 *   offset 0x000: zero  (x0)
 *   offset 0x008: ra    (x1)
 *   offset 0x010: sp    (x2)
 *   offset 0x018: gp    (x3)
 *   offset 0x020: tp    (x4)
 *   offset 0x028: t0    (x5)
 *   offset 0x030: t1    (x6)
 *   offset 0x038: t2    (x7)
 *   offset 0x040: s0    (x8)
 *   offset 0x048: s1    (x9)
 *   offset 0x050: a0    (x10)
 *   offset 0x058: a1    (x11)
 *   offset 0x060: a2    (x12)
 *   offset 0x068: a3    (x13)
 *   offset 0x070: a4    (x14)
 *   offset 0x078: a5    (x15)
 *   offset 0x080: a6    (x16)
 *   offset 0x088: a7    (x17)
 *   offset 0x090: s2    (x18)
 *   offset 0x098: s3    (x19)
 *   offset 0x0a0: s4    (x20)
 *   offset 0x0a8: s5    (x21)
 *   offset 0x0b0: s6    (x22)
 *   offset 0x0b8: s7    (x23)
 *   offset 0x0c0: s8    (x24)
 *   offset 0x0c8: s9    (x25)
 *   offset 0x0d0: s10   (x26)
 *   offset 0x0d8: s11   (x27)
 *   offset 0x0e0: t3    (x28)
 *   offset 0x0e8: t4    (x29)
 *   offset 0x0f0: t5    (x30)
 *   offset 0x0f8: t6    (x31)
 *   offset 0x100: mepc
 *   offset 0x108: mstatus
 */

#include <sbi/riscv_encoding.h>

#define MSTATUS_OFF  0x108
#define MEPC_OFF     0x100

	.section .text
	.align 3
	.globl sbi_trap_exit
sbi_trap_exit:
	/* Save a0 (pointer to regs) in t0 temporarily */
	mv	t0, a0

	/* Set up mepc and mstatus before touching GPRs */
	ld	t1, MEPC_OFF(t0)
	ld	t2, MSTATUS_OFF(t0)
	csrw	CSR_MEPC, t1
	csrw	CSR_MSTATUS, t2

	/* Load all GPRs from trap frame */
	ld	ra,  0x008(t0)
	ld	sp,  0x010(t0)
	ld	gp,  0x018(t0)
	ld	tp,  0x020(t0)
	/* t0 loaded last (it's our pointer) */
	ld	t1,  0x030(t0)
	ld	t2,  0x038(t0)
	ld	s0,  0x040(t0)
	ld	s1,  0x048(t0)
	ld	a0,  0x050(t0)
	ld	a1,  0x058(t0)
	ld	a2,  0x060(t0)
	ld	a3,  0x068(t0)
	ld	a4,  0x070(t0)
	ld	a5,  0x078(t0)
	ld	a6,  0x080(t0)
	ld	a7,  0x088(t0)
	ld	s2,  0x090(t0)
	ld	s3,  0x098(t0)
	ld	s4,  0x0a0(t0)
	ld	s5,  0x0a8(t0)
	ld	s6,  0x0b0(t0)
	ld	s7,  0x0b8(t0)
	ld	s8,  0x0c0(t0)
	ld	s9,  0x0c8(t0)
	ld	s10, 0x0d0(t0)
	ld	s11, 0x0d8(t0)
	ld	t3,  0x0e0(t0)
	ld	t4,  0x0e8(t0)
	ld	t5,  0x0f0(t0)
	ld	t6,  0x0f8(t0)

	/* Load t0 last */
	ld	t0,  0x028(t0)

	mret
