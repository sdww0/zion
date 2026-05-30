/*
 * Compatibility shim for keystone SM (OpenSBI v1.1 API).
 * Maps old sbi_misaligned_load/store_handler(mtval, mtval2, mtinst, regs)
 * to new sbi_misaligned_load/store_handler(tcntx).
 */
#ifndef _ZION_SBI_MISALIGNED_LDST_H
#define _ZION_SBI_MISALIGNED_LDST_H

#include <sbi/sbi_trap_ldst.h>
#include <sbi/sbi_trap.h>

/* Old API: sbi_misaligned_load_handler(mtval, mtval2, mtinst, regs) */
static inline int sbi_misaligned_load_handler_compat(
    unsigned long mtval, unsigned long mtval2,
    unsigned long mtinst, struct sbi_trap_regs *regs)
{
    struct sbi_trap_context tcntx;
    tcntx.regs = *regs;
    tcntx.trap.cause = CAUSE_MISALIGNED_LOAD;
    tcntx.trap.tval = mtval;
    tcntx.trap.tval2 = mtval2;
    tcntx.trap.tinst = mtinst;
    int rc = sbi_misaligned_load_handler(&tcntx);
    *regs = tcntx.regs;
    return rc;
}

/* Old API: sbi_misaligned_store_handler(mtval, mtval2, mtinst, regs) */
static inline int sbi_misaligned_store_handler_compat(
    unsigned long mtval, unsigned long mtval2,
    unsigned long mtinst, struct sbi_trap_regs *regs)
{
    struct sbi_trap_context tcntx;
    tcntx.regs = *regs;
    tcntx.trap.cause = CAUSE_MISALIGNED_STORE;
    tcntx.trap.tval = mtval;
    tcntx.trap.tval2 = mtval2;
    tcntx.trap.tinst = mtinst;
    int rc = sbi_misaligned_store_handler(&tcntx);
    *regs = tcntx.regs;
    return rc;
}

/* Replace original function calls with compat wrappers */
#define sbi_misaligned_load_handler(_mtval, _mtval2, _mtinst, _regs) \
    sbi_misaligned_load_handler_compat(_mtval, _mtval2, _mtinst, _regs)

#define sbi_misaligned_store_handler(_mtval, _mtval2, _mtinst, _regs) \
    sbi_misaligned_store_handler_compat(_mtval, _mtval2, _mtinst, _regs)

#endif /* _ZION_SBI_MISALIGNED_LDST_H */
