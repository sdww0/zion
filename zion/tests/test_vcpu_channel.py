#!/usr/bin/env python3
"""Compile the actual channel-check helpers with host-side CSR/type stand-ins."""
import os
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "src/context.c").read_text()
start = source.index("#define GUEST_SAVED_REG_SANITY_LIST")
registers = source[start:source.index("\n\n", start)]
helpers = source[source.index("static bool sanitize_guest_saved_reg"):
                 source.index("static inline void copy_guest_arg_regs_to_trap_regs")]

fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
typedef struct { long counter; } atomic_t;
static atomic_t invalid_registers_print;
static const unsigned long guest_saved_reg_reset_sentinel = 0x1234;
static long atomic_read(atomic_t *a) { return __atomic_load_n(&a->counter, __ATOMIC_SEQ_CST); }
static long atomic_cmpxchg(atomic_t *a, long old, long value) {
    __atomic_compare_exchange_n(&a->counter, &old, value, false,
                               __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return old;
}
struct kvm_cpu_context { unsigned long s2,s3,s4,s5,s6,s7,s8,s9,s10; };
struct kvm_vcpu_channel { struct kvm_cpu_context *guest_context; };
#define mhartid 0
#define csr_read(csr) 0UL
static int alerts;
#define sbi_printf(format, ...) do { \
    if (strstr(format, "register=%s")) __atomic_add_fetch(&alerts, 1, __ATOMIC_SEQ_CST); \
} while (0)
'''

tests = r'''
static void *race(void *unused) {
    (void)unused;
    struct kvm_cpu_context regs = {.s2=1};
    struct kvm_vcpu_channel channel = {&regs};
    check_guest_saved_regs(&channel, ~0U);
    return NULL;
}
int main(void) {
    struct kvm_cpu_context regs = {.s10=0x100};
    struct kvm_vcpu_channel channel = {&regs};
    unsigned int rd = offsetof(struct kvm_cpu_context, s10)/sizeof(unsigned long);
    check_guest_saved_regs(&channel, rd);
    assert(alerts == 0 && regs.s10 == 0x100);
    clear_guest_saved_regs(&channel);
    check_guest_saved_regs(&channel, ~0U);
    assert(alerts == 0 && regs.s10 == 0);
    regs.s2 = 0x1234;
    regs.s3 = 0x55;
    check_guest_saved_regs(&channel, ~0U);
    assert(alerts == 1 && regs.s2 == 0 && regs.s3 == 0x55);
    check_guest_saved_regs(&channel, ~0U);
    assert(alerts == 1);
    __atomic_store_n(&invalid_registers_print.counter, 0, __ATOMIC_SEQ_CST);
    alerts = 0;
    pthread_t threads[8];
    for (int i=0; i<8; i++) assert(!pthread_create(&threads[i], NULL, race, NULL));
    for (int i=0; i<8; i++) assert(!pthread_join(threads[i], NULL));
    assert(alerts == 1);
    puts("PASS: MMIO exemption, stale clearing, sentinel, and atomic one-shot alert");
}
'''

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory)
    (path / "test.c").write_text(fixture + registers + "\n" + helpers + tests)
    subprocess.run([os.environ.get("HOSTCC", "cc"), "-std=gnu11", "-pthread",
                    "-Wno-unused-parameter", str(path / "test.c"),
                    "-o", str(path / "test")], check=True)
    subprocess.run([str(path / "test")], check=True)
