#include <sbi/sbi_types.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_scratch.h>
#include "ree.h"
#include "zion.h"
#include "cvm.h"
#include "context.h"

struct ree ree;

unsigned int zion_current_hart_index(void)
{
	u32 hartid = current_hartid();
	u32 hart_index = sbi_hartid_to_hartindex(hartid);

	if (!sbi_hartindex_valid(hart_index) || hart_index >= MAX_REE_HARTS) {
		tee_log("[SM] unsupported hart: id=%u index=%u max=%u\n",
			 hartid, hart_index, MAX_REE_HARTS);
		sm_error("[SM] fatal: unsupported hart topology\n");
		sbi_hart_hang();
	}

	return hart_index;
}

struct zion_state *hart_get_caller()
{
	return ree.harts[zion_current_hart_index()].current_state;
}

unsigned int hart_get_caller_rtid()
{
	return ree.harts[zion_current_hart_index()].current_state->rtid;
}

unsigned int hart_get_caller_ttid()
{
	return ree.harts[zion_current_hart_index()].current_state->ttid;
}

unsigned int hart_get_callee_rtid(unsigned int tid)
{
	unsigned int rtid = (unsigned int)-1;

	zion_mode mode = hart_get_mode();
	if (mode == REE) {
		if (tid >= MAX_TEES)
			return rtid;
		rtid = ree.tees[tid].id;
	} else if (mode == CVM) {
		unsigned int caller_rtid = hart_get_caller_rtid();
		if (caller_rtid >= MAX_CVMS || tid >= MAX_TEES)
			return rtid;
		rtid			 = cvms[caller_rtid].tees[tid].id;
	} else if (mode == ENCLAVE) {
		return tid;
	}
	return rtid;
}

zion_mode hart_get_mode()
{
	return ree.harts[zion_current_hart_index()].current_state->mode;
}

void hart_enter_context(struct tee_thread *d_tthread)
{
	unsigned int hart_index = zion_current_hart_index();
	d_tthread->prev_state = ree.harts[hart_index].current_state;
	ree.harts[hart_index].current_state = &d_tthread->state;
}

void hart_exit_context(struct tee_thread *s_tthread)
{
	unsigned int hart_index = zion_current_hart_index();

	ree.harts[hart_index].current_state = s_tthread->prev_state;
	s_tthread->prev_state = NULL;
}

void save_tthread_state(struct zion_state *state, unsigned int rtid,
			unsigned int ttid, struct tee_thread *tthread,
			zion_mode mode)
{
	state->rtid    = rtid;
	state->ttid    = ttid;
	state->tthread = tthread;
	state->mode    = mode;
}

void ree_metadata_init()
{
	unsigned int ree_rtid = (unsigned int)REE;

	tee_thread_next = 0;

	ree.tee_id_next = 0;

	for (size_t i = 0; i < MAX_REE_HARTS; i++) {
		ree.harts[i].tthread = &(tee_threads[tee_thread_next++]);

		save_tthread_state(&ree.harts[i].tthread->state, ree_rtid,
				   (unsigned int)i, ree.harts[i].tthread,
				   REE);

		ree.harts[i].current_state = &ree.harts[i].tthread->state;
	}
}
