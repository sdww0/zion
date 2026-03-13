#include <sbi/sbi_types.h>
#include <sbi/riscv_asm.h>
#include "ree.h"
#include "zion.h"
#include "cvm.h"
#include "context.h"
#include "pmp.h"

struct ree ree;

struct zion_state *hart_get_caller()
{
	return ree.harts[csr_read(mhartid)].current_state;
}

unsigned int hart_get_caller_rtid()
{
	return ree.harts[csr_read(mhartid)].current_state->rtid;
}

unsigned int hart_get_caller_ttid()
{
	return ree.harts[csr_read(mhartid)].current_state->ttid;
}

unsigned int hart_get_callee_rtid(unsigned int tid)
{
	unsigned int rtid;

	zion_mode mode = hart_get_mode();
	if (mode == REE) {
		rtid = ree.tees[tid].id;
	} else if (mode == CVM) {
		unsigned int caller_rtid = hart_get_caller_rtid();
		rtid			 = cvms[caller_rtid].tees[tid].id;
	} else if (mode == ENCLAVE) {
		return tid;
	}
	return rtid;
}

zion_mode hart_get_mode()
{
	return ree.harts[csr_read(mhartid)].current_state->mode;
}

void hart_enter_context(struct tee_thread *d_tthread)
{
	unsigned long mhartid = csr_read(mhartid);
	d_tthread->prev_state		 = ree.harts[mhartid].current_state;
	ree.harts[mhartid].current_state = &d_tthread->state;
}

void hart_exit_context(struct tee_thread *s_tthread)
{
	unsigned long mhartid = csr_read(mhartid);

	ree.harts[mhartid].current_state = s_tthread->prev_state;
	s_tthread->prev_state		 = NULL;
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

int osm_init()
{
	sbi_printf("[SM] osm_init()\n");
	int region = -1;
	int ret	  = pmp_region_init_atomic(0, -1UL, PMP_PRI_BOTTOM, &region, 1);
	if (ret)
		return -1;

	return region;
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
