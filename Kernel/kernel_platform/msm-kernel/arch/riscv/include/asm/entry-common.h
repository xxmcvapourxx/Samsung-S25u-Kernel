/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_RISCV_ENTRY_COMMON_H
#define _ASM_RISCV_ENTRY_COMMON_H

#include <asm/stacktrace.h>
#include <asm/thread_info.h>
#include <asm/vector.h>

static inline void arch_exit_to_user_mode_prepare(struct pt_regs *regs,
						  unsigned long ti_work)
{
	if (ti_work & _TIF_RISCV_V_DEFER_RESTORE) {
		clear_thread_flag(TIF_RISCV_V_DEFER_RESTORE);
		/*
		 * We are already called with irq disabled, so go without
		 * keeping track of riscv_v_flags.
		 */
		riscv_v_vstate_restore(&current->thread.vstate, regs);
	}
}

#define arch_exit_to_user_mode_prepare arch_exit_to_user_mode_prepare

void handle_page_fault(struct pt_regs *regs);
void handle_break(struct pt_regs *regs);

#endif /* _ASM_RISCV_ENTRY_COMMON_H */
