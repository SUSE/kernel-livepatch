/*
 * livepatch_bsc1200059
 *
 * Fix for CVE-2022-21499, bsc#1200059
 *
 *  Upstream commit:
 *  eadb2f47a3ce ("lockdown: also lock down previous kgdb use")
 *
 *  SLE12-SP4 commit:
 *  0b6608d35aa3f0087f2370ab6bde40070dfdacba
 *
 *  SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  1cd17a0e830009531fc4a55f185b4d5cb14e9557
 *
 *  SLE15-SP2 and -SP3 commit:
 *  090b59efc25d5edb0c8e2468964c264c3c0debb2
 *
 *  SLE15-SP4 commit:
 *  251570ddfff55a5a7ed492de51156e299430c39e
 *
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if IS_ENABLED(CONFIG_KGDB)

/* klp-ccp: from kernel/debug/debug_core.c */
#define pr_fmt(fmt) "KGDB: " fmt

#include <linux/pid_namespace.h>

/* klp-ccp: from include/linux/rcupdate.h */
#if defined(CONFIG_TREE_RCU) || defined(CONFIG_PREEMPT_RCU)

/* klp-ccp: from include/linux/rcutree.h */
static void (*klpe_rcu_cpu_stall_reset)(void);

/* klp-ccp: from include/linux/rcupdate.h */
#elif defined(CONFIG_TINY_RCU)
#error "klp-ccp: non-taken branch"
#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from include/linux/clocksource.h */
static void (*klpe_clocksource_touch_watchdog)(void);

/* klp-ccp: from kernel/debug/debug_core.c */
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/threads.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sysrq.h>
#include <linux/init.h>
#include <linux/kgdb.h>

/* klp-ccp: from include/linux/kgdb.h */
static int (*klpe_kgdb_skipexception)(int exception, struct pt_regs *regs);

static atomic_t			(*klpe_kgdb_setting_breakpoint);
static atomic_t			(*klpe_kgdb_cpu_doing_single_step);

static struct task_struct	*(*klpe_kgdb_contthread);

static void (*klpe_kgdb_roundup_cpus)(unsigned long flags);

static struct kgdb_arch		(*klpe_arch_kgdb_ops);

static struct kgdb_io *(*klpe_dbg_io_ops);

static int			(*klpe_kgdb_single_step);

/* klp-ccp: from include/linux/nmi.h */
#ifdef CONFIG_LOCKUP_DETECTOR

static void (*klpe_touch_softlockup_watchdog_sync)(void);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/debug/debug_core.c */
#include <linux/pid.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>
#include <asm/byteorder.h>
#include <linux/atomic.h>

/* klp-ccp: from kernel/debug/debug_core.h */
struct kgdb_state {
	int			ex_vector;
	int			signo;
	int			err_code;
	int			cpu;
	int			pass_exception;
	unsigned long		thr_query;
	unsigned long		threadid;
	long			kgdb_usethreadid;
	struct pt_regs		*linux_regs;
	atomic_t		*send_ready;
};

#define DCPU_WANT_MASTER 0x1 /* Waiting to become a master kgdb cpu */
#define DCPU_NEXT_MASTER 0x2 /* Transition from one master cpu to another */
#define DCPU_IS_SLAVE    0x4 /* Slave cpu enter exception */

struct debuggerinfo_struct {
	void			*debuggerinfo;
	struct task_struct	*task;
	int			exception_state;
	int			ret_state;
	int			irq_depth;
	int			enter_kgdb;
};

static struct debuggerinfo_struct (*klpe_kgdb_info)[];

static int (*klpe_dbg_deactivate_sw_breakpoints)(void);

#define DBG_PASS_EVENT -12345

#define DBG_SWITCH_CPU_EVENT -123456
static int (*klpe_dbg_switch_cpu);

static int (*klpe_gdb_serial_stub)(struct kgdb_state *ks);

static int (*klpe_dbg_kdb_mode);

#ifdef CONFIG_KGDB_KDB
static int (*klpe_kdb_stub)(struct kgdb_state *ks);

#else /* ! CONFIG_KGDB_KDB */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_KGDB_KDB */

/* klp-ccp: from kernel/debug/debug_core.c */
extern int				kgdb_connected;

static int			(*klpe_exception_level);

extern atomic_t			kgdb_active;

static raw_spinlock_t (*klpe_dbg_master_lock);
static raw_spinlock_t (*klpe_dbg_slave_lock);

static atomic_t			(*klpe_masters_in_kgdb);
static atomic_t			(*klpe_slaves_in_kgdb);

static pid_t			(*klpe_kgdb_sstep_pid);

static int (*klpe_kgdb_do_roundup);

static int klpr_kgdb_io_ready(int print_wait)
{
	if (!(*klpe_dbg_io_ops))
		return 0;
	if (kgdb_connected)
		return 1;
	if (atomic_read(&(*klpe_kgdb_setting_breakpoint)))
		return 1;
	if (print_wait) {
#ifdef CONFIG_KGDB_KDB
		if (!(*klpe_dbg_kdb_mode))
			pr_crit("waiting... or $3#33 for KDB\n");
#else
#error "klp-ccp: non-taken branch"
#endif
	}
	return 1;
}

static void klpr_dbg_touch_watchdogs(void)
{
	(*klpe_touch_softlockup_watchdog_sync)();
	(*klpe_clocksource_touch_watchdog)();
	(*klpe_rcu_cpu_stall_reset)();
}

int klpp_kgdb_cpu_enter(struct kgdb_state *ks, struct pt_regs *regs,
		int exception_state)
{
	unsigned long flags;
	int sstep_tries = 100;
	int error;
	int cpu;
	int trace_on = 0;
	int online_cpus = num_online_cpus();
	u64 time_left;

	(*klpe_kgdb_info)[ks->cpu].enter_kgdb++;
	(*klpe_kgdb_info)[ks->cpu].exception_state |= exception_state;

	if (exception_state == DCPU_WANT_MASTER)
		atomic_inc(&(*klpe_masters_in_kgdb));
	else
		atomic_inc(&(*klpe_slaves_in_kgdb));

	if ((*klpe_arch_kgdb_ops).disable_hw_break)
		(*klpe_arch_kgdb_ops).disable_hw_break(regs);

acquirelock:
	/*
	 * Interrupts will be restored by the 'trap return' code, except when
	 * single stepping.
	 */
	local_irq_save(flags);

	cpu = ks->cpu;
	(*klpe_kgdb_info)[cpu].debuggerinfo = regs;
	(*klpe_kgdb_info)[cpu].task = current;
	(*klpe_kgdb_info)[cpu].ret_state = 0;
	(*klpe_kgdb_info)[cpu].irq_depth = hardirq_count() >> HARDIRQ_SHIFT;

	/* Make sure the above info reaches the primary CPU */
	smp_mb();

	if ((*klpe_exception_level) == 1) {
		if (raw_spin_trylock(&(*klpe_dbg_master_lock)))
			atomic_xchg(&kgdb_active, cpu);
		goto cpu_master_loop;
	}

	/*
	 * CPU will loop if it is a slave or request to become a kgdb
	 * master cpu and acquire the kgdb_active lock:
	 */
	while (1) {
cpu_loop:
		if ((*klpe_kgdb_info)[cpu].exception_state & DCPU_NEXT_MASTER) {
			(*klpe_kgdb_info)[cpu].exception_state &= ~DCPU_NEXT_MASTER;
			goto cpu_master_loop;
		} else if ((*klpe_kgdb_info)[cpu].exception_state & DCPU_WANT_MASTER) {
			if (raw_spin_trylock(&(*klpe_dbg_master_lock))) {
				atomic_xchg(&kgdb_active, cpu);
				break;
			}
		} else if ((*klpe_kgdb_info)[cpu].exception_state & DCPU_IS_SLAVE) {
			if (!raw_spin_is_locked(&(*klpe_dbg_slave_lock)))
				goto return_normal;
		} else {
return_normal:
			/* Return to normal operation by executing any
			 * hw breakpoint fixup.
			 */
			if ((*klpe_arch_kgdb_ops).correct_hw_break)
				(*klpe_arch_kgdb_ops).correct_hw_break();
			if (trace_on)
				tracing_on();
			(*klpe_kgdb_info)[cpu].exception_state &=
				~(DCPU_WANT_MASTER | DCPU_IS_SLAVE);
			(*klpe_kgdb_info)[cpu].enter_kgdb--;
			smp_mb__before_atomic();
			atomic_dec(&(*klpe_slaves_in_kgdb));
			klpr_dbg_touch_watchdogs();
			local_irq_restore(flags);
			return 0;
		}
		cpu_relax();
	}

	/*
	 * For single stepping, try to only enter on the processor
	 * that was single stepping.  To guard against a deadlock, the
	 * kernel will only try for the value of sstep_tries before
	 * giving up and continuing on.
	 */
	if (atomic_read(&(*klpe_kgdb_cpu_doing_single_step)) != -1 &&
	    ((*klpe_kgdb_info)[cpu].task &&
	     (*klpe_kgdb_info)[cpu].task->pid != (*klpe_kgdb_sstep_pid)) && --sstep_tries) {
		atomic_set(&kgdb_active, -1);
		raw_spin_unlock(&(*klpe_dbg_master_lock));
		klpr_dbg_touch_watchdogs();
		local_irq_restore(flags);

		goto acquirelock;
	}

	if (!klpr_kgdb_io_ready(1)) {
		(*klpe_kgdb_info)[cpu].ret_state = 1;
		goto kgdb_restore; /* No I/O connection, resume the system */
	}

	/*
	 * Don't enter if we have hit a removed breakpoint.
	 */
	if ((*klpe_kgdb_skipexception)(ks->ex_vector, ks->linux_regs))
		goto kgdb_restore;

	/* Call the I/O driver's pre_exception routine */
	if ((*klpe_dbg_io_ops)->pre_exception)
		(*klpe_dbg_io_ops)->pre_exception();

	/*
	 * Get the passive CPU lock which will hold all the non-primary
	 * CPU in a spin state while the debugger is active
	 */
	if (!(*klpe_kgdb_single_step))
		raw_spin_lock(&(*klpe_dbg_slave_lock));

#ifdef CONFIG_SMP
	if (ks->send_ready)
		atomic_set(ks->send_ready, 1);

	/* Signal the other CPUs to enter kgdb_wait() */
	else if ((!(*klpe_kgdb_single_step)) && (*klpe_kgdb_do_roundup))
		(*klpe_kgdb_roundup_cpus)(flags);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	time_left = MSEC_PER_SEC;
	while ((*klpe_kgdb_do_roundup) && --time_left &&
	       (atomic_read(&(*klpe_masters_in_kgdb)) + atomic_read(&(*klpe_slaves_in_kgdb))) !=
		   online_cpus)
		udelay(1000);
	if (!time_left)
		pr_crit("Timed out waiting for secondary CPUs.\n");

	/*
	 * At this point the primary processor is completely
	 * in the debugger and all secondary CPUs are quiescent
	 */
	(*klpe_dbg_deactivate_sw_breakpoints)();
	(*klpe_kgdb_single_step) = 0;
	(*klpe_kgdb_contthread) = current;
	(*klpe_exception_level) = 0;
	trace_on = tracing_is_on();
	if (trace_on)
		tracing_off();

	while (1) {
cpu_master_loop:
		/*
		 * Fix CVE-2022-21499
		 *  +2 lines
		 */
		if (kernel_is_locked_down())
			break;
		if ((*klpe_dbg_kdb_mode)) {
			kgdb_connected = 1;
			error = (*klpe_kdb_stub)(ks);
			if (error == -1)
				continue;
			kgdb_connected = 0;
		} else {
			error = (*klpe_gdb_serial_stub)(ks);
		}

		if (error == DBG_PASS_EVENT) {
			(*klpe_dbg_kdb_mode) = !(*klpe_dbg_kdb_mode);
		} else if (error == DBG_SWITCH_CPU_EVENT) {
			(*klpe_kgdb_info)[(*klpe_dbg_switch_cpu)].exception_state |=
				DCPU_NEXT_MASTER;
			goto cpu_loop;
		} else {
			(*klpe_kgdb_info)[cpu].ret_state = error;
			break;
		}
	}

	/* Call the I/O driver's post_exception routine */
	if ((*klpe_dbg_io_ops)->post_exception)
		(*klpe_dbg_io_ops)->post_exception();

	if (!(*klpe_kgdb_single_step)) {
		raw_spin_unlock(&(*klpe_dbg_slave_lock));
		/* Wait till all the CPUs have quit from the debugger. */
		while ((*klpe_kgdb_do_roundup) && atomic_read(&(*klpe_slaves_in_kgdb)))
			cpu_relax();
	}

kgdb_restore:
	if (atomic_read(&(*klpe_kgdb_cpu_doing_single_step)) != -1) {
		int sstep_cpu = atomic_read(&(*klpe_kgdb_cpu_doing_single_step));
		if ((*klpe_kgdb_info)[sstep_cpu].task)
			(*klpe_kgdb_sstep_pid) = (*klpe_kgdb_info)[sstep_cpu].task->pid;
		else
			(*klpe_kgdb_sstep_pid) = 0;
	}
	if ((*klpe_arch_kgdb_ops).correct_hw_break)
		(*klpe_arch_kgdb_ops).correct_hw_break();
	if (trace_on)
		tracing_on();

	(*klpe_kgdb_info)[cpu].exception_state &=
		~(DCPU_WANT_MASTER | DCPU_IS_SLAVE);
	(*klpe_kgdb_info)[cpu].enter_kgdb--;
	smp_mb__before_atomic();
	atomic_dec(&(*klpe_masters_in_kgdb));
	/* Free kgdb_active */
	atomic_set(&kgdb_active, -1);
	raw_spin_unlock(&(*klpe_dbg_master_lock));
	klpr_dbg_touch_watchdogs();
	local_irq_restore(flags);

	return (*klpe_kgdb_info)[cpu].ret_state;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1200059.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "arch_kgdb_ops", (void *)&klpe_arch_kgdb_ops },
	{ "clocksource_touch_watchdog",
	  (void *)&klpe_clocksource_touch_watchdog },
	{ "dbg_deactivate_sw_breakpoints",
	  (void *)&klpe_dbg_deactivate_sw_breakpoints },
	{ "dbg_io_ops", (void *)&klpe_dbg_io_ops },
	{ "dbg_kdb_mode", (void *)&klpe_dbg_kdb_mode },
	{ "dbg_master_lock", (void *)&klpe_dbg_master_lock },
	{ "dbg_slave_lock", (void *)&klpe_dbg_slave_lock },
	{ "dbg_switch_cpu", (void *)&klpe_dbg_switch_cpu },
	{ "exception_level", (void *)&klpe_exception_level },
	{ "gdb_serial_stub", (void *)&klpe_gdb_serial_stub },
	{ "kdb_stub", (void *)&klpe_kdb_stub },
	{ "kgdb_contthread", (void *)&klpe_kgdb_contthread },
	{ "kgdb_cpu_doing_single_step",
	  (void *)&klpe_kgdb_cpu_doing_single_step },
	{ "kgdb_do_roundup", (void *)&klpe_kgdb_do_roundup },
	{ "kgdb_info", (void *)&klpe_kgdb_info },
	{ "kgdb_roundup_cpus", (void *)&klpe_kgdb_roundup_cpus },
	{ "kgdb_setting_breakpoint", (void *)&klpe_kgdb_setting_breakpoint },
	{ "kgdb_single_step", (void *)&klpe_kgdb_single_step },
	{ "kgdb_skipexception", (void *)&klpe_kgdb_skipexception },
	{ "kgdb_sstep_pid", (void *)&klpe_kgdb_sstep_pid },
	{ "masters_in_kgdb", (void *)&klpe_masters_in_kgdb },
	{ "rcu_cpu_stall_reset", (void *)&klpe_rcu_cpu_stall_reset },
	{ "slaves_in_kgdb", (void *)&klpe_slaves_in_kgdb },
	{ "touch_softlockup_watchdog_sync",
	  (void *)&klpe_touch_softlockup_watchdog_sync },
};

int livepatch_bsc1200059_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_KGDB) */
