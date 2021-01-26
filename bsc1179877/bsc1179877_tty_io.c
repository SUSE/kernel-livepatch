/*
 * bsc1179877_tty_io
 *
 * Fix for CVE-2020-29660 and CVE-2020-29661, bsc#1179877 (tty_io.c part)
 *
 *  Copyright (c) 2021 SUSE
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

#include <linux/kernel.h>
#include <linux/module.h>
#include "bsc1179877.h"
#include "../kallsyms_relocs.h"

/* klp-ccp: from drivers/tty/tty_io.c */
#include <linux/types.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/signal.h>

/* klp-ccp: from include/linux/signal.h */
static int (*klpe_group_send_sig_info)(int sig, struct kernel_siginfo *info,
			       struct task_struct *p, enum pid_type type);

/* klp-ccp: from drivers/tty/tty_io.c */
#include <linux/fcntl.h>
#include <linux/sched/signal.h>

/* klp-ccp: from include/linux/sched/task.h */
static rwlock_t (*klpe_tasklist_lock);

/* klp-ccp: from drivers/tty/tty_io.c */
#include <linux/sched/task.h>
#include <linux/interrupt.h>
#include <linux/tty.h>

/* klp-ccp: from include/linux/tty.h */
static const char *(*klpe_tty_driver_name)(const struct tty_struct *tty);

void klpp___do_SAK(struct tty_struct *tty);

#define klpr_tty_msg(fn, tty, f, ...) \
	fn("%s %s: " f, (*klpe_tty_driver_name)(tty), tty_name(tty), ##__VA_ARGS__)

#define klpr_tty_notice(tty, f, ...)	klpr_tty_msg(pr_notice, tty, f, ##__VA_ARGS__)

/* klp-ccp: from drivers/tty/tty_io.c */
#include <linux/tty_driver.h>
#include <linux/fdtable.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/seq_file.h>
#include <linux/ratelimit.h>
#include <linux/uaccess.h>
#include <linux/kmod.h>

const char *tty_name(const struct tty_struct *tty);

static const char *(*klpe_tty_driver_name)(const struct tty_struct *tty);

static int (*klpe_this_tty)(const void *t, struct file *file, unsigned fd);

void klpp___do_SAK(struct tty_struct *tty)
{
#ifdef TTY_SOFT_SAK
#error "klp-ccp: non-taken branch"
#else
	struct task_struct *g, *p;
	struct pid *session;
	int		i;
	/*
	 * Fix CVE-2020-29660
	 *  +1 line
	 */
	unsigned long flags;

	if (!tty)
		return;
	/*
	 * Fix CVE-2020-29660
	 *  -1 line, +3 lines
	 */
	spin_lock_irqsave(&tty->ctrl_lock, flags);
	session = get_pid(tty->session);
	spin_unlock_irqrestore(&tty->ctrl_lock, flags);

	tty_ldisc_flush(tty);

	tty_driver_flush_buffer(tty);

	read_lock(&(*klpe_tasklist_lock));
	/* Kill the entire session */
	do_each_pid_task(session, PIDTYPE_SID, p) {
		klpr_tty_notice(tty, "SAK: killed process %d (%s): by session\n",
			   task_pid_nr(p), p->comm);
		(*klpe_group_send_sig_info)(SIGKILL, SEND_SIG_PRIV, p, PIDTYPE_SID);
	} while_each_pid_task(session, PIDTYPE_SID, p);

	/* Now kill any processes that happen to have the tty open */
	do_each_thread(g, p) {
		if (p->signal->tty == tty) {
			klpr_tty_notice(tty, "SAK: killed process %d (%s): by controlling tty\n",
				   task_pid_nr(p), p->comm);
			(*klpe_group_send_sig_info)(SIGKILL, SEND_SIG_PRIV, p, PIDTYPE_SID);
			continue;
		}
		task_lock(p);
		i = iterate_fd(p->files, 0, (*klpe_this_tty), tty);
		if (i != 0) {
			klpr_tty_notice(tty, "SAK: killed process %d (%s): by fd#%d\n",
				   task_pid_nr(p), p->comm, i - 1);
			(*klpe_group_send_sig_info)(SIGKILL, SEND_SIG_PRIV, p, PIDTYPE_SID);
		}
		task_unlock(p);
	} while_each_thread(g, p);
	read_unlock(&(*klpe_tasklist_lock));
	/*
	 * Fix CVE-2020-29660
	 *  +1 line
	 */
	put_pid(session);
#endif
}

void klpp_do_SAK_work(struct work_struct *work)
{
	struct tty_struct *tty =
		container_of(work, struct tty_struct, SAK_work);
	klpp___do_SAK(tty);
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tasklist_lock", (void *)&klpe_tasklist_lock },
	{ "group_send_sig_info", (void *)&klpe_group_send_sig_info },
	{ "tty_driver_name", (void *)&klpe_tty_driver_name },
	{ "this_tty", (void *)&klpe_this_tty },
};

int livepatch_bsc1179877_tty_io_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
