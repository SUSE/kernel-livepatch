/*
 * bsc1179877_tty_jobctrl
 *
 * Fix for CVE-2020-29660 and CVE-2020-29661, bsc#1179877 (tty_jobctrl.c part)
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

/* klp-ccp: from drivers/tty/tty_jobctrl.c */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>

/* klp-ccp: from include/linux/sched/task.h */
static rwlock_t (*klpe_tasklist_lock);

/* klp-ccp: from drivers/tty/tty_jobctrl.c */
#include <linux/sched/task.h>
#include <linux/tty.h>

/* klp-ccp: from include/linux/tty.h */
void klpp_disassociate_ctty(int priv);

static const char *(*klpe_tty_driver_name)(const struct tty_struct *tty);

static void (*klpe_tty_vhangup_session)(struct tty_struct *tty);

static void (*klpe_session_clear_tty)(struct pid *session);
static void (*klpe_no_tty)(void);

long klpp_tty_jobctrl_ioctl(struct tty_struct *tty, struct tty_struct *real_tty,
			      struct file *file, unsigned int cmd, unsigned long arg);

#define klpr_tty_msg(fn, tty, f, ...) \
	fn("%s %s: " f, (*klpe_tty_driver_name)(tty), tty_name(tty), ##__VA_ARGS__)

#define klpr_tty_debug(tty, f, ...)	klpr_tty_msg(pr_debug, tty, f, ##__VA_ARGS__)

/* klp-ccp: from drivers/tty/tty_jobctrl.c */
#include <linux/fcntl.h>
#include <linux/uaccess.h>

int tty_check_change(struct tty_struct *tty);

void klpp___proc_set_tty(struct tty_struct *tty)
{
	unsigned long flags;

	spin_lock_irqsave(&tty->ctrl_lock, flags);
	/*
	 * The session and fg pgrp references will be non-NULL if
	 * tiocsctty() is stealing the controlling tty
	 */
	put_pid(tty->session);
	put_pid(tty->pgrp);
	tty->pgrp = get_pid(task_pgrp(current));
	/*
	 * Fix CVE-2020-29660
	 *  -1 line
	 */
	tty->session = get_pid(task_session(current));
	/*
	 * Fix CVE-2020-29660
	 *  +1 line
	 */
	spin_unlock_irqrestore(&tty->ctrl_lock, flags);
	if (current->signal->tty) {
		klpr_tty_debug(tty, "current tty %s not NULL!!\n",
			  current->signal->tty->name);
		tty_kref_put(current->signal->tty);
	}
	put_pid(current->signal->tty_old_pgrp);
	current->signal->tty = tty_kref_get(tty);
	current->signal->tty_old_pgrp = NULL;
}

static void klpr_proc_set_tty(struct tty_struct *tty)
{
	spin_lock_irq(&current->sighand->siglock);
	klpp___proc_set_tty(tty);
	spin_unlock_irq(&current->sighand->siglock);
}

struct tty_struct *get_current_tty(void);

void klpp_disassociate_ctty(int on_exit)
{
	struct tty_struct *tty;

	if (!current->signal->leader)
		return;

	tty = get_current_tty();
	if (tty) {
		if (on_exit && tty->driver->type != TTY_DRIVER_TYPE_PTY) {
			(*klpe_tty_vhangup_session)(tty);
		} else {
			struct pid *tty_pgrp = tty_get_pgrp(tty);
			if (tty_pgrp) {
				kill_pgrp(tty_pgrp, SIGHUP, on_exit);
				if (!on_exit)
					kill_pgrp(tty_pgrp, SIGCONT, on_exit);
				put_pid(tty_pgrp);
			}
		}
		tty_kref_put(tty);

	} else if (on_exit) {
		struct pid *old_pgrp;
		spin_lock_irq(&current->sighand->siglock);
		old_pgrp = current->signal->tty_old_pgrp;
		current->signal->tty_old_pgrp = NULL;
		spin_unlock_irq(&current->sighand->siglock);
		if (old_pgrp) {
			kill_pgrp(old_pgrp, SIGHUP, on_exit);
			kill_pgrp(old_pgrp, SIGCONT, on_exit);
			put_pid(old_pgrp);
		}
		return;
	}

	spin_lock_irq(&current->sighand->siglock);
	put_pid(current->signal->tty_old_pgrp);
	current->signal->tty_old_pgrp = NULL;

	tty = tty_kref_get(current->signal->tty);
	/*
	 * Fix CVE-2020-29660
	 *  +1 line
	 */
	spin_unlock_irq(&current->sighand->siglock);
	if (tty) {
		unsigned long flags;
		/*
		 * Fix CVE-2020-29660
		 *  +1 line
		 */
		tty_lock(tty);
		spin_lock_irqsave(&tty->ctrl_lock, flags);
		put_pid(tty->session);
		put_pid(tty->pgrp);
		tty->session = NULL;
		tty->pgrp = NULL;
		spin_unlock_irqrestore(&tty->ctrl_lock, flags);
		/*
		 * Fix CVE-2020-29660
		 *  +1 line
		 */
		tty_unlock(tty);
		tty_kref_put(tty);
	}

	/*
	 * Fix CVE-2020-29660
	 *  -1 line
	 */
	/* Now clear signal->tty under the lock */
	read_lock(&(*klpe_tasklist_lock));
	(*klpe_session_clear_tty)(task_session(current));
	read_unlock(&(*klpe_tasklist_lock));
}

static int klpr_tiocsctty(struct tty_struct *tty, struct file *file, int arg)
{
	int ret = 0;

	tty_lock(tty);
	read_lock(&(*klpe_tasklist_lock));

	if (current->signal->leader && (task_session(current) == tty->session))
		goto unlock;

	/*
	 * The process must be a session leader and
	 * not have a controlling tty already.
	 */
	if (!current->signal->leader || current->signal->tty) {
		ret = -EPERM;
		goto unlock;
	}

	if (tty->session) {
		/*
		 * This tty is already the controlling
		 * tty for another session group!
		 */
		if (arg == 1 && capable(CAP_SYS_ADMIN)) {
			/*
			 * Steal it away
			 */
			(*klpe_session_clear_tty)(tty->session);
		} else {
			ret = -EPERM;
			goto unlock;
		}
	}

	/* See the comment in tty_open_proc_set_tty(). */
	if ((file->f_mode & FMODE_READ) == 0 && !capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto unlock;
	}

	klpr_proc_set_tty(tty);
unlock:
	read_unlock(&(*klpe_tasklist_lock));
	tty_unlock(tty);
	return ret;
}

struct pid *tty_get_pgrp(struct tty_struct *tty);

static struct pid *session_of_pgrp(struct pid *pgrp)
{
	struct task_struct *p;
	struct pid *sid = NULL;

	p = pid_task(pgrp, PIDTYPE_PGID);
	if (p == NULL)
		p = pid_task(pgrp, PIDTYPE_PID);
	if (p != NULL)
		sid = task_session(p);

	return sid;
}

static int tiocgpgrp(struct tty_struct *tty, struct tty_struct *real_tty, pid_t __user *p)
{
	struct pid *pid;
	int ret;
	/*
	 * (tty == real_tty) is a cheap way of
	 * testing if the tty is NOT a master pty.
	 */
	if (tty == real_tty && current->signal->tty != real_tty)
		return -ENOTTY;
	pid = tty_get_pgrp(real_tty);
	ret =  put_user(pid_vnr(pid), p);
	put_pid(pid);
	return ret;
}

static int klpp_tiocspgrp(struct tty_struct *tty, struct tty_struct *real_tty, pid_t __user *p)
{
	struct pid *pgrp;
	pid_t pgrp_nr;
	int retval = tty_check_change(real_tty);

	if (retval == -EIO)
		return -ENOTTY;
	if (retval)
		return retval;
	/*
	 * Fix CVE-2020-29660
	 *  -4 lines
	 */
	if (get_user(pgrp_nr, p))
		return -EFAULT;
	if (pgrp_nr < 0)
		return -EINVAL;

	/*
	 * Fix CVE-2020-29660
	 *  +7 lines
	 */
	spin_lock_irq(&real_tty->ctrl_lock);
	if (!current->signal->tty ||
	    (current->signal->tty != real_tty) ||
	    (real_tty->session != task_session(current))) {
		retval = -ENOTTY;
		goto out_unlock_ctrl;
	}
	rcu_read_lock();
	pgrp = find_vpid(pgrp_nr);
	retval = -ESRCH;
	if (!pgrp)
		goto out_unlock;
	retval = -EPERM;
	if (session_of_pgrp(pgrp) != task_session(current))
		goto out_unlock;
	retval = 0;
	/*
	 * Fix CVE-2020-29660, CVE-2020-29661
	 *  -1 line
	 */
	put_pid(real_tty->pgrp);
	real_tty->pgrp = get_pid(pgrp);
	/*
	 * Fix CVE-2020-29660, CVE-2020-29661
	 *  -1 line
	 */
out_unlock:
	rcu_read_unlock();
	/*
	 * Fix CVE-2020-29660
	 *  +2 lines
	 */
out_unlock_ctrl:
	spin_unlock_irq(&real_tty->ctrl_lock);
	return retval;
}

static int klpp_tiocgsid(struct tty_struct *tty, struct tty_struct *real_tty, pid_t __user *p)
{
	/*
	 * Fix CVE-2020-29660
	 *  +3 lines
	 */
	 unsigned long flags;
	 pid_t sid;

	 /*
	 * (tty == real_tty) is a cheap way of
	 * testing if the tty is NOT a master pty.
	*/
	if (tty == real_tty && current->signal->tty != real_tty)
		return -ENOTTY;

	/*
	 * Fix CVE-2020-29660
	 *  +1 line
	 */
	spin_lock_irqsave(&real_tty->ctrl_lock, flags);
	if (!real_tty->session)
		/*
		 * Fix CVE-2020-29660
		 *  -1 line, +1 line
		 */
		goto err;
	/*
	 * Fix CVE-2020-29660
	 *  -1 line, +8 lines
	 */
	sid = pid_vnr(real_tty->session);
	spin_unlock_irqrestore(&real_tty->ctrl_lock, flags);

	return put_user(sid, p);

err:
	spin_unlock_irqrestore(&real_tty->ctrl_lock, flags);
	return -ENOTTY;
}

long klpp_tty_jobctrl_ioctl(struct tty_struct *tty, struct tty_struct *real_tty,
		       struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *p = (void __user *)arg;

	switch (cmd) {
	case TIOCNOTTY:
		if (current->signal->tty != tty)
			return -ENOTTY;
		(*klpe_no_tty)();
		return 0;
	case TIOCSCTTY:
		return klpr_tiocsctty(real_tty, file, arg);
	case TIOCGPGRP:
		return tiocgpgrp(tty, real_tty, p);
	case TIOCSPGRP:
		return klpp_tiocspgrp(tty, real_tty, p);
	case TIOCGSID:
		return klpp_tiocgsid(tty, real_tty, p);
	}
	return -ENOIOCTLCMD;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tasklist_lock", (void *)&klpe_tasklist_lock },
	{ "tty_driver_name", (void *)&klpe_tty_driver_name },
	{ "tty_vhangup_session", (void *)&klpe_tty_vhangup_session },
	{ "session_clear_tty", (void *)&klpe_session_clear_tty },
	{ "no_tty", (void *)&klpe_no_tty },
};

int livepatch_bsc1179877_tty_jobctrl_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
