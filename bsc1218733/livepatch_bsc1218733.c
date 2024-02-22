/*
 * livepatch_bsc1218733
 *
 * Fix for CVE-2023-51780, bsc#1218733
 *
 *  Upstream commit:
 *  24e90b9e34f9 ("atm: Fix Use-After-Free in do_vcc_ioctl")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  42f1cd3cdce15b7a4be633cad494ff81af3e3d6f
 *
 *  SLE15-SP2 and -SP3 commit:
 *  6405c59f72581f2d81e1ddd39b46d6dbd5f28954
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#if IS_ENABLED(CONFIG_ATM)

#if !IS_MODULE(CONFIG_ATM)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/atm/ioctl.c */
#include <linux/kmod.h>
#include <linux/net.h>		/* struct socket, struct proto_ops */
#include <linux/atm.h>		/* ATM stuff */
#include <linux/atmdev.h>
#include <linux/atmclip.h>	/* CLIP_*ENCAP */

/* klp-ccp: from include/uapi/linux/atmarp.h */
#define ATMARPD_CTRL	_IO('a',ATMIOC_CLIP+1)	/* become atmarpd ctrl sock */

/* klp-ccp: from net/atm/ioctl.c */
#include <linux/capability.h>

/* klp-ccp: from include/uapi/linux/atmsvc.h */
#define _LINUX_ATMSVC_H

#define ATMSIGD_CTRL _IO('a',ATMIOC_SPECIAL)

/* klp-ccp: from include/uapi/linux/atmmpc.h */
#define ATMMPC_CTRL _IO('a', ATMIOC_MPOA)
#define ATMMPC_DATA _IO('a', ATMIOC_MPOA+1)

/* klp-ccp: from include/uapi/linux/atmlec.h */
#define ATMLEC_CTRL	_IO('a', ATMIOC_LANE)

/* klp-ccp: from net/atm/ioctl.c */
#include <linux/mutex.h>
#include <asm/ioctls.h>
/* klp-ccp: from net/atm/resources.h */
#include <linux/atmdev.h>
#include <linux/mutex.h>

static int (*klpe_atm_getnames)(void __user *buf, int __user *iobuf_len);
static int (*klpe_atm_dev_ioctl)(unsigned int cmd, void __user *buf, int __user *sioc_len,
		  int number, int compat);

#ifdef CONFIG_PROC_FS

#include <linux/proc_fs.h>

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PROC_FS */

/* klp-ccp: from net/atm/signaling.h */
#include <linux/atm.h>
#include <linux/atmdev.h>
#include <linux/atmsvc.h>

static int (*klpe_sigd_attach)(struct atm_vcc *vcc);

/* klp-ccp: from net/atm/common.h */
#include <linux/net.h>
#include <linux/poll.h> /* for poll_table */

/* klp-ccp: from net/atm/ioctl.c */
static struct mutex (*klpe_ioctl_mutex);
static struct list_head (*klpe_ioctl_list);

int klpp_do_vcc_ioctl(struct socket *sock, unsigned int cmd,
			unsigned long arg, int compat)
{
	struct sock *sk = sock->sk;
	struct atm_vcc *vcc;
	int error;
	struct list_head *pos;
	void __user *argp = (void __user *)arg;
	void __user *buf;
	int __user *len;

	vcc = ATM_SD(sock);
	switch (cmd) {
	case SIOCOUTQ:
		if (sock->state != SS_CONNECTED ||
		    !test_bit(ATM_VF_READY, &vcc->flags)) {
			error =  -EINVAL;
			goto done;
		}
		error = put_user(sk->sk_sndbuf - sk_wmem_alloc_get(sk),
				 (int __user *)argp) ? -EFAULT : 0;
		goto done;
	case SIOCINQ:
	{
		struct sk_buff *skb;
		int amount;

		if (sock->state != SS_CONNECTED) {
			error = -EINVAL;
			goto done;
		}
		spin_lock_irq(&sk->sk_receive_queue.lock);
		skb = skb_peek(&sk->sk_receive_queue);
		amount = skb ? skb->len : 0;
		spin_unlock_irq(&sk->sk_receive_queue.lock);
		error = put_user(amount, (int __user *)argp) ? -EFAULT : 0;
		goto done;
	}
	case ATM_SETSC:
		net_warn_ratelimited("ATM_SETSC is obsolete; used by %s:%d\n",
				     current->comm, task_pid_nr(current));
		error = 0;
		goto done;
	case ATMSIGD_CTRL:
		if (!capable(CAP_NET_ADMIN)) {
			error = -EPERM;
			goto done;
		}
		/*
		 * The user/kernel protocol for exchanging signalling
		 * info uses kernel pointers as opaque references,
		 * so the holder of the file descriptor can scribble
		 * on the kernel... so we should make sure that we
		 * have the same privileges that /proc/kcore needs
		 */
		if (!capable(CAP_SYS_RAWIO)) {
			error = -EPERM;
			goto done;
		}
#ifdef CONFIG_COMPAT
		if (compat) {
			net_warn_ratelimited("32-bit task cannot be atmsigd\n");
			error = -EINVAL;
			goto done;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		error = (*klpe_sigd_attach)(vcc);
		if (!error)
			sock->state = SS_CONNECTED;
		goto done;
	case ATM_SETBACKEND:
	case ATM_NEWBACKENDIF:
	{
		atm_backend_t backend;
		error = get_user(backend, (atm_backend_t __user *)argp);
		if (error)
			goto done;
		switch (backend) {
		case ATM_BACKEND_PPP:
			request_module("pppoatm");
			break;
		case ATM_BACKEND_BR2684:
			request_module("br2684");
			break;
		}
		break;
	}
	case ATMMPC_CTRL:
	case ATMMPC_DATA:
		request_module("mpoa");
		break;
	case ATMARPD_CTRL:
		request_module("clip");
		break;
	case ATMLEC_CTRL:
		request_module("lec");
		break;
	}

	error = -ENOIOCTLCMD;

	mutex_lock(&(*klpe_ioctl_mutex));
	list_for_each(pos, &(*klpe_ioctl_list)) {
		struct atm_ioctl *ic = list_entry(pos, struct atm_ioctl, list);
		if (try_module_get(ic->owner)) {
			error = ic->ioctl(sock, cmd, arg);
			module_put(ic->owner);
			if (error != -ENOIOCTLCMD)
				break;
		}
	}
	mutex_unlock(&(*klpe_ioctl_mutex));

	if (error != -ENOIOCTLCMD)
		goto done;

	if (cmd == ATM_GETNAMES) {
		if (IS_ENABLED(CONFIG_COMPAT) && compat) {
#ifdef CONFIG_COMPAT
			struct compat_atm_iobuf __user *ciobuf = argp;
			compat_uptr_t cbuf;
			len = &ciobuf->length;
			if (get_user(cbuf, &ciobuf->buffer))
				return -EFAULT;
			buf = compat_ptr(cbuf);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		} else {
			struct atm_iobuf __user *iobuf = argp;
			len = &iobuf->length;
			if (get_user(buf, &iobuf->buffer))
				return -EFAULT;
		}
		error = (*klpe_atm_getnames)(buf, len);
	} else {
		int number;

		if (IS_ENABLED(CONFIG_COMPAT) && compat) {
#ifdef CONFIG_COMPAT
			struct compat_atmif_sioc __user *csioc = argp;
			compat_uptr_t carg;

			len = &csioc->length;
			if (get_user(carg, &csioc->arg))
				return -EFAULT;
			buf = compat_ptr(carg);
			if (get_user(number, &csioc->number))
				return -EFAULT;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		} else {
			struct atmif_sioc __user *sioc = argp;

			len = &sioc->length;
			if (get_user(buf, &sioc->arg))
				return -EFAULT;
			if (get_user(number, &sioc->number))
				return -EFAULT;
		}
		error = (*klpe_atm_dev_ioctl)(cmd, buf, len, number, compat);
	}

done:
	return error;
}


#include "livepatch_bsc1218733.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "atm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "atm_dev_ioctl", (void *)&klpe_atm_dev_ioctl, "atm" },
	{ "atm_getnames", (void *)&klpe_atm_getnames, "atm" },
	{ "ioctl_list", (void *)&klpe_ioctl_list, "atm" },
	{ "ioctl_mutex", (void *)&klpe_ioctl_mutex, "atm" },
	{ "sigd_attach", (void *)&klpe_sigd_attach, "atm" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1218733_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1218733_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_ATM) */
