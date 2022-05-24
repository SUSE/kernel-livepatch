/*
 * livepatch_bsc1188842
 *
 * Fix for CVE-2021-37576, bsc#1188842
 *
 *  Upstream commit:
 *  f62f3c20647e ("KVM: PPC: Book3S: Fix H_RTAS rets buffer overflow")
 *
 *  SLE12-SP3 commit:
 *  3d8113155789b080b8f35ab9f8330060d394062d
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  50c1fabbee471a0cc0e005f65426b7911392e18c
 *
 *  SLE15-SP2 and -SP3 commit:
 *  0162dcdcb6e79aafaf8e1f7e7378f200fdb57e32
 *
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

#if IS_ENABLED(CONFIG_KVM_BOOK3S_64)

#if !IS_MODULE(CONFIG_KVM_BOOK3S_64)
#error "Live patch supports only CONFIG_KVM_BOOK3S_64=m"
#endif

/* klp-ccp: from arch/powerpc/kvm/book3s_rtas.c */
#include <linux/kernel.h>
#include <linux/kvm_host.h>

/* klp-ccp: from include/linux/kvm_host.h */
static int (*klpe_kvm_read_guest)(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len);

static int (*klpe_kvm_write_guest)(struct kvm *kvm, gpa_t gpa, const void *data,
		    unsigned long len);

/* klp-ccp: from arch/powerpc/kvm/book3s_rtas.c */
#include <linux/kvm.h>
#include <linux/err.h>

#include <linux/uaccess.h>
#include <asm/kvm_book3s.h>
#include <asm/kvm_ppc.h>
#include <asm/hvcall.h>
#include <asm/rtas.h>

struct rtas_handler {
	void (*handler)(struct kvm_vcpu *vcpu, struct rtas_args *args);
	char *name;
};

struct rtas_token_definition {
	struct list_head list;
	struct rtas_handler *handler;
	u64 token;
};

int klpp_kvmppc_rtas_hcall(struct kvm_vcpu *vcpu)
{
	struct rtas_token_definition *d;
	struct rtas_args args;
	rtas_arg_t *orig_rets;
	gpa_t args_phys;
	int rc;

	/*
	 * r4 contains the guest physical address of the RTAS args
	 * Mask off the top 4 bits since this is a guest real address
	 */
	args_phys = kvmppc_get_gpr(vcpu, 4) & KVM_PAM;

	rc = (*klpe_kvm_read_guest)(vcpu->kvm, args_phys, &args, sizeof(args));
	if (rc)
		goto fail;

	/*
	 * args->rets is a pointer into args->args. Now that we've
	 * copied args we need to fix it up to point into our copy,
	 * not the guest args. We also need to save the original
	 * value so we can restore it on the way out.
	 */
	orig_rets = args.rets;
	/*
	 * Fix CVE-2021-37576
	 *  +11 lines
	 */
	if (be32_to_cpu(args.nargs) >= ARRAY_SIZE(args.args)) {
		/*
		 * Don't overflow our args array: ensure there is room for
		 * at least rets[0] (even if the call specifies 0 nret).
		 *
		 * Each handler must then check for the correct nargs and nret
		 * values, but they may always return failure in rets[0].
		 */
		rc = -EINVAL;
		goto fail;
	}
	args.rets = &args.args[be32_to_cpu(args.nargs)];

	mutex_lock(&vcpu->kvm->lock);

	rc = -ENOENT;
	list_for_each_entry(d, &vcpu->kvm->arch.rtas_tokens, list) {
		if (d->token == be32_to_cpu(args.token)) {
			d->handler->handler(vcpu, &args);
			rc = 0;
			break;
		}
	}

	mutex_unlock(&vcpu->kvm->lock);

	if (rc == 0) {
		args.rets = orig_rets;
		rc = (*klpe_kvm_write_guest)(vcpu->kvm, args_phys, &args, sizeof(args));
		if (rc)
			goto fail;
	}

	return rc;

fail:
	/*
	 * We only get here if the guest has called RTAS with a bogus
	 * args pointer. That means we can't get to the args, and so we
	 * can't fail the RTAS call. So fail right out to userspace,
	 * which should kill the guest.
	 */
	return rc;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1188842.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "kvm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "kvm_read_guest", (void *)&klpe_kvm_read_guest, "kvm" },
	{ "kvm_write_guest", (void *)&klpe_kvm_write_guest, "kvm" },
};

static int livepatch_bsc1188842_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1188842_module_nb = {
	.notifier_call = livepatch_bsc1188842_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1188842_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1188842_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1188842_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1188842_module_nb);
}

#endif /* IS_ENABLED(CONFIG_KVM_BOOK3S_64) */
