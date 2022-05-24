/*
 * livepatch_bsc1187052
 *
 * Fix for CVE-2020-36385, bsc#1187052
 *
 *  Upstream commit:
 *  f5449e74802c ("RDMA/ucma: Rework ucma_migrate_id() to avoid races with
 *                 destroy")
 *
 *  SLE12-SP3 commit:
 *  a9ceda8e4abe663d59dc9eed75857cf9a1205951
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  ee0f2ccfcbf86c868ee15d83bf68ab14e9fd90d8
 *
 *  SLE15-SP2 and -SP3 commit:
 *  d6301269b4f302657ab6d5bc061ba6bf1d6c6be1
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

#if !IS_MODULE(CONFIG_INFINIBAND_USER_ACCESS)
#error "Live patch supports only CONFIG_INFINIBAND_USER_ACCESS=m"
#endif

/* klp-ccp: from drivers/infiniband/core/ucma.c */
#include <linux/completion.h>
#include <linux/file.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <rdma/rdma_user_cm.h>
#include <rdma/ib_addr.h>

struct ucma_file {
	struct mutex		mut;
	struct file		*filp;
	struct list_head	ctx_list;
	struct list_head	event_list;
	wait_queue_head_t	poll_wait;
	struct workqueue_struct	*close_wq;
};

struct ucma_context {
	int			id;
	struct completion	comp;
	atomic_t		ref;
	int			events_reported;
	int			backlog;

	struct ucma_file	*file;
	struct rdma_cm_id	*cm_id;
	struct mutex		mutex;
	u64			uid;

	struct list_head	list;
	struct list_head	mc_list;
	/* mark that device is in process of destroying the internal HW
	 * resources, protected by the global mut
	 */
	int			closing;
	/* sync between removal event and id destroy, protected by file mut */
	int			destroying;
	struct work_struct	close_work;
};

struct ucma_event {
	struct ucma_context	*ctx;
	struct ucma_multicast	*mc;
	struct list_head	list;
	struct rdma_cm_id	*cm_id;
	struct rdma_ucm_event_resp resp;
	struct work_struct	close_work;
};

static struct mutex (*klpe_mut);

static struct idr (*klpe_ctx_idr);

static const struct file_operations (*klpe_ucma_fops);

static inline struct ucma_context *klpr__ucma_find_context(int id,
						      struct ucma_file *file)
{
	struct ucma_context *ctx;

	ctx = idr_find(&(*klpe_ctx_idr), id);
	if (!ctx)
		ctx = ERR_PTR(-ENOENT);
	else if (ctx->file != file || !ctx->cm_id)
		ctx = ERR_PTR(-EINVAL);
	return ctx;
}

static struct ucma_context *(*klpe_ucma_get_ctx)(struct ucma_file *file, int id);

static void ucma_put_ctx(struct ucma_context *ctx)
{
	if (atomic_dec_and_test(&ctx->ref))
		complete(&ctx->comp);
}

static void ucma_lock_files(struct ucma_file *file1, struct ucma_file *file2)
{
	/* Acquire mutex's based on pointer comparison to prevent deadlock. */
	if (file1 < file2) {
		mutex_lock(&file1->mut);
		mutex_lock_nested(&file2->mut, SINGLE_DEPTH_NESTING);
	} else {
		mutex_lock(&file2->mut);
		mutex_lock_nested(&file1->mut, SINGLE_DEPTH_NESTING);
	}
}

static void ucma_unlock_files(struct ucma_file *file1, struct ucma_file *file2)
{
	if (file1 < file2) {
		mutex_unlock(&file2->mut);
		mutex_unlock(&file1->mut);
	} else {
		mutex_unlock(&file1->mut);
		mutex_unlock(&file2->mut);
	}
}

static void ucma_move_events(struct ucma_context *ctx, struct ucma_file *file)
{
	struct ucma_event *uevent, *tmp;

	list_for_each_entry_safe(uevent, tmp, &ctx->file->event_list, list)
		if (uevent->ctx == ctx)
			list_move_tail(&uevent->list, &file->event_list);
}

ssize_t klpp_ucma_migrate_id(struct ucma_file *new_file,
			       const char __user *inbuf,
			       int in_len, int out_len)
{
	struct rdma_ucm_migrate_id cmd;
	struct rdma_ucm_migrate_resp resp;
	struct ucma_context *ctx;
	struct fd f;
	struct ucma_file *cur_file;
	int ret = 0;

	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;

	/* Get current fd to protect against it being closed */
	f = fdget(cmd.fd);
	if (!f.file)
		return -ENOENT;
	if (f.file->f_op != &(*klpe_ucma_fops)) {
		ret = -EINVAL;
		goto file_put;
	}

	/* Validate current fd and prevent destruction of id. */
	ctx = (*klpe_ucma_get_ctx)(f.file->private_data, cmd.id);
	if (IS_ERR(ctx)) {
		ret = PTR_ERR(ctx);
		goto file_put;
	}

	cur_file = ctx->file;
	if (cur_file == new_file) {
		resp.events_reported = ctx->events_reported;
		goto response;
	}

	/*
	 * Migrate events between fd's, maintaining order, and avoiding new
	 * events being added before existing events.
	 */
	ucma_lock_files(cur_file, new_file);
	mutex_lock(&(*klpe_mut));

	/*
	 * Fix CVE-2020-36385
	 *  +7 lines
	 */
	if (klpr__ucma_find_context(cmd.id, cur_file) != ctx) {
		mutex_unlock(&(*klpe_mut));
		ucma_unlock_files(cur_file, new_file);
		ret = -ENOENT;
		goto err_unlock;
	}

	list_move_tail(&ctx->list, &new_file->ctx_list);
	ucma_move_events(ctx, new_file);
	ctx->file = new_file;
	resp.events_reported = ctx->events_reported;

	mutex_unlock(&(*klpe_mut));
	ucma_unlock_files(cur_file, new_file);

response:
	if (copy_to_user(u64_to_user_ptr(cmd.response),
			 &resp, sizeof(resp)))
		ret = -EFAULT;

/*
 * Fix CVE-2020-36385
 *  +1 line
 */
err_unlock:
	ucma_put_ctx(ctx);
file_put:
	fdput(f);
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1187052.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "rdma_ucm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "mut", (void *)&klpe_mut, "rdma_ucm" },
	{ "ctx_idr", (void *)&klpe_ctx_idr, "rdma_ucm" },
	{ "ucma_fops", (void *)&klpe_ucma_fops, "rdma_ucm" },
	{ "ucma_get_ctx", (void *)&klpe_ucma_get_ctx, "rdma_ucm" },
};

static int livepatch_bsc1187052_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1187052_module_nb = {
	.notifier_call = livepatch_bsc1187052_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1187052_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1187052_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1187052_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1187052_module_nb);
}
