/*
 * livepatch_bsc1204424
 *
 * Fix for CVE-2022-3545, bsc#1204424
 *
 *  Upstream commit:
 *  02e1a114fdb7 ("nfp: fix use-after-free in area_cache_get()")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  6a86a39fd05772b2a6433ff04208d54240475054
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b08143661515769c9cc1b0694b3f71b3f75558cb
 *
 *  SLE15-SP4 commit:
 *  de3f916fb2fe873eff4717cc5ce3824315fa4675
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

#if !IS_MODULE(CONFIG_NFP)
#error "Live patch supports only CONFIG_NFP=m"
#endif

/* klp-ccp: from drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c */
#include <asm/unaligned.h>
#include <linux/device.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/wait.h>
/* klp-ccp: from drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cpp.h */
#include <linux/types.h>
#include <linux/sizes.h>

#define NFP_CPP_SAFE_AREA_SIZE		SZ_2M

struct nfp_cpp;

static struct nfp_cpp_area *(*klpe_nfp_cpp_area_alloc)(struct nfp_cpp *cpp, u32 cpp_id,
					unsigned long long address,
					unsigned long size);

static void (*klpe_nfp_cpp_area_free)(struct nfp_cpp_area *area);
static int (*klpe_nfp_cpp_area_acquire)(struct nfp_cpp_area *area);

static void (*klpe_nfp_cpp_area_release)(struct nfp_cpp_area *area);
static void (*klpe_nfp_cpp_area_release_free)(struct nfp_cpp_area *area);
static int (*klpe_nfp_cpp_area_read)(struct nfp_cpp_area *area, unsigned long offset,
		      void *buffer, size_t length);
static int (*klpe_nfp_cpp_area_write)(struct nfp_cpp_area *area, unsigned long offset,
		       const void *buffer, size_t length);

int klpp_nfp_cpp_read(struct nfp_cpp *cpp, u32 cpp_id,
		 unsigned long long address, void *kernel_vaddr, size_t length);
int klpp_nfp_cpp_write(struct nfp_cpp *cpp, u32 cpp_id,
		  unsigned long long address, const void *kernel_vaddr,
		  size_t length);

struct nfp_cpp_explicit;

struct nfp_cpp_explicit_command;

#define NFP_SERIAL_LEN		6

struct nfp_cpp_operations {
	size_t area_priv_size;
	struct module *owner;

	int (*init)(struct nfp_cpp *cpp);
	void (*free)(struct nfp_cpp *cpp);

	int (*read_serial)(struct device *dev, u8 *serial);
	int (*get_interface)(struct device *dev);

	int (*area_init)(struct nfp_cpp_area *area,
			 u32 dest, unsigned long long address,
			 unsigned long size);
	void (*area_cleanup)(struct nfp_cpp_area *area);
	int (*area_acquire)(struct nfp_cpp_area *area);
	void (*area_release)(struct nfp_cpp_area *area);
	struct resource *(*area_resource)(struct nfp_cpp_area *area);
	phys_addr_t (*area_phys)(struct nfp_cpp_area *area);
	void __iomem *(*area_iomem)(struct nfp_cpp_area *area);
	int (*area_read)(struct nfp_cpp_area *area, void *kernel_vaddr,
			 unsigned long offset, unsigned int length);
	int (*area_write)(struct nfp_cpp_area *area, const void *kernel_vaddr,
			  unsigned long offset, unsigned int length);

	size_t explicit_priv_size;
	int (*explicit_acquire)(struct nfp_cpp_explicit *expl);
	void (*explicit_release)(struct nfp_cpp_explicit *expl);
	int (*explicit_put)(struct nfp_cpp_explicit *expl,
			    const void *buff, size_t len);
	int (*explicit_get)(struct nfp_cpp_explicit *expl,
			    void *buff, size_t len);
	int (*explicit_do)(struct nfp_cpp_explicit *expl,
			   const struct nfp_cpp_explicit_command *cmd,
			   u64 address);
};

/* klp-ccp: from drivers/net/ethernet/netronome/nfp/nfpcore/nfp6000/nfp6000.h */
#include <linux/errno.h>
#include <linux/types.h>

static int (*klpe_nfp_target_cpp)(u32 cpp_island_id, u64 cpp_island_address,
		   u32 *cpp_target_id, u64 *cpp_target_address,
		   const u32 *imb_table);

/* klp-ccp: from drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c */
struct nfp_cpp {
	struct device dev;

	void *priv;

	u32 model;
	u16 interface;
	u8 serial[NFP_SERIAL_LEN];

	const struct nfp_cpp_operations *op;
	struct list_head resource_list;
	rwlock_t resource_lock;
	wait_queue_head_t waitq;

	u32 imb_cat_table[16];
	unsigned int mu_locality_lsb;

	struct mutex area_cache_mutex;
	struct list_head area_cache_list;
};

struct nfp_cpp_area_cache {
	struct list_head entry;
	u32 id;
	u64 addr;
	u32 size;
	struct nfp_cpp_area *area;
};

static struct nfp_cpp_area_cache *
klpp_area_cache_get(struct nfp_cpp *cpp, u32 id,
	       u64 addr, unsigned long *offset, size_t length)
{
	struct nfp_cpp_area_cache *cache;
	int err;

	/* Early exit when length == 0, which prevents
	 * the need for special case code below when
	 * checking against available cache size.
	 */
	if (length == 0 || id == 0)
		return NULL;

	/* Remap from cpp_island to cpp_target */
	err = (*klpe_nfp_target_cpp)(id, addr, &id, &addr, cpp->imb_cat_table);
	if (err < 0)
		return NULL;

	mutex_lock(&cpp->area_cache_mutex);

	if (list_empty(&cpp->area_cache_list)) {
		mutex_unlock(&cpp->area_cache_mutex);
		return NULL;
	}

	addr += *offset;

	/* See if we have a match */
	list_for_each_entry(cache, &cpp->area_cache_list, entry) {
		if (id == cache->id &&
		    addr >= cache->addr &&
		    addr + length <= cache->addr + cache->size)
			goto exit;
	}

	/* No matches - inspect the tail of the LRU */
	cache = list_entry(cpp->area_cache_list.prev,
			   struct nfp_cpp_area_cache, entry);

	/* Can we fit in the cache entry? */
	if (round_down(addr + length - 1, cache->size) !=
	    round_down(addr, cache->size)) {
		mutex_unlock(&cpp->area_cache_mutex);
		return NULL;
	}

	/* If id != 0, we will need to release it */
	if (cache->id) {
		(*klpe_nfp_cpp_area_release)(cache->area);
		cache->id = 0;
		cache->addr = 0;
	}

	/* Adjust the start address to be cache size aligned */
	/*
	 * Fix CVE-2022-3545
	 *  -1 line
	 */

	cache->addr = addr & ~(u64)(cache->size - 1);

	/* Re-init to the new ID and address */
	if (cpp->op->area_init) {
		err = cpp->op->area_init(cache->area,
					 id, cache->addr, cache->size);
		if (err < 0) {
			mutex_unlock(&cpp->area_cache_mutex);
			return NULL;
		}
	}

	/* Attempt to acquire */
	err = (*klpe_nfp_cpp_area_acquire)(cache->area);
	if (err < 0) {
		mutex_unlock(&cpp->area_cache_mutex);
		return NULL;
	}

	/*
	 * Fix CVE-2022-3545
	 *  +1 line
	 */
	cache->id = id;

exit:
	/* Adjust offset */
	*offset = addr - cache->addr;
	return cache;
}

static void
area_cache_put(struct nfp_cpp *cpp, struct nfp_cpp_area_cache *cache)
{
	if (!cache)
		return;

	/* Move to front of LRU */
	list_del(&cache->entry);
	list_add(&cache->entry, &cpp->area_cache_list);

	mutex_unlock(&cpp->area_cache_mutex);
}

static int klpp___nfp_cpp_read(struct nfp_cpp *cpp, u32 destination,
			  unsigned long long address, void *kernel_vaddr,
			  size_t length)
{
	struct nfp_cpp_area_cache *cache;
	struct nfp_cpp_area *area;
	unsigned long offset = 0;
	int err;

	cache = klpp_area_cache_get(cpp, destination, address, &offset, length);
	if (cache) {
		area = cache->area;
	} else {
		area = (*klpe_nfp_cpp_area_alloc)(cpp, destination, address, length);
		if (!area)
			return -ENOMEM;

		err = (*klpe_nfp_cpp_area_acquire)(area);
		if (err) {
			(*klpe_nfp_cpp_area_free)(area);
			return err;
		}
	}

	err = (*klpe_nfp_cpp_area_read)(area, offset, kernel_vaddr, length);

	if (cache)
		area_cache_put(cpp, cache);
	else
		(*klpe_nfp_cpp_area_release_free)(area);

	return err;
}

int klpp_nfp_cpp_read(struct nfp_cpp *cpp, u32 destination,
		 unsigned long long address, void *kernel_vaddr,
		 size_t length)
{
	size_t n, offset;
	int ret;

	for (offset = 0; offset < length; offset += n) {
		unsigned long long r_addr = address + offset;

		/* make first read smaller to align to safe window */
		n = min_t(size_t, length - offset,
			  ALIGN(r_addr + 1, NFP_CPP_SAFE_AREA_SIZE) - r_addr);

		ret = klpp___nfp_cpp_read(cpp, destination, address + offset,
				     kernel_vaddr + offset, n);
		if (ret < 0)
			return ret;
		if (ret != n)
			return offset + n;
	}

	return length;
}

static int klpp___nfp_cpp_write(struct nfp_cpp *cpp, u32 destination,
			   unsigned long long address,
			   const void *kernel_vaddr, size_t length)
{
	struct nfp_cpp_area_cache *cache;
	struct nfp_cpp_area *area;
	unsigned long offset = 0;
	int err;

	cache = klpp_area_cache_get(cpp, destination, address, &offset, length);
	if (cache) {
		area = cache->area;
	} else {
		area = (*klpe_nfp_cpp_area_alloc)(cpp, destination, address, length);
		if (!area)
			return -ENOMEM;

		err = (*klpe_nfp_cpp_area_acquire)(area);
		if (err) {
			(*klpe_nfp_cpp_area_free)(area);
			return err;
		}
	}

	err = (*klpe_nfp_cpp_area_write)(area, offset, kernel_vaddr, length);

	if (cache)
		area_cache_put(cpp, cache);
	else
		(*klpe_nfp_cpp_area_release_free)(area);

	return err;
}

int klpp_nfp_cpp_write(struct nfp_cpp *cpp, u32 destination,
		  unsigned long long address,
		  const void *kernel_vaddr, size_t length)
{
	size_t n, offset;
	int ret;

	for (offset = 0; offset < length; offset += n) {
		unsigned long long w_addr = address + offset;

		/* make first write smaller to align to safe window */
		n = min_t(size_t, length - offset,
			  ALIGN(w_addr + 1, NFP_CPP_SAFE_AREA_SIZE) - w_addr);

		ret = klpp___nfp_cpp_write(cpp, destination, address + offset,
				      kernel_vaddr + offset, n);
		if (ret < 0)
			return ret;
		if (ret != n)
			return offset + n;
	}

	return length;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1204424.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nfp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfp_cpp_area_acquire", (void *)&klpe_nfp_cpp_area_acquire, "nfp" },
	{ "nfp_cpp_area_alloc", (void *)&klpe_nfp_cpp_area_alloc, "nfp" },
	{ "nfp_cpp_area_free", (void *)&klpe_nfp_cpp_area_free, "nfp" },
	{ "nfp_cpp_area_read", (void *)&klpe_nfp_cpp_area_read, "nfp" },
	{ "nfp_cpp_area_release", (void *)&klpe_nfp_cpp_area_release, "nfp" },
	{ "nfp_cpp_area_release_free", (void *)&klpe_nfp_cpp_area_release_free,
	  "nfp" },
	{ "nfp_cpp_area_write", (void *)&klpe_nfp_cpp_area_write, "nfp" },
	{ "nfp_target_cpp", (void *)&klpe_nfp_target_cpp, "nfp" },
};

static int livepatch_bsc1204424_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1204424_module_nb = {
	.notifier_call = livepatch_bsc1204424_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1204424_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1204424_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1204424_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1204424_module_nb);
}
