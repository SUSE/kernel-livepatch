/*
 * livepatch_bsc1214812
 *
 * Fix for CVE-2023-4004, bsc#1214812
 *
 *  Upstream commit:
 *  87b5a5c20940 ("netfilter: nft_set_pipapo: fix improper element removal")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  4902a9982bca45b9b14fcb3973815802fcaccd69
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#if !IS_MODULE(CONFIG_NF_TABLES)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/netfilter/nft_set_pipapo.c */
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>
#include <uapi/linux/netfilter/nf_tables.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>

/* klp-ccp: from net/netfilter/nft_set_pipapo_avx2.h */
#if defined(CONFIG_X86_64) && !defined(CONFIG_UML)
#include <asm/fpu/xstate.h>
#define NFT_PIPAPO_ALIGN	(XSAVE_YMM_SIZE / BITS_PER_BYTE)
#endif

/* klp-ccp: from net/netfilter/nft_set_pipapo.h */
#ifndef _NFT_SET_PIPAPO_H

#include <linux/log2.h>

#define NFT_PIPAPO_MAX_FIELDS		NFT_REG32_COUNT

#define NFT_PIPAPO_MAX_BYTES		(sizeof(struct in6_addr))
#define NFT_PIPAPO_MAX_BITS		(NFT_PIPAPO_MAX_BYTES * BITS_PER_BYTE)

#define NFT_PIPAPO_GROUPS_PER_BYTE(f)	(BITS_PER_BYTE / (f)->bb)

#define NFT_PIPAPO_GROUPS_PADDED_SIZE(f)					(round_up((f)->groups / NFT_PIPAPO_GROUPS_PER_BYTE(f), sizeof(u32)))
#define NFT_PIPAPO_GROUPS_PADDING(f)						(NFT_PIPAPO_GROUPS_PADDED_SIZE(f) - (f)->groups /							    NFT_PIPAPO_GROUPS_PER_BYTE(f))

#define NFT_PIPAPO_BUCKETS(bb)		(1 << (bb))

#define NFT_PIPAPO_MAP_NBITS		(const_ilog2(NFT_PIPAPO_MAX_BITS * 2))

#if BITS_PER_LONG == 64
#define NFT_PIPAPO_MAP_TOBITS		32
#else
#define NFT_PIPAPO_MAP_TOBITS		(BITS_PER_LONG - NFT_PIPAPO_MAP_NBITS)
#endif

#ifdef NFT_PIPAPO_ALIGN
#define NFT_PIPAPO_LT_ALIGN(lt)		(PTR_ALIGN((lt), NFT_PIPAPO_ALIGN))
#else
#define NFT_PIPAPO_LT_ALIGN(lt)		(lt)
#endif

#define nft_pipapo_for_each_field(field, index, match)			for ((field) = (match)->f, (index) = 0;				     (index) < (match)->field_count;				     (index)++, (field)++)

union nft_pipapo_map_bucket {
	struct {
#if BITS_PER_LONG == 64
		static_assert(NFT_PIPAPO_MAP_TOBITS <= 32);
		u32 to;

		static_assert(NFT_PIPAPO_MAP_NBITS <= 32);
		u32 n;
#else
#error "klp-ccp: non-taken branch"
#endif
	};
	struct nft_pipapo_elem *e;
};

struct nft_pipapo_field {
	int groups;
	unsigned long rules;
	size_t bsize;
	int bb;
#ifdef NFT_PIPAPO_ALIGN
	unsigned long *lt_aligned;
#endif
	unsigned long *lt;
	union nft_pipapo_map_bucket *mt;
};

struct nft_pipapo_match {
	int field_count;
#ifdef NFT_PIPAPO_ALIGN
	unsigned long * __percpu *scratch_aligned;
#endif
	unsigned long * __percpu *scratch;
	size_t bsize_max;
	struct rcu_head rcu;
	struct nft_pipapo_field f[];
};

struct nft_pipapo {
	struct nft_pipapo_match __rcu *match;
	struct nft_pipapo_match *clone;
	int width;
	bool dirty;
	unsigned long last_gc;
};

struct nft_pipapo_elem {
	struct nft_set_ext ext;
};

static int (*klpe_pipapo_refill)(unsigned long *map, int len, int rules, unsigned long *dst,
		  union nft_pipapo_map_bucket *mt, bool match_only);

static inline void pipapo_and_field_buckets_4bit(struct nft_pipapo_field *f,
						 unsigned long *dst,
						 const u8 *data)
{
	unsigned long *lt = NFT_PIPAPO_LT_ALIGN(f->lt);
	int group;

	for (group = 0; group < f->groups; group += BITS_PER_BYTE / 4, data++) {
		u8 v;

		v = *data >> 4;
		__bitmap_and(dst, dst, lt + v * f->bsize,
			     f->bsize * BITS_PER_LONG);
		lt += f->bsize * NFT_PIPAPO_BUCKETS(4);

		v = *data & 0x0f;
		__bitmap_and(dst, dst, lt + v * f->bsize,
			     f->bsize * BITS_PER_LONG);
		lt += f->bsize * NFT_PIPAPO_BUCKETS(4);
	}
}

static inline void pipapo_and_field_buckets_8bit(struct nft_pipapo_field *f,
						 unsigned long *dst,
						 const u8 *data)
{
	unsigned long *lt = NFT_PIPAPO_LT_ALIGN(f->lt);
	int group;

	for (group = 0; group < f->groups; group++, data++) {
		__bitmap_and(dst, dst, lt + *data * f->bsize,
			     f->bsize * BITS_PER_LONG);
		lt += f->bsize * NFT_PIPAPO_BUCKETS(8);
	}
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _NFT_SET_PIPAPO_H */

static struct nft_pipapo_elem *klpr_pipapo_get(const struct net *net,
					  const struct nft_set *set,
					  const u8 *data, u8 genmask)
{
	struct nft_pipapo_elem *ret = ERR_PTR(-ENOENT);
	struct nft_pipapo *priv = nft_set_priv(set);
	struct nft_pipapo_match *m = priv->clone;
	unsigned long *res_map, *fill_map = NULL;
	struct nft_pipapo_field *f;
	int i;

	res_map = kmalloc_array(m->bsize_max, sizeof(*res_map), GFP_ATOMIC);
	if (!res_map) {
		ret = ERR_PTR(-ENOMEM);
		goto out;
	}

	fill_map = kcalloc(m->bsize_max, sizeof(*res_map), GFP_ATOMIC);
	if (!fill_map) {
		ret = ERR_PTR(-ENOMEM);
		goto out;
	}

	memset(res_map, 0xff, m->bsize_max * sizeof(*res_map));

	nft_pipapo_for_each_field(f, i, m) {
		bool last = i == m->field_count - 1;
		int b;

		/* For each bit group: select lookup table bucket depending on
		 * packet bytes value, then AND bucket value
		 */
		if (f->bb == 8)
			pipapo_and_field_buckets_8bit(f, res_map, data);
		else if (f->bb == 4)
			pipapo_and_field_buckets_4bit(f, res_map, data);
		else
			BUG();

		data += f->groups / NFT_PIPAPO_GROUPS_PER_BYTE(f);

		/* Now populate the bitmap for the next field, unless this is
		 * the last field, in which case return the matched 'ext'
		 * pointer if any.
		 *
		 * Now res_map contains the matching bitmap, and fill_map is the
		 * bitmap for the next field.
		 */
next_match:
		b = (*klpe_pipapo_refill)(res_map, f->bsize, f->rules, fill_map, f->mt,
				  last);
		if (b < 0)
			goto out;

		if (last) {
			if (nft_set_elem_expired(&f->mt[b].e->ext) ||
			    (genmask &&
			     !nft_set_elem_active(&f->mt[b].e->ext, genmask)))
				goto next_match;

			ret = f->mt[b].e;
			goto out;
		}

		data += NFT_PIPAPO_GROUPS_PADDING(f);

		/* Swap bitmap indices: fill_map will be the initial bitmap for
		 * the next field (i.e. the new res_map), and res_map is
		 * guaranteed to be all-zeroes at this point, ready to be filled
		 * according to the next mapping table.
		 */
		swap(res_map, fill_map);
	}

out:
	kfree(fill_map);
	kfree(res_map);
	return ret;
}

static int pipapo_rules_same_key(struct nft_pipapo_field *f, int first)
{
	struct nft_pipapo_elem *e = NULL; /* Keep gcc happy */
	int r;

	for (r = first; r < f->rules; r++) {
		if (r != first && e != f->mt[r].e)
			return r - first;

		e = f->mt[r].e;
	}

	if (r != first)
		return r - first;

	return 0;
}

static void (*klpe_pipapo_drop)(struct nft_pipapo_match *m,
			union nft_pipapo_map_bucket rulemap[]);

static void (*klpe_pipapo_commit)(const struct nft_set *set);

static int pipapo_get_boundaries(struct nft_pipapo_field *f, int first_rule,
				 int rule_count, u8 *left, u8 *right)
{
	int g, mask_len = 0, bit_offset = 0;
	u8 *l = left, *r = right;

	for (g = 0; g < f->groups; g++) {
		int b, x0, x1;

		x0 = -1;
		x1 = -1;
		for (b = 0; b < NFT_PIPAPO_BUCKETS(f->bb); b++) {
			unsigned long *pos;

			pos = NFT_PIPAPO_LT_ALIGN(f->lt) +
			      (g * NFT_PIPAPO_BUCKETS(f->bb) + b) * f->bsize;
			if (test_bit(first_rule, pos) && x0 == -1)
				x0 = b;
			if (test_bit(first_rule + rule_count - 1, pos))
				x1 = b;
		}

		*l |= x0 << (BITS_PER_BYTE - f->bb - bit_offset);
		*r |= x1 << (BITS_PER_BYTE - f->bb - bit_offset);

		bit_offset += f->bb;
		if (bit_offset >= BITS_PER_BYTE) {
			bit_offset %= BITS_PER_BYTE;
			l++;
			r++;
		}

		if (x1 - x0 == 0)
			mask_len += 4;
		else if (x1 - x0 == 1)
			mask_len += 3;
		else if (x1 - x0 == 3)
			mask_len += 2;
		else if (x1 - x0 == 7)
			mask_len += 1;
	}

	return mask_len;
}

static bool pipapo_match_field(struct nft_pipapo_field *f,
			       int first_rule, int rule_count,
			       const u8 *start, const u8 *end)
{
	u8 right[NFT_PIPAPO_MAX_BYTES] = { 0 };
	u8 left[NFT_PIPAPO_MAX_BYTES] = { 0 };

	pipapo_get_boundaries(f, first_rule, rule_count, left, right);

	return !memcmp(start, left,
		       f->groups / NFT_PIPAPO_GROUPS_PER_BYTE(f)) &&
	       !memcmp(end, right, f->groups / NFT_PIPAPO_GROUPS_PER_BYTE(f));
}

void klpp_nft_pipapo_remove(const struct net *net, const struct nft_set *set,
			      const struct nft_set_elem *elem)
{
	struct nft_pipapo *priv = nft_set_priv(set);
	struct nft_pipapo_match *m = priv->clone;
	struct nft_pipapo_elem *e = elem->priv;
	int rules_f0, first_rule = 0;
	const u8 *data;

	data = (const u8 *)nft_set_ext_key(&e->ext);

	e = klpr_pipapo_get(net, set, data, 0);
	if (IS_ERR(e))
		return;

	while ((rules_f0 = pipapo_rules_same_key(m->f, first_rule))) {
		union nft_pipapo_map_bucket rulemap[NFT_PIPAPO_MAX_FIELDS];
		const u8 *match_start, *match_end;
		struct nft_pipapo_field *f;
		int i, start, rules_fx;

		match_start = data;

		if (nft_set_ext_exists(&e->ext, NFT_SET_EXT_KEY_END))
			match_end = (const u8 *)nft_set_ext_key_end(&e->ext)->data;
		else
			match_end = data;

		start = first_rule;
		rules_fx = rules_f0;

		nft_pipapo_for_each_field(f, i, m) {
			if (!pipapo_match_field(f, start, rules_fx,
						match_start, match_end))
				break;

			rulemap[i].to = start;
			rulemap[i].n = rules_fx;

			rules_fx = f->mt[start].n;
			start = f->mt[start].to;

			match_start += NFT_PIPAPO_GROUPS_PADDED_SIZE(f);
			match_end += NFT_PIPAPO_GROUPS_PADDED_SIZE(f);
		}

		if (i == m->field_count) {
			priv->dirty = true;
			(*klpe_pipapo_drop)(m, rulemap);
			(*klpe_pipapo_commit)(set);
			return;
		}

		first_rule += rules_f0;
	}
}



#include "livepatch_bsc1214812.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nf_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "pipapo_commit", (void *)&klpe_pipapo_commit, "nf_tables" },
	{ "pipapo_drop", (void *)&klpe_pipapo_drop, "nf_tables" },
	{ "pipapo_refill", (void *)&klpe_pipapo_refill, "nf_tables" },
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

int livepatch_bsc1214812_init(void)
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

void livepatch_bsc1214812_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
