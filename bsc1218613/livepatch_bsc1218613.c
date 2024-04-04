/*
 * livepatch_bsc1218613
 *
 * Fix for CVE-2023-42753, bsc#1218613
 *
 *  Upstream commit:
 *  050d91c03b28 ("netfilter: ipset: add the missing IP_SET_HASH_WITH_NET0 macro for ip_set_hash_netportnet.c")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  c0f449e04a540870e9694c105999ece02515fcf9
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


#if !IS_MODULE(CONFIG_IP_SET_HASH_NETPORTNET)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/netfilter/ipset/ip_set_hash_netportnet.c */
#include <linux/jhash.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/tcp.h>
#include <linux/netfilter.h>

/* klp-ccp: from include/linux/netfilter/ipset/pfxlen.h */
static const union nf_inet_addr (*klpe_ip_set_netmask_map)[];

static inline __be32
klpr_ip_set_netmask(u8 pfxlen)
{
	return (*klpe_ip_set_netmask_map)[pfxlen].ip;
}

static inline const __be32 *
klpr_ip_set_netmask6(u8 pfxlen)
{
	return &(*klpe_ip_set_netmask_map)[pfxlen].ip6[0];
}

static inline void
klpr_ip6_netmask(union nf_inet_addr *ip, u8 prefix)
{
	ip->ip6[0] &= klpr_ip_set_netmask6(prefix)[0];
	ip->ip6[1] &= klpr_ip_set_netmask6(prefix)[1];
	ip->ip6[2] &= klpr_ip_set_netmask6(prefix)[2];
	ip->ip6[3] &= klpr_ip_set_netmask6(prefix)[3];
}

/* klp-ccp: from net/netfilter/ipset/ip_set_hash_netportnet.c */
#include <linux/netfilter/ipset/ip_set.h>

/* klp-ccp: from include/linux/netfilter/ipset/ip_set.h */
static const struct ip_set_ext_type (*klpe_ip_set_extensions)[];

static inline void
klpr_ip_set_ext_destroy(struct ip_set *set, void *data)
{
	/* Check that the extension is enabled for the set and
	 * call it's destroy function for its extension part in data.
	 */
	if (SET_WITH_COMMENT(set)) {
		struct ip_set_comment *c = ext_comment(data, set);

		(*klpe_ip_set_extensions)[IPSET_EXT_ID_COMMENT].destroy(set, c);
	}
}

static bool (*klpe_ip_set_match_extensions)(struct ip_set *set,
				    const struct ip_set_ext *ext,
				    struct ip_set_ext *mext,
				    u32 flags, void *data);

static void (*klpe_ip_set_init_comment)(struct ip_set *set, struct ip_set_comment *comment,
			 const struct ip_set_ext *ext);

/* klp-ccp: from net/netfilter/ipset/ip_set_hash_netportnet.c */
#include <linux/netfilter/ipset/ip_set_hash.h>

#define IP_SET_HASH_WITH_NETS
#define IPSET_NET_COUNT 2

struct hash_netportnet4_elem {
	union {
		__be32 ip[2];
		__be64 ipcmp;
	};
	__be16 port;
	union {
		u8 cidr[2];
		u16 ccmp;
	};
	u16 padding;
	u8 nomatch;
	u8 proto;
};

static bool
hash_netportnet4_data_equal(const struct hash_netportnet4_elem *ip1,
			    const struct hash_netportnet4_elem *ip2,
			    u32 *multi)
{
	return ip1->ipcmp == ip2->ipcmp &&
	       ip1->ccmp == ip2->ccmp &&
	       ip1->port == ip2->port &&
	       ip1->proto == ip2->proto;
}

static int
hash_netportnet4_do_data_match(const struct hash_netportnet4_elem *elem)
{
	return elem->nomatch ? -ENOTEMPTY : 1;
}

static void
hash_netportnet4_data_set_flags(struct hash_netportnet4_elem *elem, u32 flags)
{
	elem->nomatch = !!((flags >> 16) & IPSET_FLAG_NOMATCH);
}

static void
hash_netportnet4_data_reset_elem(struct hash_netportnet4_elem *elem,
				 struct hash_netportnet4_elem *orig)
{
	elem->ip[1] = orig->ip[1];
}

static void
klpr_hash_netportnet4_data_netmask(struct hash_netportnet4_elem *elem,
			      u8 cidr, bool inner)
{
	if (inner) {
		elem->ip[1] &= klpr_ip_set_netmask(cidr);
		elem->cidr[1] = cidr;
	} else {
		elem->ip[0] &= klpr_ip_set_netmask(cidr);
		elem->cidr[0] = cidr;
	}
}

static void
hash_netportnet4_data_next(struct hash_netportnet4_elem *next,
			   const struct hash_netportnet4_elem *d)
{
	next->ipcmp = d->ipcmp;
	next->port = d->port;
}

#define MTYPE		hash_netportnet4
#define HOST_MASK	32

/* klp-ccp: from net/netfilter/ipset/ip_set_hash_gen.h */
#ifndef _IP_SET_HASH_GEN_H

#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <linux/types.h>
#include <linux/netfilter/ipset/ip_set.h>

#define AHASH_INIT_SIZE			2

#define AHASH_MAX_TUNED			64

#define AHASH_MAX(h)			((h)->bucketsize)

#define TUNE_BUCKETSIZE(h, multi)

struct hbucket {
	struct rcu_head rcu;	/* for call_rcu */
	/* Which positions are used in the array */
	DECLARE_BITMAP(used, AHASH_MAX_TUNED);
	u8 size;		/* size of the array */
	u8 pos;			/* position of the first free entry */
	unsigned char value[]	/* the array of the values */
		__aligned(__alignof__(u64));
};

#define HTABLE_REGION_BITS	10
#define ahash_numof_locks(htable_bits)			((htable_bits) < HTABLE_REGION_BITS ? 1			: jhash_size((htable_bits) - HTABLE_REGION_BITS))

#define ahash_region(n, htable_bits)			((n) % ahash_numof_locks(htable_bits))

struct htable_gc {
	struct delayed_work dwork;
	struct ip_set *set;	/* Set the gc belongs to */
	u32 region;		/* Last gc run position */
};

struct htable {
	atomic_t ref;		/* References for resizing */
	atomic_t uref;		/* References for dumping and gc */
	u8 htable_bits;		/* size of hash table == 2^htable_bits */
	u32 maxelem;		/* Maxelem per region */
	struct ip_set_region *hregion;	/* Region locks and ext sizes */
	struct hbucket __rcu *bucket[]; /* hashtable buckets */
};

struct net_prefixes {
	u32 nets[IPSET_NET_COUNT]; /* number of elements for this cidr */
	u8 cidr[IPSET_NET_COUNT];  /* the cidr value */
};

#define __CIDR(cidr, i)		(cidr[i])

#define NCIDR_PUT(cidr)		((cidr) + 1)
#define NCIDR_GET(cidr)		((cidr) - 1)

#define DCIDR_GET(cidr, i)	__CIDR(cidr, i)

#define NLEN			HOST_MASK
#define CIDR_POS(c)		((c) - 2)

#define SET_ELEM_EXPIRED(set, d)		(SET_WITH_TIMEOUT(set) &&		 ip_set_timeout_expired(ext_timeout(d, set)))

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _IP_SET_HASH_GEN_H */

#define mtype_data_equal	IPSET_TOKEN(MTYPE, _data_equal)

#define mtype_do_data_match	IPSET_TOKEN(MTYPE, _do_data_match)

#define mtype_data_set_flags	IPSET_TOKEN(MTYPE, _data_set_flags)
#define mtype_data_reset_elem	IPSET_TOKEN(MTYPE, _data_reset_elem)

#define mtype_data_next		IPSET_TOKEN(MTYPE, _data_next)
#define mtype_elem		IPSET_TOKEN(MTYPE, _elem)

#define klpp_mtype_add_cidr		IPSET_TOKEN(MTYPE, _add_cidr)

#define mtype_resize_ad		IPSET_TOKEN(MTYPE, _resize_ad)

#define HKEY_DATALEN		sizeof(struct mtype_elem)

#define htype			MTYPE

#define HKEY(data, initval, htable_bits)			({									const u32 *__k = (const u32 *)data;				u32 __l = HKEY_DATALEN / sizeof(u32);												BUILD_BUG_ON(HKEY_DATALEN % sizeof(u32) != 0);											jhash2(__k, __l, initval) & jhash_mask(htable_bits);	})

struct htype {
	struct htable __rcu *table; /* the hash table */
	struct htable_gc gc;	/* gc workqueue */
	u32 maxelem;		/* max elements in the hash */
	u32 initval;		/* random jhash init value */
#ifdef IP_SET_HASH_WITH_MARKMASK
#error "klp-ccp: non-taken branch"
#endif
	u8 bucketsize;		/* max elements in an array block */
#ifdef IP_SET_HASH_WITH_NETMASK
#error "klp-ccp: non-taken branch"
#endif
	struct list_head ad;	/* Resize add|del backlist */
	struct mtype_elem next; /* temporary storage for uadd */
#ifdef IP_SET_HASH_WITH_NETS
	struct net_prefixes nets[NLEN]; /* book-keeping of prefixes */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct mtype_resize_ad {
	struct list_head list;
	enum ipset_adt ad;	/* ADD|DEL element */
	struct mtype_elem d;	/* Element value */
	struct ip_set_ext ext;	/* Extensions for ADD */
	struct ip_set_ext mext;	/* Target extensions for ADD */
	u32 flags;		/* Flags for ADD */
};

#ifdef IP_SET_HASH_WITH_NETS

static void
klpp_mtype_add_cidr(struct ip_set *set, struct htype *h, u8 cidr, u8 n)
{
	int i, j;

	spin_lock_bh(&set->lock);
	/* Add in increasing prefix order, so larger cidr first */
	for (i = 0, j = -1; i < NLEN && h->nets[i].cidr[n]; i++) {
		if (j != -1) {
			continue;
		} else if (h->nets[i].cidr[n] < cidr) {
			j = i;
		} else if (h->nets[i].cidr[n] == cidr) {
			if (NCIDR_GET(cidr) != 0)
				h->nets[CIDR_POS(cidr)].nets[n]++;
			goto unlock;
		}
	}
	if (j != -1) {
		for (; i > j; i--)
			if (i < NLEN)
				h->nets[i].cidr[n] = h->nets[i - 1].cidr[n];
	}
	if (i < NLEN)
		h->nets[i].cidr[n] = cidr;
	if (NCIDR_GET(cidr) != 0)
		h->nets[CIDR_POS(cidr)].nets[n] = 1;
unlock:
	spin_unlock_bh(&set->lock);
}

void
klpp_hash_netportnet4_del_cidr(struct ip_set *set, struct htype *h, u8 cidr, u8 n)
{
	u8 i, j, net_end = NLEN - 1;

	if (NCIDR_GET(cidr) == 0)
		return;

	spin_lock_bh(&set->lock);
	for (i = 0; i < NLEN; i++) {
		if (h->nets[i].cidr[n] != cidr)
			continue;
		h->nets[CIDR_POS(cidr)].nets[n]--;
		if (h->nets[CIDR_POS(cidr)].nets[n] > 0)
			goto unlock;
		for (j = i; j < net_end && h->nets[j].cidr[n]; j++)
			h->nets[j].cidr[n] = h->nets[j + 1].cidr[n];
		h->nets[j].cidr[n] = 0;
		goto unlock;
	}
unlock:
	spin_unlock_bh(&set->lock);
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define ahash_data(n, i, dsize)		((struct mtype_elem *)((n)->value + ((i) * (dsize))))

static void
(*klpe_hash_netportnet4_ahash_destroy)(struct ip_set *set, struct htable *t, bool ext_destroy);

static void
(*klpe_hash_netportnet4_gc_do)(struct ip_set *set, struct htype *h, struct htable *t, u32 r);

int
klpp_hash_netportnet4_add(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t;
	const struct mtype_elem *d = value;
	struct mtype_elem *data;
	struct hbucket *n, *old = ERR_PTR(-ENOENT);
	int i, j = -1, ret;
	bool flag_exist = flags & IPSET_FLAG_EXIST;
	bool deleted = false, forceadd = false, reuse = false;
	u32 r, key, multi = 0, elements, maxelem;

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
	key = HKEY(value, h->initval, t->htable_bits);
	r = ahash_region(key, t->htable_bits);
	atomic_inc(&t->uref);
	elements = t->hregion[r].elements;
	maxelem = t->maxelem;
	if (elements >= maxelem) {
		u32 e;
		if (SET_WITH_TIMEOUT(set)) {
			rcu_read_unlock_bh();
			(*klpe_hash_netportnet4_gc_do)(set, h, t, r);
			rcu_read_lock_bh();
		}
		maxelem = h->maxelem;
		elements = 0;
		for (e = 0; e < ahash_numof_locks(t->htable_bits); e++)
			elements += t->hregion[e].elements;
		if (elements >= maxelem && SET_WITH_FORCEADD(set))
			forceadd = true;
	}
	rcu_read_unlock_bh();

	spin_lock_bh(&t->hregion[r].lock);
	n = 

#define hbucket(h, i)		((h)->bucket[i])
rcu_dereference_bh(hbucket(t, key));
	if (!n) {
		if (forceadd || elements >= maxelem)
			goto set_full;
		old = NULL;
		n = kzalloc(sizeof(*n) + AHASH_INIT_SIZE * set->dsize,
			    GFP_ATOMIC);
		if (!n) {
			ret = -ENOMEM;
			goto unlock;
		}
		n->size = AHASH_INIT_SIZE;
		t->hregion[r].ext_size +=
			

#define ext_size(n, dsize)		(sizeof(struct hbucket) + (n) * (dsize))
ext_size(AHASH_INIT_SIZE, set->dsize);
		goto copy_elem;
	}
	for (i = 0; i < n->pos; i++) {
		if (!test_bit(i, n->used)) {
			/* Reuse first deleted entry */
			if (j == -1) {
				deleted = reuse = true;
				j = i;
			}
			continue;
		}
		data = ahash_data(n, i, set->dsize);
		if (mtype_data_equal(data, d, &multi)) {
			if (flag_exist || SET_ELEM_EXPIRED(set, data)) {
				/* Just the extensions could be overwritten */
				j = i;
				goto overwrite_extensions;
			}
			ret = -IPSET_ERR_EXIST;
			goto unlock;
		}
		/* Reuse first timed out entry */
		if (SET_ELEM_EXPIRED(set, data) && j == -1) {
			j = i;
			reuse = true;
		}
	}
	if (reuse || forceadd) {
		if (j == -1)
			j = 0;
		data = ahash_data(n, j, set->dsize);
		if (!deleted) {
#ifdef IP_SET_HASH_WITH_NETS
			for (i = 0; i < IPSET_NET_COUNT; i++)
				klpp_hash_netportnet4_del_cidr(set, h,
					NCIDR_PUT(DCIDR_GET(data->cidr, i)),
					i);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
			klpr_ip_set_ext_destroy(set, data);
			t->hregion[r].elements--;
		}
		goto copy_data;
	}
	if (elements >= maxelem)
		goto set_full;
	/* Create a new slot */
	if (n->pos >= n->size) {
		TUNE_BUCKETSIZE(h, multi);
		if (n->size >= AHASH_MAX(h)) {
			/* Trigger rehashing */
			mtype_data_next(&h->next, d);
			ret = -EAGAIN;
			goto resize;
		}
		old = n;
		n = kzalloc(sizeof(*n) +
			    (old->size + AHASH_INIT_SIZE) * set->dsize,
			    GFP_ATOMIC);
		if (!n) {
			ret = -ENOMEM;
			goto unlock;
		}
		memcpy(n, old, sizeof(struct hbucket) +
		       old->size * set->dsize);
		n->size = old->size + AHASH_INIT_SIZE;
		t->hregion[r].ext_size +=
			ext_size(AHASH_INIT_SIZE, set->dsize);
	}

copy_elem:
	j = n->pos++;
	data = ahash_data(n, j, set->dsize);
copy_data:
	t->hregion[r].elements++;
#ifdef IP_SET_HASH_WITH_NETS
	for (i = 0; i < IPSET_NET_COUNT; i++)
		klpp_mtype_add_cidr(set, h, NCIDR_PUT(DCIDR_GET(d->cidr, i)), i);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	memcpy(data, d, sizeof(struct mtype_elem));
overwrite_extensions:
#ifdef IP_SET_HASH_WITH_NETS
	mtype_data_set_flags(data, flags);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (SET_WITH_COUNTER(set))
		ip_set_init_counter(ext_counter(data, set), ext);
	if (SET_WITH_COMMENT(set))
		(*klpe_ip_set_init_comment)(set, ext_comment(data, set), ext);
	if (SET_WITH_SKBINFO(set))
		ip_set_init_skbinfo(ext_skbinfo(data, set), ext);
	/* Must come last for the case when timed out entry is reused */
	if (SET_WITH_TIMEOUT(set))
		ip_set_timeout_set(ext_timeout(data, set), ext->timeout);
	smp_mb__before_atomic();
	set_bit(j, n->used);
	if (old != ERR_PTR(-ENOENT)) {
		rcu_assign_pointer(hbucket(t, key), n);
		if (old)
			kfree_rcu(old, rcu);
	}
	ret = 0;
resize:
	spin_unlock_bh(&t->hregion[r].lock);
	if (atomic_read(&t->ref) && ext->target) {
		/* Resize is in process and kernel side add, save values */
		struct mtype_resize_ad *x;

		x = kzalloc(sizeof(struct mtype_resize_ad), GFP_ATOMIC);
		if (!x)
			/* Don't bother */
			goto out;
		x->ad = IPSET_ADD;
		memcpy(&x->d, value, sizeof(struct mtype_elem));
		memcpy(&x->ext, ext, sizeof(struct ip_set_ext));
		memcpy(&x->mext, mext, sizeof(struct ip_set_ext));
		x->flags = flags;
		spin_lock_bh(&set->lock);
		list_add_tail(&x->list, &h->ad);
		spin_unlock_bh(&set->lock);
	}
	goto out;

set_full:
	if (net_ratelimit())
		pr_warn("Set %s is full, maxelem %u reached\n",
			set->name, maxelem);
	ret = -IPSET_ERR_HASH_FULL;
unlock:
	spin_unlock_bh(&t->hregion[r].lock);
out:
	if (atomic_dec_and_test(&t->uref) && atomic_read(&t->ref)) {
		pr_debug("Table destroy after resize by add: %p\n", t);
		(*klpe_hash_netportnet4_ahash_destroy)(set, t, false);
	}
	return ret;
}

static int
klpr_hash_netportnet4_data_match(struct mtype_elem *data, const struct ip_set_ext *ext,
		 struct ip_set_ext *mext, struct ip_set *set, u32 flags)
{
	if (!(*klpe_ip_set_match_extensions)(set, ext, mext, flags, data))
		return 0;
	/* nomatch entries return -ENOTEMPTY */
	return mtype_do_data_match(data);
}

#ifdef IP_SET_HASH_WITH_NETS

static int
klpp_hash_netportnet4_test_cidrs(struct ip_set *set, struct mtype_elem *d,
		 const struct ip_set_ext *ext,
		 struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t = rcu_dereference_bh(h->table);
	struct hbucket *n;
	struct mtype_elem *data;
#if IPSET_NET_COUNT == 2
	struct mtype_elem orig = *d;
	int ret, i, j = 0, k;
#else
#error "klp-ccp: non-taken branch"
#endif
	u32 key, multi = 0;

	pr_debug("test by nets\n");
	for (; j <= NLEN && !multi; j++) {
		bool outer_is_zero_prefix = j == NLEN || h->nets[j].cidr[0] <= 1;

#if IPSET_NET_COUNT == 2
		mtype_data_reset_elem(d, &orig);
		if (!outer_is_zero_prefix) {
			klpr_hash_netportnet4_data_netmask(d, NCIDR_GET(h->nets[j].cidr[0]), false);
		} else {
			klpr_hash_netportnet4_data_netmask(d, 0, false);
		}

		for (k = 0; k <= NLEN && !multi; k++) {
			bool inner_is_zero_prefix = k == NLEN || h->nets[k].cidr[1] <= 1;

			if (!inner_is_zero_prefix) {
				klpr_hash_netportnet4_data_netmask(d, NCIDR_GET(h->nets[k].cidr[1]),
								   true);
			} else {
				klpr_hash_netportnet4_data_netmask(d, 0, true);
			}
#else
#error "klp-ccp: non-taken branch"
#endif
		key = HKEY(d, h->initval, t->htable_bits);
		n = rcu_dereference_bh(hbucket(t, key));
		if (!n)
			continue;
		for (i = 0; i < n->pos; i++) {
			if (!test_bit(i, n->used))
				continue;
			data = ahash_data(n, i, set->dsize);
			if (!mtype_data_equal(data, d, &multi))
				continue;
			ret = klpr_hash_netportnet4_data_match(data, ext, mext, set, flags);
			if (ret != 0)
				return ret;
#ifdef IP_SET_HASH_WITH_MULTI
#error "klp-ccp: non-taken branch"
#endif
		}
#if IPSET_NET_COUNT == 2
			if (inner_is_zero_prefix)
				break;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		if (outer_is_zero_prefix)
			break;
	}

	return 0;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

int
klpp_hash_netportnet4_test(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	   struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t;
	struct mtype_elem *d = value;
	struct hbucket *n;
	struct mtype_elem *data;
	int i, ret = 0;
	u32 key, multi = 0;

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
#ifdef IP_SET_HASH_WITH_NETS
	for (i = 0; i < IPSET_NET_COUNT; i++)
		if (DCIDR_GET(d->cidr, i) != HOST_MASK)
			break;
	if (i == IPSET_NET_COUNT) {
		ret = klpp_hash_netportnet4_test_cidrs(set, d, ext, mext, flags);
		goto out;
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	key = HKEY(d, h->initval, t->htable_bits);
	n = rcu_dereference_bh(hbucket(t, key));
	if (!n) {
		ret = 0;
		goto out;
	}
	for (i = 0; i < n->pos; i++) {
		if (!test_bit(i, n->used))
			continue;
		data = ahash_data(n, i, set->dsize);
		if (!mtype_data_equal(data, d, &multi))
			continue;
		ret = klpr_hash_netportnet4_data_match(data, ext, mext, set, flags);
		if (ret != 0)
			goto out;
	}
out:
	rcu_read_unlock_bh();
	return ret;
}

/* klp-ccp: from net/netfilter/ipset/ip_set_hash_netportnet.c */
struct hash_netportnet6_elem {
	union nf_inet_addr ip[2];
	__be16 port;
	union {
		u8 cidr[2];
		u16 ccmp;
	};
	u16 padding;
	u8 nomatch;
	u8 proto;
};

static bool
hash_netportnet6_data_equal(const struct hash_netportnet6_elem *ip1,
			    const struct hash_netportnet6_elem *ip2,
			    u32 *multi)
{
	return ipv6_addr_equal(&ip1->ip[0].in6, &ip2->ip[0].in6) &&
	       ipv6_addr_equal(&ip1->ip[1].in6, &ip2->ip[1].in6) &&
	       ip1->ccmp == ip2->ccmp &&
	       ip1->port == ip2->port &&
	       ip1->proto == ip2->proto;
}

static int
hash_netportnet6_do_data_match(const struct hash_netportnet6_elem *elem)
{
	return elem->nomatch ? -ENOTEMPTY : 1;
}

static void
hash_netportnet6_data_set_flags(struct hash_netportnet6_elem *elem, u32 flags)
{
	elem->nomatch = !!((flags >> 16) & IPSET_FLAG_NOMATCH);
}

static void
hash_netportnet6_data_reset_elem(struct hash_netportnet6_elem *elem,
				 struct hash_netportnet6_elem *orig)
{
	elem->ip[1] = orig->ip[1];
}

static void
klpr_hash_netportnet6_data_netmask(struct hash_netportnet6_elem *elem,
			      u8 cidr, bool inner)
{
	if (inner) {
		klpr_ip6_netmask(&elem->ip[1], cidr);
		elem->cidr[1] = cidr;
	} else {
		klpr_ip6_netmask(&elem->ip[0], cidr);
		elem->cidr[0] = cidr;
	}
}

static void
hash_netportnet6_data_next(struct hash_netportnet6_elem *next,
			   const struct hash_netportnet6_elem *d)
{
	next->port = d->port;
}

#undef MTYPE
#define MTYPE		hash_netportnet6

#undef HOST_MASK
#define HOST_MASK	128

/* klp-ccp: from net/netfilter/ipset/ip_set_hash_gen.h */
struct htype {
	struct htable __rcu *table; /* the hash table */
	struct htable_gc gc;	/* gc workqueue */
	u32 maxelem;		/* max elements in the hash */
	u32 initval;		/* random jhash init value */
#ifdef IP_SET_HASH_WITH_MARKMASK
#error "klp-ccp: non-taken branch"
#endif
	u8 bucketsize;		/* max elements in an array block */
#ifdef IP_SET_HASH_WITH_NETMASK
#error "klp-ccp: non-taken branch"
#endif
	struct list_head ad;	/* Resize add|del backlist */
	struct mtype_elem next; /* temporary storage for uadd */
#ifdef IP_SET_HASH_WITH_NETS
	struct net_prefixes nets[NLEN]; /* book-keeping of prefixes */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct mtype_resize_ad {
	struct list_head list;
	enum ipset_adt ad;	/* ADD|DEL element */
	struct mtype_elem d;	/* Element value */
	struct ip_set_ext ext;	/* Extensions for ADD */
	struct ip_set_ext mext;	/* Target extensions for ADD */
	u32 flags;		/* Flags for ADD */
};

#ifdef IP_SET_HASH_WITH_NETS

static void
klpp_mtype_add_cidr(struct ip_set *set, struct htype *h, u8 cidr, u8 n)
{
	int i, j;

	spin_lock_bh(&set->lock);
	/* Add in increasing prefix order, so larger cidr first */
	for (i = 0, j = -1; i < NLEN && h->nets[i].cidr[n]; i++) {
		if (j != -1) {
			continue;
		} else if (h->nets[i].cidr[n] < cidr) {
			j = i;
		} else if (h->nets[i].cidr[n] == cidr) {
			if (NCIDR_GET(cidr) != 0)
				h->nets[CIDR_POS(cidr)].nets[n]++;
			goto unlock;
		}
	}
	if (j != -1) {
		for (; i > j; i--)
			if (i < NLEN)
				h->nets[i].cidr[n] = h->nets[i - 1].cidr[n];
	}
	if (i < NLEN)
		h->nets[i].cidr[n] = cidr;
	if (NCIDR_GET(cidr) != 0)
		h->nets[CIDR_POS(cidr)].nets[n] = 1;
unlock:
	spin_unlock_bh(&set->lock);
}

void
klpp_hash_netportnet6_del_cidr(struct ip_set *set, struct htype *h, u8 cidr, u8 n)
{
	u8 i, j, net_end = NLEN - 1;

	if (NCIDR_GET(cidr) == 0)
		return;

	spin_lock_bh(&set->lock);
	for (i = 0; i < NLEN; i++) {
		if (h->nets[i].cidr[n] != cidr)
			continue;
		h->nets[CIDR_POS(cidr)].nets[n]--;
		if (h->nets[CIDR_POS(cidr)].nets[n] > 0)
			goto unlock;
		for (j = i; j < net_end && h->nets[j].cidr[n]; j++)
			h->nets[j].cidr[n] = h->nets[j + 1].cidr[n];
		h->nets[j].cidr[n] = 0;
		goto unlock;
	}
unlock:
	spin_unlock_bh(&set->lock);
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static void
(*klpe_hash_netportnet6_ahash_destroy)(struct ip_set *set, struct htable *t, bool ext_destroy);

static void
(*klpe_hash_netportnet6_gc_do)(struct ip_set *set, struct htype *h, struct htable *t, u32 r);

int
klpp_hash_netportnet6_add(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t;
	const struct mtype_elem *d = value;
	struct mtype_elem *data;
	struct hbucket *n, *old = ERR_PTR(-ENOENT);
	int i, j = -1, ret;
	bool flag_exist = flags & IPSET_FLAG_EXIST;
	bool deleted = false, forceadd = false, reuse = false;
	u32 r, key, multi = 0, elements, maxelem;

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
	key = HKEY(value, h->initval, t->htable_bits);
	r = ahash_region(key, t->htable_bits);
	atomic_inc(&t->uref);
	elements = t->hregion[r].elements;
	maxelem = t->maxelem;
	if (elements >= maxelem) {
		u32 e;
		if (SET_WITH_TIMEOUT(set)) {
			rcu_read_unlock_bh();
			(*klpe_hash_netportnet6_gc_do)(set, h, t, r);
			rcu_read_lock_bh();
		}
		maxelem = h->maxelem;
		elements = 0;
		for (e = 0; e < ahash_numof_locks(t->htable_bits); e++)
			elements += t->hregion[e].elements;
		if (elements >= maxelem && SET_WITH_FORCEADD(set))
			forceadd = true;
	}
	rcu_read_unlock_bh();

	spin_lock_bh(&t->hregion[r].lock);
	n = rcu_dereference_bh(hbucket(t, key));
	if (!n) {
		if (forceadd || elements >= maxelem)
			goto set_full;
		old = NULL;
		n = kzalloc(sizeof(*n) + AHASH_INIT_SIZE * set->dsize,
			    GFP_ATOMIC);
		if (!n) {
			ret = -ENOMEM;
			goto unlock;
		}
		n->size = AHASH_INIT_SIZE;
		t->hregion[r].ext_size +=
			ext_size(AHASH_INIT_SIZE, set->dsize);
		goto copy_elem;
	}
	for (i = 0; i < n->pos; i++) {
		if (!test_bit(i, n->used)) {
			/* Reuse first deleted entry */
			if (j == -1) {
				deleted = reuse = true;
				j = i;
			}
			continue;
		}
		data = ahash_data(n, i, set->dsize);
		if (mtype_data_equal(data, d, &multi)) {
			if (flag_exist || SET_ELEM_EXPIRED(set, data)) {
				/* Just the extensions could be overwritten */
				j = i;
				goto overwrite_extensions;
			}
			ret = -IPSET_ERR_EXIST;
			goto unlock;
		}
		/* Reuse first timed out entry */
		if (SET_ELEM_EXPIRED(set, data) && j == -1) {
			j = i;
			reuse = true;
		}
	}
	if (reuse || forceadd) {
		if (j == -1)
			j = 0;
		data = ahash_data(n, j, set->dsize);
		if (!deleted) {
#ifdef IP_SET_HASH_WITH_NETS
			for (i = 0; i < IPSET_NET_COUNT; i++)
				klpp_hash_netportnet6_del_cidr(set, h,
					NCIDR_PUT(DCIDR_GET(data->cidr, i)),
					i);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
			klpr_ip_set_ext_destroy(set, data);
			t->hregion[r].elements--;
		}
		goto copy_data;
	}
	if (elements >= maxelem)
		goto set_full;
	/* Create a new slot */
	if (n->pos >= n->size) {
		TUNE_BUCKETSIZE(h, multi);
		if (n->size >= AHASH_MAX(h)) {
			/* Trigger rehashing */
			mtype_data_next(&h->next, d);
			ret = -EAGAIN;
			goto resize;
		}
		old = n;
		n = kzalloc(sizeof(*n) +
			    (old->size + AHASH_INIT_SIZE) * set->dsize,
			    GFP_ATOMIC);
		if (!n) {
			ret = -ENOMEM;
			goto unlock;
		}
		memcpy(n, old, sizeof(struct hbucket) +
		       old->size * set->dsize);
		n->size = old->size + AHASH_INIT_SIZE;
		t->hregion[r].ext_size +=
			ext_size(AHASH_INIT_SIZE, set->dsize);
	}

copy_elem:
	j = n->pos++;
	data = ahash_data(n, j, set->dsize);
copy_data:
	t->hregion[r].elements++;
#ifdef IP_SET_HASH_WITH_NETS
	for (i = 0; i < IPSET_NET_COUNT; i++)
		klpp_mtype_add_cidr(set, h, NCIDR_PUT(DCIDR_GET(d->cidr, i)), i);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	memcpy(data, d, sizeof(struct mtype_elem));
overwrite_extensions:
#ifdef IP_SET_HASH_WITH_NETS
	mtype_data_set_flags(data, flags);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (SET_WITH_COUNTER(set))
		ip_set_init_counter(ext_counter(data, set), ext);
	if (SET_WITH_COMMENT(set))
		(*klpe_ip_set_init_comment)(set, ext_comment(data, set), ext);
	if (SET_WITH_SKBINFO(set))
		ip_set_init_skbinfo(ext_skbinfo(data, set), ext);
	/* Must come last for the case when timed out entry is reused */
	if (SET_WITH_TIMEOUT(set))
		ip_set_timeout_set(ext_timeout(data, set), ext->timeout);
	smp_mb__before_atomic();
	set_bit(j, n->used);
	if (old != ERR_PTR(-ENOENT)) {
		rcu_assign_pointer(hbucket(t, key), n);
		if (old)
			kfree_rcu(old, rcu);
	}
	ret = 0;
resize:
	spin_unlock_bh(&t->hregion[r].lock);
	if (atomic_read(&t->ref) && ext->target) {
		/* Resize is in process and kernel side add, save values */
		struct mtype_resize_ad *x;

		x = kzalloc(sizeof(struct mtype_resize_ad), GFP_ATOMIC);
		if (!x)
			/* Don't bother */
			goto out;
		x->ad = IPSET_ADD;
		memcpy(&x->d, value, sizeof(struct mtype_elem));
		memcpy(&x->ext, ext, sizeof(struct ip_set_ext));
		memcpy(&x->mext, mext, sizeof(struct ip_set_ext));
		x->flags = flags;
		spin_lock_bh(&set->lock);
		list_add_tail(&x->list, &h->ad);
		spin_unlock_bh(&set->lock);
	}
	goto out;

set_full:
	if (net_ratelimit())
		pr_warn("Set %s is full, maxelem %u reached\n",
			set->name, maxelem);
	ret = -IPSET_ERR_HASH_FULL;
unlock:
	spin_unlock_bh(&t->hregion[r].lock);
out:
	if (atomic_dec_and_test(&t->uref) && atomic_read(&t->ref)) {
		pr_debug("Table destroy after resize by add: %p\n", t);
		(*klpe_hash_netportnet6_ahash_destroy)(set, t, false);
	}
	return ret;
}

static int
klpr_hash_netportnet6_data_match(struct mtype_elem *data, const struct ip_set_ext *ext,
		 struct ip_set_ext *mext, struct ip_set *set, u32 flags)
{
	if (!(*klpe_ip_set_match_extensions)(set, ext, mext, flags, data))
		return 0;
	/* nomatch entries return -ENOTEMPTY */
	return mtype_do_data_match(data);
}

#ifdef IP_SET_HASH_WITH_NETS

static int
klpp_hash_netportnet6_test_cidrs(struct ip_set *set, struct mtype_elem *d,
		 const struct ip_set_ext *ext,
		 struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t = rcu_dereference_bh(h->table);
	struct hbucket *n;
	struct mtype_elem *data;
#if IPSET_NET_COUNT == 2
	struct mtype_elem orig = *d;
	int ret, i, j = 0, k;
#else
#error "klp-ccp: non-taken branch"
#endif
	u32 key, multi = 0;

	pr_debug("test by nets\n");
	for (; j <= NLEN && !multi; j++) {
		bool outer_is_zero_prefix = j == NLEN || h->nets[j].cidr[0] <= 1;

#if IPSET_NET_COUNT == 2
		mtype_data_reset_elem(d, &orig);
		if (!outer_is_zero_prefix) {
			klpr_hash_netportnet6_data_netmask(d, NCIDR_GET(h->nets[j].cidr[0]), false);
		} else {
			klpr_hash_netportnet6_data_netmask(d, 0, false);
		}

		for (k = 0; k <= NLEN && !multi; k++) {
			bool inner_is_zero_prefix = k == NLEN || h->nets[k].cidr[1] <= 1;

			if (!inner_is_zero_prefix) {
				klpr_hash_netportnet6_data_netmask(d, NCIDR_GET(h->nets[k].cidr[1]),
								   true);
			} else {
				klpr_hash_netportnet6_data_netmask(d, 0, true);
			}
#else
#error "klp-ccp: non-taken branch"
#endif
		key = HKEY(d, h->initval, t->htable_bits);
		n = rcu_dereference_bh(hbucket(t, key));
		if (!n)
			continue;
		for (i = 0; i < n->pos; i++) {
			if (!test_bit(i, n->used))
				continue;
			data = ahash_data(n, i, set->dsize);
			if (!mtype_data_equal(data, d, &multi))
				continue;
			ret = klpr_hash_netportnet6_data_match(data, ext, mext, set, flags);
			if (ret != 0)
				return ret;
#ifdef IP_SET_HASH_WITH_MULTI
#error "klp-ccp: non-taken branch"
#endif
		}
#if IPSET_NET_COUNT == 2
			if (inner_is_zero_prefix)
				break;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		if (outer_is_zero_prefix)
			break;
	}

	return 0;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

int
klpp_hash_netportnet6_test(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	   struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t;
	struct mtype_elem *d = value;
	struct hbucket *n;
	struct mtype_elem *data;
	int i, ret = 0;
	u32 key, multi = 0;

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
#ifdef IP_SET_HASH_WITH_NETS
	for (i = 0; i < IPSET_NET_COUNT; i++)
		if (DCIDR_GET(d->cidr, i) != HOST_MASK)
			break;
	if (i == IPSET_NET_COUNT) {
		ret = klpp_hash_netportnet6_test_cidrs(set, d, ext, mext, flags);
		goto out;
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	key = HKEY(d, h->initval, t->htable_bits);
	n = rcu_dereference_bh(hbucket(t, key));
	if (!n) {
		ret = 0;
		goto out;
	}
	for (i = 0; i < n->pos; i++) {
		if (!test_bit(i, n->used))
			continue;
		data = ahash_data(n, i, set->dsize);
		if (!mtype_data_equal(data, d, &multi))
			continue;
		ret = klpr_hash_netportnet6_data_match(data, ext, mext, set, flags);
		if (ret != 0)
			goto out;
	}
out:
	rcu_read_unlock_bh();
	return ret;
}


#include "livepatch_bsc1218613.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ip_set_hash_netportnet"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "hash_netportnet4_ahash_destroy",
	  (void *)&klpe_hash_netportnet4_ahash_destroy,
	  "ip_set_hash_netportnet" },
	{ "hash_netportnet4_gc_do", (void *)&klpe_hash_netportnet4_gc_do,
	  "ip_set_hash_netportnet" },
	{ "hash_netportnet6_ahash_destroy",
	  (void *)&klpe_hash_netportnet6_ahash_destroy,
	  "ip_set_hash_netportnet" },
	{ "hash_netportnet6_gc_do", (void *)&klpe_hash_netportnet6_gc_do,
	  "ip_set_hash_netportnet" },
	{ "ip_set_extensions", (void *)&klpe_ip_set_extensions, "ip_set" },
	{ "ip_set_init_comment", (void *)&klpe_ip_set_init_comment, "ip_set" },
	{ "ip_set_match_extensions", (void *)&klpe_ip_set_match_extensions,
	  "ip_set" },
	{ "ip_set_netmask_map", (void *)&klpe_ip_set_netmask_map, "ip_set" },
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

int livepatch_bsc1218613_init(void)
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

void livepatch_bsc1218613_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
