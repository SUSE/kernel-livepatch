/*
 * bsc1259859_security_apparmor_match
 *
 * Fix for CVE-2026-23268, bsc#1259859
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


#include "livepatch_bsc1259859.h"


/* klp-ccp: from security/apparmor/match.c */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/kref.h>
/* klp-ccp: from security/apparmor/include/lib.h */
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>
/* klp-ccp: from security/apparmor/include/match.h */
#include <linux/kref.h>

#define DFA_NOMATCH			0

#define YYTH_MAGIC	0x1B5E783D
#define YYTH_FLAG_DIFF_ENCODE	1
#define YYTH_FLAG_OOB_TRANS	2
#define YYTH_FLAGS (YYTH_FLAG_DIFF_ENCODE | YYTH_FLAG_OOB_TRANS)

struct table_set_header {
	u32 th_magic;		/* YYTH_MAGIC */
	u32 th_hsize;
	u32 th_ssize;
	u16 th_flags;
	char th_version[];
};

#define	YYTD_ID_ACCEPT	0
#define YYTD_ID_BASE	1
#define YYTD_ID_CHK	2
#define YYTD_ID_DEF	3
#define YYTD_ID_EC	4

#define YYTD_ID_ACCEPT2 6
#define YYTD_ID_NXT	7
#define YYTD_ID_TSIZE	8
#define YYTD_ID_MAX	8

#define YYTD_DATA8	1
#define YYTD_DATA16	2
#define YYTD_DATA32	4

#define ACCEPT1_FLAGS(X) ((X) & 0x3f)
#define ACCEPT2_FLAGS(X) ACCEPT1_FLAGS((X) >> YYTD_ID_ACCEPT2)

#define DFA_FLAG_VERIFY_STATES 0x1000

struct table_header {
	u16 td_id;
	u16 td_flags;
	u32 td_hilen;
	u32 td_lolen;
	char td_data[];
};

#define DEFAULT_TABLE(DFA) ((u16 *)((DFA)->tables[YYTD_ID_DEF]->td_data))
#define BASE_TABLE(DFA) ((u32 *)((DFA)->tables[YYTD_ID_BASE]->td_data))
#define NEXT_TABLE(DFA) ((u16 *)((DFA)->tables[YYTD_ID_NXT]->td_data))
#define CHECK_TABLE(DFA) ((u16 *)((DFA)->tables[YYTD_ID_CHK]->td_data))
#define EQUIV_TABLE(DFA) ((u8 *)((DFA)->tables[YYTD_ID_EC]->td_data))

struct aa_dfa {
	struct kref count;
	u16 flags;
	u32 max_oob;
	struct table_header *tables[YYTD_ID_TSIZE];
};

#define byte_to_byte(X) (X)

#define UNPACK_ARRAY(TABLE, BLOB, LEN, TTYPE, BTYPE, NTOHX)	\
	do { \
		typeof(LEN) __i; \
		TTYPE *__t = (TTYPE *) TABLE; \
		BTYPE *__b = (BTYPE *) BLOB; \
		for (__i = 0; __i < LEN; __i++) { \
			__t[__i] = NTOHX(__b[__i]); \
		} \
	} while (0)

static inline size_t table_size(size_t len, size_t el_size)
{
	return ALIGN(sizeof(struct table_header) + len * el_size, 8);
}

#define aa_state_t unsigned int

struct aa_dfa *klpp_aa_dfa_unpack(void *blob, size_t size, int flags);
aa_state_t klpp_aa_dfa_match_len(struct aa_dfa *dfa, aa_state_t start,
			    const char *str, int len);
aa_state_t klpp_aa_dfa_match(struct aa_dfa *dfa, aa_state_t start,
			const char *str);

#define MATCH_FLAG_DIFF_ENCODE 0x80000000
#define MARK_DIFF_ENCODE 0x40000000
#define MATCH_FLAG_OOB_TRANSITION 0x20000000
#define MARK_DIFF_ENCODE_VERIFIED 0x10000000
#define MATCH_FLAGS_MASK 0xff000000
#define MATCH_FLAGS_VALID (MATCH_FLAG_DIFF_ENCODE | MATCH_FLAG_OOB_TRANSITION)
#define MATCH_FLAGS_INVALID (MATCH_FLAGS_MASK & ~MATCH_FLAGS_VALID)

/* klp-ccp: from security/apparmor/match.c */
#define base_idx(X) ((X) & 0xffffff)

static struct table_header *unpack_table(char *blob, size_t bsize)
{
	struct table_header *table = NULL;
	struct table_header th;
	size_t tsize;

	if (bsize < sizeof(struct table_header))
		goto out;

	/* loaded td_id's start at 1, subtract 1 now to avoid doing
	 * it every time we use td_id as an index
	 */
	th.td_id = be16_to_cpu(*(__be16 *) (blob)) - 1;
	if (th.td_id > YYTD_ID_MAX)
		goto out;
	th.td_flags = be16_to_cpu(*(__be16 *) (blob + 2));
	th.td_lolen = be32_to_cpu(*(__be32 *) (blob + 8));
	blob += sizeof(struct table_header);

	if (!(th.td_flags == YYTD_DATA16 || th.td_flags == YYTD_DATA32 ||
	      th.td_flags == YYTD_DATA8))
		goto out;

	/* if we have a table it must have some entries */
	if (th.td_lolen == 0)
		goto out;
	tsize = table_size(th.td_lolen, th.td_flags);
	if (bsize < tsize)
		goto out;

	table = kvzalloc(tsize, GFP_KERNEL);
	if (table) {
		table->td_id = th.td_id;
		table->td_flags = th.td_flags;
		table->td_lolen = th.td_lolen;
		if (th.td_flags == YYTD_DATA8)
			UNPACK_ARRAY(table->td_data, blob, th.td_lolen,
				     u8, u8, byte_to_byte);
		else if (th.td_flags == YYTD_DATA16)
			UNPACK_ARRAY(table->td_data, blob, th.td_lolen,
				     u16, __be16, be16_to_cpu);
		else if (th.td_flags == YYTD_DATA32)
			UNPACK_ARRAY(table->td_data, blob, th.td_lolen,
				     u32, __be32, be32_to_cpu);
		else
			goto fail;
		/* if table was vmalloced make sure the page tables are synced
		 * before it is used, as it goes live to all cpus.
		 */
		if (is_vmalloc_addr(table))
			vm_unmap_aliases();
	}

out:
	return table;
fail:
	kvfree(table);
	return NULL;
}

static int verify_table_headers(struct table_header **tables, int flags)
{
	size_t state_count, trans_count;
	int error = -EPROTO;

	/* check that required tables exist */
	if (!(tables[YYTD_ID_DEF] && tables[YYTD_ID_BASE] &&
	      tables[YYTD_ID_NXT] && tables[YYTD_ID_CHK]))
		goto out;

	/* accept.size == default.size == base.size */
	state_count = tables[YYTD_ID_BASE]->td_lolen;
	if (ACCEPT1_FLAGS(flags)) {
		if (!tables[YYTD_ID_ACCEPT])
			goto out;
		if (state_count != tables[YYTD_ID_ACCEPT]->td_lolen)
			goto out;
	}
	if (ACCEPT2_FLAGS(flags)) {
		if (!tables[YYTD_ID_ACCEPT2])
			goto out;
		if (state_count != tables[YYTD_ID_ACCEPT2]->td_lolen)
			goto out;
	}
	if (state_count != tables[YYTD_ID_DEF]->td_lolen)
		goto out;

	/* next.size == chk.size */
	trans_count = tables[YYTD_ID_NXT]->td_lolen;
	if (trans_count != tables[YYTD_ID_CHK]->td_lolen)
		goto out;

	/* if equivalence classes then its table size must be 256 */
	if (tables[YYTD_ID_EC] && tables[YYTD_ID_EC]->td_lolen != 256)
		goto out;

	error = 0;
out:
	return error;
}

static int klpp_verify_dfa(struct aa_dfa *dfa)
{
	size_t i, state_count, trans_count;
	int error = -EPROTO;

	state_count = dfa->tables[YYTD_ID_BASE]->td_lolen;
	trans_count = dfa->tables[YYTD_ID_NXT]->td_lolen;
	if (state_count == 0)
		goto out;
	for (i = 0; i < state_count; i++) {
		if (DEFAULT_TABLE(dfa)[i] >= state_count) {
			pr_err("AppArmor DFA default state out of bounds");
			goto out;
		}
		if (BASE_TABLE(dfa)[i] & MATCH_FLAGS_INVALID) {
			pr_err("AppArmor DFA state with invalid match flags");
			goto out;
		}
		if ((BASE_TABLE(dfa)[i] & MATCH_FLAG_DIFF_ENCODE)) {
			if (!(dfa->flags & YYTH_FLAG_DIFF_ENCODE)) {
				pr_err("AppArmor DFA diff encoded transition state without header flag");
				goto out;
			}
		}
		if ((BASE_TABLE(dfa)[i] & MATCH_FLAG_OOB_TRANSITION)) {
			if (base_idx(BASE_TABLE(dfa)[i]) < dfa->max_oob) {
				pr_err("AppArmor DFA out of bad transition out of range");
				goto out;
			}
			if (!(dfa->flags & YYTH_FLAG_OOB_TRANS)) {
				pr_err("AppArmor DFA out of bad transition state without header flag");
				goto out;
			}
		}
		if (base_idx(BASE_TABLE(dfa)[i]) + 255 >= trans_count) {
			pr_err("AppArmor DFA next/check upper bounds error\n");
			goto out;
		}
	}

	for (i = 0; i < trans_count; i++) {
		if (NEXT_TABLE(dfa)[i] >= state_count)
			goto out;
		if (CHECK_TABLE(dfa)[i] >= state_count)
			goto out;
	}

	/* Now that all the other tables are verified, verify diffencoding */
	for (i = 0; i < state_count; i++) {
		size_t j, k;

		for (j = i;
		     ((BASE_TABLE(dfa)[j] & MATCH_FLAG_DIFF_ENCODE) &&
		      !(BASE_TABLE(dfa)[j] & MARK_DIFF_ENCODE_VERIFIED));
		     j = k) {
			if (BASE_TABLE(dfa)[j] & MARK_DIFF_ENCODE)
				/* loop in current chain */
				goto out;
			k = DEFAULT_TABLE(dfa)[j];
			if (j == k)
				/* self loop */
				goto out;
			BASE_TABLE(dfa)[j] |= MARK_DIFF_ENCODE;
		}
		/* move mark to verified */
		for (j = i;
		     (BASE_TABLE(dfa)[j] & MATCH_FLAG_DIFF_ENCODE);
		     j = k) {
			k = DEFAULT_TABLE(dfa)[j];
			if (j < i)
				/* jumps to state/chain that has been
				 * verified
				 */
				break;
			BASE_TABLE(dfa)[j] &= ~MARK_DIFF_ENCODE;
			BASE_TABLE(dfa)[j] |= MARK_DIFF_ENCODE_VERIFIED;
		}
	}
	error = 0;

out:
	return error;
}

static void dfa_free(struct aa_dfa *dfa)
{
	if (dfa) {
		int i;

		for (i = 0; i < ARRAY_SIZE(dfa->tables); i++) {
			kvfree(dfa->tables[i]);
			dfa->tables[i] = NULL;
		}
		kfree(dfa);
	}
}

struct aa_dfa *klpp_aa_dfa_unpack(void *blob, size_t size, int flags)
{
	int hsize;
	int error = -ENOMEM;
	char *data = blob;
	struct table_header *table = NULL;
	struct aa_dfa *dfa = kzalloc(sizeof(struct aa_dfa), GFP_KERNEL);
	if (!dfa)
		goto fail;

	kref_init(&dfa->count);

	error = -EPROTO;

	/* get dfa table set header */
	if (size < sizeof(struct table_set_header))
		goto fail;

	if (ntohl(*(__be32 *) data) != YYTH_MAGIC)
		goto fail;

	hsize = ntohl(*(__be32 *) (data + 4));
	if (size < hsize)
		goto fail;

	dfa->flags = ntohs(*(__be16 *) (data + 12));
	if (dfa->flags & ~(YYTH_FLAGS))
		goto fail;

	/*
	 * TODO: needed for dfa to support more than 1 oob
	 * if (dfa->flags & YYTH_FLAGS_OOB_TRANS) {
	 *	if (hsize < 16 + 4)
	 *		goto fail;
	 *	dfa->max_oob = ntol(*(__be32 *) (data + 16));
	 *	if (dfa->max <= MAX_OOB_SUPPORTED) {
	 *		pr_err("AppArmor DFA OOB greater than supported\n");
	 *		goto fail;
	 *	}
	 * }
	 */
	dfa->max_oob = 1;

	data += hsize;
	size -= hsize;

	while (size > 0) {
		table = unpack_table(data, size);
		if (!table)
			goto fail;

		switch (table->td_id) {
		case YYTD_ID_ACCEPT:
			if (!(table->td_flags & ACCEPT1_FLAGS(flags)))
				goto fail;
			break;
		case YYTD_ID_ACCEPT2:
			if (!(table->td_flags & ACCEPT2_FLAGS(flags)))
				goto fail;
			break;
		case YYTD_ID_BASE:
			if (table->td_flags != YYTD_DATA32)
				goto fail;
			break;
		case YYTD_ID_DEF:
		case YYTD_ID_NXT:
		case YYTD_ID_CHK:
			if (table->td_flags != YYTD_DATA16)
				goto fail;
			break;
		case YYTD_ID_EC:
			if (table->td_flags != YYTD_DATA8)
				goto fail;
			break;
		default:
			goto fail;
		}
		/* check for duplicate table entry */
		if (dfa->tables[table->td_id])
			goto fail;
		dfa->tables[table->td_id] = table;
		data += table_size(table->td_lolen, table->td_flags);
		size -= table_size(table->td_lolen, table->td_flags);
		table = NULL;
	}
	error = verify_table_headers(dfa->tables, flags);
	if (error)
		goto fail;

	if (flags & DFA_FLAG_VERIFY_STATES) {
		error = klpp_verify_dfa(dfa);
		if (error)
			goto fail;
	}

	return dfa;

fail:
	kvfree(table);
	dfa_free(dfa);
	return ERR_PTR(error);
}

#define match_char(state, def, base, next, check, C)	\
do {							\
	u32 b = (base)[(state)];			\
	unsigned int pos = base_idx(b) + (C);		\
	if ((check)[pos] != (state)) {			\
		(state) = (def)[(state)];		\
		if (b & MATCH_FLAG_DIFF_ENCODE)		\
			continue;			\
		break;					\
	}						\
	(state) = (next)[pos];				\
	break;						\
} while (1)

aa_state_t klpp_aa_dfa_match_len(struct aa_dfa *dfa, aa_state_t start,
			    const char *str, int len)
{
	u16 *def = DEFAULT_TABLE(dfa);
	u32 *base = BASE_TABLE(dfa);
	u16 *next = NEXT_TABLE(dfa);
	u16 *check = CHECK_TABLE(dfa);
	aa_state_t state = start;

	if (state == DFA_NOMATCH)
		return DFA_NOMATCH;

	/* current state is <state>, matching character *str */
	if (dfa->tables[YYTD_ID_EC]) {
		/* Equivalence class table defined */
		u8 *equiv = EQUIV_TABLE(dfa);
		for (; len; len--) {
			u8 c = equiv[(u8) *str];

			match_char(state, def, base, next, check, c);
			str++;
		}
	} else {
		/* default is direct to next state */
		for (; len; len--) {
			match_char(state, def, base, next, check, (u8) *str);
			str++;
		}
	}

	return state;
}

aa_state_t klpp_aa_dfa_match(struct aa_dfa *dfa, aa_state_t start, const char *str)
{
	u16 *def = DEFAULT_TABLE(dfa);
	u32 *base = BASE_TABLE(dfa);
	u16 *next = NEXT_TABLE(dfa);
	u16 *check = CHECK_TABLE(dfa);
	aa_state_t state = start;

	if (state == DFA_NOMATCH)
		return DFA_NOMATCH;

	/* current state is <state>, matching character *str */
	if (dfa->tables[YYTD_ID_EC]) {
		/* Equivalence class table defined */
		u8 *equiv = EQUIV_TABLE(dfa);
		/* default is direct to next state */
		while (*str) {
			u8 c = equiv[(u8) *str];

			match_char(state, def, base, next, check, c);
			str++;
		}
	} else {
		/* default is direct to next state */
		while (*str) {
			match_char(state, def, base, next, check, (u8) *str);
			str++;
		}
	}

	return state;
}


