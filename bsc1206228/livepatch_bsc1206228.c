/*
 * livepatch_bsc1206228
 *
 * Fix for CVE-2022-4378, bsc#1206228
 *
 *  Upstream commits:
 *  bce9332220bd ("proc: proc_skip_spaces() shouldn't think it is working on C
 *                 strings")
 *  e6cfaf34be9f ("proc: avoid integer type confusion in get_proc_long")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  4f96478c0b7812f37c51b42a588e008922034dbd
 *  ca9edcc55e8dcff98032ef1a8e324eebe9bafb83
 *
 *  SLE15-SP2 and -SP3 commits:
 *  1e50bbf3faa38a1ce277eedae7b393f1f7d7b7c5
 *  175b73bf7de41554ba04b58cffb0b93666d30f2d
 *
 *  SLE15-SP4 commits:
 *  67938a4f1a2ff041b0e481540e9b680e9423f7cd
 *  4566ee9471a5b54116aeeb44f0826d3c57e3abb8
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

/* klp-ccp: from kernel/sysctl.c */
#include <linux/module.h>

/* klp-ccp: from include/linux/sysctl.h */
int klpp_proc_do_large_bitmap(struct ctl_table *, int,
				void __user *, size_t *, loff_t *);

/* klp-ccp: from kernel/sysctl.c */
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/bitmap.h>
#include <linux/printk.h>
#include <linux/ctype.h>
#include <linux/kmemleak.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/highuid.h>
#include <linux/writeback.h>
#include <linux/ratelimit.h>
#include <linux/key.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/vmstat.h>
#include <linux/ftrace.h>
#include <linux/perf_event.h>
#include <linux/pipe_fs_i.h>
#include <linux/kmod.h>
#include <linux/capability.h>
#include <linux/sched/coredump.h>

/* klp-ccp: from lib/kstrtox.h */
#define KSTRTOX_OVERFLOW	(1U << 31)
static const char *(*klpe__parse_integer_fixup_radix)(const char *s, unsigned int *base);
static unsigned int (*klpe__parse_integer)(const char *s, unsigned int base, unsigned long long *res);

/* klp-ccp: from kernel/sysctl.c */
#include <linux/uaccess.h>
#include <asm/processor.h>

enum sysctl_writes_mode {
	SYSCTL_WRITES_LEGACY		= -1,
	SYSCTL_WRITES_WARN		= 0,
	SYSCTL_WRITES_STRICT		= 1,
};

static enum sysctl_writes_mode (*klpe_sysctl_writes_strict);

static void warn_sysctl_write(struct ctl_table *table)
{
	pr_warn_once("%s wrote to %s when file position was not 0!\n"
		"This will not be supported in the future. To silence this\n"
		"warning, set kernel.sysctl_writes_strict = -1\n",
		current->comm, table->procname);
}

static bool klpr_proc_first_pos_non_zero_ignore(loff_t *ppos,
					   struct ctl_table *table)
{
	if (!*ppos)
		return false;

	switch ((*klpe_sysctl_writes_strict)) {
	case SYSCTL_WRITES_STRICT:
		return true;
	case SYSCTL_WRITES_WARN:
		warn_sysctl_write(table);
		return false;
	default:
		return false;
	}
}

/*
 * Fix CVE-2022-4378
 *  -1 line, +1 line
 */
static void klpp_proc_skip_spaces(char **buf, size_t *size)
{
	/*
	 * Fix CVE-2022-4378
	 *  -5 lines, +6 lines
	 */
	while (*size) {
		if (!isspace(**buf))
			break;
		(*size)--;
		(*buf)++;
	}
}

static void proc_skip_char(char **buf, size_t *size, const char v)
{
	while (*size) {
		if (**buf != v)
			break;
		(*size)--;
		(*buf)++;
	}
}

static int klpr_strtoul_lenient(const char *cp, char **endp, unsigned int base,
			   unsigned long *res)
{
	unsigned long long result;
	unsigned int rv;

	cp = (*klpe__parse_integer_fixup_radix)(cp, &base);
	rv = (*klpe__parse_integer)(cp, base, &result);
	if ((rv & KSTRTOX_OVERFLOW) || (result != (unsigned long)result))
		return -ERANGE;

	cp += rv;

	if (endp)
		*endp = (char *)cp;

	*res = (unsigned long)result;
	return 0;
}

#define TMPBUFLEN 22

static int klpp_proc_get_long(char **buf, size_t *size,
			  unsigned long *val, bool *neg,
			  const char *perm_tr, unsigned perm_tr_len, char *tr)
{
	/*
	 * Fix CVE-2022-4378
	 *  -1 line
	 */
	char *p, tmp[TMPBUFLEN];
	/*
	 * Fix CVE-2022-4378
	 *  +1 line
	 */
	ssize_t len = *size;

	/*
	 * Fix CVE-2022-4378
	 *  -1 line, +1 line
	 */
	if (len <= 0)
		return -EINVAL;

	/*
	 * Fix CVE-2022-4378
	 *  -1 line
	 */
	if (len > TMPBUFLEN - 1)
		len = TMPBUFLEN - 1;

	memcpy(tmp, *buf, len);

	tmp[len] = 0;
	p = tmp;
	if (*p == '-' && *size > 1) {
		*neg = true;
		p++;
	} else
		*neg = false;
	if (!isdigit(*p))
		return -EINVAL;

	if (klpr_strtoul_lenient(p, &p, 0, val))
		return -EINVAL;

	len = p - tmp;

	/* We don't know if the next char is whitespace thus we may accept
	 * invalid integers (e.g. 1234...a) or two integers instead of one
	 * (e.g. 123...1). So lets not allow such large numbers. */
	if (len == TMPBUFLEN - 1)
		return -EINVAL;

	if (len < *size && perm_tr_len && !memchr(perm_tr, *p, perm_tr_len))
		return -EINVAL;

	if (tr && (len < *size))
		*tr = *p;

	*buf += len;
	*size -= len;

	return 0;
}

static int (*klpe_proc_put_long)(void __user **buf, size_t *size, unsigned long val,
			  bool neg);

static int proc_put_char(void __user **buf, size_t *size, char c)
{
	if (*size) {
		char __user **buffer = (char __user **)buf;
		if (put_user(c, *buffer))
			return -EFAULT;
		(*size)--, (*buffer)++;
		*buf = *buffer;
	}
	return 0;
}

static int (*klpe_do_proc_dointvec_conv)(bool *negp, unsigned long *lvalp,
				 int *valp,
				 int write, void *data);

static int (*klpe_do_proc_douintvec_conv)(unsigned long *lvalp,
				  unsigned int *valp,
				  int write, void *data);

static const char (*klpe_proc_wspace_sep)[3];

int klpp___do_proc_dointvec(void *tbl_data, struct ctl_table *table,
		  int write, void __user *buffer,
		  size_t *lenp, loff_t *ppos,
		  int (*conv)(bool *negp, unsigned long *lvalp, int *valp,
			      int write, void *data),
		  void *data)
{
	int *i, vleft, first = 1, err = 0;
	size_t left;
	char *kbuf = NULL, *p;
	
	if (!tbl_data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}
	
	i = (int *) tbl_data;
	vleft = table->maxlen / sizeof(*i);
	left = *lenp;

	if (!conv)
		conv = (*klpe_do_proc_dointvec_conv);

	if (write) {
		if (klpr_proc_first_pos_non_zero_ignore(ppos, table))
			goto out;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;
		p = kbuf = memdup_user_nul(buffer, left);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
	}

	for (; left && vleft--; i++, first=0) {
		unsigned long lval;
		bool neg;

		if (write) {
			/*
			 * Fix CVE-2022-4378
			 *  -1 line, +1 line
			 */
			klpp_proc_skip_spaces(&p, &left);

			if (!left)
				break;
			err = klpp_proc_get_long(&p, &left, &lval, &neg,
					     (*klpe_proc_wspace_sep),
					     sizeof((*klpe_proc_wspace_sep)), NULL);
			if (err)
				break;
			if (conv(&neg, &lval, i, 1, data)) {
				err = -EINVAL;
				break;
			}
		} else {
			if (conv(&neg, &lval, i, 0, data)) {
				err = -EINVAL;
				break;
			}
			if (!first)
				err = proc_put_char(&buffer, &left, '\t');
			if (err)
				break;
			err = (*klpe_proc_put_long)(&buffer, &left, lval, neg);
			if (err)
				break;
		}
	}

	if (!write && !first && left && !err)
		err = proc_put_char(&buffer, &left, '\n');
	if (write && !err && left)
		/*
		 * Fix CVE-2022-4378
		 *  -1 line, +1 line
		 */
		klpp_proc_skip_spaces(&p, &left);
	if (write) {
		kfree(kbuf);
		if (first)
			return err ? : -EINVAL;
	}
	*lenp -= left;
out:
	*ppos += *lenp;
	return err;
}

static int klpp_do_proc_douintvec_w(unsigned int *tbl_data,
			       struct ctl_table *table,
			       void __user *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned long lval;
	int err = 0;
	size_t left;
	bool neg;
	char *kbuf = NULL, *p;

	left = *lenp;

	if (klpr_proc_first_pos_non_zero_ignore(ppos, table))
		goto bail_early;

	if (left > PAGE_SIZE - 1)
		left = PAGE_SIZE - 1;

	p = kbuf = memdup_user_nul(buffer, left);
	if (IS_ERR(kbuf))
		return -EINVAL;

	/*
	 * Fix CVE-2022-4378
	 *  -1 line, +1 line
	 */
	klpp_proc_skip_spaces(&p, &left);
	if (!left) {
		err = -EINVAL;
		goto out_free;
	}

	err = klpp_proc_get_long(&p, &left, &lval, &neg,
			     (*klpe_proc_wspace_sep),
			     sizeof((*klpe_proc_wspace_sep)), NULL);
	if (err || neg) {
		err = -EINVAL;
		goto out_free;
	}

	if (conv(&lval, tbl_data, 1, data)) {
		err = -EINVAL;
		goto out_free;
	}

	if (!err && left)
		/*
		 * Fix CVE-2022-4378
		 *  -1 line, +1 line
		 */
		klpp_proc_skip_spaces(&p, &left);

out_free:
	kfree(kbuf);
	if (err)
		return -EINVAL;

	return 0;

	/* This is in keeping with old __do_proc_dointvec() */
bail_early:
	*ppos += *lenp;
	return err;
}

static int klpr_do_proc_douintvec_r(unsigned int *tbl_data, void __user *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned long lval;
	int err = 0;
	size_t left;

	left = *lenp;

	if (conv(&lval, tbl_data, 0, data)) {
		err = -EINVAL;
		goto out;
	}

	err = (*klpe_proc_put_long)(&buffer, &left, lval, false);
	if (err || !left)
		goto out;

	err = proc_put_char(&buffer, &left, '\n');

out:
	*lenp -= left;
	*ppos += *lenp;

	return err;
}

int klpp___do_proc_douintvec(void *tbl_data, struct ctl_table *table,
			       int write, void __user *buffer,
			       size_t *lenp, loff_t *ppos,
			       int (*conv)(unsigned long *lvalp,
					   unsigned int *valp,
					   int write, void *data),
			       void *data)
{
	unsigned int *i, vleft;

	if (!tbl_data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = (unsigned int *) tbl_data;
	vleft = table->maxlen / sizeof(*i);

	/*
	 * Arrays are not supported, keep this simple. *Do not* add
	 * support for them.
	 */
	if (vleft != 1) {
		*lenp = 0;
		return -EINVAL;
	}

	if (!conv)
		conv = (*klpe_do_proc_douintvec_conv);

	if (write)
		return klpp_do_proc_douintvec_w(i, table, buffer, lenp, ppos,
					   conv, data);
	return klpr_do_proc_douintvec_r(i, buffer, lenp, ppos, conv, data);
}

int klpp___do_proc_doulongvec_minmax(void *data, struct ctl_table *table, int write,
				     void __user *buffer,
				     size_t *lenp, loff_t *ppos,
				     unsigned long convmul,
				     unsigned long convdiv)
{
	unsigned long *i, *min, *max;
	int vleft, first = 1, err = 0;
	size_t left;
	char *kbuf = NULL, *p;

	if (!data || !table->maxlen || !*lenp || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	i = (unsigned long *) data;
	min = (unsigned long *) table->extra1;
	max = (unsigned long *) table->extra2;
	vleft = table->maxlen / sizeof(unsigned long);
	left = *lenp;

	if (write) {
		if (klpr_proc_first_pos_non_zero_ignore(ppos, table))
			goto out;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;
		p = kbuf = memdup_user_nul(buffer, left);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
	}

	for (; left && vleft--; i++, first = 0) {
		unsigned long val;

		if (write) {
			bool neg;

			/*
			 * Fix CVE-2022-4378
			 *  -1 line, +1 line
			 */
			klpp_proc_skip_spaces(&p, &left);
			if (!left)
				break;

			err = klpp_proc_get_long(&p, &left, &val, &neg,
					     (*klpe_proc_wspace_sep),
					     sizeof((*klpe_proc_wspace_sep)), NULL);
			if (err)
				break;
			if (neg)
				continue;
			val = convmul * val / convdiv;
			if ((min && val < *min) || (max && val > *max))
				continue;
			*i = val;
		} else {
			val = convdiv * (*i) / convmul;
			if (!first) {
				err = proc_put_char(&buffer, &left, '\t');
				if (err)
					break;
			}
			err = (*klpe_proc_put_long)(&buffer, &left, val, false);
			if (err)
				break;
		}
	}

	if (!write && !first && left && !err)
		err = proc_put_char(&buffer, &left, '\n');
	if (write && !err)
		/*
		 * Fix CVE-2022-4378
		 *  -1 line, +1 line
		 */
		klpp_proc_skip_spaces(&p, &left);
	if (write) {
		kfree(kbuf);
		if (first)
			return err ? : -EINVAL;
	}
	*lenp -= left;
out:
	*ppos += *lenp;
	return err;
}

int klpp_proc_do_large_bitmap(struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int err = 0;
	bool first = 1;
	size_t left = *lenp;
	unsigned long bitmap_len = table->maxlen;
	unsigned long *bitmap = *(unsigned long **) table->data;
	unsigned long *tmp_bitmap = NULL;
	char tr_a[] = { '-', ',', '\n' }, tr_b[] = { ',', '\n', 0 }, c;

	if (!bitmap || !bitmap_len || !left || (*ppos && !write)) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		char *kbuf, *p;

		if (left > PAGE_SIZE - 1)
			left = PAGE_SIZE - 1;

		p = kbuf = memdup_user_nul(buffer, left);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);

		tmp_bitmap = kzalloc(BITS_TO_LONGS(bitmap_len) * sizeof(unsigned long),
				     GFP_KERNEL);
		if (!tmp_bitmap) {
			kfree(kbuf);
			return -ENOMEM;
		}
		proc_skip_char(&p, &left, '\n');
		while (!err && left) {
			unsigned long val_a, val_b;
			bool neg;

			err = klpp_proc_get_long(&p, &left, &val_a, &neg, tr_a,
					     sizeof(tr_a), &c);
			if (err)
				break;
			if (val_a >= bitmap_len || neg) {
				err = -EINVAL;
				break;
			}

			val_b = val_a;
			if (left) {
				p++;
				left--;
			}

			if (c == '-') {
				err = klpp_proc_get_long(&p, &left, &val_b,
						     &neg, tr_b, sizeof(tr_b),
						     &c);
				if (err)
					break;
				if (val_b >= bitmap_len || neg ||
				    val_a > val_b) {
					err = -EINVAL;
					break;
				}
				if (left) {
					p++;
					left--;
				}
			}

			bitmap_set(tmp_bitmap, val_a, val_b - val_a + 1);
			first = 0;
			proc_skip_char(&p, &left, '\n');
		}
		kfree(kbuf);
	} else {
		unsigned long bit_a, bit_b = 0;

		while (left) {
			bit_a = find_next_bit(bitmap, bitmap_len, bit_b);
			if (bit_a >= bitmap_len)
				break;
			bit_b = find_next_zero_bit(bitmap, bitmap_len,
						   bit_a + 1) - 1;

			if (!first) {
				err = proc_put_char(&buffer, &left, ',');
				if (err)
					break;
			}
			err = (*klpe_proc_put_long)(&buffer, &left, bit_a, false);
			if (err)
				break;
			if (bit_a != bit_b) {
				err = proc_put_char(&buffer, &left, '-');
				if (err)
					break;
				err = (*klpe_proc_put_long)(&buffer, &left, bit_b, false);
				if (err)
					break;
			}

			first = 0; bit_b++;
		}
		if (!err)
			err = proc_put_char(&buffer, &left, '\n');
	}

	if (!err) {
		if (write) {
			if (*ppos)
				bitmap_or(bitmap, bitmap, tmp_bitmap, bitmap_len);
			else
				bitmap_copy(bitmap, tmp_bitmap, bitmap_len);
		}
		kfree(tmp_bitmap);
		*lenp -= left;
		*ppos += *lenp;
		return 0;
	} else {
		kfree(tmp_bitmap);
		return err;
	}
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1206228.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "_parse_integer", (void *)&klpe__parse_integer },
	{ "_parse_integer_fixup_radix",
	  (void *)&klpe__parse_integer_fixup_radix },
	{ "do_proc_dointvec_conv", (void *)&klpe_do_proc_dointvec_conv },
	{ "do_proc_douintvec_conv", (void *)&klpe_do_proc_douintvec_conv },
	{ "proc_put_long", (void *)&klpe_proc_put_long },
	{ "proc_wspace_sep", (void *)&klpe_proc_wspace_sep },
	{ "sysctl_writes_strict", (void *)&klpe_sysctl_writes_strict },
};

int livepatch_bsc1206228_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
