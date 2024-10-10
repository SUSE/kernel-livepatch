/*
 * livepatch_bsc1228573
 *
 * Fix for CVE-2024-41059, bsc#1228573
 *
 *  Upstream commit:
 *  0570730c1630 ("hfsplus: fix uninit-value in copy_name")
 *
 *  SLE12-SP5 commit:
 *  8d75c301b880e278b7a9c4d2cb757837375f25fd
 *
 *  SLE15-SP2 and -SP3 commit:
 *  97ed1481a00a9b1afd4f650378084d7e872817bb
 *
 *  SLE15-SP4 and -SP5 commit:
 *  cfc2db1738357f69f59d81427b1ad46de9b88f21
 *
 *  SLE15-SP6 commit:
 *  4f0ad7bad7ee2a47e881c08f989eb0c2b1085f87
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from fs/hfsplus/hfsplus_fs.h */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
/* klp-ccp: from fs/hfsplus/hfsplus_raw.h */
#include <linux/types.h>

typedef __be32 hfsplus_cnid;
typedef __be16 hfsplus_unichr;

#define HFSPLUS_MAX_STRLEN 255
#define HFSPLUS_ATTR_MAX_STRLEN 127

struct hfsplus_unistr {
	__be16 length;
	hfsplus_unichr unicode[HFSPLUS_MAX_STRLEN];
} __packed;

struct hfsplus_attr_unistr {
	__be16 length;
	hfsplus_unichr unicode[HFSPLUS_ATTR_MAX_STRLEN];
} __packed;

struct hfsplus_perm {
	__be32 owner;
	__be32 group;
	u8  rootflags;
	u8  userflags;
	__be16 mode;
	__be32 dev;
} __packed;

struct hfsplus_extent {
	__be32 start_block;
	__be32 block_count;
} __packed;
typedef struct hfsplus_extent hfsplus_extent_rec[8];

struct hfsplus_fork_raw {
	__be64 total_size;
	__be32 clump_size;
	__be32 total_blocks;
	hfsplus_extent_rec extents;
} __packed;

struct hfsplus_cat_key {
	__be16 key_len;
	hfsplus_cnid parent;
	struct hfsplus_unistr name;
} __packed;

struct hfsp_point {
	__be16 v;
	__be16 h;
} __packed;

struct hfsp_rect {
	__be16 top;
	__be16 left;
	__be16 bottom;
	__be16 right;
} __packed;

struct DInfo {
	struct hfsp_rect frRect;
	__be16 frFlags;
	struct hfsp_point frLocation;
	__be16 frView;
} __packed;

struct DXInfo {
	struct hfsp_point frScroll;
	__be32 frOpenChain;
	__be16 frUnused;
	__be16 frComment;
	__be32 frPutAway;
} __packed;

struct hfsplus_cat_folder {
	__be16 type;
	__be16 flags;
	__be32 valence;
	hfsplus_cnid id;
	__be32 create_date;
	__be32 content_mod_date;
	__be32 attribute_mod_date;
	__be32 access_date;
	__be32 backup_date;
	struct hfsplus_perm permissions;
	struct DInfo user_info;
	struct DXInfo finder_info;
	__be32 text_encoding;
	__be32 subfolders;	/* Subfolder count in HFSX. Reserved in HFS+. */
} __packed;

struct FInfo {
	__be32 fdType;
	__be32 fdCreator;
	__be16 fdFlags;
	struct hfsp_point fdLocation;
	__be16 fdFldr;
} __packed;

struct FXInfo {
	__be16 fdIconID;
	u8 fdUnused[8];
	__be16 fdComment;
	__be32 fdPutAway;
} __packed;

struct hfsplus_cat_file {
	__be16 type;
	__be16 flags;
	u32 reserved1;
	hfsplus_cnid id;
	__be32 create_date;
	__be32 content_mod_date;
	__be32 attribute_mod_date;
	__be32 access_date;
	__be32 backup_date;
	struct hfsplus_perm permissions;
	struct FInfo user_info;
	struct FXInfo finder_info;
	__be32 text_encoding;
	u32 reserved2;

	struct hfsplus_fork_raw data_fork;
	struct hfsplus_fork_raw rsrc_fork;
} __packed;

#define HFSPLUS_FOLDER         0x0001
#define HFSPLUS_FILE           0x0002

struct hfsplus_ext_key {
	__be16 key_len;
	u8 fork_type;
	u8 pad;
	hfsplus_cnid cnid;
	__be32 start_block;
} __packed;

#define HFSPLUS_XATTR_FINDER_INFO_NAME "com.apple.FinderInfo"

struct hfsplus_attr_key {
	__be16 key_len;
	__be16 pad;
	hfsplus_cnid cnid;
	__be32 start_block;
	struct hfsplus_attr_unistr key_name;
} __packed;

typedef union {
	__be16 key_len;
	struct hfsplus_cat_key cat;
	struct hfsplus_ext_key ext;
	struct hfsplus_attr_key attr;
} __packed hfsplus_btree_key;

/* klp-ccp: from fs/hfsplus/hfsplus_fs.h */
typedef int (*btree_keycmp)(const hfsplus_btree_key *,
		const hfsplus_btree_key *);

#define NODE_HASH_SIZE	256

struct hfs_btree {
	struct super_block *sb;
	struct inode *inode;
	btree_keycmp keycmp;

	u32 cnid;
	u32 root;
	u32 leaf_count;
	u32 leaf_head;
	u32 leaf_tail;
	u32 node_count;
	u32 free_nodes;
	u32 attributes;

	unsigned int node_size;
	unsigned int node_size_shift;
	unsigned int max_key_len;
	unsigned int depth;

	struct mutex tree_lock;

	unsigned int pages_per_bnode;
	spinlock_t hash_lock;
	struct hfs_bnode *node_hash[NODE_HASH_SIZE];
	int node_hash_cnt;
};

struct hfsplus_sb_info {
	void *s_vhdr_buf;
	struct hfsplus_vh *s_vhdr;
	void *s_backup_vhdr_buf;
	struct hfsplus_vh *s_backup_vhdr;
	struct hfs_btree *ext_tree;
	struct hfs_btree *cat_tree;
	struct hfs_btree *attr_tree;
	atomic_t attr_tree_state;
	struct inode *alloc_file;
	struct inode *hidden_dir;
	struct nls_table *nls;

	/* Runtime variables */
	u32 blockoffset;
	sector_t part_start;
	sector_t sect_count;
	int fs_shift;

	/* immutable data from the volume header */
	u32 alloc_blksz;
	int alloc_blksz_shift;
	u32 total_blocks;
	u32 data_clump_blocks, rsrc_clump_blocks;

	/* mutable data from the volume header, protected by alloc_mutex */
	u32 free_blocks;
	struct mutex alloc_mutex;

	/* mutable data from the volume header, protected by vh_mutex */
	u32 next_cnid;
	u32 file_count;
	u32 folder_count;
	struct mutex vh_mutex;

	/* Config options */
	u32 creator;
	u32 type;

	umode_t umask;
	kuid_t uid;
	kgid_t gid;

	int part, session;
	unsigned long flags;

	int work_queued;               /* non-zero delayed work is queued */
	struct delayed_work sync_work; /* FS sync delayed work */
	spinlock_t work_lock;          /* protects sync_work and work_queued */
};

static inline struct hfsplus_sb_info *HFSPLUS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

struct hfsplus_inode_info {
	atomic_t opencnt;

	/*
	 * Extent allocation information, protected by extents_lock.
	 */
	u32 first_blocks;
	u32 clump_blocks;
	u32 alloc_blocks;
	u32 cached_start;
	u32 cached_blocks;
	hfsplus_extent_rec first_extents;
	hfsplus_extent_rec cached_extents;
	unsigned int extent_state;
	struct mutex extents_lock;

	/*
	 * Immutable data.
	 */
	struct inode *rsrc_inode;
	__be32 create_date;

	/*
	 * Protected by sbi->vh_mutex.
	 */
	u32 linkid;

	/*
	 * Accessed using atomic bitops.
	 */
	unsigned long flags;

	/*
	 * Protected by i_mutex.
	 */
	sector_t fs_blocks;
	u8 userflags;		/* BSD user file flags */
	u32 subfolders;		/* Subfolder count (HFSX only) */
	struct list_head open_dir_list;
	spinlock_t open_dir_lock;
	loff_t phys_size;

	struct inode vfs_inode;
};

#define HFSPLUS_I_RSRC		0	/* represents a resource fork */

#define HFSPLUS_IS_RSRC(inode) \
	test_bit(HFSPLUS_I_RSRC, &HFSPLUS_I(inode)->flags)

static inline struct hfsplus_inode_info *HFSPLUS_I(struct inode *inode)
{
	return container_of(inode, struct hfsplus_inode_info, vfs_inode);
}

struct hfs_find_data {
	/* filled by caller */
	hfsplus_btree_key *search_key;
	hfsplus_btree_key *key;
	/* filled by find */
	struct hfs_btree *tree;
	struct hfs_bnode *bnode;
	/* filled by findrec */
	int record;
	int keyoffset, keylength;
	int entryoffset, entrylength;
};

static int (*klpe_hfsplus_find_attr)(struct super_block *sb, u32 cnid, const char *name,
		      struct hfs_find_data *fd);

static void (*klpe_hfsplus_bnode_read)(struct hfs_bnode *node, void *buf, int off, int len);
static u16 (*klpe_hfsplus_bnode_read_u16)(struct hfs_bnode *node, int off);

static int (*klpe_hfsplus_find_init)(struct hfs_btree *tree, struct hfs_find_data *fd);
static void (*klpe_hfsplus_find_exit)(struct hfs_find_data *fd);

static int (*klpe_hfsplus_brec_goto)(struct hfs_find_data *fd, int cnt);

static int (*klpe_hfsplus_find_cat)(struct super_block *sb, u32 cnid,
		     struct hfs_find_data *fd);

static int (*klpe_hfsplus_uni2asc)(struct super_block *sb, const struct hfsplus_unistr *ustr,
		    char *astr, int *len_p);

/* klp-ccp: from include/linux/nls.h */
#define NLS_MAX_CHARSET_SIZE 6 /* for UTF-8 */

/* klp-ccp: from include/uapi/linux/xattr.h */
#define XATTR_MAC_OSX_PREFIX "osx."
#define XATTR_MAC_OSX_PREFIX_LEN (sizeof(XATTR_MAC_OSX_PREFIX) - 1)

#define XATTR_TRUSTED_PREFIX "trusted."
#define XATTR_TRUSTED_PREFIX_LEN (sizeof(XATTR_TRUSTED_PREFIX) - 1)

/* klp-ccp: from fs/hfsplus/xattr.c */
static bool (*klpe_is_known_namespace)(const char *name);

static int klpr_name_len(const char *xattr_name, int xattr_name_len)
{
	int len = xattr_name_len + 1;

	if (!(*klpe_is_known_namespace)(xattr_name))
		len += XATTR_MAC_OSX_PREFIX_LEN;

	return len;
}

static int (*klpe_copy_name)(char *buffer, const char *xattr_name, int name_len);

static inline int can_list(const char *xattr_name)
{
	if (!xattr_name)
		return 0;

	return strncmp(xattr_name, XATTR_TRUSTED_PREFIX,
			XATTR_TRUSTED_PREFIX_LEN) ||
				capable(CAP_SYS_ADMIN);
}

static ssize_t klpr_hfsplus_listxattr_finder_info(struct dentry *dentry,
						char *buffer, size_t size)
{
	ssize_t res = 0;
	struct inode *inode = d_inode(dentry);
	struct hfs_find_data fd;
	u16 entry_type;
	u8 folder_finder_info[sizeof(struct DInfo) + sizeof(struct DXInfo)];
	u8 file_finder_info[sizeof(struct FInfo) + sizeof(struct FXInfo)];
	unsigned long len, found_bit;
	int xattr_name_len, symbols_count;

	res = (*klpe_hfsplus_find_init)(HFSPLUS_SB(inode->i_sb)->cat_tree, &fd);
	if (res) {
		pr_err("can't init xattr find struct\n");
		return res;
	}

	res = (*klpe_hfsplus_find_cat)(inode->i_sb, inode->i_ino, &fd);
	if (res)
		goto end_listxattr_finder_info;

	entry_type = (*klpe_hfsplus_bnode_read_u16)(fd.bnode, fd.entryoffset);
	if (entry_type == HFSPLUS_FOLDER) {
		len = sizeof(struct DInfo) + sizeof(struct DXInfo);
		(*klpe_hfsplus_bnode_read)(fd.bnode, folder_finder_info,
				fd.entryoffset +
				offsetof(struct hfsplus_cat_folder, user_info),
				len);
		found_bit = find_first_bit((void *)folder_finder_info, len*8);
	} else if (entry_type == HFSPLUS_FILE) {
		len = sizeof(struct FInfo) + sizeof(struct FXInfo);
		(*klpe_hfsplus_bnode_read)(fd.bnode, file_finder_info,
				fd.entryoffset +
				offsetof(struct hfsplus_cat_file, user_info),
				len);
		found_bit = find_first_bit((void *)file_finder_info, len*8);
	} else {
		res = -EOPNOTSUPP;
		goto end_listxattr_finder_info;
	}

	if (found_bit >= (len*8))
		res = 0;
	else {
		symbols_count = sizeof(HFSPLUS_XATTR_FINDER_INFO_NAME) - 1;
		xattr_name_len =
			klpr_name_len(HFSPLUS_XATTR_FINDER_INFO_NAME, symbols_count);
		if (!buffer || !size) {
			if (can_list(HFSPLUS_XATTR_FINDER_INFO_NAME))
				res = xattr_name_len;
		} else if (can_list(HFSPLUS_XATTR_FINDER_INFO_NAME)) {
			if (size < xattr_name_len)
				res = -ERANGE;
			else {
				res = (*klpe_copy_name)(buffer,
						HFSPLUS_XATTR_FINDER_INFO_NAME,
						symbols_count);
			}
		}
	}

end_listxattr_finder_info:
	(*klpe_hfsplus_find_exit)(&fd);

	return res;
}

ssize_t klpp_hfsplus_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	ssize_t err;
	ssize_t res = 0;
	struct inode *inode = d_inode(dentry);
	struct hfs_find_data fd;
	u16 key_len = 0;
	struct hfsplus_attr_key attr_key;
	char *strbuf;
	int xattr_name_len;

	if ((!S_ISREG(inode->i_mode) &&
			!S_ISDIR(inode->i_mode)) ||
				HFSPLUS_IS_RSRC(inode))
		return -EOPNOTSUPP;

	res = klpr_hfsplus_listxattr_finder_info(dentry, buffer, size);
	if (res < 0)
		return res;
	else if (!HFSPLUS_SB(inode->i_sb)->attr_tree)
		return (res == 0) ? -EOPNOTSUPP : res;

	err = (*klpe_hfsplus_find_init)(HFSPLUS_SB(inode->i_sb)->attr_tree, &fd);
	if (err) {
		pr_err("can't init xattr find struct\n");
		return err;
	}

	strbuf = kzalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN +
			XATTR_MAC_OSX_PREFIX_LEN + 1, GFP_KERNEL);
	if (!strbuf) {
		res = -ENOMEM;
		goto out;
	}

	err = (*klpe_hfsplus_find_attr)(inode->i_sb, inode->i_ino, NULL, &fd);
	if (err) {
		if (err == -ENOENT) {
			if (res == 0)
				res = -ENODATA;
			goto end_listxattr;
		} else {
			res = err;
			goto end_listxattr;
		}
	}

	for (;;) {
		key_len = (*klpe_hfsplus_bnode_read_u16)(fd.bnode, fd.keyoffset);
		if (key_len == 0 || key_len > fd.tree->max_key_len) {
			pr_err("invalid xattr key length: %d\n", key_len);
			res = -EIO;
			goto end_listxattr;
		}

		(*klpe_hfsplus_bnode_read)(fd.bnode, &attr_key,
				fd.keyoffset, key_len + sizeof(key_len));

		if (be32_to_cpu(attr_key.cnid) != inode->i_ino)
			goto end_listxattr;

		xattr_name_len = NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN;
		if ((*klpe_hfsplus_uni2asc)(inode->i_sb,
			(const struct hfsplus_unistr *)&fd.key->attr.key_name,
					strbuf, &xattr_name_len)) {
			pr_err("unicode conversion failed\n");
			res = -EIO;
			goto end_listxattr;
		}

		if (!buffer || !size) {
			if (can_list(strbuf))
				res += klpr_name_len(strbuf, xattr_name_len);
		} else if (can_list(strbuf)) {
			if (size < (res + klpr_name_len(strbuf, xattr_name_len))) {
				res = -ERANGE;
				goto end_listxattr;
			} else
				res += (*klpe_copy_name)(buffer + res,
						strbuf, xattr_name_len);
		}

		if ((*klpe_hfsplus_brec_goto)(&fd, 1))
			goto end_listxattr;
	}

end_listxattr:
	kfree(strbuf);
out:
	(*klpe_hfsplus_find_exit)(&fd);
	return res;
}


#include "livepatch_bsc1228573.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "hfsplus"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "copy_name", (void *)&klpe_copy_name, "hfsplus" },
	{ "hfsplus_bnode_read", (void *)&klpe_hfsplus_bnode_read, "hfsplus" },
	{ "hfsplus_bnode_read_u16", (void *)&klpe_hfsplus_bnode_read_u16,
	  "hfsplus" },
	{ "hfsplus_brec_goto", (void *)&klpe_hfsplus_brec_goto, "hfsplus" },
	{ "hfsplus_find_attr", (void *)&klpe_hfsplus_find_attr, "hfsplus" },
	{ "hfsplus_find_cat", (void *)&klpe_hfsplus_find_cat, "hfsplus" },
	{ "hfsplus_find_exit", (void *)&klpe_hfsplus_find_exit, "hfsplus" },
	{ "hfsplus_find_init", (void *)&klpe_hfsplus_find_init, "hfsplus" },
	{ "hfsplus_uni2asc", (void *)&klpe_hfsplus_uni2asc, "hfsplus" },
	{ "is_known_namespace", (void *)&klpe_is_known_namespace, "hfsplus" },
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

int livepatch_bsc1228573_init(void)
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

void livepatch_bsc1228573_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
