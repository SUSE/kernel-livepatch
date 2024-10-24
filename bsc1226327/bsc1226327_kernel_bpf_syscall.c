/*
 * bsc1226327_kernel_bpf_syscall
 *
 * Fix for CVE-2024-35905, bsc#1226327
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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

/* klp-ccp: from kernel/bpf/syscall.c */
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/bpf_trace.h>
#include <linux/bpf_lirc.h>

#include <linux/bsearch.h>
#include <linux/btf.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>
#include <linux/mmzone.h>
#include <linux/anon_inodes.h>

/* klp-ccp: from kernel/bpf/syscall.c */
#include <linux/file.h>
#include <linux/fs.h>

#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/cred.h>
#include <linux/timekeeping.h>
#include <linux/ctype.h>
#include <linux/nospec.h>

#include <uapi/linux/btf.h>
#include <linux/pgtable.h>

#include <linux/poll.h>

#include <linux/bpf-netns.h>
#include <linux/rcupdate_trace.h>
#include <linux/memcontrol.h>
#include <linux/trace_events.h>
#include <net/netfilter/nf_bpf_link.h>

#include <net/tcx.h>

extern int __percpu bpf_prog_active;

#define IS_FD_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_CGROUP_ARRAY || \
			  (map)->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
#define IS_FD_PROG_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PROG_ARRAY)
#define IS_FD_HASH(map) ((map)->map_type == BPF_MAP_TYPE_HASH_OF_MAPS)
#define IS_FD_MAP(map) (IS_FD_ARRAY(map) || IS_FD_PROG_ARRAY(map) || \
			IS_FD_HASH(map))

#define BPF_OBJ_FLAG_MASK   (BPF_F_RDONLY | BPF_F_WRONLY)

extern struct idr prog_idr;
extern spinlock_t prog_idr_lock;
extern struct idr map_idr;
extern spinlock_t map_idr_lock;
extern struct idr link_idr;
extern spinlock_t link_idr_lock;

extern int sysctl_unprivileged_bpf_disabled __read_mostly;

extern const struct bpf_map_ops * const bpf_map_types[33]

/* klp-ccp: from include/linux/bpf_types.h */
#ifdef CONFIG_NET

#ifdef CONFIG_CGROUP_BPF

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_BPF_EVENTS

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CGROUP_BPF

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_BPF_LIRC_MODE2
#error "klp-ccp: non-taken branch"
#endif
#ifdef CONFIG_INET

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#if defined(CONFIG_BPF_JIT)

#ifdef CONFIG_BPF_LSM

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_BPF_LSM */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_NETFILTER_BPF_LINK

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_CGROUPS

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CGROUP_BPF

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_PERF_EVENTS

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_BPF_LSM

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_NET

#if defined(CONFIG_XDP_SOCKETS)

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_INET

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#if defined(CONFIG_BPF_JIT)

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_CGROUP_BPF

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_NET

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_PERF_EVENTS

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
/* klp-ccp: from kernel/bpf/syscall.c */
;

int bpf_check_uarg_tail_zero(bpfptr_t uaddr,
			     size_t expected_size,
			     size_t actual_size);

extern const struct bpf_map_ops bpf_map_offload_ops;

static void bpf_map_write_active_inc(struct bpf_map *map)
{
	atomic64_inc(&map->writecnt);
}

static void bpf_map_write_active_dec(struct bpf_map *map)
{
	atomic64_dec(&map->writecnt);
}

bool bpf_map_write_active(const struct bpf_map *map);

static u32 bpf_map_value_size(const struct bpf_map *map)
{
	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
		return round_up(map->value_size, 8) * num_possible_cpus();
	else if (IS_FD_MAP(map))
		return sizeof(u32);
	else
		return  map->value_size;
}

static void maybe_wait_bpf_programs(struct bpf_map *map)
{
	/* Wait for any running BPF programs to complete so that
	 * userspace, when we return to it, knows that all programs
	 * that could be running use the new map value.
	 */
	if (map->map_type == BPF_MAP_TYPE_HASH_OF_MAPS ||
	    map->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
		synchronize_rcu();
}

extern int bpf_map_update_value(struct bpf_map *map, struct file *map_file,
				void *key, void *value, __u64 flags);

extern int bpf_map_copy_value(struct bpf_map *map, void *key, void *value,
			      __u64 flags);

static int bpf_map_alloc_id(struct bpf_map *map)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&map_idr_lock);
	id = idr_alloc_cyclic(&map_idr, map, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		map->id = id;
	spin_unlock_bh(&map_idr_lock);
	idr_preload_end();

	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

#ifdef CONFIG_MEMCG_KMEM
static void bpf_map_save_memcg(struct bpf_map *map)
{
	/* Currently if a map is created by a process belonging to the root
	 * memory cgroup, get_obj_cgroup_from_current() will return NULL.
	 * So we have to check map->objcg for being NULL each time it's
	 * being used.
	 */
	if (memcg_bpf_enabled())
		map->objcg = get_obj_cgroup_from_current();
}

#else
#error "klp-ccp: non-taken branch"
#endif

void bpf_map_free_record(struct bpf_map *map);

void bpf_map_put(struct bpf_map *map);

extern typeof(bpf_map_put) bpf_map_put;

void bpf_map_put_with_uref(struct bpf_map *map);

static fmode_t map_get_sys_perms(struct bpf_map *map, struct fd f)
{
	fmode_t mode = f.file->f_mode;

	/* Our file permissions may have been overridden by global
	 * map permissions facing syscall side.
	 */
	if (READ_ONCE(map->frozen))
		mode &= ~FMODE_CAN_WRITE;
	return mode;
}

int bpf_map_new_fd(struct bpf_map *map, int flags);

int bpf_get_file_flag(int flags);

#define CHECK_ATTR(CMD) \
	memchr_inv((void *) &attr->CMD##_LAST_FIELD + \
		   sizeof(attr->CMD##_LAST_FIELD), 0, \
		   sizeof(*attr) - \
		   offsetof(union bpf_attr, CMD##_LAST_FIELD) - \
		   sizeof(attr->CMD##_LAST_FIELD)) != NULL

int bpf_obj_name_cpy(char *dst, const char *src, unsigned int size);

static int map_check_btf(struct bpf_map *map, const struct btf *btf,
			 u32 btf_key_id, u32 btf_value_id)
{
	const struct btf_type *key_type, *value_type;
	u32 key_size, value_size;
	int ret = 0;

	/* Some maps allow key to be unspecified. */
	if (btf_key_id) {
		key_type = btf_type_id_size(btf, &btf_key_id, &key_size);
		if (!key_type || key_size != map->key_size)
			return -EINVAL;
	} else {
		key_type = btf_type_by_id(btf, 0);
		if (!map->ops->map_check_btf)
			return -EINVAL;
	}

	value_type = btf_type_id_size(btf, &btf_value_id, &value_size);
	if (!value_type || value_size != map->value_size)
		return -EINVAL;

	map->record = btf_parse_fields(btf, value_type,
				       BPF_SPIN_LOCK | BPF_TIMER | BPF_KPTR | BPF_LIST_HEAD |
				       BPF_RB_ROOT | BPF_REFCOUNT,
				       map->value_size);
	if (!IS_ERR_OR_NULL(map->record)) {
		int i;

		if (!bpf_capable()) {
			ret = -EPERM;
			goto free_map_tab;
		}
		if (map->map_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)) {
			ret = -EACCES;
			goto free_map_tab;
		}
		for (i = 0; i < sizeof(map->record->field_mask) * 8; i++) {
			switch (map->record->field_mask & (1 << i)) {
			case 0:
				continue;
			case BPF_SPIN_LOCK:
				if (map->map_type != BPF_MAP_TYPE_HASH &&
				    map->map_type != BPF_MAP_TYPE_ARRAY &&
				    map->map_type != BPF_MAP_TYPE_CGROUP_STORAGE &&
				    map->map_type != BPF_MAP_TYPE_SK_STORAGE &&
				    map->map_type != BPF_MAP_TYPE_INODE_STORAGE &&
				    map->map_type != BPF_MAP_TYPE_TASK_STORAGE &&
				    map->map_type != BPF_MAP_TYPE_CGRP_STORAGE) {
					ret = -EOPNOTSUPP;
					goto free_map_tab;
				}
				break;
			case BPF_TIMER:
				if (map->map_type != BPF_MAP_TYPE_HASH &&
				    map->map_type != BPF_MAP_TYPE_LRU_HASH &&
				    map->map_type != BPF_MAP_TYPE_ARRAY) {
					ret = -EOPNOTSUPP;
					goto free_map_tab;
				}
				break;
			case BPF_KPTR_UNREF:
			case BPF_KPTR_REF:
			case BPF_REFCOUNT:
				if (map->map_type != BPF_MAP_TYPE_HASH &&
				    map->map_type != BPF_MAP_TYPE_PERCPU_HASH &&
				    map->map_type != BPF_MAP_TYPE_LRU_HASH &&
				    map->map_type != BPF_MAP_TYPE_LRU_PERCPU_HASH &&
				    map->map_type != BPF_MAP_TYPE_ARRAY &&
				    map->map_type != BPF_MAP_TYPE_PERCPU_ARRAY &&
				    map->map_type != BPF_MAP_TYPE_SK_STORAGE &&
				    map->map_type != BPF_MAP_TYPE_INODE_STORAGE &&
				    map->map_type != BPF_MAP_TYPE_TASK_STORAGE &&
				    map->map_type != BPF_MAP_TYPE_CGRP_STORAGE) {
					ret = -EOPNOTSUPP;
					goto free_map_tab;
				}
				break;
			case BPF_LIST_HEAD:
			case BPF_RB_ROOT:
				if (map->map_type != BPF_MAP_TYPE_HASH &&
				    map->map_type != BPF_MAP_TYPE_LRU_HASH &&
				    map->map_type != BPF_MAP_TYPE_ARRAY) {
					ret = -EOPNOTSUPP;
					goto free_map_tab;
				}
				break;
			default:
				/* Fail if map_type checks are missing for a field type */
				ret = -EOPNOTSUPP;
				goto free_map_tab;
			}
		}
	}

	ret = btf_check_and_fixup_fields(btf, map->record);
	if (ret < 0)
		goto free_map_tab;

	if (map->ops->map_check_btf) {
		ret = map->ops->map_check_btf(map, btf, key_type, value_type);
		if (ret < 0)
			goto free_map_tab;
	}

	return ret;
free_map_tab:
	bpf_map_free_record(map);
	return ret;
}

#define BPF_MAP_CREATE_LAST_FIELD map_extra

/* Called from syscall */
static int bloom_map_alloc_check(union bpf_attr *attr)
{
	if (attr->value_size > KMALLOC_MAX_SIZE)
		/* if value_size is bigger, the user space won't be able to
		* access the elements.
		*/
		return -E2BIG;

	return 0;
}

static int map_create(union bpf_attr *attr)
{
	const struct bpf_map_ops *ops;
	int numa_node = bpf_map_attr_numa_node(attr);
	u32 map_type = attr->map_type;
	struct bpf_map *map;
	int f_flags;
	int err;

	err = CHECK_ATTR(BPF_MAP_CREATE);
	if (err)
		return -EINVAL;

	if (attr->btf_vmlinux_value_type_id) {
		if (attr->map_type != BPF_MAP_TYPE_STRUCT_OPS ||
		    attr->btf_key_type_id || attr->btf_value_type_id)
			return -EINVAL;
	} else if (attr->btf_key_type_id && !attr->btf_value_type_id) {
		return -EINVAL;
	}

	if (attr->map_type != BPF_MAP_TYPE_BLOOM_FILTER &&
	    attr->map_extra != 0)
		return -EINVAL;

	f_flags = bpf_get_file_flag(attr->map_flags);
	if (f_flags < 0)
		return f_flags;

	if (numa_node != NUMA_NO_NODE &&
	    ((unsigned int)numa_node >= nr_node_ids ||
	     !node_online(numa_node)))
		return -EINVAL;

	/* find map type and init map: hashtable vs rbtree vs bloom vs ... */
	map_type = attr->map_type;
	if (map_type >= ARRAY_SIZE(bpf_map_types))
		return -EINVAL;
	map_type = array_index_nospec(map_type, ARRAY_SIZE(bpf_map_types));
	ops = bpf_map_types[map_type];
	if (!ops)
		return -EINVAL;

	if (map_type == BPF_MAP_TYPE_BLOOM_FILTER) {
		err = bloom_map_alloc_check(attr);
		if (err)
			return err;
	}
	if (ops->map_alloc_check) {
		err = ops->map_alloc_check(attr);
		if (err)
			return err;
	}
	if (attr->map_ifindex)
		ops = &bpf_map_offload_ops;
	if (!ops->map_mem_usage)
		return -EINVAL;

	/* Intent here is for unprivileged_bpf_disabled to block BPF map
	 * creation for unprivileged users; other actions depend
	 * on fd availability and access to bpffs, so are dependent on
	 * object creation success. Even with unprivileged BPF disabled,
	 * capability checks are still carried out.
	 */
	if (sysctl_unprivileged_bpf_disabled && !bpf_capable())
		return -EPERM;

	/* check privileged map type permissions */
	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
	case BPF_MAP_TYPE_PERCPU_ARRAY:
	case BPF_MAP_TYPE_PROG_ARRAY:
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
	case BPF_MAP_TYPE_CGROUP_ARRAY:
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
	case BPF_MAP_TYPE_HASH:
	case BPF_MAP_TYPE_PERCPU_HASH:
	case BPF_MAP_TYPE_HASH_OF_MAPS:
	case BPF_MAP_TYPE_RINGBUF:
	case BPF_MAP_TYPE_USER_RINGBUF:
	case BPF_MAP_TYPE_CGROUP_STORAGE:
	case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		/* unprivileged */
		break;
	case BPF_MAP_TYPE_SK_STORAGE:
	case BPF_MAP_TYPE_INODE_STORAGE:
	case BPF_MAP_TYPE_TASK_STORAGE:
	case BPF_MAP_TYPE_CGRP_STORAGE:
	case BPF_MAP_TYPE_BLOOM_FILTER:
	case BPF_MAP_TYPE_LPM_TRIE:
	case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
	case BPF_MAP_TYPE_STACK_TRACE:
	case BPF_MAP_TYPE_QUEUE:
	case BPF_MAP_TYPE_STACK:
	case BPF_MAP_TYPE_LRU_HASH:
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:
	case BPF_MAP_TYPE_STRUCT_OPS:
	case BPF_MAP_TYPE_CPUMAP:
		if (!bpf_capable())
			return -EPERM;
		break;
	case BPF_MAP_TYPE_SOCKMAP:
	case BPF_MAP_TYPE_SOCKHASH:
	case BPF_MAP_TYPE_DEVMAP:
	case BPF_MAP_TYPE_DEVMAP_HASH:
	case BPF_MAP_TYPE_XSKMAP:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		break;
	default:
		WARN(1, "unsupported map type %d", map_type);
		return -EPERM;
	}

	map = ops->map_alloc(attr);
	if (IS_ERR(map))
		return PTR_ERR(map);
	map->ops = ops;
	map->map_type = map_type;

	err = bpf_obj_name_cpy(map->name, attr->map_name,
			       sizeof(attr->map_name));
	if (err < 0)
		goto free_map;

	atomic64_set(&map->refcnt, 1);
	atomic64_set(&map->usercnt, 1);
	mutex_init(&map->freeze_mutex);
	spin_lock_init(&map->owner.lock);

	if (attr->btf_key_type_id || attr->btf_value_type_id ||
	    /* Even the map's value is a kernel's struct,
	     * the bpf_prog.o must have BTF to begin with
	     * to figure out the corresponding kernel's
	     * counter part.  Thus, attr->btf_fd has
	     * to be valid also.
	     */
	    attr->btf_vmlinux_value_type_id) {
		struct btf *btf;

		btf = btf_get_by_fd(attr->btf_fd);
		if (IS_ERR(btf)) {
			err = PTR_ERR(btf);
			goto free_map;
		}
		if (btf_is_kernel(btf)) {
			btf_put(btf);
			err = -EACCES;
			goto free_map;
		}
		map->btf = btf;

		if (attr->btf_value_type_id) {
			err = map_check_btf(map, btf, attr->btf_key_type_id,
					    attr->btf_value_type_id);
			if (err)
				goto free_map;
		}

		map->btf_key_type_id = attr->btf_key_type_id;
		map->btf_value_type_id = attr->btf_value_type_id;
		map->btf_vmlinux_value_type_id =
			attr->btf_vmlinux_value_type_id;
	}

	err = security_bpf_map_alloc(map);
	if (err)
		goto free_map;

	err = bpf_map_alloc_id(map);
	if (err)
		goto free_map_sec;

	bpf_map_save_memcg(map);

	err = bpf_map_new_fd(map, f_flags);
	if (err < 0) {
		/* failed to allocate fd.
		 * bpf_map_put_with_uref() is needed because the above
		 * bpf_map_alloc_id() has published the map
		 * to the userspace and the userspace may
		 * have refcnt-ed it through BPF_MAP_GET_FD_BY_ID.
		 */
		bpf_map_put_with_uref(map);
		return err;
	}

	return err;

free_map_sec:
	security_bpf_map_free(map);
free_map:
	btf_put(map->btf);
	map->ops->map_free(map);
	return err;
}

struct bpf_map *__bpf_map_get(struct fd f);

struct bpf_map *bpf_map_get(u32 ufd);

extern typeof(bpf_map_get) bpf_map_get;

struct bpf_map *__bpf_map_inc_not_zero(struct bpf_map *map, bool uref);

static void *__bpf_copy_key(void __user *ukey, u64 key_size)
{
	if (key_size)
		return vmemdup_user(ukey, key_size);

	if (ukey)
		return ERR_PTR(-EINVAL);

	return NULL;
}

static void *___bpf_copy_key(bpfptr_t ukey, u64 key_size)
{
	if (key_size)
		return kvmemdup_bpfptr(ukey, key_size);

	if (!bpfptr_is_null(ukey))
		return ERR_PTR(-EINVAL);

	return NULL;
}

#define BPF_MAP_LOOKUP_ELEM_LAST_FIELD flags

static int map_lookup_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *uvalue = u64_to_user_ptr(attr->value);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *value;
	u32 value_size;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_LOOKUP_ELEM))
		return -EINVAL;

	if (attr->flags & ~BPF_F_LOCK)
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_READ)) {
		err = -EPERM;
		goto err_put;
	}

	if ((attr->flags & BPF_F_LOCK) &&
	    !btf_record_has_field(map->record, BPF_SPIN_LOCK)) {
		err = -EINVAL;
		goto err_put;
	}

	key = __bpf_copy_key(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	value_size = bpf_map_value_size(map);

	err = -ENOMEM;
	value = kvmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value)
		goto free_key;

	if (map->map_type == BPF_MAP_TYPE_BLOOM_FILTER) {
		if (copy_from_user(value, uvalue, value_size))
			err = -EFAULT;
		else
			err = bpf_map_copy_value(map, key, value, attr->flags);
		goto free_value;
	}

	err = bpf_map_copy_value(map, key, value, attr->flags);
	if (err)
		goto free_value;

	err = -EFAULT;
	if (copy_to_user(uvalue, value, value_size) != 0)
		goto free_value;

	err = 0;

free_value:
	kvfree(value);
free_key:
	kvfree(key);
err_put:
	fdput(f);
	return err;
}

#define BPF_MAP_UPDATE_ELEM_LAST_FIELD flags

static int map_update_elem(union bpf_attr *attr, bpfptr_t uattr)
{
	bpfptr_t ukey = make_bpfptr(attr->key, uattr.is_kernel);
	bpfptr_t uvalue = make_bpfptr(attr->value, uattr.is_kernel);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *value;
	u32 value_size;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_UPDATE_ELEM))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	bpf_map_write_active_inc(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	if ((attr->flags & BPF_F_LOCK) &&
	    !btf_record_has_field(map->record, BPF_SPIN_LOCK)) {
		err = -EINVAL;
		goto err_put;
	}

	key = ___bpf_copy_key(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	value_size = bpf_map_value_size(map);
	value = kvmemdup_bpfptr(uvalue, value_size);
	if (IS_ERR(value)) {
		err = PTR_ERR(value);
		goto free_key;
	}

	err = bpf_map_update_value(map, f.file, key, value, attr->flags);

	kvfree(value);
free_key:
	kvfree(key);
err_put:
	bpf_map_write_active_dec(map);
	fdput(f);
	return err;
}

#define BPF_MAP_DELETE_ELEM_LAST_FIELD key

static int map_delete_elem(union bpf_attr *attr, bpfptr_t uattr)
{
	bpfptr_t ukey = make_bpfptr(attr->key, uattr.is_kernel);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	struct fd f;
	void *key;
	int err;

	if (CHECK_ATTR(BPF_MAP_DELETE_ELEM))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	bpf_map_write_active_inc(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	key = ___bpf_copy_key(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	if (bpf_map_is_offloaded(map)) {
		err = bpf_map_offload_delete_elem(map, key);
		goto out;
	} else if (IS_FD_PROG_ARRAY(map) ||
		   map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
		/* These maps require sleepable context */
		err = map->ops->map_delete_elem(map, key);
		goto out;
	}

	bpf_disable_instrumentation();
	rcu_read_lock();
	err = map->ops->map_delete_elem(map, key);
	rcu_read_unlock();
	bpf_enable_instrumentation();
	maybe_wait_bpf_programs(map);
out:
	kvfree(key);
err_put:
	bpf_map_write_active_dec(map);
	fdput(f);
	return err;
}

#define BPF_MAP_GET_NEXT_KEY_LAST_FIELD next_key

static int map_get_next_key(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *unext_key = u64_to_user_ptr(attr->next_key);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *next_key;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_GET_NEXT_KEY))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_READ)) {
		err = -EPERM;
		goto err_put;
	}

	if (ukey) {
		key = __bpf_copy_key(ukey, map->key_size);
		if (IS_ERR(key)) {
			err = PTR_ERR(key);
			goto err_put;
		}
	} else {
		key = NULL;
	}

	err = -ENOMEM;
	next_key = kvmalloc(map->key_size, GFP_USER);
	if (!next_key)
		goto free_key;

	if (bpf_map_is_offloaded(map)) {
		err = bpf_map_offload_get_next_key(map, key, next_key);
		goto out;
	}

	rcu_read_lock();
	err = map->ops->map_get_next_key(map, key, next_key);
	rcu_read_unlock();
out:
	if (err)
		goto free_next_key;

	err = -EFAULT;
	if (copy_to_user(unext_key, next_key, map->key_size) != 0)
		goto free_next_key;

	err = 0;

free_next_key:
	kvfree(next_key);
free_key:
	kvfree(key);
err_put:
	fdput(f);
	return err;
}

#define BPF_MAP_LOOKUP_AND_DELETE_ELEM_LAST_FIELD flags

static int map_lookup_and_delete_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *uvalue = u64_to_user_ptr(attr->value);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *value;
	u32 value_size;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_LOOKUP_AND_DELETE_ELEM))
		return -EINVAL;

	if (attr->flags & ~BPF_F_LOCK)
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);
	bpf_map_write_active_inc(map);
	if (!(map_get_sys_perms(map, f) & FMODE_CAN_READ) ||
	    !(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	if (attr->flags &&
	    (map->map_type == BPF_MAP_TYPE_QUEUE ||
	     map->map_type == BPF_MAP_TYPE_STACK)) {
		err = -EINVAL;
		goto err_put;
	}

	if ((attr->flags & BPF_F_LOCK) &&
	    !btf_record_has_field(map->record, BPF_SPIN_LOCK)) {
		err = -EINVAL;
		goto err_put;
	}

	key = __bpf_copy_key(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	value_size = bpf_map_value_size(map);

	err = -ENOMEM;
	value = kvmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value)
		goto free_key;

	err = -ENOTSUPP;
	if (map->map_type == BPF_MAP_TYPE_QUEUE ||
	    map->map_type == BPF_MAP_TYPE_STACK) {
		err = map->ops->map_pop_elem(map, value);
	} else if (map->map_type == BPF_MAP_TYPE_HASH ||
		   map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
		   map->map_type == BPF_MAP_TYPE_LRU_HASH ||
		   map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
		if (!bpf_map_is_offloaded(map)) {
			bpf_disable_instrumentation();
			rcu_read_lock();
			err = map->ops->map_lookup_and_delete_elem(map, key, value, attr->flags);
			rcu_read_unlock();
			bpf_enable_instrumentation();
		}
	}

	if (err)
		goto free_value;

	if (copy_to_user(uvalue, value, value_size) != 0) {
		err = -EFAULT;
		goto free_value;
	}

	err = 0;

free_value:
	kvfree(value);
free_key:
	kvfree(key);
err_put:
	bpf_map_write_active_dec(map);
	fdput(f);
	return err;
}

#define BPF_MAP_FREEZE_LAST_FIELD map_fd

static int map_freeze(const union bpf_attr *attr)
{
	int err = 0, ufd = attr->map_fd;
	struct bpf_map *map;
	struct fd f;

	if (CHECK_ATTR(BPF_MAP_FREEZE))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	if (map->map_type == BPF_MAP_TYPE_STRUCT_OPS || !IS_ERR_OR_NULL(map->record)) {
		fdput(f);
		return -ENOTSUPP;
	}

	if (!(map_get_sys_perms(map, f) & FMODE_CAN_WRITE)) {
		fdput(f);
		return -EPERM;
	}

	mutex_lock(&map->freeze_mutex);
	if (bpf_map_write_active(map)) {
		err = -EBUSY;
		goto err_put;
	}
	if (READ_ONCE(map->frozen)) {
		err = -EBUSY;
		goto err_put;
	}

	WRITE_ONCE(map->frozen, true);
err_put:
	mutex_unlock(&map->freeze_mutex);
	fdput(f);
	return err;
}

void bpf_prog_put(struct bpf_prog *prog);

extern typeof(bpf_prog_put) bpf_prog_put;

int bpf_prog_new_fd(struct bpf_prog *prog);

void bpf_prog_inc(struct bpf_prog *prog);

extern typeof(bpf_prog_inc) bpf_prog_inc;

struct bpf_prog *bpf_prog_get(u32 ufd);

struct bpf_prog *bpf_prog_get_type_dev(u32 ufd, enum bpf_prog_type type,
				       bool attach_drv);

extern typeof(bpf_prog_get_type_dev) bpf_prog_get_type_dev;

extern int bpf_prog_load(union bpf_attr *attr, bpfptr_t uattr, u32 uattr_size);

#define BPF_OBJ_LAST_FIELD path_fd

static int bpf_obj_pin(const union bpf_attr *attr)
{
	int path_fd;

	if (CHECK_ATTR(BPF_OBJ) || attr->file_flags & ~BPF_F_PATH_FD)
		return -EINVAL;

	/* path_fd has to be accompanied by BPF_F_PATH_FD flag */
	if (!(attr->file_flags & BPF_F_PATH_FD) && attr->path_fd)
		return -EINVAL;

	path_fd = attr->file_flags & BPF_F_PATH_FD ? attr->path_fd : AT_FDCWD;
	return bpf_obj_pin_user(attr->bpf_fd, path_fd,
				u64_to_user_ptr(attr->pathname));
}

static int bpf_obj_get(const union bpf_attr *attr)
{
	int path_fd;

	if (CHECK_ATTR(BPF_OBJ) || attr->bpf_fd != 0 ||
	    attr->file_flags & ~(BPF_OBJ_FLAG_MASK | BPF_F_PATH_FD))
		return -EINVAL;

	/* path_fd has to be accompanied by BPF_F_PATH_FD flag */
	if (!(attr->file_flags & BPF_F_PATH_FD) && attr->path_fd)
		return -EINVAL;

	path_fd = attr->file_flags & BPF_F_PATH_FD ? attr->path_fd : AT_FDCWD;
	return bpf_obj_get_user(path_fd, u64_to_user_ptr(attr->pathname),
				attr->file_flags);
}

void bpf_link_init(struct bpf_link *link, enum bpf_link_type type,
		   const struct bpf_link_ops *ops, struct bpf_prog *prog);

void bpf_link_cleanup(struct bpf_link_primer *primer);

extern void bpf_link_free(struct bpf_link *link);

static void bpf_link_put_direct(struct bpf_link *link)
{
	if (!atomic64_dec_and_test(&link->refcnt))
		return;
	bpf_link_free(link);
}

extern const struct file_operations bpf_link_fops

#ifdef CONFIG_PROC_FS

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
;

int bpf_link_prime(struct bpf_link *link, struct bpf_link_primer *primer);

int bpf_link_settle(struct bpf_link_primer *primer);

int bpf_link_new_fd(struct bpf_link *link);

struct bpf_link *bpf_link_get_from_fd(u32 ufd);

extern typeof(bpf_link_get_from_fd) bpf_link_get_from_fd;

extern int bpf_tracing_prog_attach(struct bpf_prog *prog,
				   int tgt_prog_fd,
				   u32 btf_id,
				   u64 bpf_cookie);

struct bpf_raw_tp_link {
	struct bpf_link link;
	struct bpf_raw_event_map *btp;
};

extern const struct bpf_link_ops bpf_raw_tp_link_lops;

#ifdef CONFIG_PERF_EVENTS
struct bpf_perf_link {
	struct bpf_link link;
	struct file *perf_file;
};

extern const struct bpf_link_ops bpf_perf_link_lops;

static int bpf_perf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct bpf_link_primer link_primer;
	struct bpf_perf_link *link;
	struct perf_event *event;
	struct file *perf_file;
	int err;

	if (attr->link_create.flags)
		return -EINVAL;

	perf_file = perf_event_get(attr->link_create.target_fd);
	if (IS_ERR(perf_file))
		return PTR_ERR(perf_file);

	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		err = -ENOMEM;
		goto out_put_file;
	}
	bpf_link_init(&link->link, BPF_LINK_TYPE_PERF_EVENT, &bpf_perf_link_lops, prog);
	link->perf_file = perf_file;

	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		goto out_put_file;
	}

	event = perf_file->private_data;
	err = perf_event_set_bpf_prog(event, prog, attr->link_create.perf_event.bpf_cookie);
	if (err) {
		bpf_link_cleanup(&link_primer);
		goto out_put_file;
	}
	/* perf_event_set_bpf_prog() doesn't take its own refcnt on prog */
	bpf_prog_inc(prog);

	return bpf_link_settle(&link_primer);

out_put_file:
	fput(perf_file);
	return err;
}
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PERF_EVENTS */

extern int bpf_raw_tp_link_attach(struct bpf_prog *prog,
				  const char __user *user_tp_name);

#define BPF_RAW_TRACEPOINT_OPEN_LAST_FIELD raw_tracepoint.prog_fd

static int bpf_raw_tracepoint_open(const union bpf_attr *attr)
{
	struct bpf_prog *prog;
	int fd;

	if (CHECK_ATTR(BPF_RAW_TRACEPOINT_OPEN))
		return -EINVAL;

	prog = bpf_prog_get(attr->raw_tracepoint.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	fd = bpf_raw_tp_link_attach(prog, u64_to_user_ptr(attr->raw_tracepoint.name));
	if (fd < 0)
		bpf_prog_put(prog);
	return fd;
}

static enum bpf_prog_type
attach_type_to_prog_type(enum bpf_attach_type attach_type)
{
	switch (attach_type) {
	case BPF_CGROUP_INET_INGRESS:
	case BPF_CGROUP_INET_EGRESS:
		return BPF_PROG_TYPE_CGROUP_SKB;
	case BPF_CGROUP_INET_SOCK_CREATE:
	case BPF_CGROUP_INET_SOCK_RELEASE:
	case BPF_CGROUP_INET4_POST_BIND:
	case BPF_CGROUP_INET6_POST_BIND:
		return BPF_PROG_TYPE_CGROUP_SOCK;
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET6_BIND:
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_INET6_CONNECT:
	case BPF_CGROUP_INET4_GETPEERNAME:
	case BPF_CGROUP_INET6_GETPEERNAME:
	case BPF_CGROUP_INET4_GETSOCKNAME:
	case BPF_CGROUP_INET6_GETSOCKNAME:
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP6_SENDMSG:
	case BPF_CGROUP_UDP4_RECVMSG:
	case BPF_CGROUP_UDP6_RECVMSG:
		return BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
	case BPF_CGROUP_SOCK_OPS:
		return BPF_PROG_TYPE_SOCK_OPS;
	case BPF_CGROUP_DEVICE:
		return BPF_PROG_TYPE_CGROUP_DEVICE;
	case BPF_SK_MSG_VERDICT:
		return BPF_PROG_TYPE_SK_MSG;
	case BPF_SK_SKB_STREAM_PARSER:
	case BPF_SK_SKB_STREAM_VERDICT:
	case BPF_SK_SKB_VERDICT:
		return BPF_PROG_TYPE_SK_SKB;
	case BPF_LIRC_MODE2:
		return BPF_PROG_TYPE_LIRC_MODE2;
	case BPF_FLOW_DISSECTOR:
		return BPF_PROG_TYPE_FLOW_DISSECTOR;
	case BPF_CGROUP_SYSCTL:
		return BPF_PROG_TYPE_CGROUP_SYSCTL;
	case BPF_CGROUP_GETSOCKOPT:
	case BPF_CGROUP_SETSOCKOPT:
		return BPF_PROG_TYPE_CGROUP_SOCKOPT;
	case BPF_TRACE_ITER:
	case BPF_TRACE_RAW_TP:
	case BPF_TRACE_FENTRY:
	case BPF_TRACE_FEXIT:
	case BPF_MODIFY_RETURN:
		return BPF_PROG_TYPE_TRACING;
	case BPF_LSM_MAC:
		return BPF_PROG_TYPE_LSM;
	case BPF_SK_LOOKUP:
		return BPF_PROG_TYPE_SK_LOOKUP;
	case BPF_XDP:
		return BPF_PROG_TYPE_XDP;
	case BPF_LSM_CGROUP:
		return BPF_PROG_TYPE_LSM;
	case BPF_TCX_INGRESS:
	case BPF_TCX_EGRESS:
		return BPF_PROG_TYPE_SCHED_CLS;
	default:
		return BPF_PROG_TYPE_UNSPEC;
	}
}

extern int bpf_prog_attach_check_attach_type(const struct bpf_prog *prog,
					     enum bpf_attach_type attach_type);

#define BPF_PROG_ATTACH_LAST_FIELD expected_revision

#define BPF_F_ATTACH_MASK_BASE	\
	(BPF_F_ALLOW_OVERRIDE |	\
	 BPF_F_ALLOW_MULTI |	\
	 BPF_F_REPLACE)

#define BPF_F_ATTACH_MASK_MPROG	\
	(BPF_F_REPLACE |	\
	 BPF_F_BEFORE |		\
	 BPF_F_AFTER |		\
	 BPF_F_ID |		\
	 BPF_F_LINK)

static int bpf_prog_attach(const union bpf_attr *attr)
{
	enum bpf_prog_type ptype;
	struct bpf_prog *prog;
	int ret;

	if (CHECK_ATTR(BPF_PROG_ATTACH))
		return -EINVAL;

	ptype = attach_type_to_prog_type(attr->attach_type);
	if (ptype == BPF_PROG_TYPE_UNSPEC)
		return -EINVAL;
	if (bpf_mprog_supported(ptype)) {
		if (attr->attach_flags & ~BPF_F_ATTACH_MASK_MPROG)
			return -EINVAL;
	} else {
		if (attr->attach_flags & ~BPF_F_ATTACH_MASK_BASE)
			return -EINVAL;
		if (attr->relative_fd ||
		    attr->expected_revision)
			return -EINVAL;
	}

	prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (bpf_prog_attach_check_attach_type(prog, attr->attach_type)) {
		bpf_prog_put(prog);
		return -EINVAL;
	}

	switch (ptype) {
	case BPF_PROG_TYPE_SK_SKB:
	case BPF_PROG_TYPE_SK_MSG:
		ret = sock_map_get_from_fd(attr, prog);
		break;
	case BPF_PROG_TYPE_LIRC_MODE2:
		ret = lirc_prog_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
		ret = netns_bpf_prog_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_SOCK_OPS:
	case BPF_PROG_TYPE_LSM:
		if (ptype == BPF_PROG_TYPE_LSM &&
		    prog->expected_attach_type != BPF_LSM_CGROUP)
			ret = -EINVAL;
		else
			ret = cgroup_bpf_prog_attach(attr, ptype, prog);
		break;
	case BPF_PROG_TYPE_SCHED_CLS:
		ret = tcx_prog_attach(attr, prog);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		bpf_prog_put(prog);
	return ret;
}

#define BPF_PROG_DETACH_LAST_FIELD expected_revision

static int bpf_prog_detach(const union bpf_attr *attr)
{
	struct bpf_prog *prog = NULL;
	enum bpf_prog_type ptype;
	int ret;

	if (CHECK_ATTR(BPF_PROG_DETACH))
		return -EINVAL;

	ptype = attach_type_to_prog_type(attr->attach_type);
	if (bpf_mprog_supported(ptype)) {
		if (ptype == BPF_PROG_TYPE_UNSPEC)
			return -EINVAL;
		if (attr->attach_flags & ~BPF_F_ATTACH_MASK_MPROG)
			return -EINVAL;
		if (attr->attach_bpf_fd) {
			prog = bpf_prog_get_type(attr->attach_bpf_fd, ptype);
			if (IS_ERR(prog))
				return PTR_ERR(prog);
		}
	} else if (attr->attach_flags ||
		   attr->relative_fd ||
		   attr->expected_revision) {
		return -EINVAL;
	}

	switch (ptype) {
	case BPF_PROG_TYPE_SK_MSG:
	case BPF_PROG_TYPE_SK_SKB:
		ret = sock_map_prog_detach(attr, ptype);
		break;
	case BPF_PROG_TYPE_LIRC_MODE2:
		ret = lirc_prog_detach(attr);
		break;
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
		ret = netns_bpf_prog_detach(attr, ptype);
		break;
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_SOCK_OPS:
	case BPF_PROG_TYPE_LSM:
		ret = cgroup_bpf_prog_detach(attr, ptype);
		break;
	case BPF_PROG_TYPE_SCHED_CLS:
		ret = tcx_prog_detach(attr, prog);
		break;
	default:
		ret = -EINVAL;
	}

	if (prog)
		bpf_prog_put(prog);
	return ret;
}

#define BPF_PROG_QUERY_LAST_FIELD query.revision

static int bpf_prog_query(const union bpf_attr *attr,
			  union bpf_attr __user *uattr)
{
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	if (CHECK_ATTR(BPF_PROG_QUERY))
		return -EINVAL;
	if (attr->query.query_flags & ~BPF_F_QUERY_EFFECTIVE)
		return -EINVAL;

	switch (attr->query.attach_type) {
	case BPF_CGROUP_INET_INGRESS:
	case BPF_CGROUP_INET_EGRESS:
	case BPF_CGROUP_INET_SOCK_CREATE:
	case BPF_CGROUP_INET_SOCK_RELEASE:
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET6_BIND:
	case BPF_CGROUP_INET4_POST_BIND:
	case BPF_CGROUP_INET6_POST_BIND:
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_INET6_CONNECT:
	case BPF_CGROUP_INET4_GETPEERNAME:
	case BPF_CGROUP_INET6_GETPEERNAME:
	case BPF_CGROUP_INET4_GETSOCKNAME:
	case BPF_CGROUP_INET6_GETSOCKNAME:
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP6_SENDMSG:
	case BPF_CGROUP_UDP4_RECVMSG:
	case BPF_CGROUP_UDP6_RECVMSG:
	case BPF_CGROUP_SOCK_OPS:
	case BPF_CGROUP_DEVICE:
	case BPF_CGROUP_SYSCTL:
	case BPF_CGROUP_GETSOCKOPT:
	case BPF_CGROUP_SETSOCKOPT:
	case BPF_LSM_CGROUP:
		return cgroup_bpf_prog_query(attr, uattr);
	case BPF_LIRC_MODE2:
		return lirc_prog_query(attr, uattr);
	case BPF_FLOW_DISSECTOR:
	case BPF_SK_LOOKUP:
		return netns_bpf_prog_query(attr, uattr);
	case BPF_SK_SKB_STREAM_PARSER:
	case BPF_SK_SKB_STREAM_VERDICT:
	case BPF_SK_MSG_VERDICT:
	case BPF_SK_SKB_VERDICT:
		return sock_map_bpf_prog_query(attr, uattr);
	case BPF_TCX_INGRESS:
	case BPF_TCX_EGRESS:
		return tcx_prog_query(attr, uattr);
	default:
		return -EINVAL;
	}
}

#define BPF_PROG_TEST_RUN_LAST_FIELD test.batch_size

static int bpf_prog_test_run(const union bpf_attr *attr,
			     union bpf_attr __user *uattr)
{
	struct bpf_prog *prog;
	int ret = -ENOTSUPP;

	if (CHECK_ATTR(BPF_PROG_TEST_RUN))
		return -EINVAL;

	if ((attr->test.ctx_size_in && !attr->test.ctx_in) ||
	    (!attr->test.ctx_size_in && attr->test.ctx_in))
		return -EINVAL;

	if ((attr->test.ctx_size_out && !attr->test.ctx_out) ||
	    (!attr->test.ctx_size_out && attr->test.ctx_out))
		return -EINVAL;

	prog = bpf_prog_get(attr->test.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (prog->aux->ops->test_run)
		ret = prog->aux->ops->test_run(prog, attr, uattr);

	bpf_prog_put(prog);
	return ret;
}

extern int bpf_obj_get_next_id(const union bpf_attr *attr,
			       union bpf_attr __user *uattr,
			       struct idr *idr,
			       spinlock_t *lock);

#define BPF_PROG_GET_FD_BY_ID_LAST_FIELD prog_id

struct bpf_prog *bpf_prog_by_id(u32 id);

static int bpf_prog_get_fd_by_id(const union bpf_attr *attr)
{
	struct bpf_prog *prog;
	u32 id = attr->prog_id;
	int fd;

	if (CHECK_ATTR(BPF_PROG_GET_FD_BY_ID))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	prog = bpf_prog_by_id(id);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	fd = bpf_prog_new_fd(prog);
	if (fd < 0)
		bpf_prog_put(prog);

	return fd;
}

#define BPF_MAP_GET_FD_BY_ID_LAST_FIELD open_flags

static int bpf_map_get_fd_by_id(const union bpf_attr *attr)
{
	struct bpf_map *map;
	u32 id = attr->map_id;
	int f_flags;
	int fd;

	if (CHECK_ATTR(BPF_MAP_GET_FD_BY_ID) ||
	    attr->open_flags & ~BPF_OBJ_FLAG_MASK)
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	f_flags = bpf_get_file_flag(attr->open_flags);
	if (f_flags < 0)
		return f_flags;

	spin_lock_bh(&map_idr_lock);
	map = idr_find(&map_idr, id);
	if (map)
		map = __bpf_map_inc_not_zero(map, true);
	else
		map = ERR_PTR(-ENOENT);
	spin_unlock_bh(&map_idr_lock);

	if (IS_ERR(map))
		return PTR_ERR(map);

	fd = bpf_map_new_fd(map, f_flags);
	if (fd < 0)
		bpf_map_put_with_uref(map);

	return fd;
}

extern int bpf_obj_get_info_by_fd(const union bpf_attr *attr,
				  union bpf_attr __user *uattr);

#define BPF_BTF_LOAD_LAST_FIELD btf_log_true_size

static int bpf_btf_load(const union bpf_attr *attr, bpfptr_t uattr, __u32 uattr_size)
{
	if (CHECK_ATTR(BPF_BTF_LOAD))
		return -EINVAL;

	if (!bpf_capable())
		return -EPERM;

	return btf_new_fd(attr, uattr, uattr_size);
}

#define BPF_BTF_GET_FD_BY_ID_LAST_FIELD btf_id

static int bpf_btf_get_fd_by_id(const union bpf_attr *attr)
{
	if (CHECK_ATTR(BPF_BTF_GET_FD_BY_ID))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return btf_get_fd_by_id(attr->btf_id);
}

static int bpf_task_fd_query_copy(const union bpf_attr *attr,
				    union bpf_attr __user *uattr,
				    u32 prog_id, u32 fd_type,
				    const char *buf, u64 probe_offset,
				    u64 probe_addr)
{
	char __user *ubuf = u64_to_user_ptr(attr->task_fd_query.buf);
	u32 len = buf ? strlen(buf) : 0, input_len;
	int err = 0;

	if (put_user(len, &uattr->task_fd_query.buf_len))
		return -EFAULT;
	input_len = attr->task_fd_query.buf_len;
	if (input_len && ubuf) {
		if (!len) {
			/* nothing to copy, just make ubuf NULL terminated */
			char zero = '\0';

			if (put_user(zero, ubuf))
				return -EFAULT;
		} else if (input_len >= len + 1) {
			/* ubuf can hold the string with NULL terminator */
			if (copy_to_user(ubuf, buf, len + 1))
				return -EFAULT;
		} else {
			/* ubuf cannot hold the string with NULL terminator,
			 * do a partial copy with NULL terminator.
			 */
			char zero = '\0';

			err = -ENOSPC;
			if (copy_to_user(ubuf, buf, input_len - 1))
				return -EFAULT;
			if (put_user(zero, ubuf + input_len - 1))
				return -EFAULT;
		}
	}

	if (put_user(prog_id, &uattr->task_fd_query.prog_id) ||
	    put_user(fd_type, &uattr->task_fd_query.fd_type) ||
	    put_user(probe_offset, &uattr->task_fd_query.probe_offset) ||
	    put_user(probe_addr, &uattr->task_fd_query.probe_addr))
		return -EFAULT;

	return err;
}

#define BPF_TASK_FD_QUERY_LAST_FIELD task_fd_query.probe_addr

static int bpf_task_fd_query(const union bpf_attr *attr,
			     union bpf_attr __user *uattr)
{
	pid_t pid = attr->task_fd_query.pid;
	u32 fd = attr->task_fd_query.fd;
	const struct perf_event *event;
	struct task_struct *task;
	struct file *file;
	int err;

	if (CHECK_ATTR(BPF_TASK_FD_QUERY))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (attr->task_fd_query.flags != 0)
		return -EINVAL;

	rcu_read_lock();
	task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
	rcu_read_unlock();
	if (!task)
		return -ENOENT;

	err = 0;
	file = fget_task(task, fd);
	put_task_struct(task);
	if (!file)
		return -EBADF;

	if (file->f_op == &bpf_link_fops) {
		struct bpf_link *link = file->private_data;

		if (link->ops == &bpf_raw_tp_link_lops) {
			struct bpf_raw_tp_link *raw_tp =
				container_of(link, struct bpf_raw_tp_link, link);
			struct bpf_raw_event_map *btp = raw_tp->btp;

			err = bpf_task_fd_query_copy(attr, uattr,
						     raw_tp->link.prog->aux->id,
						     BPF_FD_TYPE_RAW_TRACEPOINT,
						     btp->tp->name, 0, 0);
			goto put_file;
		}
		goto out_not_supp;
	}

	event = perf_get_event(file);
	if (!IS_ERR(event)) {
		u64 probe_offset, probe_addr;
		u32 prog_id, fd_type;
		const char *buf;

		err = bpf_get_perf_event_info(event, &prog_id, &fd_type,
					      &buf, &probe_offset,
					      &probe_addr);
		if (!err)
			err = bpf_task_fd_query_copy(attr, uattr, prog_id,
						     fd_type, buf,
						     probe_offset,
						     probe_addr);
		goto put_file;
	}

out_not_supp:
	err = -ENOTSUPP;
put_file:
	fput(file);
	return err;
}

extern int bpf_map_do_batch(const union bpf_attr *attr,
			    union bpf_attr __user *uattr,
			    int cmd);

#define BPF_LINK_CREATE_LAST_FIELD link_create.uprobe_multi.pid
static int link_create(union bpf_attr *attr, bpfptr_t uattr)
{
	struct bpf_prog *prog;
	int ret;

	if (CHECK_ATTR(BPF_LINK_CREATE))
		return -EINVAL;

	if (attr->link_create.attach_type == BPF_STRUCT_OPS)
		return bpf_struct_ops_link_create(attr);

	prog = bpf_prog_get(attr->link_create.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	ret = bpf_prog_attach_check_attach_type(prog,
						attr->link_create.attach_type);
	if (ret)
		goto out;

	switch (prog->type) {
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_SOCK_OPS:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		ret = cgroup_bpf_link_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_EXT:
		ret = bpf_tracing_prog_attach(prog,
					      attr->link_create.target_fd,
					      attr->link_create.target_btf_id,
					      attr->link_create.tracing.cookie);
		break;
	case BPF_PROG_TYPE_LSM:
	case BPF_PROG_TYPE_TRACING:
		if (attr->link_create.attach_type != prog->expected_attach_type) {
			ret = -EINVAL;
			goto out;
		}
		if (prog->expected_attach_type == BPF_TRACE_RAW_TP)
			ret = bpf_raw_tp_link_attach(prog, NULL);
		else if (prog->expected_attach_type == BPF_TRACE_ITER)
			ret = bpf_iter_link_attach(attr, uattr, prog);
		else if (prog->expected_attach_type == BPF_LSM_CGROUP)
			ret = cgroup_bpf_link_attach(attr, prog);
		else
			ret = bpf_tracing_prog_attach(prog,
						      attr->link_create.target_fd,
						      attr->link_create.target_btf_id,
						      attr->link_create.tracing.cookie);
		break;
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
	case BPF_PROG_TYPE_SK_LOOKUP:
		ret = netns_bpf_link_create(attr, prog);
		break;
#ifdef CONFIG_NET
	case BPF_PROG_TYPE_XDP:
		ret = bpf_xdp_link_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_SCHED_CLS:
		ret = tcx_link_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_NETFILTER:
		ret = bpf_nf_link_attach(attr, prog);
		break;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_TRACEPOINT:
		ret = bpf_perf_link_attach(attr, prog);
		break;
	case BPF_PROG_TYPE_KPROBE:
		if (attr->link_create.attach_type == BPF_PERF_EVENT)
			ret = bpf_perf_link_attach(attr, prog);
		else if (attr->link_create.attach_type == BPF_TRACE_KPROBE_MULTI)
			ret = bpf_kprobe_multi_link_attach(attr, prog);
		else if (attr->link_create.attach_type == BPF_TRACE_UPROBE_MULTI)
			ret = bpf_uprobe_multi_link_attach(attr, prog);
		break;
	default:
		ret = -EINVAL;
	}

out:
	if (ret < 0)
		bpf_prog_put(prog);
	return ret;
}

static int link_update_map(struct bpf_link *link, union bpf_attr *attr)
{
	struct bpf_map *new_map, *old_map = NULL;
	int ret;

	new_map = bpf_map_get(attr->link_update.new_map_fd);
	if (IS_ERR(new_map))
		return PTR_ERR(new_map);

	if (attr->link_update.flags & BPF_F_REPLACE) {
		old_map = bpf_map_get(attr->link_update.old_map_fd);
		if (IS_ERR(old_map)) {
			ret = PTR_ERR(old_map);
			goto out_put;
		}
	} else if (attr->link_update.old_map_fd) {
		ret = -EINVAL;
		goto out_put;
	}

	ret = link->ops->update_map(link, new_map, old_map);

	if (old_map)
		bpf_map_put(old_map);
out_put:
	bpf_map_put(new_map);
	return ret;
}

#define BPF_LINK_UPDATE_LAST_FIELD link_update.old_prog_fd

static int link_update(union bpf_attr *attr)
{
	struct bpf_prog *old_prog = NULL, *new_prog;
	struct bpf_link *link;
	u32 flags;
	int ret;

	if (CHECK_ATTR(BPF_LINK_UPDATE))
		return -EINVAL;

	flags = attr->link_update.flags;
	if (flags & ~BPF_F_REPLACE)
		return -EINVAL;

	link = bpf_link_get_from_fd(attr->link_update.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	if (link->ops->update_map) {
		ret = link_update_map(link, attr);
		goto out_put_link;
	}

	new_prog = bpf_prog_get(attr->link_update.new_prog_fd);
	if (IS_ERR(new_prog)) {
		ret = PTR_ERR(new_prog);
		goto out_put_link;
	}

	if (flags & BPF_F_REPLACE) {
		old_prog = bpf_prog_get(attr->link_update.old_prog_fd);
		if (IS_ERR(old_prog)) {
			ret = PTR_ERR(old_prog);
			old_prog = NULL;
			goto out_put_progs;
		}
	} else if (attr->link_update.old_prog_fd) {
		ret = -EINVAL;
		goto out_put_progs;
	}

	if (link->ops->update_prog)
		ret = link->ops->update_prog(link, new_prog, old_prog);
	else
		ret = -EINVAL;

out_put_progs:
	if (old_prog)
		bpf_prog_put(old_prog);
	if (ret)
		bpf_prog_put(new_prog);
out_put_link:
	bpf_link_put_direct(link);
	return ret;
}

#define BPF_LINK_DETACH_LAST_FIELD link_detach.link_fd

static int link_detach(union bpf_attr *attr)
{
	struct bpf_link *link;
	int ret;

	if (CHECK_ATTR(BPF_LINK_DETACH))
		return -EINVAL;

	link = bpf_link_get_from_fd(attr->link_detach.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	if (link->ops->detach)
		ret = link->ops->detach(link);
	else
		ret = -EOPNOTSUPP;

	bpf_link_put_direct(link);
	return ret;
}

struct bpf_link *bpf_link_by_id(u32 id);

#define BPF_LINK_GET_FD_BY_ID_LAST_FIELD link_id

static int bpf_link_get_fd_by_id(const union bpf_attr *attr)
{
	struct bpf_link *link;
	u32 id = attr->link_id;
	int fd;

	if (CHECK_ATTR(BPF_LINK_GET_FD_BY_ID))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	link = bpf_link_by_id(id);
	if (IS_ERR(link))
		return PTR_ERR(link);

	fd = bpf_link_new_fd(link);
	if (fd < 0)
		bpf_link_put_direct(link);

	return fd;
}

extern struct mutex bpf_stats_enabled_mutex;

extern const struct file_operations bpf_stats_fops;

static int bpf_enable_runtime_stats(void)
{
	int fd;

	mutex_lock(&bpf_stats_enabled_mutex);

	/* Set a very high limit to avoid overflow */
	if (static_key_count(&bpf_stats_enabled_key.key) > INT_MAX / 2) {
		mutex_unlock(&bpf_stats_enabled_mutex);
		return -EBUSY;
	}

	fd = anon_inode_getfd("bpf-stats", &bpf_stats_fops, NULL, O_CLOEXEC);
	if (fd >= 0)
		static_key_slow_inc(&bpf_stats_enabled_key.key);

	mutex_unlock(&bpf_stats_enabled_mutex);
	return fd;
}

#define BPF_ENABLE_STATS_LAST_FIELD enable_stats.type

static int bpf_enable_stats(union bpf_attr *attr)
{

	if (CHECK_ATTR(BPF_ENABLE_STATS))
		return -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	switch (attr->enable_stats.type) {
	case BPF_STATS_RUN_TIME:
		return bpf_enable_runtime_stats();
	default:
		break;
	}
	return -EINVAL;
}

#define BPF_ITER_CREATE_LAST_FIELD iter_create.flags

static int bpf_iter_create(union bpf_attr *attr)
{
	struct bpf_link *link;
	int err;

	if (CHECK_ATTR(BPF_ITER_CREATE))
		return -EINVAL;

	if (attr->iter_create.flags)
		return -EINVAL;

	link = bpf_link_get_from_fd(attr->iter_create.link_fd);
	if (IS_ERR(link))
		return PTR_ERR(link);

	err = bpf_iter_new_fd(link);
	bpf_link_put_direct(link);

	return err;
}

#define BPF_PROG_BIND_MAP_LAST_FIELD prog_bind_map.flags

static int bpf_prog_bind_map(union bpf_attr *attr)
{
	struct bpf_prog *prog;
	struct bpf_map *map;
	struct bpf_map **used_maps_old, **used_maps_new;
	int i, ret = 0;

	if (CHECK_ATTR(BPF_PROG_BIND_MAP))
		return -EINVAL;

	if (attr->prog_bind_map.flags)
		return -EINVAL;

	prog = bpf_prog_get(attr->prog_bind_map.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	map = bpf_map_get(attr->prog_bind_map.map_fd);
	if (IS_ERR(map)) {
		ret = PTR_ERR(map);
		goto out_prog_put;
	}

	mutex_lock(&prog->aux->used_maps_mutex);

	used_maps_old = prog->aux->used_maps;

	for (i = 0; i < prog->aux->used_map_cnt; i++)
		if (used_maps_old[i] == map) {
			bpf_map_put(map);
			goto out_unlock;
		}

	used_maps_new = kmalloc_array(prog->aux->used_map_cnt + 1,
				      sizeof(used_maps_new[0]),
				      GFP_KERNEL);
	if (!used_maps_new) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/* The bpf program will not access the bpf map, but for the sake of
	 * simplicity, increase sleepable_refcnt for sleepable program as well.
	 */
	if (prog->aux->sleepable)
		atomic64_inc(&map->sleepable_refcnt);
	memcpy(used_maps_new, used_maps_old,
	       sizeof(used_maps_old[0]) * prog->aux->used_map_cnt);
	used_maps_new[prog->aux->used_map_cnt] = map;

	prog->aux->used_map_cnt++;
	prog->aux->used_maps = used_maps_new;

	kfree(used_maps_old);

out_unlock:
	mutex_unlock(&prog->aux->used_maps_mutex);

	if (ret)
		bpf_map_put(map);
out_prog_put:
	bpf_prog_put(prog);
	return ret;
}

int klpp___sys_bpf(int cmd, bpfptr_t uattr, unsigned int size)
{
	union bpf_attr attr;
	int err;

	err = bpf_check_uarg_tail_zero(uattr, sizeof(attr), size);
	if (err)
		return err;
	size = min_t(u32, size, sizeof(attr));

	/* copy attributes from user space, may be less than sizeof(bpf_attr) */
	memset(&attr, 0, sizeof(attr));
	if (copy_from_bpfptr(&attr, uattr, size) != 0)
		return -EFAULT;

	err = security_bpf(cmd, &attr, size);
	if (err < 0)
		return err;

	switch (cmd) {
	case BPF_MAP_CREATE:
		err = map_create(&attr);
		break;
	case BPF_MAP_LOOKUP_ELEM:
		err = map_lookup_elem(&attr);
		break;
	case BPF_MAP_UPDATE_ELEM:
		err = map_update_elem(&attr, uattr);
		break;
	case BPF_MAP_DELETE_ELEM:
		err = map_delete_elem(&attr, uattr);
		break;
	case BPF_MAP_GET_NEXT_KEY:
		err = map_get_next_key(&attr);
		break;
	case BPF_MAP_FREEZE:
		err = map_freeze(&attr);
		break;
	case BPF_PROG_LOAD:
		err = bpf_prog_load(&attr, uattr, size);
		break;
	case BPF_OBJ_PIN:
		err = bpf_obj_pin(&attr);
		break;
	case BPF_OBJ_GET:
		err = bpf_obj_get(&attr);
		break;
	case BPF_PROG_ATTACH:
		err = bpf_prog_attach(&attr);
		break;
	case BPF_PROG_DETACH:
		err = bpf_prog_detach(&attr);
		break;
	case BPF_PROG_QUERY:
		err = bpf_prog_query(&attr, uattr.user);
		break;
	case BPF_PROG_TEST_RUN:
		err = bpf_prog_test_run(&attr, uattr.user);
		break;
	case BPF_PROG_GET_NEXT_ID:
		err = bpf_obj_get_next_id(&attr, uattr.user,
					  &prog_idr, &prog_idr_lock);
		break;
	case BPF_MAP_GET_NEXT_ID:
		err = bpf_obj_get_next_id(&attr, uattr.user,
					  &map_idr, &map_idr_lock);
		break;
	case BPF_BTF_GET_NEXT_ID:
		err = bpf_obj_get_next_id(&attr, uattr.user,
					  &btf_idr, &btf_idr_lock);
		break;
	case BPF_PROG_GET_FD_BY_ID:
		err = bpf_prog_get_fd_by_id(&attr);
		break;
	case BPF_MAP_GET_FD_BY_ID:
		err = bpf_map_get_fd_by_id(&attr);
		break;
	case BPF_OBJ_GET_INFO_BY_FD:
		err = bpf_obj_get_info_by_fd(&attr, uattr.user);
		break;
	case BPF_RAW_TRACEPOINT_OPEN:
		err = bpf_raw_tracepoint_open(&attr);
		break;
	case BPF_BTF_LOAD:
		err = bpf_btf_load(&attr, uattr, size);
		break;
	case BPF_BTF_GET_FD_BY_ID:
		err = bpf_btf_get_fd_by_id(&attr);
		break;
	case BPF_TASK_FD_QUERY:
		err = bpf_task_fd_query(&attr, uattr.user);
		break;
	case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
		err = map_lookup_and_delete_elem(&attr);
		break;
	case BPF_MAP_LOOKUP_BATCH:
		err = bpf_map_do_batch(&attr, uattr.user, BPF_MAP_LOOKUP_BATCH);
		break;
	case BPF_MAP_LOOKUP_AND_DELETE_BATCH:
		err = bpf_map_do_batch(&attr, uattr.user,
				       BPF_MAP_LOOKUP_AND_DELETE_BATCH);
		break;
	case BPF_MAP_UPDATE_BATCH:
		err = bpf_map_do_batch(&attr, uattr.user, BPF_MAP_UPDATE_BATCH);
		break;
	case BPF_MAP_DELETE_BATCH:
		err = bpf_map_do_batch(&attr, uattr.user, BPF_MAP_DELETE_BATCH);
		break;
	case BPF_LINK_CREATE:
		err = link_create(&attr, uattr);
		break;
	case BPF_LINK_UPDATE:
		err = link_update(&attr);
		break;
	case BPF_LINK_GET_FD_BY_ID:
		err = bpf_link_get_fd_by_id(&attr);
		break;
	case BPF_LINK_GET_NEXT_ID:
		err = bpf_obj_get_next_id(&attr, uattr.user,
					  &link_idr, &link_idr_lock);
		break;
	case BPF_ENABLE_STATS:
		err = bpf_enable_stats(&attr);
		break;
	case BPF_ITER_CREATE:
		err = bpf_iter_create(&attr);
		break;
	case BPF_LINK_DETACH:
		err = link_detach(&attr);
		break;
	case BPF_PROG_BIND_MAP:
		err = bpf_prog_bind_map(&attr);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

#include <linux/livepatch.h>

extern typeof(__bpf_map_get) __bpf_map_get
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __bpf_map_get);
extern typeof(__bpf_map_inc_not_zero) __bpf_map_inc_not_zero
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __bpf_map_inc_not_zero);
extern typeof(bpf_check_uarg_tail_zero) bpf_check_uarg_tail_zero
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_check_uarg_tail_zero);
extern typeof(bpf_get_file_flag) bpf_get_file_flag
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_get_file_flag);
extern typeof(bpf_get_perf_event_info) bpf_get_perf_event_info
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_get_perf_event_info);
extern typeof(bpf_iter_link_attach) bpf_iter_link_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_iter_link_attach);
extern typeof(bpf_iter_new_fd) bpf_iter_new_fd
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_iter_new_fd);
extern typeof(bpf_kprobe_multi_link_attach) bpf_kprobe_multi_link_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_kprobe_multi_link_attach);
extern typeof(bpf_link_by_id) bpf_link_by_id
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_by_id);
extern typeof(bpf_link_cleanup) bpf_link_cleanup
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_cleanup);
extern typeof(bpf_link_fops) bpf_link_fops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_fops);
extern typeof(bpf_link_free) bpf_link_free
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_free);
extern typeof(bpf_link_init) bpf_link_init
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_init);
extern typeof(bpf_link_new_fd) bpf_link_new_fd
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_new_fd);
extern typeof(bpf_link_prime) bpf_link_prime
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_prime);
extern typeof(bpf_link_settle) bpf_link_settle
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_settle);
extern typeof(bpf_map_copy_value) bpf_map_copy_value
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_copy_value);
extern typeof(bpf_map_do_batch) bpf_map_do_batch
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_do_batch);
extern typeof(bpf_map_free_record) bpf_map_free_record
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_free_record);
extern typeof(bpf_map_new_fd) bpf_map_new_fd
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_new_fd);
extern typeof(bpf_map_offload_delete_elem) bpf_map_offload_delete_elem
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_offload_delete_elem);
extern typeof(bpf_map_offload_get_next_key) bpf_map_offload_get_next_key
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_offload_get_next_key);
extern typeof(bpf_map_offload_ops) bpf_map_offload_ops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_offload_ops);
extern typeof(bpf_map_put_with_uref) bpf_map_put_with_uref
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_put_with_uref);
extern typeof(bpf_map_types) bpf_map_types
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_types);
extern typeof(bpf_map_update_value) bpf_map_update_value
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_update_value);
extern typeof(bpf_map_write_active) bpf_map_write_active
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_map_write_active);
extern typeof(bpf_nf_link_attach) bpf_nf_link_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_nf_link_attach);
extern typeof(bpf_obj_get_info_by_fd) bpf_obj_get_info_by_fd
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_obj_get_info_by_fd);
extern typeof(bpf_obj_get_next_id) bpf_obj_get_next_id
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_obj_get_next_id);
extern typeof(bpf_obj_get_user) bpf_obj_get_user
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_obj_get_user);
extern typeof(bpf_obj_name_cpy) bpf_obj_name_cpy
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_obj_name_cpy);
extern typeof(bpf_obj_pin_user) bpf_obj_pin_user
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_obj_pin_user);
extern typeof(bpf_perf_link_lops) bpf_perf_link_lops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_perf_link_lops);
extern typeof(bpf_prog_active) bpf_prog_active
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_prog_active);
extern typeof(bpf_prog_attach_check_attach_type)
	 bpf_prog_attach_check_attach_type
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_prog_attach_check_attach_type);
extern typeof(bpf_prog_by_id) bpf_prog_by_id
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_prog_by_id);
extern typeof(bpf_prog_get) bpf_prog_get
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_prog_get);
extern typeof(bpf_prog_load) bpf_prog_load
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_prog_load);
extern typeof(bpf_prog_new_fd) bpf_prog_new_fd
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_prog_new_fd);
extern typeof(bpf_raw_tp_link_attach) bpf_raw_tp_link_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_raw_tp_link_attach);
extern typeof(bpf_raw_tp_link_lops) bpf_raw_tp_link_lops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_raw_tp_link_lops);
extern typeof(bpf_stats_enabled_mutex) bpf_stats_enabled_mutex
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_stats_enabled_mutex);
extern typeof(bpf_stats_fops) bpf_stats_fops
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_stats_fops);
extern typeof(bpf_struct_ops_link_create) bpf_struct_ops_link_create
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_struct_ops_link_create);
extern typeof(bpf_tracing_prog_attach) bpf_tracing_prog_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_tracing_prog_attach);
extern typeof(bpf_uprobe_multi_link_attach) bpf_uprobe_multi_link_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_uprobe_multi_link_attach);
extern typeof(bpf_xdp_link_attach) bpf_xdp_link_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_xdp_link_attach);
extern typeof(btf_check_and_fixup_fields) btf_check_and_fixup_fields
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_check_and_fixup_fields);
extern typeof(btf_get_by_fd) btf_get_by_fd
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_get_by_fd);
extern typeof(btf_get_fd_by_id) btf_get_fd_by_id
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_get_fd_by_id);
extern typeof(btf_idr) btf_idr KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_idr);
extern typeof(btf_idr_lock) btf_idr_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_idr_lock);
extern typeof(btf_is_kernel) btf_is_kernel
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_is_kernel);
extern typeof(btf_new_fd) btf_new_fd
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_new_fd);
extern typeof(btf_parse_fields) btf_parse_fields
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_parse_fields);
extern typeof(btf_put) btf_put KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_put);
extern typeof(btf_type_id_size) btf_type_id_size
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, btf_type_id_size);
extern typeof(cgroup_bpf_link_attach) cgroup_bpf_link_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, cgroup_bpf_link_attach);
extern typeof(cgroup_bpf_prog_attach) cgroup_bpf_prog_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, cgroup_bpf_prog_attach);
extern typeof(cgroup_bpf_prog_detach) cgroup_bpf_prog_detach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, cgroup_bpf_prog_detach);
extern typeof(cgroup_bpf_prog_query) cgroup_bpf_prog_query
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, cgroup_bpf_prog_query);
extern typeof(fget_task) fget_task KLP_RELOC_SYMBOL(vmlinux, vmlinux, fget_task);
extern typeof(get_obj_cgroup_from_current) get_obj_cgroup_from_current
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, get_obj_cgroup_from_current);
extern typeof(link_idr) link_idr KLP_RELOC_SYMBOL(vmlinux, vmlinux, link_idr);
extern typeof(link_idr_lock) link_idr_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, link_idr_lock);
extern typeof(map_idr) map_idr KLP_RELOC_SYMBOL(vmlinux, vmlinux, map_idr);
extern typeof(map_idr_lock) map_idr_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, map_idr_lock);
extern typeof(netns_bpf_link_create) netns_bpf_link_create
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, netns_bpf_link_create);
extern typeof(netns_bpf_prog_attach) netns_bpf_prog_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, netns_bpf_prog_attach);
extern typeof(netns_bpf_prog_detach) netns_bpf_prog_detach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, netns_bpf_prog_detach);
extern typeof(netns_bpf_prog_query) netns_bpf_prog_query
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, netns_bpf_prog_query);
extern typeof(perf_event_get) perf_event_get
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, perf_event_get);
extern typeof(perf_event_set_bpf_prog) perf_event_set_bpf_prog
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, perf_event_set_bpf_prog);
extern typeof(perf_get_event) perf_get_event
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, perf_get_event);
extern typeof(prog_idr) prog_idr KLP_RELOC_SYMBOL(vmlinux, vmlinux, prog_idr);
extern typeof(prog_idr_lock) prog_idr_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, prog_idr_lock);
extern typeof(security_bpf) security_bpf
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_bpf);
extern typeof(security_bpf_map_alloc) security_bpf_map_alloc
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_bpf_map_alloc);
extern typeof(security_bpf_map_free) security_bpf_map_free
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_bpf_map_free);
extern typeof(sock_map_bpf_prog_query) sock_map_bpf_prog_query
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sock_map_bpf_prog_query);
extern typeof(sock_map_get_from_fd) sock_map_get_from_fd
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sock_map_get_from_fd);
extern typeof(sock_map_prog_detach) sock_map_prog_detach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sock_map_prog_detach);
extern typeof(sysctl_unprivileged_bpf_disabled) sysctl_unprivileged_bpf_disabled
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sysctl_unprivileged_bpf_disabled);
extern typeof(tcx_link_attach) tcx_link_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcx_link_attach);
extern typeof(tcx_prog_attach) tcx_prog_attach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcx_prog_attach);
extern typeof(tcx_prog_detach) tcx_prog_detach
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcx_prog_detach);
extern typeof(tcx_prog_query) tcx_prog_query
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tcx_prog_query);
