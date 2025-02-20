/*
 * livepatch_bsc1227371
 *
 * Fix for CVE-2024-36974, bsc#1227371
 *
 *  Upstream commit:
 *  f921a58ae208 ("net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  b592e7962005d1ee9f801502c84d49f2ca208a4b
 *
 *  SLE15-SP4 and -SP5 commit:
 *  433e33d049e45f640a148c5fbde06849ff613d07
 *
 *  SLE15-SP6 commit:
 *  f911add91ef8639c8215066df4d3326808fa45ec
 *
 *  SLE MICRO-6-0 commit:
 *  f911add91ef8639c8215066df4d3326808fa45ec
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/sched/sch_taprio.c */
#include <linux/ethtool.h>
#include <linux/ethtool_netlink.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/time.h>

#include <net/netlink.h>
#include <net/pkt_sched.h>

#include <net/sch_generic.h>

/* klp-ccp: from net/sched/sch_mqprio_lib.h */
#include <linux/types.h>

int mqprio_validate_qopt(struct net_device *dev, struct tc_mqprio_qopt *qopt,
			 bool validate_queue_counts,
			 bool allow_overlapping_txqs,
			 struct netlink_ext_ack *extack);
void mqprio_qopt_reconstruct(struct net_device *dev,
			     struct tc_mqprio_qopt *qopt);
void mqprio_fp_to_offload(u32 fp[TC_QOPT_MAX_QUEUE],
			  struct tc_mqprio_qopt_offload *mqprio);

/* klp-ccp: from net/sched/sch_taprio.c */
#define TXTIME_ASSIST_IS_ENABLED(flags) ((flags) & TCA_TAPRIO_ATTR_FLAG_TXTIME_ASSIST)
#define FULL_OFFLOAD_IS_ENABLED(flags) ((flags) & TCA_TAPRIO_ATTR_FLAG_FULL_OFFLOAD)
#define TAPRIO_FLAGS_INVALID U32_MAX

struct sched_entry {
	/* Durations between this GCL entry and the GCL entry where the
	 * respective traffic class gate closes
	 */
	u64 gate_duration[TC_MAX_QUEUE];
	atomic_t budget[TC_MAX_QUEUE];
	/* The qdisc makes some effort so that no packet leaves
	 * after this time
	 */
	ktime_t gate_close_time[TC_MAX_QUEUE];
	struct list_head list;
	/* Used to calculate when to advance the schedule */
	ktime_t end_time;
	ktime_t next_txtime;
	int index;
	u32 gate_mask;
	u32 interval;
	u8 command;
};

struct sched_gate_list {
	/* Longest non-zero contiguous gate durations per traffic class,
	 * or 0 if a traffic class gate never opens during the schedule.
	 */
	u64 max_open_gate_duration[TC_MAX_QUEUE];
	u32 max_frm_len[TC_MAX_QUEUE]; /* for the fast path */
	u32 max_sdu[TC_MAX_QUEUE]; /* for dump */
	struct rcu_head rcu;
	struct list_head entries;
	size_t num_entries;
	ktime_t cycle_end_time;
	s64 cycle_time;
	s64 cycle_time_extension;
	s64 base_time;
};

struct taprio_sched {
	struct Qdisc **qdiscs;
	struct Qdisc *root;
	u32 flags;
	enum tk_offsets tk_offset;
	int clockid;
	bool offloaded;
	bool detected_mqprio;
	bool broken_mqprio;
	atomic64_t picos_per_byte; /* Using picoseconds because for 10Gbps+
				    * speeds it's sub-nanoseconds per byte
				    */

	/* Protects the update side of the RCU protected current_entry */
	spinlock_t current_entry_lock;
	struct sched_entry __rcu *current_entry;
	struct sched_gate_list __rcu *oper_sched;
	struct sched_gate_list __rcu *admin_sched;
	struct hrtimer advance_timer;
	struct list_head taprio_list;
	int cur_txq[TC_MAX_QUEUE];
	u32 max_sdu[TC_MAX_QUEUE]; /* save info from the user */
	u32 fp[TC_QOPT_MAX_QUEUE]; /* only for dump and offloading */
	u32 txtime_delay;
};

struct __tc_taprio_qopt_offload {
	refcount_t users;
	struct tc_taprio_qopt_offload offload;
};

static ktime_t sched_base_time(const struct sched_gate_list *sched)
{
	if (!sched)
		return KTIME_MAX;

	return ns_to_ktime(sched->base_time);
}

extern ktime_t taprio_get_time(const struct taprio_sched *q);

extern void taprio_free_sched_cb(struct rcu_head *head);

static void switch_schedules(struct taprio_sched *q,
			     struct sched_gate_list **admin,
			     struct sched_gate_list **oper)
{
	rcu_assign_pointer(q->oper_sched, *admin);
	rcu_assign_pointer(q->admin_sched, NULL);

	if (*oper)
		call_rcu(&(*oper)->rcu, taprio_free_sched_cb);

	*oper = *admin;
	*admin = NULL;
}

extern void taprio_update_queue_max_sdu(struct taprio_sched *q,
					struct sched_gate_list *sched,
					struct qdisc_size_table *stab);

static bool taprio_flags_valid(u32 flags)
{
	/* Make sure no other flag bits are set. */
	if (flags & ~(TCA_TAPRIO_ATTR_FLAG_TXTIME_ASSIST |
		      TCA_TAPRIO_ATTR_FLAG_FULL_OFFLOAD))
		return false;
	/* txtime-assist and full offload are mutually exclusive */
	if ((flags & TCA_TAPRIO_ATTR_FLAG_TXTIME_ASSIST) &&
	    (flags & TCA_TAPRIO_ATTR_FLAG_FULL_OFFLOAD))
		return false;
	return true;
}

static void taprio_set_budgets(struct taprio_sched *q,
			       struct sched_gate_list *sched,
			       struct sched_entry *entry)
{
	struct net_device *dev = qdisc_dev(q->root);
	int num_tc = netdev_get_num_tc(dev);
	int tc, budget;

	for (tc = 0; tc < num_tc; tc++) {
		/* Traffic classes which never close have infinite budget */
		if (entry->gate_duration[tc] == sched->cycle_time)
			budget = INT_MAX;
		else
			budget = div64_u64((u64)entry->gate_duration[tc] * PSEC_PER_NSEC,
					   atomic64_read(&q->picos_per_byte));

		atomic_set(&entry->budget[tc], budget);
	}
}

extern enum hrtimer_restart advance_sched(struct hrtimer *timer);

extern const struct nla_policy taprio_policy[TCA_TAPRIO_ATTR_MAX + 1];

extern int parse_taprio_schedule(struct taprio_sched *q, struct nlattr **tb,
				 struct sched_gate_list *new,
				 struct netlink_ext_ack *extack);

static int taprio_parse_mqprio_opt(struct net_device *dev,
				   struct tc_mqprio_qopt *qopt,
				   struct netlink_ext_ack *extack,
				   u32 taprio_flags)
{
	bool allow_overlapping_txqs = TXTIME_ASSIST_IS_ENABLED(taprio_flags);

	if (!qopt) {
		if (!dev->num_tc) {
			NL_SET_ERR_MSG(extack, "'mqprio' configuration is necessary");
			return -EINVAL;
		}
		return 0;
	}

	/* taprio imposes that traffic classes map 1:n to tx queues */
	if (qopt->num_tc > dev->num_tx_queues) {
		NL_SET_ERR_MSG(extack, "Number of traffic classes is greater than number of HW queues");
		return -EINVAL;
	}

	/* For some reason, in txtime-assist mode, we allow TXQ ranges for
	 * different TCs to overlap, and just validate the TXQ ranges.
	 */
	return mqprio_validate_qopt(dev, qopt, true, allow_overlapping_txqs,
				    extack);
}

static int taprio_get_start_time(struct Qdisc *sch,
				 struct sched_gate_list *sched,
				 ktime_t *start)
{
	struct taprio_sched *q = qdisc_priv(sch);
	ktime_t now, base, cycle;
	s64 n;

	base = sched_base_time(sched);
	now = taprio_get_time(q);

	if (ktime_after(base, now)) {
		*start = base;
		return 0;
	}

	cycle = sched->cycle_time;

	/* The qdisc is expected to have at least one sched_entry.  Moreover,
	 * any entry must have 'interval' > 0. Thus if the cycle time is zero,
	 * something went really wrong. In that case, we should warn about this
	 * inconsistent state and return error.
	 */
	if (WARN_ON(!cycle))
		return -EFAULT;

	/* Schedule the start time for the beginning of the next
	 * cycle.
	 */
	n = div64_s64(ktime_sub_ns(now, base), cycle);
	*start = ktime_add_ns(base, (n + 1) * cycle);
	return 0;
}

static void setup_first_end_time(struct taprio_sched *q,
				 struct sched_gate_list *sched, ktime_t base)
{
	struct net_device *dev = qdisc_dev(q->root);
	int num_tc = netdev_get_num_tc(dev);
	struct sched_entry *first;
	ktime_t cycle;
	int tc;

	first = list_first_entry(&sched->entries,
				 struct sched_entry, list);

	cycle = sched->cycle_time;

	/* FIXME: find a better place to do this */
	sched->cycle_end_time = ktime_add_ns(base, cycle);

	first->end_time = ktime_add_ns(base, first->interval);
	taprio_set_budgets(q, sched, first);

	for (tc = 0; tc < num_tc; tc++) {
		if (first->gate_duration[tc] == sched->cycle_time)
			first->gate_close_time[tc] = KTIME_MAX;
		else
			first->gate_close_time[tc] = ktime_add_ns(base, first->gate_duration[tc]);
	}

	rcu_assign_pointer(q->current_entry, NULL);
}

static void taprio_start_sched(struct Qdisc *sch,
			       ktime_t start, struct sched_gate_list *new)
{
	struct taprio_sched *q = qdisc_priv(sch);
	ktime_t expires;

	if (FULL_OFFLOAD_IS_ENABLED(q->flags))
		return;

	expires = hrtimer_get_expires(&q->advance_timer);
	if (expires == 0)
		expires = KTIME_MAX;

	/* If the new schedule starts before the next expiration, we
	 * reprogram it to the earliest one, so we change the admin
	 * schedule to the operational one at the right time.
	 */
	start = min_t(ktime_t, start, expires);

	hrtimer_start(&q->advance_timer, start, HRTIMER_MODE_ABS);
}

extern void taprio_set_picos_per_byte(struct net_device *dev,
				      struct taprio_sched *q);

static void setup_txtime(struct taprio_sched *q,
			 struct sched_gate_list *sched, ktime_t base)
{
	struct sched_entry *entry;
	u64 interval = 0;

	list_for_each_entry(entry, &sched->entries, list) {
		entry->next_txtime = ktime_add_ns(base, interval);
		interval += entry->interval;
	}
}

static struct tc_taprio_qopt_offload *taprio_offload_alloc(int num_entries)
{
	struct __tc_taprio_qopt_offload *__offload;

	__offload = kzalloc(struct_size(__offload, offload.entries, num_entries),
			    GFP_KERNEL);
	if (!__offload)
		return NULL;

	refcount_set(&__offload->users, 1);

	return &__offload->offload;
}

void taprio_offload_free(struct tc_taprio_qopt_offload *offload);

extern typeof(taprio_offload_free) taprio_offload_free;

static void taprio_offload_config_changed(struct taprio_sched *q)
{
	struct sched_gate_list *oper, *admin;

	oper = rtnl_dereference(q->oper_sched);
	admin = rtnl_dereference(q->admin_sched);

	switch_schedules(q, &admin, &oper);
}

static u32 tc_map_to_queue_mask(struct net_device *dev, u32 tc_mask)
{
	u32 i, queue_mask = 0;

	for (i = 0; i < dev->num_tc; i++) {
		u32 offset, count;

		if (!(tc_mask & BIT(i)))
			continue;

		offset = dev->tc_to_txq[i].offset;
		count = dev->tc_to_txq[i].count;

		queue_mask |= GENMASK(offset + count - 1, offset);
	}

	return queue_mask;
}

static void taprio_sched_to_offload(struct net_device *dev,
				    struct sched_gate_list *sched,
				    struct tc_taprio_qopt_offload *offload,
				    const struct tc_taprio_caps *caps)
{
	struct sched_entry *entry;
	int i = 0;

	offload->base_time = sched->base_time;
	offload->cycle_time = sched->cycle_time;
	offload->cycle_time_extension = sched->cycle_time_extension;

	list_for_each_entry(entry, &sched->entries, list) {
		struct tc_taprio_sched_entry *e = &offload->entries[i];

		e->command = entry->command;
		e->interval = entry->interval;
		if (caps->gate_mask_per_txq)
			e->gate_mask = tc_map_to_queue_mask(dev,
							    entry->gate_mask);
		else
			e->gate_mask = entry->gate_mask;

		i++;
	}

	offload->num_entries = i;
}

static int taprio_enable_offload(struct net_device *dev,
				 struct taprio_sched *q,
				 struct sched_gate_list *sched,
				 struct netlink_ext_ack *extack)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	struct tc_taprio_qopt_offload *offload;
	struct tc_taprio_caps caps;
	int tc, err = 0;

	if (!ops->ndo_setup_tc) {
		NL_SET_ERR_MSG(extack,
			       "Device does not support taprio offload");
		return -EOPNOTSUPP;
	}

	qdisc_offload_query_caps(dev, TC_SETUP_QDISC_TAPRIO,
				 &caps, sizeof(caps));

	if (!caps.supports_queue_max_sdu) {
		for (tc = 0; tc < TC_MAX_QUEUE; tc++) {
			if (q->max_sdu[tc]) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Device does not handle queueMaxSDU");
				return -EOPNOTSUPP;
			}
		}
	}

	offload = taprio_offload_alloc(sched->num_entries);
	if (!offload) {
		NL_SET_ERR_MSG(extack,
			       "Not enough memory for enabling offload mode");
		return -ENOMEM;
	}
	offload->cmd = TAPRIO_CMD_REPLACE;
	offload->extack = extack;
	mqprio_qopt_reconstruct(dev, &offload->mqprio.qopt);
	offload->mqprio.extack = extack;
	taprio_sched_to_offload(dev, sched, offload, &caps);
	mqprio_fp_to_offload(q->fp, &offload->mqprio);

	for (tc = 0; tc < TC_MAX_QUEUE; tc++)
		offload->max_sdu[tc] = q->max_sdu[tc];

	err = ops->ndo_setup_tc(dev, TC_SETUP_QDISC_TAPRIO, offload);
	if (err < 0) {
		NL_SET_ERR_MSG_WEAK(extack,
				    "Device failed to setup taprio offload");
		goto done;
	}

	q->offloaded = true;

done:
	/* The offload structure may linger around via a reference taken by the
	 * device driver, so clear up the netlink extack pointer so that the
	 * driver isn't tempted to dereference data which stopped being valid
	 */
	offload->extack = NULL;
	offload->mqprio.extack = NULL;
	taprio_offload_free(offload);

	return err;
}

static int taprio_disable_offload(struct net_device *dev,
				  struct taprio_sched *q,
				  struct netlink_ext_ack *extack)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	struct tc_taprio_qopt_offload *offload;
	int err;

	if (!q->offloaded)
		return 0;

	offload = taprio_offload_alloc(0);
	if (!offload) {
		NL_SET_ERR_MSG(extack,
			       "Not enough memory to disable offload mode");
		return -ENOMEM;
	}
	offload->cmd = TAPRIO_CMD_DESTROY;

	err = ops->ndo_setup_tc(dev, TC_SETUP_QDISC_TAPRIO, offload);
	if (err < 0) {
		NL_SET_ERR_MSG(extack,
			       "Device failed to disable offload");
		goto out;
	}

	q->offloaded = false;

out:
	taprio_offload_free(offload);

	return err;
}

static int taprio_parse_clockid(struct Qdisc *sch, struct nlattr **tb,
				struct netlink_ext_ack *extack)
{
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	int err = -EINVAL;

	if (FULL_OFFLOAD_IS_ENABLED(q->flags)) {
		const struct ethtool_ops *ops = dev->ethtool_ops;
		struct ethtool_ts_info info = {
			.cmd = ETHTOOL_GET_TS_INFO,
			.phc_index = -1,
		};

		if (tb[TCA_TAPRIO_ATTR_SCHED_CLOCKID]) {
			NL_SET_ERR_MSG(extack,
				       "The 'clockid' cannot be specified for full offload");
			goto out;
		}

		if (ops && ops->get_ts_info)
			err = ops->get_ts_info(dev, &info);

		if (err || info.phc_index < 0) {
			NL_SET_ERR_MSG(extack,
				       "Device does not have a PTP clock");
			err = -ENOTSUPP;
			goto out;
		}
	} else if (tb[TCA_TAPRIO_ATTR_SCHED_CLOCKID]) {
		int clockid = nla_get_s32(tb[TCA_TAPRIO_ATTR_SCHED_CLOCKID]);
		enum tk_offsets tk_offset;

		/* We only support static clockids and we don't allow
		 * for it to be modified after the first init.
		 */
		if (clockid < 0 ||
		    (q->clockid != -1 && q->clockid != clockid)) {
			NL_SET_ERR_MSG(extack,
				       "Changing the 'clockid' of a running schedule is not supported");
			err = -ENOTSUPP;
			goto out;
		}

		switch (clockid) {
		case CLOCK_REALTIME:
			tk_offset = TK_OFFS_REAL;
			break;
		case CLOCK_MONOTONIC:
			tk_offset = TK_OFFS_MAX;
			break;
		case CLOCK_BOOTTIME:
			tk_offset = TK_OFFS_BOOT;
			break;
		case CLOCK_TAI:
			tk_offset = TK_OFFS_TAI;
			break;
		default:
			NL_SET_ERR_MSG(extack, "Invalid 'clockid'");
			err = -EINVAL;
			goto out;
		}
		/* This pairs with READ_ONCE() in taprio_mono_to_any */
		WRITE_ONCE(q->tk_offset, tk_offset);

		q->clockid = clockid;
	} else {
		NL_SET_ERR_MSG(extack, "Specifying a 'clockid' is mandatory");
		goto out;
	}

	/* Everything went ok, return success. */
	err = 0;

out:
	return err;
}

extern int taprio_parse_tc_entries(struct Qdisc *sch,
				   struct nlattr *opt,
				   struct netlink_ext_ack *extack);

static int taprio_mqprio_cmp(const struct net_device *dev,
			     const struct tc_mqprio_qopt *mqprio)
{
	int i;

	if (!mqprio || mqprio->num_tc != dev->num_tc)
		return -1;

	for (i = 0; i < mqprio->num_tc; i++)
		if (dev->tc_to_txq[i].count != mqprio->count[i] ||
		    dev->tc_to_txq[i].offset != mqprio->offset[i])
			return -1;

	for (i = 0; i <= TC_BITMASK; i++)
		if (dev->prio_tc_map[i] != mqprio->prio_tc_map[i])
			return -1;

	return 0;
}

static int taprio_new_flags(const struct nlattr *attr, u32 old,
			    struct netlink_ext_ack *extack)
{
	u32 new = 0;

	if (attr)
		new = nla_get_u32(attr);

	if (old != TAPRIO_FLAGS_INVALID && old != new) {
		NL_SET_ERR_MSG_MOD(extack, "Changing 'flags' of a running schedule is not supported");
		return -EOPNOTSUPP;
	}

	if (!taprio_flags_valid(new)) {
		NL_SET_ERR_MSG_MOD(extack, "Specified 'flags' are not valid");
		return -EINVAL;
	}

	return new;
}

int klpp_taprio_change(struct Qdisc *sch, struct nlattr *opt,
			 struct netlink_ext_ack *extack)
{
	struct qdisc_size_table *stab = rtnl_dereference(sch->stab);
	struct nlattr *tb[TCA_TAPRIO_ATTR_MAX + 1] = { };
	struct sched_gate_list *oper, *admin, *new_admin;
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct tc_mqprio_qopt *mqprio = NULL;
	unsigned long flags;
	ktime_t start;
	int i, err;

	err = nla_parse_nested_deprecated(tb, TCA_TAPRIO_ATTR_MAX, opt,
					  taprio_policy, extack);
	if (err < 0)
		return err;

	if (tb[TCA_TAPRIO_ATTR_PRIOMAP])
		mqprio = nla_data(tb[TCA_TAPRIO_ATTR_PRIOMAP]);

	err = taprio_new_flags(tb[TCA_TAPRIO_ATTR_FLAGS],
			       q->flags, extack);
	if (err < 0)
		return err;

	q->flags = err;

	err = taprio_parse_mqprio_opt(dev, mqprio, extack, q->flags);
	if (err < 0)
		return err;

	err = taprio_parse_tc_entries(sch, opt, extack);
	if (err)
		return err;

	new_admin = kzalloc(sizeof(*new_admin), GFP_KERNEL);
	if (!new_admin) {
		NL_SET_ERR_MSG(extack, "Not enough memory for a new schedule");
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&new_admin->entries);

	oper = rtnl_dereference(q->oper_sched);
	admin = rtnl_dereference(q->admin_sched);

	/* no changes - no new mqprio settings */
	if (!taprio_mqprio_cmp(dev, mqprio))
		mqprio = NULL;

	if (mqprio && (oper || admin)) {
		NL_SET_ERR_MSG(extack, "Changing the traffic mapping of a running schedule is not supported");
		err = -ENOTSUPP;
		goto free_sched;
	}

	if (mqprio) {
		err = netdev_set_num_tc(dev, mqprio->num_tc);
		if (err)
			goto free_sched;
		for (i = 0; i < mqprio->num_tc; i++) {
			netdev_set_tc_queue(dev, i,
					    mqprio->count[i],
					    mqprio->offset[i]);
			q->cur_txq[i] = mqprio->offset[i];
		}

		/* Always use supplied priority mappings */
		for (i = 0; i <= TC_BITMASK; i++)
			netdev_set_prio_tc_map(dev, i,
					       mqprio->prio_tc_map[i]);
	}

	err = parse_taprio_schedule(q, tb, new_admin, extack);
	if (err < 0)
		goto free_sched;

	if (new_admin->num_entries == 0) {
		NL_SET_ERR_MSG(extack, "There should be at least one entry in the schedule");
		err = -EINVAL;
		goto free_sched;
	}

	err = taprio_parse_clockid(sch, tb, extack);
	if (err < 0)
		goto free_sched;

	taprio_set_picos_per_byte(dev, q);
	taprio_update_queue_max_sdu(q, new_admin, stab);

	if (FULL_OFFLOAD_IS_ENABLED(q->flags))
		err = taprio_enable_offload(dev, q, new_admin, extack);
	else
		err = taprio_disable_offload(dev, q, extack);
	if (err)
		goto free_sched;

	/* Protects against enqueue()/dequeue() */
	spin_lock_bh(qdisc_lock(sch));

	if (tb[TCA_TAPRIO_ATTR_TXTIME_DELAY]) {
		if (!TXTIME_ASSIST_IS_ENABLED(q->flags)) {
			NL_SET_ERR_MSG_MOD(extack, "txtime-delay can only be set when txtime-assist mode is enabled");
			err = -EINVAL;
			goto unlock;
		}

		q->txtime_delay = nla_get_u32(tb[TCA_TAPRIO_ATTR_TXTIME_DELAY]);
	}

	if (!TXTIME_ASSIST_IS_ENABLED(q->flags) &&
	    !FULL_OFFLOAD_IS_ENABLED(q->flags) &&
	    !hrtimer_active(&q->advance_timer)) {
		hrtimer_init(&q->advance_timer, q->clockid, HRTIMER_MODE_ABS);
		q->advance_timer.function = advance_sched;
	}

	err = taprio_get_start_time(sch, new_admin, &start);
	if (err < 0) {
		NL_SET_ERR_MSG(extack, "Internal error: failed get start time");
		goto unlock;
	}

	setup_txtime(q, new_admin, start);

	if (TXTIME_ASSIST_IS_ENABLED(q->flags)) {
		if (!oper) {
			rcu_assign_pointer(q->oper_sched, new_admin);
			err = 0;
			new_admin = NULL;
			goto unlock;
		}

		rcu_assign_pointer(q->admin_sched, new_admin);
		if (admin)
			call_rcu(&admin->rcu, taprio_free_sched_cb);
	} else {
		setup_first_end_time(q, new_admin, start);

		/* Protects against advance_sched() */
		spin_lock_irqsave(&q->current_entry_lock, flags);

		taprio_start_sched(sch, start, new_admin);

		rcu_assign_pointer(q->admin_sched, new_admin);
		if (admin)
			call_rcu(&admin->rcu, taprio_free_sched_cb);

		spin_unlock_irqrestore(&q->current_entry_lock, flags);

		if (FULL_OFFLOAD_IS_ENABLED(q->flags))
			taprio_offload_config_changed(q);
	}

	new_admin = NULL;
	err = 0;

	if (!stab)
		NL_SET_ERR_MSG_MOD(extack,
				   "Size table not specified, frame length estimations may be inaccurate");

unlock:
	spin_unlock_bh(qdisc_lock(sch));

free_sched:
	if (new_admin)
		call_rcu(&new_admin->rcu, taprio_free_sched_cb);

	return err;
}


#include "livepatch_bsc1227371.h"

#include <linux/livepatch.h>

extern typeof(advance_sched) advance_sched
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, advance_sched);
extern typeof(parse_taprio_schedule) parse_taprio_schedule
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, parse_taprio_schedule);
extern typeof(taprio_free_sched_cb) taprio_free_sched_cb
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_free_sched_cb);
extern typeof(taprio_get_time) taprio_get_time
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_get_time);
extern typeof(taprio_offload_free) taprio_offload_free
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_offload_free);
extern typeof(taprio_parse_tc_entries) taprio_parse_tc_entries
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_parse_tc_entries);
extern typeof(taprio_policy) taprio_policy
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_policy);
extern typeof(taprio_set_picos_per_byte) taprio_set_picos_per_byte
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_set_picos_per_byte);
extern typeof(taprio_update_queue_max_sdu) taprio_update_queue_max_sdu
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_update_queue_max_sdu);
extern typeof(mqprio_fp_to_offload) mqprio_fp_to_offload
	 KLP_RELOC_SYMBOL(sch_taprio, sch_mqprio_lib, mqprio_fp_to_offload);
extern typeof(mqprio_qopt_reconstruct) mqprio_qopt_reconstruct
	 KLP_RELOC_SYMBOL(sch_taprio, sch_mqprio_lib, mqprio_qopt_reconstruct);
extern typeof(mqprio_validate_qopt) mqprio_validate_qopt
	 KLP_RELOC_SYMBOL(sch_taprio, sch_mqprio_lib, mqprio_validate_qopt);
