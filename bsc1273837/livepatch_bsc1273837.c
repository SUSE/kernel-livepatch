/*
 * livepatch_bsc1273837
 *
 * Fix for CVE-2026-64121, bsc#1273837
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1273837.h"


/* klp-ccp: from drivers/net/ifb.c */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_netdev.h>
#include <net/pkt_sched.h>
#include <net/net_namespace.h>

struct ifb_q_stats {
	u64 packets;
	u64 bytes;
	struct u64_stats_sync	sync;
};

struct ifb_q_private {
	struct net_device	*dev;
	struct tasklet_struct   ifb_tasklet;
	int			tasklet_pending;
	int			txqnum;
	struct sk_buff_head     rq;
	struct sk_buff_head     tq;
	struct ifb_q_stats	rx_stats;
	struct ifb_q_stats	tx_stats;
} ____cacheline_aligned_in_smp;

struct ifb_dev_private {
	struct ifb_q_private *tx_private;
};

struct ifb_q_stats_desc {
	char	desc[ETH_GSTRING_LEN];
	size_t	offset;
};

extern const struct ifb_q_stats_desc ifb_q_stats_desc[2];

#define IFB_Q_STATS_LEN	ARRAY_SIZE(ifb_q_stats_desc)

void klpp_ifb_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	u8 *p = buf;
	int i, j;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < dev->num_tx_queues; i++)
			for (j = 0; j < IFB_Q_STATS_LEN; j++)
				ethtool_sprintf(&p, "rx_queue_%u_%.18s",
						i, ifb_q_stats_desc[j].desc);

		for (i = 0; i < dev->num_tx_queues; i++)
			for (j = 0; j < IFB_Q_STATS_LEN; j++)
				ethtool_sprintf(&p, "tx_queue_%u_%.18s",
						i, ifb_q_stats_desc[j].desc);

		break;
	}
}

int klpp_ifb_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return IFB_Q_STATS_LEN * dev->num_tx_queues * 2;
	default:
		return -EOPNOTSUPP;
	}
}

static void ifb_fill_stats_data(u64 **data,
				struct ifb_q_stats *q_stats)
{
	void *stats_base = (void *)q_stats;
	unsigned int start;
	size_t offset;
	int j;

	do {
		start = u64_stats_fetch_begin(&q_stats->sync);
		for (j = 0; j < IFB_Q_STATS_LEN; j++) {
			offset = ifb_q_stats_desc[j].offset;
			(*data)[j] = *(u64 *)(stats_base + offset);
		}
	} while (u64_stats_fetch_retry(&q_stats->sync, start));

	*data += IFB_Q_STATS_LEN;
}

void klpp_ifb_get_ethtool_stats(struct net_device *dev, struct ethtool_stats *stats, u64 *data)
{
	struct ifb_dev_private *dp = netdev_priv(dev);
	struct ifb_q_private *txp;
	int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		txp = dp->tx_private + i;
		ifb_fill_stats_data(&data, &txp->rx_stats);
	}

	for (i = 0; i < dev->num_tx_queues; i++) {
		txp = dp->tx_private + i;
		ifb_fill_stats_data(&data, &txp->tx_stats);
	}
}


#include <linux/livepatch.h>

extern typeof(ifb_q_stats_desc) ifb_q_stats_desc
	 KLP_RELOC_SYMBOL(ifb, ifb, ifb_q_stats_desc);
