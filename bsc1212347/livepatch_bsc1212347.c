/*
 * livepatch_bsc1212347
 *
 * Fix for CVE-2023-3159, bsc#1212347
 *
 *  Upstream commit:
 *  b7c81f80246f ("firewire: fix potential uaf in outbound_phy_packet_callback()")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  f62d406b51c73c455fcaa1dac7918fd6950176ef
 *
 *  SLE15-SP2 and -SP3 commit:
 *  444321df3f2d3f3ed7fa2697c6f3176677f7a5e1
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
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

#if IS_ENABLED(CONFIG_FIREWIRE)

#if !IS_MODULE(CONFIG_FIREWIRE)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/firewire/core-cdev.c */
#include <linux/bug.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/errno.h>
#include <linux/firewire.h>
#include <linux/firewire-cdev.h>
#include <linux/idr.h>
#include <linux/irqflags.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched.h> /* required for linux/wait.h */
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
/* klp-ccp: from drivers/firewire/core.h */
#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/idr.h>
#include <linux/mm_types.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/refcount.h>

/* klp-ccp: from drivers/firewire/core-cdev.c */
struct client;

static void (*klpe_client_put)(struct client *client);

struct event {
	struct { void *data; size_t size; } v[2];
	struct list_head link;
};

struct outbound_phy_packet_event {
	struct event event;
	struct client *client;
	struct fw_packet p;
	struct fw_cdev_event_phy_packet phy_packet;
};

static void (*klpe_queue_event)(struct client *client, struct event *event,
			void *data0, size_t size0, void *data1, size_t size1);

void klpp_outbound_phy_packet_callback(struct fw_packet *packet,
					 struct fw_card *card, int status)
{
	struct outbound_phy_packet_event *e =
		container_of(packet, struct outbound_phy_packet_event, p);
	struct client *e_client;

	switch (status) {
	/* expected: */
	case ACK_COMPLETE:	e->phy_packet.rcode = RCODE_COMPLETE;	break;
	/* should never happen with PHY packets: */
	case ACK_PENDING:	e->phy_packet.rcode = RCODE_COMPLETE;	break;
	case ACK_BUSY_X:
	case ACK_BUSY_A:
	case ACK_BUSY_B:	e->phy_packet.rcode = RCODE_BUSY;	break;
	case ACK_DATA_ERROR:	e->phy_packet.rcode = RCODE_DATA_ERROR;	break;
	case ACK_TYPE_ERROR:	e->phy_packet.rcode = RCODE_TYPE_ERROR;	break;
	/* stale generation; cancelled; on certain controllers: no ack */
	default:		e->phy_packet.rcode = status;		break;
	}
	e->phy_packet.data[0] = packet->timestamp;

	e_client = e->client;
	(*klpe_queue_event)(e->client, &e->event, &e->phy_packet,
		    sizeof(e->phy_packet) + e->phy_packet.length, NULL, 0);
	(*klpe_client_put)(e_client);
}



#include "livepatch_bsc1212347.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "firewire_core"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "client_put", (void *)&klpe_client_put, "firewire_core" },
	{ "queue_event", (void *)&klpe_queue_event, "firewire_core" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1212347_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1212347_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_FIREWIRE) */
