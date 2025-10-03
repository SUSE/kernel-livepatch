/*
 * livepatch_bsc1249458
 *
 * Fix for CVE-2025-38110, bsc#1249458
 *
 *  Copyright (c) 2025 SUSE
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



#include <linux/delay.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>

/* klp-ccp: from include/linux/gpio/consumer.h */
#define __LINUX_GPIO_CONSUMER_H

/* klp-ccp: from drivers/net/phy/mdio_bus.c */
#include <linux/gpio/consumer.h>
#include <linux/init.h>
#include <linux/interrupt.h>

/* klp-ccp: from include/linux/io.h */
#define _LINUX_IO_H

/* klp-ccp: from drivers/net/phy/mdio_bus.c */
#include <linux/kernel.h>
#include <linux/micrel_phy.h>
#include <linux/mii.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>

/* klp-ccp: from include/linux/mod_devicetable.h */
#define LINUX_MOD_DEVICETABLE_H

#define MDIO_NAME_SIZE		32

/* klp-ccp: from include/linux/of.h */
#define _LINUX_OF_H

/* klp-ccp: from drivers/net/phy/mdio_bus.c */
#include <linux/of_mdio.h>

/* klp-ccp: from drivers/net/phy/mdio_bus.c */
#include <linux/phy.h>

#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>

#define CREATE_TRACE_POINTS

/* klp-ccp: from include/trace/events/mdio.h */
#if !defined(_TRACE_MDIO_H) || defined(TRACE_HEADER_MULTI_READ)

#include "../klp_trace.h"

KLPR_TRACE_EVENT_CONDITION(libphy, mdio_access,
	TP_PROTO(struct mii_bus *bus, char read,
		 u8 addr, unsigned regnum, u16 val, int err),
	TP_ARGS(bus, read, addr, regnum, val, err),
	TP_CONDITION(err >= 0))

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* if !defined(_TRACE_MDIO_H) || defined(TRACE_HEADER_MULTI_READ) */

/* klp-ccp: from drivers/net/phy/mdio-boardinfo.h */
#include <linux/phy.h>
#include <linux/mutex.h>

/* klp-ccp: from drivers/net/phy/mdio_bus.c */
extern void mdiobus_stats_acct(struct mdio_bus_stats *stats, bool op, int ret);

int klpp___mdiobus_c45_read(struct mii_bus *bus, int addr, int devad, u32 regnum)
{
	int retval;

	lockdep_assert_held_once(&bus->mdio_lock);

	if (addr >= PHY_MAX_ADDR)
		return -ENXIO;

	if (bus->read_c45)
		retval = bus->read_c45(bus, addr, devad, regnum);
	else
		retval = -EOPNOTSUPP;

	klpr_trace_mdio_access(bus, 1, addr, regnum, retval, retval);
	mdiobus_stats_acct(&bus->stats[addr], true, retval);

	return retval;
}

typeof(klpp___mdiobus_c45_read) klpp___mdiobus_c45_read;

int klpp___mdiobus_c45_write(struct mii_bus *bus, int addr, int devad, u32 regnum,
			u16 val)
{
	int err;

	lockdep_assert_held_once(&bus->mdio_lock);

	if (addr >= PHY_MAX_ADDR)
		return -ENXIO;

	if (bus->write_c45)
		err = bus->write_c45(bus, addr, devad, regnum, val);
	else
		err = -EOPNOTSUPP;

	klpr_trace_mdio_access(bus, 0, addr, regnum, val, err);
	mdiobus_stats_acct(&bus->stats[addr], false, err);

	return err;
}

typeof(klpp___mdiobus_c45_write) klpp___mdiobus_c45_write;


#include "livepatch_bsc1249458.h"

#include <linux/livepatch.h>

extern typeof(mdiobus_stats_acct) mdiobus_stats_acct
	KLP_RELOC_SYMBOL(libphy, libphy, mdiobus_stats_acct);
