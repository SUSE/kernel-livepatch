/*
 * livepatch_bsc1219157
 *
 * Fix for bsc#1219157
 *
 *  Upstream commit:
 *  3c978492c333 ("scsi: mpt3sas: Fix loop logic")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  872bee1071cde748e559a54a65369554f024fee2
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

#if IS_ENABLED(CONFIG_SCSI_MPT3SAS)

#if !IS_MODULE(CONFIG_SCSI_MPT3SAS)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/scsi/mpt3sas/mpt3sas_base.c */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>

#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/time.h>
#include <linux/ktime.h>

#include <asm/page.h>        /* To get host page size per arch */

/* klp-ccp: from drivers/scsi/mpt3sas/mpt3sas_base.h */
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#include <linux/pci.h>

/* klp-ccp: from drivers/scsi/mpt3sas/mpt3sas_base.c */
u32
klpp__base_readl_ext_retry(const volatile void __iomem *addr)
{
	u32 i, ret_val;

	for (i = 0 ; i < 30 ; i++) {
		ret_val = readl(addr);
		if (ret_val != 0)
			break;
	}

	return ret_val;
}

#include "livepatch_bsc1219157.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "mpt3sas"

#endif /* IS_ENABLED(CONFIG_SCSI_MPT3SAS) */
