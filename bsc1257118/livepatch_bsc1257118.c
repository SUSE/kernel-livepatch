/*
 * livepatch_bsc1257118
 *
 * Fix for CVE-2025-21738, bsc#1257118
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_ATA)

#if !IS_MODULE(CONFIG_ATA)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1257118.h"

/* klp-ccp: from drivers/ata/libata-sff.c */
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/libata.h>
#include <linux/highmem.h>

void klpp_ata_pio_sector(struct ata_queued_cmd *qc)
{
	int do_write = (qc->tf.flags & ATA_TFLAG_WRITE);
	struct ata_port *ap = qc->ap;
	struct page *page;
	unsigned int offset, count;
	unsigned char *buf;

	if (!qc->cursg) {
		qc->curbytes = qc->nbytes;
		return;
	}
	if (qc->curbytes == qc->nbytes - qc->sect_size)
		ap->hsm_task_state = HSM_ST_LAST;

	page = sg_page(qc->cursg);
	offset = qc->cursg->offset + qc->cursg_ofs;

	/* get the current page and offset */
	page = nth_page(page, (offset >> PAGE_SHIFT));
	offset %= PAGE_SIZE;

	/* don't overrun current sg */
	count = min(qc->cursg->length - qc->cursg_ofs, qc->sect_size);

	DPRINTK("data %s\n", qc->tf.flags & ATA_TFLAG_WRITE ? "write" : "read");

	if (PageHighMem(page)) {
		unsigned long flags;

		/* FIXME: use a bounce buffer */
		local_irq_save(flags);
		buf = kmap_atomic(page);

		/* do the actual data transfer */
		ap->ops->sff_data_xfer(qc, buf + offset, count,
				       do_write);

		kunmap_atomic(buf);
		local_irq_restore(flags);
	} else {
		buf = page_address(page);
		ap->ops->sff_data_xfer(qc, buf + offset, count,
				       do_write);
	}

	if (!do_write && !PageSlab(page))
		flush_dcache_page(page);

	qc->curbytes += count;
	qc->cursg_ofs += count;

	if (qc->cursg_ofs == qc->cursg->length) {
		qc->cursg = sg_next(qc->cursg);
		if (!qc->cursg)
			ap->hsm_task_state = HSM_ST_LAST;
		qc->cursg_ofs = 0;
	}
}

#endif /* IS_ENABLED(CONFIG_ATA) */
