/*
 * livepatch_bsc1200057
 *
 * Fix for CVE-2022-1652, bsc#1200057
 *
 *  Upstream commit:
 *  f71f01394f74 ("floppy: use a statically allocated error counter")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  717327786077a867754df481dc211cec0bfe6cc9
 *
 *  SLE15-SP2 and -SP3 commit:
 *  3cde83e2894c469087dfdd4a122f7fc2b8fd09a3
 *
 *  SLE15-SP4 commit:
 *  4b74f1a06d70f63e70a2d3880cd2909eaf0d4b26
 *
 *  Copyright (c) 2022 SUSE
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

#if IS_ENABLED(CONFIG_BLK_DEV_FD)

#if !IS_MODULE(CONFIG_BLK_DEV_FD)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/block/floppy.c */
#define KLPR_DPRINT(format, args...) \
	pr_info("floppy%d: " format, (*klpe_current_drive), ##args)

#define DCL_DEBUG		/* debug disk change line */
#ifdef DCL_DEBUG
#define KLPR_debug_dcl(test, fmt, args...) \
	do { if ((test) & FD_DEBUG) KLPR_DPRINT(fmt, ##args); } while (0)
#else
#define KLPR_debug_dcl(test, fmt, args...) \
	do { if (0) KLPR_DPRINT(fmt, ##args); } while (0)
#endif

#define KLPR_DP		(&(*klpe_drive_params)[(*klpe_current_drive)])
#define KLPR_DRS	(&(*klpe_drive_state)[(*klpe_current_drive)])
#define KLPR_DRWE	(&(*klpe_write_errors)[(*klpe_current_drive)])
#define KLPR_FDCS	(&(*klpe_fdc_state)[(*klpe_fdc)])

#define KLPR_UDP	(&(*klpe_drive_params)[drive])
#define KLPR_UDRS	(&(*klpe_drive_state)[drive])
#define KLPR_UDRWE	(&(*klpe_write_errors)[drive])
#define KLPR_UFDCS	(&(*klpe_fdc_state)[drive])

#define KLPR_ST0	((*klpe_reply_buffer)[0])
#define KLPR_ST1	((*klpe_reply_buffer)[1])
#define KLPR_ST2	((*klpe_reply_buffer)[2])

#define KLPR_PH_HEAD(floppy, head) (((((floppy)->stretch & 2) >> 1) ^ head) << 2)

/* read/write */
#define KLPR_COMMAND		((*klpe_raw_cmd)->cmd[0])
#define KLPR_DR_SELECT		((*klpe_raw_cmd)->cmd[1])
#define KLPR_TRACK		((*klpe_raw_cmd)->cmd[2])
#define KLPR_HEAD		((*klpe_raw_cmd)->cmd[3])
#define KLPR_SECTOR		((*klpe_raw_cmd)->cmd[4])
#define KLPR_SIZECODE		((*klpe_raw_cmd)->cmd[5])
#define KLPR_SECT_PER_TRACK	((*klpe_raw_cmd)->cmd[6])
#define KLPR_GAP		((*klpe_raw_cmd)->cmd[7])
#define KLPR_SIZECODE2		((*klpe_raw_cmd)->cmd[8])
#define KLPR_NR_RW 9

#define KLPR_CT(x) ((x) | 0xc0)

#define KLPR_INFBOUND(a, b) (a) = max_t(int, a, b)

#if defined (CONFIG_X86_64)
/* klp-ccp: from arch/x86/include/asm/floppy.h */
#define klpr_fd_outb(value, port)      outb_p(value, port)
#elif defined (CONFIG_PPC64)
/* klp-ccp: from arch/powerpc/include/asm/floppy.h */
#define klpr_fd_outb(value, port)      outb_p(value, port)
#else
#error "Architecture support not implemented."
#endif

/* klp-ccp: from drivers/block/floppy.c */
#define REALLY_SLOW_IO

#define DEBUGT 2

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#define FDPATCHES
#include <linux/fdreg.h>
#include <linux/fd.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/fcntl.h>

/* klp-ccp: from include/linux/uapi/fdreg.h */
#undef FD_IOPORT
#undef FD_DOR

/* klp-ccp: form include/linux/uapi/fdreg.h */
#define KLPR_FD_IOPORT KLPR_FDCS->address
#define KLPR_FD_DOR  (2 + KLPR_FD_IOPORT )

/* klp-ccp: from drivers/block/floppy.c */
#include <linux/mc146818rtc.h>	/* CMOS defines */
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/init.h>

/* klp-ccp: from drivers/block/floppy.c */
#include <linux/mod_devicetable.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/compat.h>

#include <asm/dma.h>

/* klp-ccp: from drivers/block/floppy.c */
#include <asm/irq.h>

static int (*klpe_can_use_virtual_dma);

static int (*klpe_use_virtual_dma);

static spinlock_t (*klpe_floppy_lock);

#define K_64	0x10000		/* 64KB */

#if defined (CONFIG_X86_64)
/* klp-ccp: from arch/x86/include/asm/floppy.h */
#define FLOPPY_CAN_FALLBACK_ON_NODMA

static unsigned long vdma_mem_alloc(unsigned long size)
{
	return (unsigned long)vmalloc(size);
}

#define nodma_mem_alloc(size) vdma_mem_alloc(size)

static struct fd_routine_l {
	int (*_request_dma)(unsigned int dmanr, const char *device_id);
	void (*_free_dma)(unsigned int dmanr);
	int (*_get_dma_residue)(unsigned int dummy);
	unsigned long (*_dma_mem_alloc)(unsigned long size);
	int (*_dma_setup)(char *addr, unsigned long size, int mode, int io);
} (*klpe_fd_routine)[];

#define KLPR_SW (*klpe_fd_routine)[(*klpe_use_virtual_dma) & 1]
#define klpr_fd_dma_mem_alloc(size) KLPR_SW._dma_mem_alloc(ptr->length);

#define _CROSS_64KB(a, s, vdma)                        \
   (!(vdma) &&                         \
    ((unsigned long)(a)/K_64 != ((unsigned long)(a) + (s) - 1) / K_64))

#define KLPR_CROSS_64KB(a, s) _CROSS_64KB(a, s, (*klpe_use_virtual_dma) & 1)

#elif defined (CONFIG_PPC64)
/* klp-ccp: from arch/powerpc/include/asm/floppy.h */
#define KLPR_CROSS_64KB(a,s)   (0)

#else
#error "Architecture support not implemented."
#endif

/* klp-ccp: from drivers/block/floppy.c */
#ifndef klpr_fd_dma_mem_alloc
#define klpr_fd_dma_mem_alloc(size) __get_dma_pages(GFP_KERNEL, get_order(size))
#endif

#define N_FDC 2
#define N_DRIVE 8

/* klp-ccp: from drivers/block/floppy.c */
#include <linux/blkdev.h>

/* klp-ccp: from include/uapi/linux/cdrom.h */
#define CDROMEJECT		0x5309 /* Ejects the cdrom media */

/* klp-ccp: from drivers/block/floppy.c */
#include <linux/completion.h>

static struct request *(*klpe_current_req);

static inline void klpr_fallback_on_nodma_alloc(char **addr, size_t l)
{
#ifdef FLOPPY_CAN_FALLBACK_ON_NODMA
	if (*addr)
		return;		/* we have the memory */
	if ((*klpe_can_use_virtual_dma) != 2)
		return;		/* no fallback allowed */
	pr_info("DMA memory shortage. Temporarily falling back on virtual DMA\n");
	*addr = (char *)nodma_mem_alloc(l);
#else
	return;
#endif
}

static unsigned long (*klpe_fake_change);

#define ITYPE(x)  (((x) >> 2) & 0x1f)

#define UNIT(x)		((x) & 0x03)		/* drive on fdc */
#define FDC(x)		(((x) & 0x04) >> 2)	/* fdc of drive */

#define STRETCH(floppy)	((floppy)->stretch & FD_STRETCH)

#define NR_RW 9

#define MAX_DISK_SIZE 4		/* 3984 */

#define MAX_REPLIES 16
static unsigned char (*klpe_reply_buffer)[MAX_REPLIES];
static int (*klpe_inr);

static struct floppy_drive_params (*klpe_drive_params)[N_DRIVE];
static struct floppy_drive_struct (*klpe_drive_state)[N_DRIVE];
static struct floppy_write_errors (*klpe_write_errors)[N_DRIVE];

static struct gendisk *(*klpe_disks)[N_DRIVE];

static struct floppy_raw_cmd *(*klpe_raw_cmd);
static struct floppy_raw_cmd (*klpe_default_raw_cmd);
static int (*klpe_fdc_queue);

static struct floppy_struct (*klpe_floppy_type)[32];

static struct floppy_struct *(*klpe_current_type)[N_DRIVE];

static sector_t (*klpe_floppy_sizes)[256];

static int (*klpe_probing);

#define FD_COMMAND_NONE		-1

static volatile int (*klpe_command_status);
static unsigned long (*klpe_fdc_busy);
static struct wait_queue_head (*klpe_fdc_wait);

static int (*klpe_format_errors);
static int klpp_floppy_errors;

static struct format_descr (*klpe_format_req);

static char *(*klpe_floppy_track_buffer);
static int (*klpe_max_buffer_sectors);

static int *(*klpe_errors);
typedef void (*done_f)(int);
static const struct cont_t {
	void (*interrupt)(void);
				/* this is called after the interrupt of the
				 * main command */
	void (*redo)(void);	/* this is called to retry the operation */
	void (*error)(void);	/* this is called to tally an error */
	done_f done;		/* this is called to say if the operation has
				 * succeeded/failed */
} *(*klpe_cont);

static void (*klpe_floppy_start)(void);
static void klpr_process_fd_request(void);

#define NO_TRACK	-1

#define NEED_2_RECAL	-3

static int (*klpe_buffer_track);
static int (*klpe_buffer_drive);
static int (*klpe_buffer_min);
static int (*klpe_buffer_max);

static struct floppy_fdc_state (*klpe_fdc_state)[N_FDC];
static int (*klpe_fdc);

static struct floppy_struct *(*klpe__floppy);
static unsigned char (*klpe_current_drive);
static long (*klpe_current_count_sectors);
static unsigned char (*klpe_fsector_t);
static unsigned char (*klpe_in_sector_offset);

#ifndef fd_eject
static inline int fd_eject(int drive)
{
	return -EINVAL;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef DEBUGT
static long unsigned (*klpe_debugtimer);

static inline void klpr_debugt(const char *func, const char *msg)
{
	if (KLPR_DP->flags & DEBUGT)
		pr_info("%s:%s dtime=%lu\n", func, msg, jiffies - (*klpe_debugtimer));
}
#else
#error "klp-ccp: non-taken branch"
#endif /* DEBUGT */

static struct delayed_work (*klpe_fd_timeout);

static void (*(*klpe_do_floppy))(void);

static unsigned long (*klpe_lastredo);

#define current_reqD -1

static void (*klpe_reschedule_timeout)(int drive, const char *message);

#define SUPBOUND(a, b) (a) = min_t(int, a, b)

static int (*klpe_disk_change)(int drive);

static void klpr_twaddle(void)
{
	if (KLPR_DP->select_delay)
		return;
	klpr_fd_outb(KLPR_FDCS->dor & ~(0x10 << UNIT((*klpe_current_drive))), KLPR_FD_DOR);
	klpr_fd_outb(KLPR_FDCS->dor, KLPR_FD_DOR);
	KLPR_DRS->select_date = jiffies;
}

static void (*klpe_set_fdc)(int drive);

static int (*klpe_lock_fdc)(int drive);

static void klpr_unlock_fdc(void)
{
	if (!test_bit(0, &(*klpe_fdc_busy)))
		KLPR_DPRINT("FDC access conflict!\n");

	(*klpe_raw_cmd) = NULL;
	(*klpe_command_status) = FD_COMMAND_NONE;
	cancel_delayed_work(&(*klpe_fd_timeout));
	(*klpe_do_floppy) = NULL;
	(*klpe_cont) = NULL;
	clear_bit(0, &(*klpe_fdc_busy));
	wake_up(&(*klpe_fdc_wait));
}

static void (*klpe_floppy_off)(unsigned int drive);

static void (*klpe_schedule_bh)(void (*handler)(void));

static void (*klpe_tell_sector)(void);

static void klpr_print_errors(void)
{
	KLPR_DPRINT("");
	if (KLPR_ST0 & ST0_ECE) {
		pr_cont("Recalibrate failed!");
	} else if (KLPR_ST2 & ST2_CRC) {
		pr_cont("data CRC error");
		(*klpe_tell_sector)();
	} else if (KLPR_ST1 & ST1_CRC) {
		pr_cont("CRC error");
		(*klpe_tell_sector)();
	} else if ((KLPR_ST1 & (ST1_MAM | ST1_ND)) ||
		   (KLPR_ST2 & ST2_MAM)) {
		if (!(*klpe_probing)) {
			pr_cont("sector not found");
			(*klpe_tell_sector)();
		} else
			pr_cont("probe failed...");
	} else if (KLPR_ST2 & ST2_WC) {	/* seek error */
		pr_cont("wrong cylinder");
	} else if (KLPR_ST2 & ST2_BC) {	/* cylinder marked as bad */
		pr_cont("bad cylinder");
	} else {
		KLPR_DPRINT("unknown error. ST[0..2] are: 0x%x 0x%x 0x%x",
				KLPR_ST0, KLPR_ST1, KLPR_ST2);
		(*klpe_tell_sector)();
	}
	pr_cont("\n");
}

int klpp_interpret_errors(void)
{
	char bad;

	if ((*klpe_inr) != 7) {
		KLPR_DPRINT("-- FDC reply error\n");
		KLPR_FDCS->reset = 1;
		return 1;
	}

	/* check IC to find cause of interrupt */
	switch (KLPR_ST0 & ST0_INTR) {
	case 0x40:		/* error occurred during command execution */
		if (KLPR_ST1 & ST1_EOC)
			return 0;	/* occurs with pseudo-DMA */
		bad = 1;
		if (KLPR_ST1 & ST1_WP) {
			KLPR_DPRINT("Drive is write protected\n");
			clear_bit(FD_DISK_WRITABLE_BIT, &KLPR_DRS->flags);
			(*klpe_cont)->done(0);
			bad = 2;
		} else if (KLPR_ST1 & ST1_ND) {
			set_bit(FD_NEED_TWADDLE_BIT, &KLPR_DRS->flags);
		} else if (KLPR_ST1 & ST1_OR) {
			if (KLPR_DP->flags & FTD_MSG)
				KLPR_DPRINT("Over/Underrun - retrying\n");
			bad = 0;
		} else if (klpp_floppy_errors >= KLPR_DP->max_errors.reporting) {
			klpr_print_errors();
		}
		if (KLPR_ST2 & ST2_WC || KLPR_ST2 & ST2_BC)
			/* wrong cylinder => recal */
			KLPR_DRS->track = NEED_2_RECAL;
		return bad;
	case 0x80:		/* invalid command given */
		KLPR_DPRINT("Invalid FDC command given!\n");
		(*klpe_cont)->done(0);
		return 2;
	case 0xc0:
		KLPR_DPRINT("Abnormal termination caused by polling\n");
		(*klpe_cont)->error();
		return 2;
	default:		/* (0) Normal command termination */
		return 0;
	}
}

static int (*klpe_start_motor)(void (*function)(void));

static void (*klpe_floppy_start)(void);

static int (*klpe_wait_til_done)(void (*handler)(void), bool interruptible);

static int klpr_next_valid_format(void)
{
	int probed_format;

	probed_format = KLPR_DRS->probed_format;
	while (1) {
		if (probed_format >= 8 || !KLPR_DP->autodetect[probed_format]) {
			KLPR_DRS->probed_format = 0;
			return 1;
		}
		if ((*klpe_floppy_type)[KLPR_DP->autodetect[probed_format]].sect) {
			KLPR_DRS->probed_format = probed_format;
			return 0;
		}
		probed_format++;
	}
}

void klpp_bad_flp_intr(void)
{
	int err_count;

	if ((*klpe_probing)) {
		KLPR_DRS->probed_format++;
		if (!klpr_next_valid_format())
			return;
	}
	err_count = ++klpp_floppy_errors;
	KLPR_INFBOUND(KLPR_DRWE->badness, err_count);
	if (err_count > KLPR_DP->max_errors.abort)
		(*klpe_cont)->done(0);
	if (err_count > KLPR_DP->max_errors.reset)
		KLPR_FDCS->reset = 1;
	else if (err_count > KLPR_DP->max_errors.recal)
		KLPR_DRS->track = NEED_2_RECAL;
}

static void klpr_set_floppy(int drive)
{
	int type = ITYPE(KLPR_UDRS->fd_device);

	if (type)
		(*klpe__floppy) = (*klpe_floppy_type) + type;
	else
		(*klpe__floppy) = (*klpe_current_type)[drive];
}

#define FM_MODE(x, y) ((y) & ~(((x)->rate & 0x80) >> 1))

static void (*klpe_redo_format)(void);

static const struct cont_t (*klpe_format_cont);

static int klpp_do_format(int drive, struct format_descr *tmp_format_req)
{
	int ret;

	if ((*klpe_lock_fdc)(drive))
		return -EINTR;

	klpr_set_floppy(drive);
	if (!(*klpe__floppy) ||
	    (*klpe__floppy)->track > KLPR_DP->tracks ||
	    tmp_format_req->track >= (*klpe__floppy)->track ||
	    tmp_format_req->head >= (*klpe__floppy)->head ||
	    ((*klpe__floppy)->sect << 2) % (1 << FD_SIZECODE((*klpe__floppy))) ||
	    !(*klpe__floppy)->fmt_gap) {
		klpr_process_fd_request();
		return -EINVAL;
	}
	(*klpe_format_req) = *tmp_format_req;
	(*klpe_cont) = &(*klpe_format_cont);
	klpp_floppy_errors = 0;
	(*klpe_errors) = &(*klpe_format_errors);
	ret = (*klpe_wait_til_done)((*klpe_redo_format), true);
	if (ret == -EINTR)
		return -EINTR;
	klpr_process_fd_request();
	return ret;
}

static void (*klpe_request_done)(int uptodate);

static int klpr_buffer_chain_size(void)
{
	struct bio_vec bv;
	int size;
	struct req_iterator iter;
	char *base;

	base = bio_data((*klpe_current_req)->bio);
	size = 0;

	rq_for_each_segment(bv, (*klpe_current_req), iter) {
		if (page_address(bv.bv_page) + bv.bv_offset != base + size)
			break;

		size += bv.bv_len;
	}

	return size >> 9;
}

static int klpr_transfer_size(int ssize, int max_sector, int max_size)
{
	SUPBOUND(max_sector, (*klpe_fsector_t) + max_size);

	/* alignment */
	max_sector -= (max_sector % (*klpe__floppy)->sect) % ssize;

	/* transfer size, beginning not aligned */
	(*klpe_current_count_sectors) = max_sector - (*klpe_fsector_t);

	return max_sector;
}

static void (*klpe_copy_buffer)(int ssize, int max_sector, int max_sector_2);

static void (*klpe_virtualdmabug_workaround)(void);

static int klpp_make_raw_rw_request(void)
{
	int aligned_sector_t;
	int max_sector;
	int max_size;
	int tracksize;
	int ssize;

	if (WARN((*klpe_max_buffer_sectors) == 0, "VFS: Block I/O scheduled on unopened device\n"))
		return 0;

	(*klpe_set_fdc)((long)(*klpe_current_req)->rq_disk->private_data);

	(*klpe_raw_cmd) = &(*klpe_default_raw_cmd);
	(*klpe_raw_cmd)->flags = FD_RAW_SPIN | FD_RAW_NEED_DISK | FD_RAW_NEED_SEEK;
	(*klpe_raw_cmd)->cmd_count = NR_RW;
	if (rq_data_dir((*klpe_current_req)) == READ) {
		(*klpe_raw_cmd)->flags |= FD_RAW_READ;
		KLPR_COMMAND = FM_MODE((*klpe__floppy), FD_READ);
	} else if (rq_data_dir((*klpe_current_req)) == WRITE) {
		(*klpe_raw_cmd)->flags |= FD_RAW_WRITE;
		KLPR_COMMAND = FM_MODE((*klpe__floppy), FD_WRITE);
	} else {
		KLPR_DPRINT("%s: unknown command\n", __func__);
		return 0;
	}

	max_sector = (*klpe__floppy)->sect * (*klpe__floppy)->head;

	KLPR_TRACK = (int)blk_rq_pos((*klpe_current_req)) / max_sector;
	(*klpe_fsector_t) = (int)blk_rq_pos((*klpe_current_req)) % max_sector;
	if ((*klpe__floppy)->track && KLPR_TRACK >= (*klpe__floppy)->track) {
		if (blk_rq_cur_sectors((*klpe_current_req)) & 1) {
			(*klpe_current_count_sectors) = 1;
			return 1;
		} else
			return 0;
	}
	KLPR_HEAD = (*klpe_fsector_t) / (*klpe__floppy)->sect;

	if ((((*klpe__floppy)->stretch & (FD_SWAPSIDES | FD_SECTBASEMASK)) ||
	     test_bit(FD_NEED_TWADDLE_BIT, &KLPR_DRS->flags)) &&
	    (*klpe_fsector_t) < (*klpe__floppy)->sect)
		max_sector = (*klpe__floppy)->sect;

	/* 2M disks have phantom sectors on the first track */
	if (((*klpe__floppy)->rate & FD_2M) && (!KLPR_TRACK) && (!KLPR_HEAD)) {
		max_sector = 2 * (*klpe__floppy)->sect / 3;
		if ((*klpe_fsector_t) >= max_sector) {
			(*klpe_current_count_sectors) =
			    min_t(int, (*klpe__floppy)->sect - (*klpe_fsector_t),
				  blk_rq_sectors((*klpe_current_req)));
			return 1;
		}
		KLPR_SIZECODE = 2;
	} else
		KLPR_SIZECODE = FD_SIZECODE((*klpe__floppy));
	(*klpe_raw_cmd)->rate = (*klpe__floppy)->rate & 0x43;
	if (((*klpe__floppy)->rate & FD_2M) && (KLPR_TRACK || KLPR_HEAD) && (*klpe_raw_cmd)->rate == 2)
		(*klpe_raw_cmd)->rate = 1;

	if (KLPR_SIZECODE)
		KLPR_SIZECODE2 = 0xff;
	else
		KLPR_SIZECODE2 = 0x80;
	(*klpe_raw_cmd)->track = KLPR_TRACK << STRETCH((*klpe__floppy));
	KLPR_DR_SELECT = UNIT((*klpe_current_drive)) + KLPR_PH_HEAD((*klpe__floppy), KLPR_HEAD);
	KLPR_GAP = (*klpe__floppy)->gap;
	ssize = DIV_ROUND_UP(1 << KLPR_SIZECODE, 4);
	KLPR_SECT_PER_TRACK = (*klpe__floppy)->sect << 2 >> KLPR_SIZECODE;
	KLPR_SECTOR = (((*klpe_fsector_t) % (*klpe__floppy)->sect) << 2 >> KLPR_SIZECODE) +
	    FD_SECTBASE((*klpe__floppy));

	/* tracksize describes the size which can be filled up with sectors
	 * of size ssize.
	 */
	tracksize = (*klpe__floppy)->sect - (*klpe__floppy)->sect % ssize;
	if (tracksize < (*klpe__floppy)->sect) {
		KLPR_SECT_PER_TRACK++;
		if (tracksize <= (*klpe_fsector_t) % (*klpe__floppy)->sect)
			KLPR_SECTOR--;

		/* if we are beyond tracksize, fill up using smaller sectors */
		while (tracksize <= (*klpe_fsector_t) % (*klpe__floppy)->sect) {
			while (tracksize + ssize > (*klpe__floppy)->sect) {
				KLPR_SIZECODE--;
				ssize >>= 1;
			}
			KLPR_SECTOR++;
			KLPR_SECT_PER_TRACK++;
			tracksize += ssize;
		}
		max_sector = KLPR_HEAD * (*klpe__floppy)->sect + tracksize;
	} else if (!KLPR_TRACK && !KLPR_HEAD && !((*klpe__floppy)->rate & FD_2M) && (*klpe_probing)) {
		max_sector = (*klpe__floppy)->sect;
	} else if (!KLPR_HEAD && KLPR_CT(KLPR_COMMAND) == FD_WRITE) {
		/* for virtual DMA bug workaround */
		max_sector = (*klpe__floppy)->sect;
	}

	(*klpe_in_sector_offset) = ((*klpe_fsector_t) % (*klpe__floppy)->sect) % ssize;
	aligned_sector_t = (*klpe_fsector_t) - (*klpe_in_sector_offset);
	max_size = blk_rq_sectors((*klpe_current_req));
	if (((*klpe_raw_cmd)->track == (*klpe_buffer_track)) &&
	    ((*klpe_current_drive) == (*klpe_buffer_drive)) &&
	    ((*klpe_fsector_t) >= (*klpe_buffer_min)) && ((*klpe_fsector_t) < (*klpe_buffer_max))) {
		/* data already in track buffer */
		if (KLPR_CT(KLPR_COMMAND) == FD_READ) {
			(*klpe_copy_buffer)(1, max_sector, (*klpe_buffer_max));
			return 1;
		}
	} else if ((*klpe_in_sector_offset) || blk_rq_sectors((*klpe_current_req)) < ssize) {
		if (KLPR_CT(KLPR_COMMAND) == FD_WRITE) {
			unsigned int sectors;

			sectors = (*klpe_fsector_t) + blk_rq_sectors((*klpe_current_req));
			if (sectors > ssize && sectors < ssize + ssize)
				max_size = ssize + ssize;
			else
				max_size = ssize;
		}
		(*klpe_raw_cmd)->flags &= ~FD_RAW_WRITE;
		(*klpe_raw_cmd)->flags |= FD_RAW_READ;
		KLPR_COMMAND = FM_MODE((*klpe__floppy), FD_READ);
	} else if ((unsigned long)bio_data((*klpe_current_req)->bio) < MAX_DMA_ADDRESS) {
		unsigned long dma_limit;
		int direct, indirect;

		indirect =
		    klpr_transfer_size(ssize, max_sector,
				  (*klpe_max_buffer_sectors) * 2) - (*klpe_fsector_t);

		/*
		 * Do NOT use minimum() here---MAX_DMA_ADDRESS is 64 bits wide
		 * on a 64 bit machine!
		 */
		max_size = klpr_buffer_chain_size();
		dma_limit = (MAX_DMA_ADDRESS -
			     ((unsigned long)bio_data((*klpe_current_req)->bio))) >> 9;
		if ((unsigned long)max_size > dma_limit)
			max_size = dma_limit;
		/* 64 kb boundaries */
		if (KLPR_CROSS_64KB(bio_data((*klpe_current_req)->bio), max_size << 9))
			max_size = (K_64 -
				    ((unsigned long)bio_data((*klpe_current_req)->bio)) %
				    K_64) >> 9;
		direct = klpr_transfer_size(ssize, max_sector, max_size) - (*klpe_fsector_t);
		/*
		 * We try to read tracks, but if we get too many errors, we
		 * go back to reading just one sector at a time.
		 *
		 * This means we should be able to read a sector even if there
		 * are other bad sectors on this track.
		 */
		if (!direct ||
		    (indirect * 2 > direct * 3 &&
		     klpp_floppy_errors < KLPR_DP->max_errors.read_track &&
		     ((!(*klpe_probing) ||
		       (KLPR_DP->read_track & (1 << KLPR_DRS->probed_format)))))) {
			max_size = blk_rq_sectors((*klpe_current_req));
		} else {
			(*klpe_raw_cmd)->kernel_data = bio_data((*klpe_current_req)->bio);
			(*klpe_raw_cmd)->length = (*klpe_current_count_sectors) << 9;
			if ((*klpe_raw_cmd)->length == 0) {
				KLPR_DPRINT("%s: zero dma transfer attempted\n", __func__);
				KLPR_DPRINT("indirect=%d direct=%d fsector_t=%d\n",
					indirect, direct, (*klpe_fsector_t));
				return 0;
			}
			(*klpe_virtualdmabug_workaround)();
			return 2;
		}
	}

	if (KLPR_CT(KLPR_COMMAND) == FD_READ)
		max_size = max_sector;	/* unbounded */

	/* claim buffer track if needed */
	if ((*klpe_buffer_track) != (*klpe_raw_cmd)->track ||	/* bad track */
	    (*klpe_buffer_drive) != (*klpe_current_drive) ||	/* bad drive */
	    (*klpe_fsector_t) > (*klpe_buffer_max) ||
	    (*klpe_fsector_t) < (*klpe_buffer_min) ||
	    ((KLPR_CT(KLPR_COMMAND) == FD_READ ||
	      (!(*klpe_in_sector_offset) && blk_rq_sectors((*klpe_current_req)) >= ssize)) &&
	     max_sector > 2 * (*klpe_max_buffer_sectors) + (*klpe_buffer_min) &&
	     max_size + (*klpe_fsector_t) > 2 * (*klpe_max_buffer_sectors) + (*klpe_buffer_min))) {
		/* not enough space */
		(*klpe_buffer_track) = -1;
		(*klpe_buffer_drive) = (*klpe_current_drive);
		(*klpe_buffer_max) = (*klpe_buffer_min) = aligned_sector_t;
	}
	(*klpe_raw_cmd)->kernel_data = (*klpe_floppy_track_buffer) +
		((aligned_sector_t - (*klpe_buffer_min)) << 9);

	if (KLPR_CT(KLPR_COMMAND) == FD_WRITE) {
		/* copy write buffer to track buffer.
		 * if we get here, we know that the write
		 * is either aligned or the data already in the buffer
		 * (buffer will be overwritten) */
		if ((*klpe_in_sector_offset) && (*klpe_buffer_track) == -1)
			KLPR_DPRINT("internal error offset !=0 on write\n");
		(*klpe_buffer_track) = (*klpe_raw_cmd)->track;
		(*klpe_buffer_drive) = (*klpe_current_drive);
		(*klpe_copy_buffer)(ssize, max_sector,
			    2 * (*klpe_max_buffer_sectors) + (*klpe_buffer_min));
	} else
		klpr_transfer_size(ssize, max_sector,
			      2 * (*klpe_max_buffer_sectors) + (*klpe_buffer_min) -
			      aligned_sector_t);

	/* round up current_count_sectors to get dma xfer size */
	(*klpe_raw_cmd)->length = (*klpe_in_sector_offset) + (*klpe_current_count_sectors);
	(*klpe_raw_cmd)->length = (((*klpe_raw_cmd)->length - 1) | (ssize - 1)) + 1;
	(*klpe_raw_cmd)->length <<= 9;
	if (((*klpe_raw_cmd)->length < (*klpe_current_count_sectors) << 9) ||
	    ((*klpe_raw_cmd)->kernel_data != bio_data((*klpe_current_req)->bio) &&
	     KLPR_CT(KLPR_COMMAND) == FD_WRITE &&
	     (aligned_sector_t + ((*klpe_raw_cmd)->length >> 9) > (*klpe_buffer_max) ||
	      aligned_sector_t < (*klpe_buffer_min))) ||
	    (*klpe_raw_cmd)->length % (128 << KLPR_SIZECODE) ||
	    (*klpe_raw_cmd)->length <= 0 || (*klpe_current_count_sectors) <= 0) {
		KLPR_DPRINT("fractionary current count b=%lx s=%lx\n",
			(*klpe_raw_cmd)->length, (*klpe_current_count_sectors));
		if ((*klpe_raw_cmd)->kernel_data != bio_data((*klpe_current_req)->bio))
			pr_info("addr=%d, length=%ld\n",
				(int)(((*klpe_raw_cmd)->kernel_data -
				       (*klpe_floppy_track_buffer)) >> 9),
				(*klpe_current_count_sectors));
		pr_info("st=%d ast=%d mse=%d msi=%d\n",
			(*klpe_fsector_t), aligned_sector_t, max_sector, max_size);
		pr_info("ssize=%x SIZECODE=%d\n",ssize, KLPR_SIZECODE);
		pr_info("command=%x SECTOR=%d HEAD=%d, TRACK=%d\n",
			KLPR_COMMAND, KLPR_SECTOR, KLPR_HEAD, KLPR_TRACK);
		pr_info("buffer drive=%d\n", (*klpe_buffer_drive));
		pr_info("buffer track=%d\n", (*klpe_buffer_track));
		pr_info("buffer_min=%d\n", (*klpe_buffer_min));
		pr_info("buffer_max=%d\n", (*klpe_buffer_max));
		return 0;
	}

	if ((*klpe_raw_cmd)->kernel_data != bio_data((*klpe_current_req)->bio)) {
		if ((*klpe_raw_cmd)->kernel_data < (*klpe_floppy_track_buffer) ||
		    (*klpe_current_count_sectors) < 0 ||
		    (*klpe_raw_cmd)->length < 0 ||
		    (*klpe_raw_cmd)->kernel_data + (*klpe_raw_cmd)->length >
		    (*klpe_floppy_track_buffer) + ((*klpe_max_buffer_sectors) << 10)) {
			KLPR_DPRINT("buffer overrun in schedule dma\n");
			pr_info("fsector_t=%d buffer_min=%d current_count=%ld\n",
				(*klpe_fsector_t), (*klpe_buffer_min), (*klpe_raw_cmd)->length >> 9);
			pr_info("current_count_sectors=%ld\n",
				(*klpe_current_count_sectors));
			if (KLPR_CT(KLPR_COMMAND) == FD_READ)
				pr_info("read\n");
			if (KLPR_CT(KLPR_COMMAND) == FD_WRITE)
				pr_info("write\n");
			return 0;
		}
	} else if ((*klpe_raw_cmd)->length > blk_rq_bytes((*klpe_current_req)) ||
		   (*klpe_current_count_sectors) > blk_rq_sectors((*klpe_current_req))) {
		KLPR_DPRINT("buffer overrun in direct transfer\n");
		return 0;
	} else if ((*klpe_raw_cmd)->length < (*klpe_current_count_sectors) << 9) {
		KLPR_DPRINT("more sectors than bytes\n");
		pr_info("bytes=%ld\n", (*klpe_raw_cmd)->length >> 9);
		pr_info("sectors=%ld\n", (*klpe_current_count_sectors));
	}
	if ((*klpe_raw_cmd)->length == 0) {
		KLPR_DPRINT("zero dma transfer attempted from make_raw_request\n");
		return 0;
	}

	(*klpe_virtualdmabug_workaround)();
	return 2;
}

static int klpp_set_next_request(void)
{
	struct request_queue *q;
	int old_pos = (*klpe_fdc_queue);

	do {
		q = (*klpe_disks)[(*klpe_fdc_queue)]->queue;
		if (++(*klpe_fdc_queue) == N_DRIVE)
			(*klpe_fdc_queue) = 0;
		if (q) {
			(*klpe_current_req) = blk_fetch_request(q);
			if ((*klpe_current_req)) {
				klpp_floppy_errors = 0;
				break;
			}
		}
	} while ((*klpe_fdc_queue) != old_pos);

	return (*klpe_current_req) != NULL;
}

void klpp_redo_fd_request(void)
{
	int drive;
	int tmp;

	(*klpe_lastredo) = jiffies;
	if ((*klpe_current_drive) < N_DRIVE)
		(*klpe_floppy_off)((*klpe_current_drive));

do_request:
	if (!(*klpe_current_req)) {
		int pending;

		spin_lock_irq(&(*klpe_floppy_lock));
		pending = klpp_set_next_request();
		spin_unlock_irq(&(*klpe_floppy_lock));
		if (!pending) {
			(*klpe_do_floppy) = NULL;
			klpr_unlock_fdc();
			return;
		}
	}
	drive = (long)(*klpe_current_req)->rq_disk->private_data;
	(*klpe_set_fdc)(drive);
	(*klpe_reschedule_timeout)(current_reqD, "redo fd request");

	klpr_set_floppy(drive);
	(*klpe_raw_cmd) = &(*klpe_default_raw_cmd);
	(*klpe_raw_cmd)->flags = 0;
	if ((*klpe_start_motor)(klpp_redo_fd_request))
		return;

	(*klpe_disk_change)((*klpe_current_drive));
	if (test_bit((*klpe_current_drive), &(*klpe_fake_change)) ||
	    test_bit(FD_DISK_CHANGED_BIT, &KLPR_DRS->flags)) {
		KLPR_DPRINT("disk absent or changed during operation\n");
		(*klpe_request_done)(0);
		goto do_request;
	}
	if (!(*klpe__floppy)) {	/* Autodetection */
		if (!(*klpe_probing)) {
			KLPR_DRS->probed_format = 0;
			if (klpr_next_valid_format()) {
				KLPR_DPRINT("no autodetectable formats\n");
				(*klpe__floppy) = NULL;
				(*klpe_request_done)(0);
				goto do_request;
			}
		}
		(*klpe_probing) = 1;
		(*klpe__floppy) = (*klpe_floppy_type) + KLPR_DP->autodetect[KLPR_DRS->probed_format];
	} else
		(*klpe_probing) = 0;
	(*klpe_errors) = &((*klpe_current_req)->error_count);
	tmp = klpp_make_raw_rw_request();
	if (tmp < 2) {
		(*klpe_request_done)(tmp);
		goto do_request;
	}

	if (test_bit(FD_NEED_TWADDLE_BIT, &KLPR_DRS->flags))
		klpr_twaddle();
	(*klpe_schedule_bh)((*klpe_floppy_start));
	klpr_debugt(__func__, "queue fd request");
	return;
}

static const struct cont_t (*klpe_rw_cont);

static void klpr_process_fd_request(void)
{
	(*klpe_cont) = &(*klpe_rw_cont);
	(*klpe_schedule_bh)(klpp_redo_fd_request);
}

static int (*klpe_poll_drive)(bool interruptible, int flag);

static int (*klpe_user_reset_fdc)(int drive, int arg, bool interruptible);

static inline int fd_copyout(void __user *param, const void *address,
			     unsigned long size)
{
	return copy_to_user(param, address, size) ? -EFAULT : 0;
}

static inline int fd_copyin(void __user *param, void *address,
			    unsigned long size)
{
	return copy_from_user(address, param, size) ? -EFAULT : 0;
}

static const char *klpr_drive_name(int type, int drive)
{
	struct floppy_struct *floppy;

	if (type)
		floppy = (*klpe_floppy_type) + type;
	else {
		if (KLPR_UDP->native_format)
			floppy = (*klpe_floppy_type) + KLPR_UDP->native_format;
		else
			return "(null)";
	}
	if (floppy->name)
		return floppy->name;
	else
		return "(null)";
}

static const struct cont_t (*klpe_raw_cmd_cont);

static int raw_cmd_copyout(int cmd, void __user *param,
				  struct floppy_raw_cmd *ptr)
{
	int ret;

	while (ptr) {
		struct floppy_raw_cmd cmd = *ptr;
		cmd.next = NULL;
		cmd.kernel_data = NULL;
		ret = copy_to_user(param, &cmd, sizeof(cmd));
		if (ret)
			return -EFAULT;
		param += sizeof(struct floppy_raw_cmd);
		if ((ptr->flags & FD_RAW_READ) && ptr->buffer_length) {
			if (ptr->length >= 0 &&
			    ptr->length <= ptr->buffer_length) {
				long length = ptr->buffer_length - ptr->length;
				ret = fd_copyout(ptr->data, ptr->kernel_data,
						 length);
				if (ret)
					return ret;
			}
		}
		ptr = ptr->next;
	}

	return 0;
}

static void (*klpe_raw_cmd_free)(struct floppy_raw_cmd **ptr);

static int klpr_raw_cmd_copyin(int cmd, void __user *param,
				 struct floppy_raw_cmd **rcmd)
{
	struct floppy_raw_cmd *ptr;
	int ret;
	int i;

	*rcmd = NULL;

loop:
	ptr = kmalloc(sizeof(struct floppy_raw_cmd), GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	*rcmd = ptr;
	ret = copy_from_user(ptr, param, sizeof(*ptr));
	ptr->next = NULL;
	ptr->buffer_length = 0;
	ptr->kernel_data = NULL;
	if (ret)
		return -EFAULT;
	param += sizeof(struct floppy_raw_cmd);
	if (ptr->cmd_count > 33)
			/* the command may now also take up the space
			 * initially intended for the reply & the
			 * reply count. Needed for long 82078 commands
			 * such as RESTORE, which takes ... 17 command
			 * bytes. Murphy's law #137: When you reserve
			 * 16 bytes for a structure, you'll one day
			 * discover that you really need 17...
			 */
		return -EINVAL;

	for (i = 0; i < 16; i++)
		ptr->reply[i] = 0;
	ptr->resultcode = 0;

	if (ptr->flags & (FD_RAW_READ | FD_RAW_WRITE)) {
		if (ptr->length <= 0)
			return -EINVAL;
		ptr->kernel_data = (char *)klpr_fd_dma_mem_alloc(ptr->length);
		klpr_fallback_on_nodma_alloc(&ptr->kernel_data, ptr->length);
		if (!ptr->kernel_data)
			return -ENOMEM;
		ptr->buffer_length = ptr->length;
	}
	if (ptr->flags & FD_RAW_WRITE) {
		ret = fd_copyin(ptr->data, ptr->kernel_data, ptr->length);
		if (ret)
			return ret;
	}

	if (ptr->flags & FD_RAW_MORE) {
		rcmd = &(ptr->next);
		ptr->rate &= 0x43;
		goto loop;
	}

	return 0;
}

static int klpr_raw_cmd_ioctl(int cmd, void __user *param)
{
	struct floppy_raw_cmd *my_raw_cmd;
	int drive;
	int ret2;
	int ret;

	if (KLPR_FDCS->rawcmd <= 1)
		KLPR_FDCS->rawcmd = 1;
	for (drive = 0; drive < N_DRIVE; drive++) {
		if (FDC(drive) != (*klpe_fdc))
			continue;
		if (drive == (*klpe_current_drive)) {
			if (KLPR_UDRS->fd_ref > 1) {
				KLPR_FDCS->rawcmd = 2;
				break;
			}
		} else if (KLPR_UDRS->fd_ref) {
			KLPR_FDCS->rawcmd = 2;
			break;
		}
	}

	if (KLPR_FDCS->reset)
		return -EIO;

	ret = klpr_raw_cmd_copyin(cmd, param, &my_raw_cmd);
	if (ret) {
		(*klpe_raw_cmd_free)(&my_raw_cmd);
		return ret;
	}

	(*klpe_raw_cmd) = my_raw_cmd;
	(*klpe_cont) = &(*klpe_raw_cmd_cont);
	ret = (*klpe_wait_til_done)((*klpe_floppy_start), true);
	KLPR_debug_dcl(KLPR_DP->flags, "calling disk change from raw_cmd ioctl\n");

	if (ret != -EINTR && KLPR_FDCS->reset)
		ret = -EIO;

	KLPR_DRS->track = NO_TRACK;

	ret2 = raw_cmd_copyout(cmd, param, my_raw_cmd);
	if (!ret)
		ret = ret2;
	(*klpe_raw_cmd_free)(&my_raw_cmd);
	return ret;
}

static int (*klpe_invalidate_drive)(struct block_device *bdev);

static int (*klpe_set_geometry)(unsigned int cmd, struct floppy_struct *g,
			       int drive, int type, struct block_device *bdev);

static unsigned int (*klpe_ioctl_table)[25];

static int klpr_normalize_ioctl(unsigned int *cmd, int *size)
{
	int i;

	for (i = 0; i < ARRAY_SIZE((*klpe_ioctl_table)); i++) {
		if ((*cmd & 0xffff) == ((*klpe_ioctl_table)[i] & 0xffff)) {
			*size = _IOC_SIZE(*cmd);
			*cmd = (*klpe_ioctl_table)[i];
			if (*size > _IOC_SIZE(*cmd)) {
				pr_info("ioctl not yet supported\n");
				return -EFAULT;
			}
			return 0;
		}
	}
	return -EINVAL;
}

static int (*klpe_get_floppy_geometry)(int drive, int type, struct floppy_struct **g);

static bool (*klpe_valid_floppy_drive_params)(const short autodetect[8],
		int native_format);

int klpp_fd_locked_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd,
		    unsigned long param)
{
	int drive = (long)bdev->bd_disk->private_data;
	int type = ITYPE(KLPR_UDRS->fd_device);
	int i;
	int ret;
	int size;
	union inparam {
		struct floppy_struct g;	/* geometry */
		struct format_descr f;
		struct floppy_max_errors max_errors;
		struct floppy_drive_params dp;
	} inparam;		/* parameters coming from user space */
	const void *outparam;	/* parameters passed back to user space */

	/* convert compatibility eject ioctls into floppy eject ioctl.
	 * We do this in order to provide a means to eject floppy disks before
	 * installing the new fdutils package */
	if (cmd == CDROMEJECT ||	/* CD-ROM eject */
	    cmd == 0x6470) {		/* SunOS floppy eject */
		KLPR_DPRINT("obsolete eject ioctl\n");
		KLPR_DPRINT("please use floppycontrol --eject\n");
		cmd = FDEJECT;
	}

	if (!((cmd & 0xff00) == 0x0200))
		return -EINVAL;

	/* convert the old style command into a new style command */
	ret = klpr_normalize_ioctl(&cmd, &size);
	if (ret)
		return ret;

	/* permission checks */
	if (((cmd & 0x40) && !(mode & (FMODE_WRITE | FMODE_WRITE_IOCTL))) ||
	    ((cmd & 0x80) && !capable(CAP_SYS_ADMIN)))
		return -EPERM;

	if (WARN_ON(size < 0 || size > sizeof(inparam)))
		return -EINVAL;

	/* copyin */
	memset(&inparam, 0, sizeof(inparam));
	if (_IOC_DIR(cmd) & _IOC_WRITE) {
		ret = fd_copyin((void __user *)param, &inparam, size);
		if (ret)
			return ret;
	}

	switch (cmd) {
	case FDEJECT:
		if (KLPR_UDRS->fd_ref != 1)
			/* somebody else has this drive open */
			return -EBUSY;
		if ((*klpe_lock_fdc)(drive))
			return -EINTR;

		/* do the actual eject. Fails on
		 * non-Sparc architectures */
		ret = fd_eject(UNIT(drive));

		set_bit(FD_DISK_CHANGED_BIT, &KLPR_UDRS->flags);
		set_bit(FD_VERIFY_BIT, &KLPR_UDRS->flags);
		klpr_process_fd_request();
		return ret;
	case FDCLRPRM:
		if ((*klpe_lock_fdc)(drive))
			return -EINTR;
		(*klpe_current_type)[drive] = NULL;
		(*klpe_floppy_sizes)[drive] = MAX_DISK_SIZE << 1;
		KLPR_UDRS->keep_data = 0;
		return (*klpe_invalidate_drive)(bdev);
	case FDSETPRM:
	case FDDEFPRM:
		return (*klpe_set_geometry)(cmd, &inparam.g, drive, type, bdev);
	case FDGETPRM:
		ret = (*klpe_get_floppy_geometry)(drive, type,
					  (struct floppy_struct **)&outparam);
		if (ret)
			return ret;
		memcpy(&inparam.g, outparam,
				offsetof(struct floppy_struct, name));
		outparam = &inparam.g;
		break;
	case FDMSGON:
		KLPR_UDP->flags |= FTD_MSG;
		return 0;
	case FDMSGOFF:
		KLPR_UDP->flags &= ~FTD_MSG;
		return 0;
	case FDFMTBEG:
		if ((*klpe_lock_fdc)(drive))
			return -EINTR;
		if ((*klpe_poll_drive)(true, FD_RAW_NEED_DISK) == -EINTR)
			return -EINTR;
		ret = KLPR_UDRS->flags;
		klpr_process_fd_request();
		if (ret & FD_VERIFY)
			return -ENODEV;
		if (!(ret & FD_DISK_WRITABLE))
			return -EROFS;
		return 0;
	case FDFMTTRK:
		if (KLPR_UDRS->fd_ref != 1)
			return -EBUSY;
		return klpp_do_format(drive, &inparam.f);
	case FDFMTEND:
	case FDFLUSH:
		if ((*klpe_lock_fdc)(drive))
			return -EINTR;
		return (*klpe_invalidate_drive)(bdev);
	case FDSETEMSGTRESH:
		KLPR_UDP->max_errors.reporting = (unsigned short)(param & 0x0f);
		return 0;
	case FDGETMAXERRS:
		outparam = &KLPR_UDP->max_errors;
		break;
	case FDSETMAXERRS:
		KLPR_UDP->max_errors = inparam.max_errors;
		break;
	case FDGETDRVTYP:
		outparam = klpr_drive_name(type, drive);
		SUPBOUND(size, strlen((const char *)outparam) + 1);
		break;
	case FDSETDRVPRM:
		if (!(*klpe_valid_floppy_drive_params)(inparam.dp.autodetect,
				inparam.dp.native_format))
			return -EINVAL;
		*KLPR_UDP = inparam.dp;
		break;
	case FDGETDRVPRM:
		outparam = KLPR_UDP;
		break;
	case FDPOLLDRVSTAT:
		if ((*klpe_lock_fdc)(drive))
			return -EINTR;
		if ((*klpe_poll_drive)(true, FD_RAW_NEED_DISK) == -EINTR)
			return -EINTR;
		klpr_process_fd_request();
		/* fall through */
	case FDGETDRVSTAT:
		outparam = KLPR_UDRS;
		break;
	case FDRESET:
		return (*klpe_user_reset_fdc)(drive, (int)param, true);
	case FDGETFDCSTAT:
		outparam = (&(*klpe_fdc_state)[(((drive) & 0x04) >> 2)]);
		break;
	case FDWERRORCLR:
		memset(KLPR_UDRWE, 0, sizeof(*KLPR_UDRWE));
		return 0;
	case FDWERRORGET:
		outparam = KLPR_UDRWE;
		break;
	case FDRAWCMD:
		if (type)
			return -EINVAL;
		if ((*klpe_lock_fdc)(drive))
			return -EINTR;
		klpr_set_floppy(drive);
		i = klpr_raw_cmd_ioctl(cmd, (void __user *)param);
		if (i == -EINTR)
			return -EINTR;
		klpr_process_fd_request();
		return i;
	case FDTWADDLE:
		if ((*klpe_lock_fdc)(drive))
			return -EINTR;
		klpr_twaddle();
		klpr_process_fd_request();
		return 0;
	default:
		return -EINVAL;
	}

	if (_IOC_DIR(cmd) & _IOC_READ)
		return fd_copyout((void __user *)param, outparam, size);

	return 0;
}



#define LP_MODULE "floppy"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1200057.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "_floppy", (void *)&klpe__floppy, "floppy" },
	{ "buffer_drive", (void *)&klpe_buffer_drive, "floppy" },
	{ "buffer_max", (void *)&klpe_buffer_max, "floppy" },
	{ "buffer_min", (void *)&klpe_buffer_min, "floppy" },
	{ "buffer_track", (void *)&klpe_buffer_track, "floppy" },
	{ "can_use_virtual_dma", (void *)&klpe_can_use_virtual_dma, "floppy" },
	{ "command_status", (void *)&klpe_command_status, "floppy" },
	{ "cont", (void *)&klpe_cont, "floppy" },
	{ "copy_buffer", (void *)&klpe_copy_buffer, "floppy" },
	{ "current_count_sectors", (void *)&klpe_current_count_sectors,
	  "floppy" },
	{ "current_drive", (void *)&klpe_current_drive, "floppy" },
	{ "current_req", (void *)&klpe_current_req, "floppy" },
	{ "current_type", (void *)&klpe_current_type, "floppy" },
	{ "debugtimer", (void *)&klpe_debugtimer, "floppy" },
	{ "default_raw_cmd", (void *)&klpe_default_raw_cmd, "floppy" },
	{ "disk_change", (void *)&klpe_disk_change, "floppy" },
	{ "disks", (void *)&klpe_disks, "floppy" },
	{ "do_floppy", (void *)&klpe_do_floppy, "floppy" },
	{ "drive_params", (void *)&klpe_drive_params, "floppy" },
	{ "drive_state", (void *)&klpe_drive_state, "floppy" },
	{ "errors", (void *)&klpe_errors, "floppy" },
	{ "fake_change", (void *)&klpe_fake_change, "floppy" },
#if defined (CONFIG_X86_64)
	{ "fd_routine", (void *)&klpe_fd_routine, "floppy" },
#endif
	{ "fd_timeout", (void *)&klpe_fd_timeout, "floppy" },
	{ "fdc", (void *)&klpe_fdc, "floppy" },
	{ "fdc_busy", (void *)&klpe_fdc_busy, "floppy" },
	{ "fdc_queue", (void *)&klpe_fdc_queue, "floppy" },
	{ "fdc_state", (void *)&klpe_fdc_state, "floppy" },
	{ "fdc_wait", (void *)&klpe_fdc_wait, "floppy" },
	{ "floppy_lock", (void *)&klpe_floppy_lock, "floppy" },
	{ "floppy_off", (void *)&klpe_floppy_off, "floppy" },
	{ "floppy_sizes", (void *)&klpe_floppy_sizes, "floppy" },
	{ "floppy_start", (void *)&klpe_floppy_start, "floppy" },
	{ "floppy_track_buffer", (void *)&klpe_floppy_track_buffer, "floppy" },
	{ "floppy_type", (void *)&klpe_floppy_type, "floppy" },
	{ "format_cont", (void *)&klpe_format_cont, "floppy" },
	{ "format_req", (void *)&klpe_format_req, "floppy" },
	{ "format_errors", (void *)&klpe_format_errors, "floppy" },
	{ "fsector_t", (void *)&klpe_fsector_t, "floppy" },
	{ "get_floppy_geometry", (void *)&klpe_get_floppy_geometry, "floppy" },
	{ "in_sector_offset", (void *)&klpe_in_sector_offset, "floppy" },
	{ "inr", (void *)&klpe_inr, "floppy" },
	{ "invalidate_drive", (void *)&klpe_invalidate_drive, "floppy" },
	{ "ioctl_table", (void *)&klpe_ioctl_table, "floppy" },
	{ "lastredo", (void *)&klpe_lastredo, "floppy" },
	{ "lock_fdc", (void *)&klpe_lock_fdc, "floppy" },
	{ "max_buffer_sectors", (void *)&klpe_max_buffer_sectors, "floppy" },
	{ "poll_drive", (void *)&klpe_poll_drive, "floppy" },
	{ "probing", (void *)&klpe_probing, "floppy" },
	{ "raw_cmd", (void *)&klpe_raw_cmd, "floppy" },
	{ "raw_cmd_cont", (void *)&klpe_raw_cmd_cont, "floppy" },
	{ "raw_cmd_free", (void *)&klpe_raw_cmd_free, "floppy" },
	{ "redo_format", (void *)&klpe_redo_format, "floppy" },
	{ "reply_buffer", (void *)&klpe_reply_buffer, "floppy" },
	{ "request_done", (void *)&klpe_request_done, "floppy" },
	{ "reschedule_timeout", (void *)&klpe_reschedule_timeout, "floppy" },
	{ "rw_cont", (void *)&klpe_rw_cont, "floppy" },
	{ "schedule_bh", (void *)&klpe_schedule_bh, "floppy" },
	{ "set_fdc", (void *)&klpe_set_fdc, "floppy" },
	{ "set_geometry", (void *)&klpe_set_geometry, "floppy" },
	{ "start_motor", (void *)&klpe_start_motor, "floppy" },
	{ "tell_sector", (void *)&klpe_tell_sector, "floppy" },
	{ "use_virtual_dma", (void *)&klpe_use_virtual_dma, "floppy" },
	{ "user_reset_fdc", (void *)&klpe_user_reset_fdc, "floppy" },
	{ "valid_floppy_drive_params", (void *)&klpe_valid_floppy_drive_params,
	  "floppy" },
	{ "virtualdmabug_workaround", (void *)&klpe_virtualdmabug_workaround,
	  "floppy" },
	{ "wait_til_done", (void *)&klpe_wait_til_done, "floppy" },
	{ "write_errors", (void *)&klpe_write_errors, "floppy" },
};

static int livepatch_bsc1200057_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1200057_module_nb = {
	.notifier_call = livepatch_bsc1200057_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1200057_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1200057_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1200057_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1200057_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BLK_DEV_FD) */
