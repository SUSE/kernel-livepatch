/*
 * livepatch_bsc122521
 *
 * Fix for CVE-2021-47383, bsc#1225211
 *
 *  Upstream commit:
 *  3b0c40612471 ("tty: Fix out-of-bound vmalloc access in imageblit")
 *
 *  SLE12-SP5 commit:
 *  a21c7501ceb5c72fda53943843d86b8bc5a35ab9
 *
 *  SLE15-SP2 and -SP3 commit:
 *  aa2473d3cd9af50d88e4766dc8d02c280390528a
 *
 *  SLE15-SP4 and -SP5 commit:
 *  33bbd5324fd3ada090d8cf08ace7fc5c1c9b4172
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

/* klp-ccp: from drivers/tty/vt/vt.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/kd.h>
#include <linux/slab.h>
#include <linux/major.h>
#include <linux/console.h>

/* klp-ccp: from include/linux/mm.h */
#define _LINUX_MM_H

/* klp-ccp: from include/linux/console.h */
static int (*klpe_is_console_locked)(void);

#define KLPR_WARN_CONSOLE_UNLOCKED()	WARN_ON(!(*klpe_is_console_locked)() && !oops_in_progress)

/* klp-ccp: from drivers/tty/vt/vt.c */
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/vt_kern.h>

/* klp-ccp: from include/linux/vt_kern.h */
static void (*klpe_vt_event_post)(unsigned int event, unsigned int old, unsigned int new);

/* klp-ccp: from drivers/tty/vt/vt.c */
#include <linux/selection.h>

/* klp-ccp: from include/linux/selection.h */
static void (*klpe_clear_selection)(void);

static bool (*klpe_vc_is_sel)(struct vc_data *vc);

/* klp-ccp: from drivers/tty/vt/vt.c */
#include <linux/tiocl.h>

/* klp-ccp: from include/linux/interrupt.h */
#define _LINUX_INTERRUPT_H

/* klp-ccp: from include/linux/io.h */
#define _LINUX_IO_H

/* klp-ccp: from drivers/tty/vt/vt.c */
#include <linux/consolemap.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/pm.h>
#include <linux/bitops.h>
#include <linux/notifier.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/uaccess.h>

static void (*klpe_gotoxy)(struct vc_data *vc, int new_x, int new_y);
static void save_cur(struct vc_data *vc);

static struct atomic_notifier_head (*klpe_vt_notifier_list);

static void klpr_notify_update(struct vc_data *vc)
{
	struct vt_notifier_param param = { .vc = vc };
	atomic_notifier_call_chain(&(*klpe_vt_notifier_list), VT_UPDATE, &param);
}

static u8 (*klpe_build_attr)(struct vc_data *vc, u8 _color, u8 _intensity, u8 _blink,
    u8 _underline, u8 _reverse, u8 _italic);

static void klpr_update_attr(struct vc_data *vc)
{
	vc->vc_attr = (*klpe_build_attr)(vc, vc->vc_color, vc->vc_intensity,
	              vc->vc_blink, vc->vc_underline,
	              vc->vc_reverse ^ vc->vc_decscnm, vc->vc_italic);
	vc->vc_video_erase_char = ((*klpe_build_attr)(vc, vc->vc_color, 1, vc->vc_blink, 0, vc->vc_decscnm, 0) << 8) | ' ';
}

static void (*klpe_set_origin)(struct vc_data *vc);

#define VC_MAXCOL (32767)
#define VC_MAXROW (32767)

static inline int resize_screen(struct vc_data *vc, int width, int height,
				int user)
{
	/* Resizes the resolution of the display adapater */
	int err = 0;

	if (vc->vc_mode != KD_GRAPHICS && vc->vc_sw->con_resize)
		err = vc->vc_sw->con_resize(vc, width, height, user);

	return err;
}

int klpp_vc_do_resize(struct tty_struct *tty, struct vc_data *vc,
				unsigned int cols, unsigned int lines)
{
	unsigned long old_origin, new_origin, new_scr_end, rlth, rrem, err = 0;
	unsigned long end;
	unsigned int old_rows, old_row_size;
	unsigned int new_cols, new_rows, new_row_size, new_screen_size;
	unsigned int user;
	unsigned short *newscreen;

	KLPR_WARN_CONSOLE_UNLOCKED();

	if (!vc)
		return -ENXIO;

	user = vc->vc_resize_user;
	vc->vc_resize_user = 0;

	if (cols > VC_MAXCOL || lines > VC_MAXROW)
		return -EINVAL;

	new_cols = (cols ? cols : vc->vc_cols);
	new_rows = (lines ? lines : vc->vc_rows);
	new_row_size = new_cols << 1;
	new_screen_size = new_row_size * new_rows;

	if (new_cols == vc->vc_cols && new_rows == vc->vc_rows) {
		/*
		 * This function is being called here to cover the case
		 * where the userspace calls the FBIOPUT_VSCREENINFO twice,
		 * passing the same fb_var_screeninfo containing the fields
		 * yres/xres equal to a number non-multiple of vc_font.height
		 * and yres_virtual/xres_virtual equal to number lesser than the
		 * vc_font.height and yres/xres.
		 * In the second call, the struct fb_var_screeninfo isn't
		 * being modified by the underlying driver because of the
		 * if above, and this causes the fbcon_display->vrows to become
		 * negative and it eventually leads to out-of-bound
		 * access by the imageblit function.
		 * To give the correct values to the struct and to not have
		 * to deal with possible errors from the code below, we call
		 * the resize_screen here as well.
		 */
		return resize_screen(vc, new_cols, new_rows, user);
	}

	if (new_screen_size > KMALLOC_MAX_SIZE || !new_screen_size)
		return -EINVAL;
	newscreen = kzalloc(new_screen_size, GFP_USER);
	if (!newscreen)
		return -ENOMEM;

	if ((*klpe_vc_is_sel)(vc))
		(*klpe_clear_selection)();

	old_rows = vc->vc_rows;
	old_row_size = vc->vc_size_row;

	err = resize_screen(vc, new_cols, new_rows, user);
	if (err) {
		kfree(newscreen);
		return err;
	}

	vc->vc_rows = new_rows;
	vc->vc_cols = new_cols;
	vc->vc_size_row = new_row_size;
	vc->vc_screenbuf_size = new_screen_size;

	rlth = min(old_row_size, new_row_size);
	rrem = new_row_size - rlth;
	old_origin = vc->vc_origin;
	new_origin = (long) newscreen;
	new_scr_end = new_origin + new_screen_size;

	if (vc->vc_y > new_rows) {
		if (old_rows - vc->vc_y < new_rows) {
			/*
			 * Cursor near the bottom, copy contents from the
			 * bottom of buffer
			 */
			old_origin += (old_rows - new_rows) * old_row_size;
		} else {
			/*
			 * Cursor is in no man's land, copy 1/2 screenful
			 * from the top and bottom of cursor position
			 */
			old_origin += (vc->vc_y - new_rows/2) * old_row_size;
		}
	}

	end = old_origin + old_row_size * min(old_rows, new_rows);

	klpr_update_attr(vc);

	while (old_origin < end) {
		scr_memcpyw((unsigned short *) new_origin,
			    (unsigned short *) old_origin, rlth);
		if (rrem)
			scr_memsetw((void *)(new_origin + rlth),
				    vc->vc_video_erase_char, rrem);
		old_origin += old_row_size;
		new_origin += new_row_size;
	}
	if (new_scr_end > new_origin)
		scr_memsetw((void *)new_origin, vc->vc_video_erase_char,
			    new_scr_end - new_origin);
	kfree(vc->vc_screenbuf);
	vc->vc_screenbuf = newscreen;
	vc->vc_screenbuf_size = new_screen_size;
	(*klpe_set_origin)(vc);

	/* do part of a reset_terminal() */
	vc->vc_top = 0;
	vc->vc_bottom = vc->vc_rows;
	(*klpe_gotoxy)(vc, vc->vc_x, vc->vc_y);
	save_cur(vc);

	if (tty) {
		/* Rewrite the requested winsize data with the actual
		   resulting sizes */
		struct winsize ws;
		memset(&ws, 0, sizeof(ws));
		ws.ws_row = vc->vc_rows;
		ws.ws_col = vc->vc_cols;
		ws.ws_ypixel = vc->vc_scan_lines;
		tty_do_resize(tty, &ws);
	}

	if (con_is_visible(vc))
		update_screen(vc);
	(*klpe_vt_event_post)(VT_EVENT_RESIZE, vc->vc_num, vc->vc_num);
	klpr_notify_update(vc);
	return err;
}

static void save_cur(struct vc_data *vc)
{
	vc->vc_saved_x		= vc->vc_x;
	vc->vc_saved_y		= vc->vc_y;
	vc->vc_s_intensity	= vc->vc_intensity;
	vc->vc_s_italic         = vc->vc_italic;
	vc->vc_s_underline	= vc->vc_underline;
	vc->vc_s_blink		= vc->vc_blink;
	vc->vc_s_reverse	= vc->vc_reverse;
	vc->vc_s_charset	= vc->vc_charset;
	vc->vc_s_color		= vc->vc_color;
	vc->vc_saved_G0		= vc->vc_G0_charset;
	vc->vc_saved_G1		= vc->vc_G1_charset;
}



#include "livepatch_bsc1225211.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "build_attr", (void *)&klpe_build_attr },
	{ "clear_selection", (void *)&klpe_clear_selection },
	{ "gotoxy", (void *)&klpe_gotoxy },
	{ "is_console_locked", (void *)&klpe_is_console_locked },
	{ "set_origin", (void *)&klpe_set_origin },
	{ "vc_is_sel", (void *)&klpe_vc_is_sel },
	{ "vt_event_post", (void *)&klpe_vt_event_post },
	{ "vt_notifier_list", (void *)&klpe_vt_notifier_list },
};

int livepatch_bsc1225211_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

