/*
 * bsc1202087_fbcon
 *
 * Fix for CVE-2021-33655, bsc#1202087
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

#if IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE)

#define FB_EVENT_MODE_CHANGE_CHECK	0x12

/* klp-ccp: from drivers/video/console/fbcon.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/console.h>
#include <linux/string.h>
#include <linux/kd.h>
#include <linux/slab.h>
#include <linux/fb.h>
#include <linux/vt_kern.h>

/* klp-ccp: from include/linux/font.h */
#define REFCOUNT(fd)	(((int *)(fd))[-1])
#define FNTSIZE(fd)	(((int *)(fd))[-2])
#define FNTCHARCNT(fd)	(((int *)(fd))[-3])
#define FNTSUM(fd)	(((int *)(fd))[-4])

#define FONT_EXTRA_WORDS 4

/* klp-ccp: from drivers/video/console/fbcon.c */
#include <linux/smp.h>
#include <linux/init.h>

/* klp-ccp: from drivers/video/console/fbcon.c */
#include <linux/crc32.h> /* For counting font checksums */
#include <asm/fb.h>
#include <asm/irq.h>
/* klp-ccp: from drivers/video/console/fbcon.h */
#include <linux/types.h>
#include <linux/vt_buffer.h>
#include <linux/vt_kern.h>
#include <asm/io.h>

#define FBCON_FLAGS_CURSOR_TIMER 2

struct display {
    /* Filled in by the low-level console driver */
    const u_char *fontdata;
    int userfont;                   /* != 0 if fontdata kmalloc()ed */
    u_short scrollmode;             /* Scroll Method */
    u_short inverse;                /* != 0 text black on white as default */
    short yscroll;                  /* Hardware scrolling */
    int vrows;                      /* number of virtual rows */
    int cursor_shape;
    int con_rotate;
    u32 xres_virtual;
    u32 yres_virtual;
    u32 height;
    u32 width;
    u32 bits_per_pixel;
    u32 grayscale;
    u32 nonstd;
    u32 accel_flags;
    u32 rotate;
    struct fb_bitfield red;
    struct fb_bitfield green;
    struct fb_bitfield blue;
    struct fb_bitfield transp;
    const struct fb_videomode *mode;
};

struct fbcon_ops {
	void (*bmove)(struct vc_data *vc, struct fb_info *info, int sy,
		      int sx, int dy, int dx, int height, int width);
	void (*clear)(struct vc_data *vc, struct fb_info *info, int sy,
		      int sx, int height, int width);
	void (*putcs)(struct vc_data *vc, struct fb_info *info,
		      const unsigned short *s, int count, int yy, int xx,
		      int fg, int bg);
	void (*clear_margins)(struct vc_data *vc, struct fb_info *info,
			      int bottom_only);
	void (*cursor)(struct vc_data *vc, struct fb_info *info, int mode,
		       int softback_lines, int fg, int bg);
	int  (*update_start)(struct fb_info *info);
	int  (*rotate_font)(struct fb_info *info, struct vc_data *vc);
	struct fb_var_screeninfo var;  /* copy of the current fb_var_screeninfo */
	struct timer_list cursor_timer; /* Cursor timer */
	struct fb_cursor cursor_state;
	struct display *p;
        int    currcon;	                /* Current VC. */
	int    cur_blink_jiffies;
	int    cursor_flash;
	int    cursor_reset;
	int    blank_state;
	int    graphics;
	int    save_graphics; /* for debug enter/leave */
	int    flags;
	int    rotate;
	int    cur_rotate;
	char  *cursor_data;
	u8    *fontbuffer;
	u8    *fontdata;
	u8    *cursor_src;
	u32    cursor_size;
	u32    fd_size;
};

/* klp-ccp: from drivers/video/console/fbcon.c */
static struct display (*klpe_fb_display)[MAX_NR_CONSOLES];

static signed char (*klpe_con2fb_map)[MAX_NR_CONSOLES];
static signed char (*klpe_con2fb_map_boot)[MAX_NR_CONSOLES];

#if defined(CONFIG_X86_64) || defined(CONFIG_PPC64)
static int (*klpe_first_fb_vc);
static int (*klpe_last_fb_vc);
static int (*klpe_fbcon_is_default);
static int (*klpe_map_override);

#define klpr_first_fb_vc (*klpe_first_fb_vc)
#define klpr_last_fb_vc (*klpe_last_fb_vc)
#define klpr_fbcon_is_default (*klpe_fbcon_is_default)
#define klpr_map_override (*klpe_map_override)
#define klpr_registered_fb registered_fb
#define klpr_num_registered_fb num_registered_fb
#define klpr_fb_mode_is_equal fb_mode_is_equal

#elif defined(CONFIG_S390)
static int first_fb_vc;
static int last_fb_vc = MAX_NR_CONSOLES - 1;
static int fbcon_is_default = 1;
static int map_override;

static struct fb_info *(*klpe_registered_fb)[FB_MAX];
static int (*klpe_num_registered_fb);
static int (*klpe_fb_mode_is_equal)(const struct fb_videomode *mode1,
				const struct fb_videomode *mode2);

#define klpr_first_fb_vc first_fb_vc
#define klpr_last_fb_vc last_fb_vc
#define klpr_fbcon_is_default fbcon_is_default
#define klpr_map_override map_override
#define klpr_registered_fb (*klpe_registered_fb)
#define klpr_num_registered_fb (*klpe_num_registered_fb)
#define klpr_fb_mode_is_equal (*klpe_fb_mode_is_equal)
#else
#error "klp-ccp: non-taken branch"
#endif

static int (*klpe_fbcon_has_exited);
static int (*klpe_primary_device);
static int (*klpe_fbcon_has_console_bind);

static int (*klpe_info_idx);

static const struct consw (*klpe_fb_con);

static void (*klpe_fbcon_cursor)(struct vc_data *vc, int mode);

static void (*klpe_fbcon_modechanged)(struct fb_info *info);
static void (*klpe_fbcon_set_all_vcs)(struct fb_info *info);

static void (*klpe_fb_flashcursor)(struct work_struct *work);

static void klpr_fbcon_del_cursor_timer(struct fb_info *info)
{
	struct fbcon_ops *ops = info->fbcon_par;

	if (info->queue.func == (*klpe_fb_flashcursor) &&
	    ops->flags & FBCON_FLAGS_CURSOR_TIMER) {
		del_timer_sync(&ops->cursor_timer);
		ops->flags &= ~FBCON_FLAGS_CURSOR_TIMER;
	}
}

static int klpr_search_fb_in_map(int idx)
{
	int i, retval = 0;

	for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
		if ((*klpe_con2fb_map)[i] == idx)
			retval = 1;
	}
	return retval;
}

static int (*klpe_do_fbcon_takeover)(int show_logo);

#ifdef CONFIG_FB_TILEBLITTING

static int fbcon_invalid_charcount(struct fb_info *info, unsigned charcount)
{
	int err = 0;

	if (info->flags & FBINFO_MISC_TILEBLITTING &&
	    info->tileops->fb_get_tilemax(info) < charcount)
		err = 1;

	return err;
}
#else
static int fbcon_invalid_charcount(struct fb_info *info, unsigned charcount)
{
	return 0;
}
#endif /* CONFIG_MISC_TILEBLITTING */

static int klpr_con2fb_release_oldinfo(struct vc_data *vc, struct fb_info *oldinfo,
				  struct fb_info *newinfo, int unit,
				  int oldidx, int found)
{
	struct fbcon_ops *ops = oldinfo->fbcon_par;
	int err = 0, ret;

	if (oldinfo->fbops->fb_release &&
	    oldinfo->fbops->fb_release(oldinfo, 0)) {
		(*klpe_con2fb_map)[unit] = oldidx;
		if (!found && newinfo->fbops->fb_release)
			newinfo->fbops->fb_release(newinfo, 0);
		if (!found)
			module_put(newinfo->fbops->owner);
		err = -ENODEV;
	}

	if (!err) {
		klpr_fbcon_del_cursor_timer(oldinfo);
		kfree(ops->cursor_state.mask);
		kfree(ops->cursor_data);
		kfree(ops->cursor_src);
		kfree(ops->fontbuffer);
		kfree(oldinfo->fbcon_par);
		oldinfo->fbcon_par = NULL;
		module_put(oldinfo->fbops->owner);
		/*
		  If oldinfo and newinfo are driving the same hardware,
		  the fb_release() method of oldinfo may attempt to
		  restore the hardware state.  This will leave the
		  newinfo in an unIS_ENABLED state. Thus, a call to
		  fb_set_par() may be needed for the newinfo.
		*/
		if (newinfo && newinfo->fbops->fb_set_par) {
			ret = newinfo->fbops->fb_set_par(newinfo);

			if (ret)
				printk(KERN_ERR "con2fb_release_oldinfo: "
					"detected unhandled fb_set_par error, "
					"error code %d\n", ret);
		}
	}

	return err;
}

static int (*klpe_set_con2fb_map)(int unit, int newidx, int user);

#define PITCH(w) (((w) + 7) >> 3)
#define CALC_FONTSZ(h, p, c) ((h) * (p) * (c)) /* size = height * pitch * charcount */

static int (*klpe_fbcon_do_set_font)(struct vc_data *vc, int w, int h,
			     const u8 * data, int userfont);

#define FBCON_SWAP(i,r,v) ({ \
        typeof(r) _r = (r);  \
        typeof(v) _v = (v);  \
        (void) (&_r == &_v); \
        (i == FB_ROTATE_UR || i == FB_ROTATE_UD) ? _r : _v; })

int klpp_fbcon_set_font(struct vc_data *vc, struct console_font *font, unsigned flags)
{
	struct fb_info *info = klpr_registered_fb[(*klpe_con2fb_map)[vc->vc_num]];
	unsigned charcount = font->charcount;
	int w = font->width;
	int h = font->height;
	int size;
	int i, csum;
	u8 *new_data, *data = font->data;
	int pitch = PITCH(font->width);

	/* Is there a reason why fbconsole couldn't handle any charcount >256?
	 * If not this check should be changed to charcount < 256 */
	if (charcount != 256 && charcount != 512)
		return -EINVAL;

	/* font bigger than screen resolution ? */
	if (w > FBCON_SWAP(info->var.rotate, info->var.xres, info->var.yres) ||
	    h > FBCON_SWAP(info->var.rotate, info->var.yres, info->var.xres))
		return -EINVAL;

	/* Make sure drawing engine can handle the font */
	if (!(info->pixmap.blit_x & (1 << (font->width - 1))) ||
	    !(info->pixmap.blit_y & (1 << (font->height - 1))))
		return -EINVAL;

	/* Make sure driver can handle the font length */
	if (fbcon_invalid_charcount(info, charcount))
		return -EINVAL;

	size = CALC_FONTSZ(h, pitch, charcount);

	new_data = kmalloc(FONT_EXTRA_WORDS * sizeof(int) + size, GFP_USER);

	if (!new_data)
		return -ENOMEM;

	new_data += FONT_EXTRA_WORDS * sizeof(int);
	FNTSIZE(new_data) = size;
	FNTCHARCNT(new_data) = charcount;
	REFCOUNT(new_data) = 0;	/* usage counter */
	for (i=0; i< charcount; i++) {
		memcpy(new_data + i*h*pitch, data +  i*32*pitch, h*pitch);
	}

	/* Since linux has a nice crc32 function use it for counting font
	 * checksums. */
	csum = crc32(0, new_data, size);

	FNTSUM(new_data) = csum;
	/* Check if the same font is on some other console already */
	for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
		struct vc_data *tmp = vc_cons[i].d;

		if ((*klpe_fb_display)[i].userfont &&
		    (*klpe_fb_display)[i].fontdata &&
		    FNTSUM((*klpe_fb_display)[i].fontdata) == csum &&
		    FNTSIZE((*klpe_fb_display)[i].fontdata) == size &&
		    tmp->vc_font.width == w &&
		    !memcmp((*klpe_fb_display)[i].fontdata, new_data, size)) {
			kfree(new_data - FONT_EXTRA_WORDS * sizeof(int));
			new_data = (u8 *)(*klpe_fb_display)[i].fontdata;
			break;
		}
	}
	return (*klpe_fbcon_do_set_font)(vc, font->width, font->height, new_data, 1);
}

static void klpr_fbcon_suspended(struct fb_info *info)
{
	struct vc_data *vc = NULL;
	struct fbcon_ops *ops = info->fbcon_par;

	if (!ops || ops->currcon < 0)
		return;
	vc = vc_cons[ops->currcon].d;

	/* Clear cursor, restore saved data */
	(*klpe_fbcon_cursor)(vc, CM_ERASE);
}

static void fbcon_resumed(struct fb_info *info)
{
	struct vc_data *vc;
	struct fbcon_ops *ops = info->fbcon_par;

	if (!ops || ops->currcon < 0)
		return;
	vc = vc_cons[ops->currcon].d;

	update_screen(vc);
}

/* let fbcon check if it supports a new screen resolution */
static int klpp_fbcon_modechange_possible(struct fb_info *info,
				     struct fb_var_screeninfo *var)
{
	struct fbcon_ops *ops = info->fbcon_par;
	struct vc_data *vc;
	unsigned int i;

	if (!ops)
		return 0;

	/* prevent setting a screen size which is smaller than font size */
	for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
		vc = vc_cons[i].d;
		if (!vc || vc->vc_mode != KD_TEXT ||
			   klpr_registered_fb[(*klpe_con2fb_map)[i]] != info)
			continue;

		if (vc->vc_font.width  > FBCON_SWAP(var->rotate, var->xres, var->yres) ||
		    vc->vc_font.height > FBCON_SWAP(var->rotate, var->yres, var->xres))
			return notifier_from_errno(-EINVAL);
	}

	return 0;
}

static int klpr_fbcon_mode_deleted(struct fb_info *info,
			      struct fb_videomode *mode)
{
	struct fb_info *fb_info;
	struct display *p;
	int i, j, found = 0;

	/* before deletion, ensure that mode is not in use */
	for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
		j = (*klpe_con2fb_map)[i];
		if (j == -1)
			continue;
		fb_info = klpr_registered_fb[j];
		if (fb_info != info)
			continue;
		p = &(*klpe_fb_display)[i];
		if (!p || !p->mode)
			continue;
		if (klpr_fb_mode_is_equal(p->mode, mode)) {
			found = 1;
			break;
		}
	}
	return found;
}

#ifdef CONFIG_VT_HW_CONSOLE_BINDING
static int klpr_fbcon_unbind(void)
{
	int ret;

	ret = do_unbind_con_driver(&(*klpe_fb_con), klpr_first_fb_vc, klpr_last_fb_vc,
				klpr_fbcon_is_default);

	if (!ret)
		(*klpe_fbcon_has_console_bind) = 0;

	return ret;
}
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_VT_HW_CONSOLE_BINDING */

static int klpr_fbcon_fb_unbind(int idx)
{
	int i, new_idx = -1, ret = 0;

	if (!(*klpe_fbcon_has_console_bind))
		return 0;

	for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
		if ((*klpe_con2fb_map)[i] != idx &&
		    (*klpe_con2fb_map)[i] != -1) {
			new_idx = (*klpe_con2fb_map)[i];
			break;
		}
	}

	if (new_idx != -1) {
		for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
			if ((*klpe_con2fb_map)[i] == idx)
				(*klpe_set_con2fb_map)(i, new_idx, 0);
		}
	} else {
		struct fb_info *info = klpr_registered_fb[idx];

		/* This is sort of like set_con2fb_map, except it maps
		 * the consoles to no device and then releases the
		 * oldinfo to free memory and cancel the cursor blink
		 * timer. I can imagine this just becoming part of
		 * set_con2fb_map where new_idx is -1
		 */
		for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
			if ((*klpe_con2fb_map)[i] == idx) {
				(*klpe_con2fb_map)[i] = -1;
				if (!klpr_search_fb_in_map(idx)) {
					ret = klpr_con2fb_release_oldinfo(vc_cons[i].d,
								     info, NULL, i,
								     idx, 0);
					if (ret) {
						(*klpe_con2fb_map)[i] = idx;
						return ret;
					}
				}
			}
		}
		ret = klpr_fbcon_unbind();
	}

	return ret;
}

static int klpr_fbcon_fb_unregistered(struct fb_info *info)
{
	int i, idx;

	idx = info->node;
	for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
		if ((*klpe_con2fb_map)[i] == idx)
			(*klpe_con2fb_map)[i] = -1;
	}

	if (idx == (*klpe_info_idx)) {
		(*klpe_info_idx) = -1;

		for (i = 0; i < FB_MAX; i++) {
			if (klpr_registered_fb[i] != NULL) {
				(*klpe_info_idx) = i;
				break;
			}
		}
	}

	if ((*klpe_info_idx) != -1) {
		for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
			if ((*klpe_con2fb_map)[i] == -1)
				(*klpe_con2fb_map)[i] = (*klpe_info_idx);
		}
	}

	if ((*klpe_primary_device) == idx)
		(*klpe_primary_device) = -1;

	if (!klpr_num_registered_fb)
		do_unregister_con_driver(&(*klpe_fb_con));

	return 0;
}

static void klpr_fbcon_remap_all(int idx)
{
	int i;
	for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++)
		(*klpe_set_con2fb_map)(i, idx, 0);

	if (con_is_bound(&(*klpe_fb_con))) {
		printk(KERN_INFO "fbcon: Remapping primary device, "
		       "fb%i, to tty %i-%i\n", idx,
		       klpr_first_fb_vc + 1, klpr_last_fb_vc + 1);
		(*klpe_info_idx) = idx;
	}
}

#ifdef CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY
static void klpr_fbcon_select_primary(struct fb_info *info)
{
	if (!klpr_map_override && (*klpe_primary_device) == -1 &&
	    fb_is_primary_device(info)) {
		int i;

		printk(KERN_INFO "fbcon: %s (fb%i) is primary device\n",
		       info->fix.id, info->node);
		(*klpe_primary_device) = info->node;

		for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++)
			(*klpe_con2fb_map_boot)[i] = (*klpe_primary_device);

		if (con_is_bound(&(*klpe_fb_con))) {
			printk(KERN_INFO "fbcon: Remapping primary device, "
			       "fb%i, to tty %i-%i\n", info->node,
			       klpr_first_fb_vc + 1, klpr_last_fb_vc + 1);
			(*klpe_info_idx) = (*klpe_primary_device);
		}
	}

}
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_FRAMEBUFFER_DETECT_PRIMARY */

static int klpr_fbcon_fb_registered(struct fb_info *info)
{
	int ret = 0, i, idx;

	idx = info->node;
	klpr_fbcon_select_primary(info);

	if ((*klpe_info_idx) == -1) {
		for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
			if ((*klpe_con2fb_map_boot)[i] == idx) {
				(*klpe_info_idx) = idx;
				break;
			}
		}

		if ((*klpe_info_idx) != -1)
			ret = (*klpe_do_fbcon_takeover)(1);
	} else {
		for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
			if ((*klpe_con2fb_map_boot)[i] == idx)
				(*klpe_set_con2fb_map)(i, idx, 0);
		}
	}

	return ret;
}

static void klpr_fbcon_fb_blanked(struct fb_info *info, int blank)
{
	struct fbcon_ops *ops = info->fbcon_par;
	struct vc_data *vc;

	if (!ops || ops->currcon < 0)
		return;

	vc = vc_cons[ops->currcon].d;
	if (vc->vc_mode != KD_TEXT ||
			klpr_registered_fb[(*klpe_con2fb_map)[ops->currcon]] != info)
		return;

	if (con_is_visible(vc)) {
		if (blank)
			do_blank_screen(0);
		else
			do_unblank_screen(0);
	}
	ops->blank_state = blank;
}

static void (*klpe_fbcon_new_modelist)(struct fb_info *info);

static void klpr_fbcon_get_requirement(struct fb_info *info,
				  struct fb_blit_caps *caps)
{
	struct vc_data *vc;
	struct display *p;

	if (caps->flags) {
		int i, charcnt;

		for (i = klpr_first_fb_vc; i <= klpr_last_fb_vc; i++) {
			vc = vc_cons[i].d;
			if (vc && vc->vc_mode == KD_TEXT &&
			    info->node == (*klpe_con2fb_map)[i]) {
				p = &(*klpe_fb_display)[i];
				caps->x |= 1 << (vc->vc_font.width - 1);
				caps->y |= 1 << (vc->vc_font.height - 1);
				charcnt = (p->userfont) ?
					FNTCHARCNT(p->fontdata) : 256;
				if (caps->len < charcnt)
					caps->len = charcnt;
			}
		}
	} else {
		vc = vc_cons[fg_console].d;

		if (vc && vc->vc_mode == KD_TEXT &&
		    info->node == (*klpe_con2fb_map)[fg_console]) {
			p = &(*klpe_fb_display)[fg_console];
			caps->x = 1 << (vc->vc_font.width - 1);
			caps->y = 1 << (vc->vc_font.height - 1);
			caps->len = (p->userfont) ?
				FNTCHARCNT(p->fontdata) : 256;
		}
	}
}

int klpp_fbcon_event_notify(struct notifier_block *self,
			      unsigned long action, void *data)
{
	struct fb_event *event = data;
	struct fb_info *info = event->info;
	struct fb_videomode *mode;
	struct fb_con2fbmap *con2fb;
	struct fb_blit_caps *caps;
	int idx, ret = 0;

	/*
	 * ignore all events except driver registration and deregistration
	 * if fbcon is not active
	 */
	if ((*klpe_fbcon_has_exited) && !(action == FB_EVENT_FB_REGISTERED ||
				  action == FB_EVENT_FB_UNREGISTERED))
		goto done;

	switch(action) {
	case FB_EVENT_SUSPEND:
		klpr_fbcon_suspended(info);
		break;
	case FB_EVENT_RESUME:
		fbcon_resumed(info);
		break;
	case FB_EVENT_MODE_CHANGE:
		(*klpe_fbcon_modechanged)(info);
		break;
	case FB_EVENT_MODE_CHANGE_ALL:
		(*klpe_fbcon_set_all_vcs)(info);
		break;
	case FB_EVENT_MODE_DELETE:
		mode = event->data;
		ret = klpr_fbcon_mode_deleted(info, mode);
		break;
	case FB_EVENT_FB_UNBIND:
		idx = info->node;
		ret = klpr_fbcon_fb_unbind(idx);
		break;
	case FB_EVENT_FB_REGISTERED:
		ret = klpr_fbcon_fb_registered(info);
		break;
	case FB_EVENT_FB_UNREGISTERED:
		ret = klpr_fbcon_fb_unregistered(info);
		break;
	case FB_EVENT_SET_CONSOLE_MAP:
		/* called with console lock held */
		con2fb = event->data;
		ret = (*klpe_set_con2fb_map)(con2fb->console - 1,
				     con2fb->framebuffer, 1);
		break;
	case FB_EVENT_GET_CONSOLE_MAP:
		con2fb = event->data;
		con2fb->framebuffer = (*klpe_con2fb_map)[con2fb->console - 1];
		break;
	case FB_EVENT_BLANK:
		klpr_fbcon_fb_blanked(info, *(int *)event->data);
		break;
	case FB_EVENT_NEW_MODELIST:
		(*klpe_fbcon_new_modelist)(info);
		break;
	case FB_EVENT_GET_REQ:
		caps = event->data;
		klpr_fbcon_get_requirement(info, caps);
		break;
	case FB_EVENT_REMAP_ALL_CONSOLE:
		idx = info->node;
		klpr_fbcon_remap_all(idx);
		break;
	case FB_EVENT_MODE_CHANGE_CHECK:
		ret = klpp_fbcon_modechange_possible(event->info, event->data);
		break;
	}
done:
	return ret;
}



#include <linux/kernel.h>
#include "livepatch_bsc1202087.h"
#include "../kallsyms_relocs.h"

#if defined(CONFIG_S390)
static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "con2fb_map", (void *)&klpe_con2fb_map, "fbcon" },
	{ "con2fb_map_boot", (void *)&klpe_con2fb_map_boot, "fbcon" },
	{ "do_fbcon_takeover", (void *)&klpe_do_fbcon_takeover, "fbcon" },
	{ "fb_con", (void *)&klpe_fb_con, "fbcon" },
	{ "fb_display", (void *)&klpe_fb_display, "fbcon" },
	{ "fb_flashcursor", (void *)&klpe_fb_flashcursor, "fbcon" },
	{ "fbcon_cursor", (void *)&klpe_fbcon_cursor, "fbcon" },
	{ "fbcon_do_set_font", (void *)&klpe_fbcon_do_set_font, "fbcon" },
	{ "fbcon_has_console_bind", (void *)&klpe_fbcon_has_console_bind,
	  "fbcon" },
	{ "fbcon_has_exited", (void *)&klpe_fbcon_has_exited, "fbcon" },
	{ "fbcon_modechanged", (void *)&klpe_fbcon_modechanged, "fbcon" },
	{ "fbcon_new_modelist", (void *)&klpe_fbcon_new_modelist, "fbcon" },
	{ "fbcon_set_all_vcs", (void *)&klpe_fbcon_set_all_vcs, "fbcon" },
	{ "info_idx", (void *)&klpe_info_idx, "fbcon" },
	{ "primary_device", (void *)&klpe_primary_device, "fbcon" },
	{ "set_con2fb_map", (void *)&klpe_set_con2fb_map, "fbcon" },
	{ "registered_fb", (void *)&klpe_registered_fb, "fb" },
	{ "num_registered_fb", (void *)&klpe_num_registered_fb, "fb" },
	{ "fb_mode_is_equal", (void *)&klpe_fb_mode_is_equal, "fb" },
};
#elif defined(CONFIG_X86_64) || defined(CONFIG_PPC64)
static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "con2fb_map", (void *)&klpe_con2fb_map },
	{ "con2fb_map_boot", (void *)&klpe_con2fb_map_boot },
	{ "do_fbcon_takeover", (void *)&klpe_do_fbcon_takeover },
	{ "fb_con", (void *)&klpe_fb_con },
	{ "fb_display", (void *)&klpe_fb_display },
	{ "fb_flashcursor", (void *)&klpe_fb_flashcursor },
	{ "fbcon_cursor", (void *)&klpe_fbcon_cursor },
	{ "fbcon_do_set_font", (void *)&klpe_fbcon_do_set_font },
	{ "fbcon_has_console_bind", (void *)&klpe_fbcon_has_console_bind },
	{ "fbcon_has_exited", (void *)&klpe_fbcon_has_exited },
	{ "fbcon_is_default", (void *)&klpe_fbcon_is_default },
	{ "fbcon_modechanged", (void *)&klpe_fbcon_modechanged },
	{ "fbcon_new_modelist", (void *)&klpe_fbcon_new_modelist },
	{ "fbcon_set_all_vcs", (void *)&klpe_fbcon_set_all_vcs },
	{ "first_fb_vc", (void *)&klpe_first_fb_vc },
	{ "info_idx", (void *)&klpe_info_idx },
	{ "last_fb_vc", (void *)&klpe_last_fb_vc },
	{ "map_override", (void *)&klpe_map_override },
	{ "primary_device", (void *)&klpe_primary_device },
	{ "set_con2fb_map", (void *)&klpe_set_con2fb_map },
};
#else
#error "klp-ccp: non-taken branch"
#endif

#if defined(CONFIG_S390)
#define LP_MODULE "fbcon"

#include <linux/module.h>

static int bsc1202087_module_notify(struct notifier_block *nb,
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

static struct notifier_block bsc1202087_module_nb = {
	.notifier_call = bsc1202087_module_notify,
	.priority = INT_MIN+1,
};

int bsc1202087_fbcon_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&bsc1202087_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1202087_fbcon_cleanup(void)
{
	unregister_module_notifier(&bsc1202087_module_nb);
}

#elif defined(CONFIG_X86_64) || defined(CONFIG_PPC64)
int bsc1202087_fbcon_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

void bsc1202087_fbcon_cleanup(void)
{
}
#else
#error "klp-ccp: non-taken branch"
#endif

#endif /* IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE) */
