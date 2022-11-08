/*
 * bsc1202087_fbmem
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

/* klp-ccp: from drivers/video/fbdev/core/fbmem.c */
#include <linux/module.h>
#include <linux/compat.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/slab.h>

/* klp-ccp: from include/uapi/linux/vt.h */
#define MAX_NR_CONSOLES	63	/* serial lines start at 64 */

/* klp-ccp: from drivers/video/fbdev/core/fbmem.c */
#include <linux/init.h>

/* klp-ccp: from drivers/video/fbdev/core/fbmem.c */
#include <linux/console.h>
#include <linux/kmod.h>
#include <linux/err.h>
#include <linux/device.h>
#include <linux/efi.h>
#include <linux/fb.h>

static void (*klpe_fb_delete_videomode)(const struct fb_videomode *mode,
				struct list_head *head);

static int (*klpe_fb_cmap_to_user)(const struct fb_cmap *from, struct fb_cmap_user *to);

static int (*klpe_fb_set_user_cmap)(struct fb_cmap_user *cmap, struct fb_info *fb_info);

/* klp-ccp: from drivers/video/fbdev/core/fbmem.c */
#include <linux/mem_encrypt.h>

#if defined(CONFIG_X86_64) || defined(CONFIG_PPC64)
extern struct fb_info *registered_fb[FB_MAX] __read_mostly;

int lock_fb_info(struct fb_info *info);
int fb_pan_display(struct fb_info *info, struct fb_var_screeninfo *var);
int fb_blank(struct fb_info *info, int blank);

#define klpr_registered_fb registered_fb
#define klpr_fb_mode_is_equal fb_mode_is_equal
#define klpr_lock_fb_info lock_fb_info
#define klpr_fb_pan_display fb_pan_display
#define klpr_fb_blank fb_blank
#define klpr_fb_set_cmap fb_set_cmap
#define klpr_fb_var_to_videomode fb_var_to_videomode
#define klpr_fb_add_videomode fb_add_videomode

#elif defined(CONFIG_S390)
static struct fb_info *(*klpe_registered_fb)[FB_MAX];
static int (*klpe_fb_mode_is_equal)(const struct fb_videomode *mode1,
				const struct fb_videomode *mode2);
static int (*klpe_lock_fb_info)(struct fb_info *info);
static int (*klpe_fb_pan_display)(struct fb_info *info,
		struct fb_var_screeninfo *var);
static int (*klpe_fb_blank)(struct fb_info *info, int blank);
static int (*klpe_fb_set_cmap)(struct fb_cmap *cmap, struct fb_info *info);
static void (*klpe_fb_var_to_videomode)(struct fb_videomode *mode,
				const struct fb_var_screeninfo *var);
static int (*klpe_fb_add_videomode)(const struct fb_videomode *mode,
				struct list_head *head);

#define klpr_registered_fb (*klpe_registered_fb)
#define klpr_fb_mode_is_equal (*klpe_fb_mode_is_equal)
#define klpr_lock_fb_info (*klpe_lock_fb_info)
#define klpr_fb_pan_display (*klpe_fb_pan_display)
#define klpr_fb_blank (*klpe_fb_blank)
#define klpr_fb_set_cmap (*klpe_fb_set_cmap)
#define klpr_fb_var_to_videomode (*klpe_fb_var_to_videomode)
#define klpr_fb_add_videomode (*klpe_fb_add_videomode)
#else
#error "klp-ccp: non-taken branch"
#endif

static int fb_check_caps(struct fb_info *info, struct fb_var_screeninfo *var,
			 u32 activate)
{
	struct fb_event event;
	struct fb_blit_caps caps, fbcaps;
	int err = 0;

	memset(&caps, 0, sizeof(caps));
	memset(&fbcaps, 0, sizeof(fbcaps));
	caps.flags = (activate & FB_ACTIVATE_ALL) ? 1 : 0;
	event.info = info;
	event.data = &caps;
	fb_notifier_call_chain(FB_EVENT_GET_REQ, &event);
	info->fbops->fb_get_caps(info, &fbcaps, var);

	if (((fbcaps.x ^ caps.x) & caps.x) ||
	    ((fbcaps.y ^ caps.y) & caps.y) ||
	    (fbcaps.len < caps.len))
		err = -EINVAL;

	return err;
}

int
klpp_fb_set_var(struct fb_info *info, struct fb_var_screeninfo *var)
{
	int flags = info->flags;
	int ret = 0;
	u32 unused;

	/* verify that virtual resolution >= physical resolution */
	if (var->xres_virtual < var->xres ||
	    var->yres_virtual < var->yres) {
		pr_warn("WARNING: fbcon: Driver '%s' missed to adjust virtual screen size (%ux%u vs. %ux%u)\n",
			info->fix.id,
			var->xres_virtual, var->yres_virtual,
			var->xres, var->yres);
		return -EINVAL;
	}

	if (var->activate & FB_ACTIVATE_INV_MODE) {
		struct fb_videomode mode1, mode2;

		klpr_fb_var_to_videomode(&mode1, var);
		klpr_fb_var_to_videomode(&mode2, &info->var);
		/* make sure we don't delete the videomode of current var */
		ret = klpr_fb_mode_is_equal(&mode1, &mode2);

		if (!ret) {
		    struct fb_event event;

		    event.info = info;
		    event.data = &mode1;
		    ret = fb_notifier_call_chain(FB_EVENT_MODE_DELETE, &event);
		}

		if (!ret)
		    (*klpe_fb_delete_videomode)(&mode1, &info->modelist);


		ret = (ret) ? -EINVAL : 0;
		goto done;
	}

	if ((var->activate & FB_ACTIVATE_FORCE) ||
	    memcmp(&info->var, var, sizeof(struct fb_var_screeninfo))) {
		u32 activate = var->activate;

		/* When using FOURCC mode, make sure the red, green, blue and
		 * transp fields are set to 0.
		 */
		if ((info->fix.capabilities & FB_CAP_FOURCC) &&
		    var->grayscale > 1) {
			if (var->red.offset     || var->green.offset    ||
			    var->blue.offset    || var->transp.offset   ||
			    var->red.length     || var->green.length    ||
			    var->blue.length    || var->transp.length   ||
			    var->red.msb_right  || var->green.msb_right ||
			    var->blue.msb_right || var->transp.msb_right)
				return -EINVAL;
		}

		if (!info->fbops->fb_check_var) {
			*var = info->var;
			goto done;
		}

		/* bitfill_aligned() assumes that it's at least 8x8 */
		if (var->xres < 8 || var->yres < 8)
			return -EINVAL;

		/* Too huge resolution causes multiplication overflow. */
		if (check_mul_overflow(var->xres, var->yres, &unused) ||
		    check_mul_overflow(var->xres_virtual, var->yres_virtual, &unused))
			return -EINVAL;

		ret = info->fbops->fb_check_var(var, info);

		if (ret)
			goto done;

		if ((var->activate & FB_ACTIVATE_MASK) == FB_ACTIVATE_NOW) {
			struct fb_var_screeninfo old_var;
			struct fb_videomode mode;

			if (info->fbops->fb_get_caps) {
				ret = fb_check_caps(info, var, activate);

				if (ret)
					goto done;
			}

			old_var = info->var;
			info->var = *var;

			if (info->fbops->fb_set_par) {
				ret = info->fbops->fb_set_par(info);

				if (ret) {
					info->var = old_var;
					printk(KERN_WARNING "detected "
						"fb_set_par error, "
						"error code: %d\n", ret);
					goto done;
				}
			}

			klpr_fb_pan_display(info, &info->var);
			klpr_fb_set_cmap(&info->cmap, info);
			klpr_fb_var_to_videomode(&mode, &info->var);

			if (info->modelist.prev && info->modelist.next &&
			    !list_empty(&info->modelist))
				ret = klpr_fb_add_videomode(&mode, &info->modelist);

			if (!ret && (flags & FBINFO_MISC_USEREVENT)) {
				struct fb_event event;
				int evnt = (activate & FB_ACTIVATE_ALL) ?
					FB_EVENT_MODE_CHANGE_ALL :
					FB_EVENT_MODE_CHANGE;

				info->flags &= ~FBINFO_MISC_USEREVENT;
				event.info = info;
				event.data = &mode;
				fb_notifier_call_chain(evnt, &event);
			}
		}
	}

 done:
	return ret;
}

long klpp_do_fb_ioctl(struct fb_info *info, unsigned int cmd,
			unsigned long arg)
{
	struct fb_ops *fb;
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	struct fb_con2fbmap con2fb;
	struct fb_cmap cmap_from;
	struct fb_cmap_user cmap;
	struct fb_event event;
	void __user *argp = (void __user *)arg;
	long ret = 0;

	switch (cmd) {
	case FBIOGET_VSCREENINFO:
		if (!klpr_lock_fb_info(info))
			return -ENODEV;
		var = info->var;
		unlock_fb_info(info);

		ret = copy_to_user(argp, &var, sizeof(var)) ? -EFAULT : 0;
		break;
	case FBIOPUT_VSCREENINFO:
		if (copy_from_user(&var, argp, sizeof(var)))
			return -EFAULT;
		console_lock();
		if (!klpr_lock_fb_info(info)) {
			console_unlock();
			return -ENODEV;
		}
		info->flags |= FBINFO_MISC_USEREVENT;
		event.info = info;
		event.data = &var;
		ret = fb_notifier_call_chain(FB_EVENT_MODE_CHANGE_CHECK, &event);
		ret = notifier_to_errno(ret);
		if (!ret)
			ret = klpp_fb_set_var(info, &var);
		info->flags &= ~FBINFO_MISC_USEREVENT;
		unlock_fb_info(info);
		console_unlock();
		if (!ret && copy_to_user(argp, &var, sizeof(var)))
			ret = -EFAULT;
		break;
	case FBIOGET_FSCREENINFO:
		if (!klpr_lock_fb_info(info))
			return -ENODEV;
		memcpy(&fix, &info->fix, sizeof(fix));
		unlock_fb_info(info);

		ret = copy_to_user(argp, &fix, sizeof(fix)) ? -EFAULT : 0;
		break;
	case FBIOPUTCMAP:
		if (copy_from_user(&cmap, argp, sizeof(cmap)))
			return -EFAULT;
		ret = (*klpe_fb_set_user_cmap)(&cmap, info);
		break;
	case FBIOGETCMAP:
		if (copy_from_user(&cmap, argp, sizeof(cmap)))
			return -EFAULT;
		if (!klpr_lock_fb_info(info))
			return -ENODEV;
		cmap_from = info->cmap;
		unlock_fb_info(info);
		ret = (*klpe_fb_cmap_to_user)(&cmap_from, &cmap);
		break;
	case FBIOPAN_DISPLAY:
		if (copy_from_user(&var, argp, sizeof(var)))
			return -EFAULT;
		console_lock();
		if (!klpr_lock_fb_info(info)) {
			console_unlock();
			return -ENODEV;
		}
		ret = klpr_fb_pan_display(info, &var);
		unlock_fb_info(info);
		console_unlock();
		if (ret == 0 && copy_to_user(argp, &var, sizeof(var)))
			return -EFAULT;
		break;
	case FBIO_CURSOR:
		ret = -EINVAL;
		break;
	case FBIOGET_CON2FBMAP:
		if (copy_from_user(&con2fb, argp, sizeof(con2fb)))
			return -EFAULT;
		if (con2fb.console < 1 || con2fb.console > MAX_NR_CONSOLES)
			return -EINVAL;
		con2fb.framebuffer = -1;
		event.data = &con2fb;
		if (!klpr_lock_fb_info(info))
			return -ENODEV;
		event.info = info;
		fb_notifier_call_chain(FB_EVENT_GET_CONSOLE_MAP, &event);
		unlock_fb_info(info);
		ret = copy_to_user(argp, &con2fb, sizeof(con2fb)) ? -EFAULT : 0;
		break;
	case FBIOPUT_CON2FBMAP:
		if (copy_from_user(&con2fb, argp, sizeof(con2fb)))
			return -EFAULT;
		if (con2fb.console < 1 || con2fb.console > MAX_NR_CONSOLES)
			return -EINVAL;
		if (con2fb.framebuffer >= FB_MAX)
			return -EINVAL;
		if (!klpr_registered_fb[con2fb.framebuffer])
			request_module("fb%d", con2fb.framebuffer);
		if (!klpr_registered_fb[con2fb.framebuffer]) {
			ret = -EINVAL;
			break;
		}
		event.data = &con2fb;
		console_lock();
		if (!klpr_lock_fb_info(info)) {
			console_unlock();
			return -ENODEV;
		}
		event.info = info;
		ret = fb_notifier_call_chain(FB_EVENT_SET_CONSOLE_MAP, &event);
		unlock_fb_info(info);
		console_unlock();
		break;
	case FBIOBLANK:
		console_lock();
		if (!klpr_lock_fb_info(info)) {
			console_unlock();
			return -ENODEV;
		}
		info->flags |= FBINFO_MISC_USEREVENT;
		ret = klpr_fb_blank(info, arg);
		info->flags &= ~FBINFO_MISC_USEREVENT;
		unlock_fb_info(info);
		console_unlock();
		break;
	default:
		if (!klpr_lock_fb_info(info))
			return -ENODEV;
		fb = info->fbops;
		if (fb->fb_ioctl)
			ret = fb->fb_ioctl(info, cmd, arg);
		else
			ret = -ENOTTY;
		unlock_fb_info(info);
	}
	return ret;
}



#include <linux/kernel.h>
#include "livepatch_bsc1202087.h"
#include "../kallsyms_relocs.h"

#if defined(CONFIG_S390)
static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fb_cmap_to_user", (void *)&klpe_fb_cmap_to_user, "fb" },
	{ "fb_delete_videomode", (void *)&klpe_fb_delete_videomode, "fb" },
	{ "fb_set_user_cmap", (void *)&klpe_fb_set_user_cmap, "fb" },
	{ "registered_fb", (void *)&klpe_registered_fb, "fb" },
	{ "lock_fb_info", (void *)&klpe_lock_fb_info, "fb" },
	{ "fb_pan_display", (void *)&klpe_fb_pan_display, "fb" },
	{ "fb_blank", (void *)&klpe_fb_blank, "fb" },
	{ "fb_set_cmap", (void *)&klpe_fb_set_cmap, "fb" },
	{ "fb_mode_is_equal", (void *)&klpe_fb_mode_is_equal, "fb" },
	{ "fb_var_to_videomode", (void *)&klpe_fb_var_to_videomode, "fb" },
	{ "fb_add_videomode", (void *)&klpe_fb_add_videomode, "fb" },
};
#elif defined(CONFIG_X86_64) || defined(CONFIG_PPC64)
static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fb_cmap_to_user", (void *)&klpe_fb_cmap_to_user },
	{ "fb_delete_videomode", (void *)&klpe_fb_delete_videomode },
	{ "fb_set_user_cmap", (void *)&klpe_fb_set_user_cmap },
};
#else
#error "klp-ccp: non-taken branch"
#endif

#if defined(CONFIG_S390)
#define LP_MODULE "fb"

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

int bsc1202087_fbmem_init(void)
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

void bsc1202087_fbmem_cleanup(void)
{
	unregister_module_notifier(&bsc1202087_module_nb);
}

#elif defined(CONFIG_X86_64) || defined(CONFIG_PPC64)
int bsc1202087_fbmem_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

void bsc1202087_fbmem_cleanup(void)
{
}
#else
#error "klp-ccp: non-taken branch"
#endif

#endif /* IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE) */
