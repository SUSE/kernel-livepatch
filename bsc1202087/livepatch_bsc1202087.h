#ifndef _LIVEPATCH_BSC1202087_H
#define _LIVEPATCH_BSC1202087_H

#if IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE)

struct vc_data;
struct console_font;

int klpp_fbcon_set_font(struct vc_data *vc, struct console_font *font, unsigned flags);

struct notifier_block;

int klpp_fbcon_event_notify(struct notifier_block *self,
			      unsigned long action, void *data);

struct fb_info;
struct fb_var_screeninfo;

int
klpp_fb_set_var(struct fb_info *info, struct fb_var_screeninfo *var);

long klpp_do_fb_ioctl(struct fb_info *info, unsigned int cmd,
			unsigned long arg);

int bsc1202087_fbcon_init(void);
void bsc1202087_fbcon_cleanup(void);

int bsc1202087_fbmem_init(void);
void bsc1202087_fbmem_cleanup(void);

int livepatch_bsc1202087_init(void);
void livepatch_bsc1202087_cleanup(void);

#else /* !IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE) */

static inline int livepatch_bsc1202087_init(void) { return 0; }
static inline void livepatch_bsc1202087_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_FRAMEBUFFER_CONSOLE) */

#endif /* _LIVEPATCH_BSC1202087_H */
