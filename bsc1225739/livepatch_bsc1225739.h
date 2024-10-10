#ifndef _LIVEPATCH_BSC1225739_H
#define _LIVEPATCH_BSC1225739_H

#if IS_ENABLED(CONFIG_GPIO_CDEV)

int klpp_gpio_chrdev_release(struct inode *inode, struct file *file);

#endif /* IS_ENABLED(CONFIG_GPIO_CDEV) */

static inline int livepatch_bsc1225739_init(void) { return 0; }
static inline void livepatch_bsc1225739_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1225739_H */
