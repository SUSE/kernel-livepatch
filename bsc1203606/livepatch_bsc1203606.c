/*
 * livepatch_bsc1203606
 *
 * Fix for CVE-2022-41218, bsc#1203606
 *
 *  Upstream commit:
 *  None yet
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  231362ab4c29ef0e20575dbd887a1f782bb9a972
 *
 *  SLE15-SP2 and -SP3 commit:
 *  260d9857f92ce083e1b970d0cb1dbf82af6d7d26
 *
 *  SLE15-SP4 commit:
 *  bdcd7abd6fce9d77cd1f5d7d02665858820fcbde
 *
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if IS_ENABLED(CONFIG_DVB_CORE)

#if !IS_MODULE(CONFIG_DVB_CORE)
#error "Live patch supports only CONFIG_DVB_CORE=m"
#endif

/* klp-ccp: from drivers/media/dvb-core/dmxdev.c */
#define pr_fmt(fmt) "dmxdev: " fmt

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/ioctl.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
/* klp-ccp: from drivers/media/dvb-core/dmxdev.h */
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/dvb/dmx.h>
/* klp-ccp: from drivers/media/dvb-core/dvbdev.h */
#include <linux/types.h>
#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/list.h>

struct dvb_device {
	struct list_head list_head;
	const struct file_operations *fops;
	struct dvb_adapter *adapter;
	int type;
	int minor;
	u32 id;

	/* in theory, 'users' can vanish now,
	   but I don't want to change too much now... */
	int readers;
	int writers;
	int users;

	wait_queue_head_t	  wait_queue;
	/* don't really need those !? -- FIXME: use video_usercopy  */
	int (*kernel_ioctl)(struct file *file, unsigned int cmd, void *arg);

#if defined(CONFIG_MEDIA_CONTROLLER_DVB)
#error "klp-ccp: non-taken branch"
#endif
	void *priv;
};

static void (*klpe_dvb_unregister_device)(struct dvb_device *dvbdev);

/* klp-ccp: from drivers/media/dvb-core/demux.h */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/time.h>
#include <linux/dvb/dmx.h>

struct dmx_ts_feed;

struct dmx_section_filter;

struct dmx_section_feed;

typedef int (*dmx_ts_cb)(const u8 *buffer1,
			 size_t buffer1_length,
			 const u8 *buffer2,
			 size_t buffer2_length,
			 struct dmx_ts_feed *source);

typedef int (*dmx_section_cb)(const u8 *buffer1,
			      size_t buffer1_len,
			      const u8 *buffer2,
			      size_t buffer2_len,
			      struct dmx_section_filter *source);

enum dmx_demux_caps {
	DMX_TS_FILTERING = 1,
	DMX_SECTION_FILTERING = 4,
	DMX_MEMORY_BASED_FILTERING = 8,
};

struct dmx_demux {
	enum dmx_demux_caps capabilities;
	struct dmx_frontend *frontend;
	void *priv;
	int (*open)(struct dmx_demux *demux);
	int (*close)(struct dmx_demux *demux);
	int (*write)(struct dmx_demux *demux, const char __user *buf,
		     size_t count);
	int (*allocate_ts_feed)(struct dmx_demux *demux,
				struct dmx_ts_feed **feed,
				dmx_ts_cb callback);
	int (*release_ts_feed)(struct dmx_demux *demux,
			       struct dmx_ts_feed *feed);
	int (*allocate_section_feed)(struct dmx_demux *demux,
				     struct dmx_section_feed **feed,
				     dmx_section_cb callback);
	int (*release_section_feed)(struct dmx_demux *demux,
				    struct dmx_section_feed *feed);
	int (*add_frontend)(struct dmx_demux *demux,
			    struct dmx_frontend *frontend);
	int (*remove_frontend)(struct dmx_demux *demux,
			       struct dmx_frontend *frontend);
	struct list_head *(*get_frontends)(struct dmx_demux *demux);
	int (*connect_frontend)(struct dmx_demux *demux,
				struct dmx_frontend *frontend);
	int (*disconnect_frontend)(struct dmx_demux *demux);

	int (*get_pes_pids)(struct dmx_demux *demux, u16 *pids);

	/* private: */

	/*
	 * Only used at av7110, to read some data from firmware.
	 * As this was never documented, we have no clue about what's
	 * there, and its usage on other drivers aren't encouraged.
	 */
	int (*get_stc)(struct dmx_demux *demux, unsigned int num,
		       u64 *stc, unsigned int *base);
};

/* klp-ccp: from drivers/media/dvb-core/dvb_ringbuffer.h */
#include <linux/spinlock.h>
#include <linux/wait.h>

struct dvb_ringbuffer {
	u8               *data;
	ssize_t           size;
	ssize_t           pread;
	ssize_t           pwrite;
	int               error;

	wait_queue_head_t queue;
	spinlock_t        lock;
};

static void (*klpe_dvb_ringbuffer_init)(struct dvb_ringbuffer *rbuf, void *data,
				size_t len);

/* klp-ccp: from drivers/media/dvb-core/dmxdev.h */
enum dmxdev_type {
	DMXDEV_TYPE_NONE,
	DMXDEV_TYPE_SEC,
	DMXDEV_TYPE_PES,
};

enum dmxdev_state {
	DMXDEV_STATE_FREE,
	DMXDEV_STATE_ALLOCATED,
	DMXDEV_STATE_SET,
	DMXDEV_STATE_GO,
	DMXDEV_STATE_DONE,
	DMXDEV_STATE_TIMEDOUT
};

struct dmxdev_filter {
	union {
		struct dmx_section_filter *sec;
	} filter;

	union {
		/* list of TS and PES feeds (struct dmxdev_feed) */
		struct list_head ts;
		struct dmx_section_feed *sec;
	} feed;

	union {
		struct dmx_sct_filter_params sec;
		struct dmx_pes_filter_params pes;
	} params;

	enum dmxdev_type type;
	enum dmxdev_state state;
	struct dmxdev *dev;
	struct dvb_ringbuffer buffer;

	struct mutex mutex;

	/* only for sections */
	struct timer_list timer;
	int todo;
	u8 secheader[3];
};

struct dmxdev {
	struct dvb_device *dvbdev;
	struct dvb_device *dvr_dvbdev;

	struct dmxdev_filter *filter;
	struct dmx_demux *demux;

	int filternum;
	int capabilities;

	unsigned int exit:1;
	struct dmx_frontend *dvr_orig_fe;

	struct dvb_ringbuffer dvr_buffer;

	struct mutex mutex;
	spinlock_t lock;
};

void klpp_dvb_dmxdev_release(struct dmxdev *dmxdev);

/* klp-ccp: from drivers/media/dvb-core/dmxdev.c */
static inline void dvb_dmxdev_filter_state_set(struct dmxdev_filter
					       *dmxdevfilter, int state)
{
	spin_lock_irq(&dmxdevfilter->dev->lock);
	dmxdevfilter->state = state;
	spin_unlock_irq(&dmxdevfilter->dev->lock);
}

int klpp_dvb_demux_open(struct inode *inode, struct file *file)
{
	struct dvb_device *dvbdev = file->private_data;
	struct dmxdev *dmxdev = dvbdev->priv;
	int i;
	struct dmxdev_filter *dmxdevfilter;

	if (!dmxdev->filter)
		return -EINVAL;

	if (mutex_lock_interruptible(&dmxdev->mutex))
		return -ERESTARTSYS;

	/*
	 * Fix CVE-2022-41218
	 *  +4 lines
	 */
	if (dmxdev->exit) {
		mutex_unlock(&dmxdev->mutex);
		return -ENODEV;
	}

	for (i = 0; i < dmxdev->filternum; i++)
		if (dmxdev->filter[i].state == DMXDEV_STATE_FREE)
			break;

	if (i == dmxdev->filternum) {
		mutex_unlock(&dmxdev->mutex);
		return -EMFILE;
	}

	dmxdevfilter = &dmxdev->filter[i];
	mutex_init(&dmxdevfilter->mutex);
	file->private_data = dmxdevfilter;

	(*klpe_dvb_ringbuffer_init)(&dmxdevfilter->buffer, NULL, 8192);
	dmxdevfilter->type = DMXDEV_TYPE_NONE;
	dvb_dmxdev_filter_state_set(dmxdevfilter, DMXDEV_STATE_ALLOCATED);
	init_timer(&dmxdevfilter->timer);

	dvbdev->users++;

	mutex_unlock(&dmxdev->mutex);
	return 0;
}

void klpp_dvb_dmxdev_release(struct dmxdev *dmxdev)
{
	/*
	 * Fix CVE-2022-41218
	 *  -1 line, +3 lines
	 */
	mutex_lock(&dmxdev->mutex);
	dmxdev->exit = 1;
	mutex_unlock(&dmxdev->mutex);

	if (dmxdev->dvbdev->users > 1) {
		wait_event(dmxdev->dvbdev->wait_queue,
				dmxdev->dvbdev->users == 1);
	}
	if (dmxdev->dvr_dvbdev->users > 1) {
		wait_event(dmxdev->dvr_dvbdev->wait_queue,
				dmxdev->dvr_dvbdev->users == 1);
	}

	(*klpe_dvb_unregister_device)(dmxdev->dvbdev);
	(*klpe_dvb_unregister_device)(dmxdev->dvr_dvbdev);

	vfree(dmxdev->filter);
	dmxdev->filter = NULL;
	dmxdev->demux->close(dmxdev->demux);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1203606.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "dvb_core"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "dvb_ringbuffer_init", (void *)&klpe_dvb_ringbuffer_init,
	  "dvb_core" },
	{ "dvb_unregister_device", (void *)&klpe_dvb_unregister_device,
	  "dvb_core" },
};

static int livepatch_bsc1203606_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1203606_module_nb = {
	.notifier_call = livepatch_bsc1203606_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1203606_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1203606_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1203606_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1203606_module_nb);
}

#endif /* IS_ENABLED(CONFIG_DVB_CORE) */
