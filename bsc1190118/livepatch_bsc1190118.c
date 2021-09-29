/*
 * livepatch_bsc1190118
 *
 * Fix for CVE-2021-38160, bsc#1190118
 *
 *  Upstream commit:
 *  d00d8da5869a ("virtio_console: Assure used length from device is limited")
 *
 *  SLE12-SP3 commit:
 *  a2f99279e171461b837d8936bf78349dcc8c24f5
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  495fc27ce1e8e6c5c2d95f2591f67801891d7fa7
 *
 *  SLE15-SP2 and -SP3 commit:
 *  966e79d238b464f512b740dd8075306e1015fdcb
 *
 *
 *  Copyright (c) 2021 SUSE
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

/* klp-ccp: from drivers/char/virtio_console.c */
#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/virtio_console.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/dma-mapping.h>
/* klp-ccp: from drivers/tty/hvc/hvc_console.h */
#include <linux/kref.h>
#include <linux/tty.h>
#include <linux/spinlock.h>

struct hvc_struct {
	struct tty_port port;
	spinlock_t lock;
	int index;
	int do_wakeup;
	char *outbuf;
	int outbuf_size;
	int n_outbuf;
	uint32_t vtermno;
	const struct hv_ops *ops;
	int irq_requested;
	int data;
	struct winsize ws;
	struct work_struct tty_resize;
	struct list_head next;
	unsigned long flags;
};

int hvc_poll(struct hvc_struct *hp);
void hvc_kick(void);

/* klp-ccp: from drivers/char/virtio_console.c */
#define is_rproc_enabled IS_ENABLED(CONFIG_REMOTEPROC)

static struct completion (*klpe_early_console_added);

struct console {
	/* We'll place all consoles in a list in the pdrvdata struct */
	struct list_head list;

	/* The hvc device associated with this console port */
	struct hvc_struct *hvc;

	/* The size of the console */
	struct winsize ws;

	/*
	 * This number identifies the number that we used to register
	 * with hvc in hvc_instantiate() and hvc_alloc(); this is the
	 * number passed on by the hvc callbacks to us to
	 * differentiate between the other console ports handled by
	 * this driver
	 */
	u32 vtermno;
};

struct port_buffer {
	char *buf;

	/* size of the buffer in *buf above */
	size_t size;

	/* used length of the buffer */
	size_t len;
	/* offset in the buf from which to consume data */
	size_t offset;

	/* DMA address of buffer */
	dma_addr_t dma;

	/* Device we got DMA memory from */
	struct device *dev;

	/* List of pending dma buffers to free */
	struct list_head list;

	/* If sgpages == 0 then buf is used */
	unsigned int sgpages;

	/* sg is used if spages > 0. sg must be the last in is struct */
	struct scatterlist sg[0];
};

struct ports_device {
	/* Next portdev in the list, head is in the pdrvdata struct */
	struct list_head list;

	/*
	 * Workqueue handlers where we process deferred work after
	 * notification
	 */
	struct work_struct control_work;
	struct work_struct config_work;

	struct list_head ports;

	/* To protect the list of ports */
	spinlock_t ports_lock;

	/* To protect the vq operations for the control channel */
	spinlock_t c_ivq_lock;
	spinlock_t c_ovq_lock;

	/* max. number of ports this device can hold */
	u32 max_nr_ports;

	/* The virtio device we're associated with */
	struct virtio_device *vdev;

	/*
	 * A couple of virtqueues for the control channel: one for
	 * guest->host transfers, one for host->guest transfers
	 */
	struct virtqueue *c_ivq, *c_ovq;

	/*
	 * A control packet buffer for guest->host requests, protected
	 * by c_ovq_lock.
	 */
	struct virtio_console_control cpkt;

	/* Array of per-port IO virtqueues */
	struct virtqueue **in_vqs, **out_vqs;

	/* Major number for this device.  Ports will be created as minors. */
	int chr_major;
};

struct port_stats {
	unsigned long bytes_sent, bytes_received, bytes_discarded;
};

struct port {
	/* Next port in the list, head is in the ports_device */
	struct list_head list;

	/* Pointer to the parent virtio_console device */
	struct ports_device *portdev;

	/* The current buffer from which data has to be fed to readers */
	struct port_buffer *inbuf;

	/*
	 * To protect the operations on the in_vq associated with this
	 * port.  Has to be a spinlock because it can be called from
	 * interrupt context (get_char()).
	 */
	spinlock_t inbuf_lock;

	/* Protect the operations on the out_vq. */
	spinlock_t outvq_lock;

	/* The IO vqs for this port */
	struct virtqueue *in_vq, *out_vq;

	/* File in the debugfs directory that exposes this port's information */
	struct dentry *debugfs_file;

	/*
	 * Keep count of the bytes sent, received and discarded for
	 * this port for accounting and debugging purposes.  These
	 * counts are not reset across port open / close events.
	 */
	struct port_stats stats;

	/*
	 * The entries in this struct will be valid if this port is
	 * hooked up to an hvc console
	 */
	struct console cons;

	/* Each port associates with a separate char device */
	struct cdev *cdev;
	struct device *dev;

	/* Reference-counting to handle port hot-unplugs and file operations */
	struct kref kref;

	/* A waitqueue for poll() or blocking read operations */
	wait_queue_head_t waitqueue;

	/* The 'name' of the port that we expose via sysfs properties */
	char *name;

	/* We can notify apps of host connect / disconnect events via SIGIO */
	struct fasync_struct *async_queue;

	/* The 'id' to identify the port with the Host */
	u32 id;

	bool outvq_full;

	/* Is the host device open */
	bool host_connected;

	/* We should allow only one process to open a port */
	bool guest_connected;
};

static struct port *(*klpe_find_port_by_id)(struct ports_device *portdev, u32 id);

static struct port *(*klpe_find_port_by_vq)(struct ports_device *portdev,
				    struct virtqueue *vq);

static bool is_console_port(struct port *port)
{
	if (port->cons.hvc)
		return true;
	return false;
}

static bool is_rproc_serial(const struct virtio_device *vdev)
{
	return is_rproc_enabled && vdev->id.device == VIRTIO_ID_RPROC_SERIAL;
}

static spinlock_t (*klpe_dma_bufs_lock);
static struct list_head (*klpe_pending_free_dma_bufs);

static void klpr_free_buf(struct port_buffer *buf, bool can_sleep)
{
	unsigned int i;

	for (i = 0; i < buf->sgpages; i++) {
		struct page *page = sg_page(&buf->sg[i]);
		if (!page)
			break;
		put_page(page);
	}

	if (!buf->dev) {
		kfree(buf->buf);
	} else if (is_rproc_enabled) {
		unsigned long flags;

		/* dma_free_coherent requires interrupts to be enabled. */
		if (!can_sleep) {
			/* queue up dma-buffers to be freed later */
			spin_lock_irqsave(&(*klpe_dma_bufs_lock), flags);
			list_add_tail(&buf->list, &(*klpe_pending_free_dma_bufs));
			spin_unlock_irqrestore(&(*klpe_dma_bufs_lock), flags);
			return;
		}
		dma_free_coherent(buf->dev, buf->size, buf->buf, buf->dma);

		/* Release device refcnt and allow it to be freed */
		put_device(buf->dev);
	}

	kfree(buf);
}

static struct port_buffer *klpp_get_inbuf(struct port *port)
{
	struct port_buffer *buf;
	unsigned int len;

	if (port->inbuf)
		return port->inbuf;

	buf = virtqueue_get_buf(port->in_vq, &len);
	if (buf) {
		/*
		 * Fix CVE-2021-38160
		 *  -1 line, +1 line
		 */
		buf->len = min_t(size_t, len, buf->size);
		buf->offset = 0;
		port->stats.bytes_received += len;
	}
	return buf;
}

static int (*klpe_add_inbuf)(struct virtqueue *vq, struct port_buffer *buf);

void klpp_discard_port_data(struct port *port)
{
	struct port_buffer *buf;
	unsigned int err;

	if (!port->portdev) {
		/* Device has been unplugged.  vqs are already gone. */
		return;
	}
	buf = klpp_get_inbuf(port);

	err = 0;
	while (buf) {
		port->stats.bytes_discarded += buf->len - buf->offset;
		if ((*klpe_add_inbuf)(port->in_vq, buf) < 0) {
			err++;
			klpr_free_buf(buf, false);
		}
		port->inbuf = NULL;
		buf = klpp_get_inbuf(port);
	}
	if (err)
		dev_warn(port->dev, "Errors adding %d buffers back to vq\n",
			 err);
}

bool klpp_port_has_data(struct port *port)
{
	unsigned long flags;
	bool ret;

	ret = false;
	spin_lock_irqsave(&port->inbuf_lock, flags);
	port->inbuf = klpp_get_inbuf(port);
	if (port->inbuf)
		ret = true;

	spin_unlock_irqrestore(&port->inbuf_lock, flags);
	return ret;
}

static ssize_t (*klpe___send_control_msg)(struct ports_device *portdev, u32 port_id,
				  unsigned int event, unsigned int value);

static ssize_t klpr_send_control_msg(struct port *port, unsigned int event,
				unsigned int value)
{
	/* Did the port get unplugged before userspace closed it? */
	if (port->portdev)
		return (*klpe___send_control_msg)(port->portdev, port->id, event, value);
	return 0;
}

static void (*klpe_reclaim_consumed_buffers)(struct port *port);

static void (*klpe_resize_console)(struct port *port);

static int (*klpe_init_port_console)(struct port *port);

static struct attribute_group (*klpe_port_attribute_group);

static void set_console_size(struct port *port, u16 rows, u16 cols)
{
	if (!port || !is_console_port(port))
		return;

	port->cons.ws.ws_row = rows;
	port->cons.ws.ws_col = cols;
}

static void send_sigio_to_port(struct port *port)
{
	if (port->async_queue && port->guest_connected)
		kill_fasync(&port->async_queue, SIGIO, POLL_OUT);
}

static int (*klpe_add_port)(struct ports_device *portdev, u32 id);

static void (*klpe_unplug_port)(struct port *port);

static void klpr_handle_control_message(struct virtio_device *vdev,
				   struct ports_device *portdev,
				   struct port_buffer *buf)
{
	struct virtio_console_control *cpkt;
	struct port *port;
	size_t name_size;
	int err;

	cpkt = (struct virtio_console_control *)(buf->buf + buf->offset);

	port = (*klpe_find_port_by_id)(portdev, virtio32_to_cpu(vdev, cpkt->id));
	if (!port &&
	    cpkt->event != cpu_to_virtio16(vdev, VIRTIO_CONSOLE_PORT_ADD)) {
		/* No valid header at start of buffer.  Drop it. */
		dev_dbg(&portdev->vdev->dev,
			"Invalid index %u in control packet\n", cpkt->id);
		return;
	}

	switch (virtio16_to_cpu(vdev, cpkt->event)) {
	case VIRTIO_CONSOLE_PORT_ADD:
		if (port) {
			dev_dbg(&portdev->vdev->dev,
				"Port %u already added\n", port->id);
			klpr_send_control_msg(port, VIRTIO_CONSOLE_PORT_READY, 1);
			break;
		}
		if (virtio32_to_cpu(vdev, cpkt->id) >=
		    portdev->max_nr_ports) {
			dev_warn(&portdev->vdev->dev,
				"Request for adding port with "
				"out-of-bound id %u, max. supported id: %u\n",
				cpkt->id, portdev->max_nr_ports - 1);
			break;
		}
		(*klpe_add_port)(portdev, virtio32_to_cpu(vdev, cpkt->id));
		break;
	case VIRTIO_CONSOLE_PORT_REMOVE:
		(*klpe_unplug_port)(port);
		break;
	case VIRTIO_CONSOLE_CONSOLE_PORT:
		if (!cpkt->value)
			break;
		if (is_console_port(port))
			break;

		(*klpe_init_port_console)(port);
		complete(&(*klpe_early_console_added));
		/*
		 * Could remove the port here in case init fails - but
		 * have to notify the host first.
		 */
		break;
	case VIRTIO_CONSOLE_RESIZE: {
		struct {
			__u16 rows;
			__u16 cols;
		} size;

		if (!is_console_port(port))
			break;

		memcpy(&size, buf->buf + buf->offset + sizeof(*cpkt),
		       sizeof(size));
		set_console_size(port, size.rows, size.cols);

		port->cons.hvc->irq_requested = 1;
		(*klpe_resize_console)(port);
		break;
	}
	case VIRTIO_CONSOLE_PORT_OPEN:
		port->host_connected = virtio16_to_cpu(vdev, cpkt->value);
		wake_up_interruptible(&port->waitqueue);
		/*
		 * If the host port got closed and the host had any
		 * unconsumed buffers, we'll be able to reclaim them
		 * now.
		 */
		spin_lock_irq(&port->outvq_lock);
		(*klpe_reclaim_consumed_buffers)(port);
		spin_unlock_irq(&port->outvq_lock);

		/*
		 * If the guest is connected, it'll be interested in
		 * knowing the host connection state changed.
		 */
		spin_lock_irq(&port->inbuf_lock);
		send_sigio_to_port(port);
		spin_unlock_irq(&port->inbuf_lock);
		break;
	case VIRTIO_CONSOLE_PORT_NAME:
		/*
		 * If we woke up after hibernation, we can get this
		 * again.  Skip it in that case.
		 */
		if (port->name)
			break;

		/*
		 * Skip the size of the header and the cpkt to get the size
		 * of the name that was sent
		 */
		name_size = buf->len - buf->offset - sizeof(*cpkt) + 1;

		port->name = kmalloc(name_size, GFP_KERNEL);
		if (!port->name) {
			dev_err(port->dev,
				"Not enough space to store port name\n");
			break;
		}
		strncpy(port->name, buf->buf + buf->offset + sizeof(*cpkt),
			name_size - 1);
		port->name[name_size - 1] = 0;

		/*
		 * Since we only have one sysfs attribute, 'name',
		 * create it only if we have a name for the port.
		 */
		err = sysfs_create_group(&port->dev->kobj,
					 &(*klpe_port_attribute_group));
		if (err) {
			dev_err(port->dev,
				"Error %d creating sysfs device attributes\n",
				err);
		} else {
			/*
			 * Generate a udev event so that appropriate
			 * symlinks can be created based on udev
			 * rules.
			 */
			kobject_uevent(&port->dev->kobj, KOBJ_CHANGE);
		}
		break;
	}
}

void klpp_control_work_handler(struct work_struct *work)
{
	struct ports_device *portdev;
	struct virtqueue *vq;
	struct port_buffer *buf;
	unsigned int len;

	portdev = container_of(work, struct ports_device, control_work);
	vq = portdev->c_ivq;

	spin_lock(&portdev->c_ivq_lock);
	while ((buf = virtqueue_get_buf(vq, &len))) {
		spin_unlock(&portdev->c_ivq_lock);

		/*
		 * Fix CVE-2021-38160
		 *  -1 line, +1 line
		 */
		buf->len = min_t(size_t, len, buf->size);
		buf->offset = 0;

		klpr_handle_control_message(vq->vdev, portdev, buf);

		spin_lock(&portdev->c_ivq_lock);
		if ((*klpe_add_inbuf)(portdev->c_ivq, buf) < 0) {
			dev_warn(&portdev->vdev->dev,
				 "Error adding buffer to queue\n");
			klpr_free_buf(buf, false);
		}
	}
	spin_unlock(&portdev->c_ivq_lock);
}

static void klpr_flush_bufs(struct virtqueue *vq, bool can_sleep)
{
	struct port_buffer *buf;
	unsigned int len;

	while ((buf = virtqueue_get_buf(vq, &len)))
		klpr_free_buf(buf, can_sleep);
}

void klpp_in_intr(struct virtqueue *vq)
{
	struct port *port;
	unsigned long flags;

	port = (*klpe_find_port_by_vq)(vq->vdev->priv, vq);
	if (!port) {
		klpr_flush_bufs(vq, false);
		return;
	}

	spin_lock_irqsave(&port->inbuf_lock, flags);
	port->inbuf = klpp_get_inbuf(port);

	/*
	 * Normally the port should not accept data when the port is
	 * closed. For generic serial ports, the host won't (shouldn't)
	 * send data till the guest is connected. But this condition
	 * can be reached when a console port is not yet connected (no
	 * tty is spawned) and the other side sends out data over the
	 * vring, or when a remote devices start sending data before
	 * the ports are opened.
	 *
	 * A generic serial port will discard data if not connected,
	 * while console ports and rproc-serial ports accepts data at
	 * any time. rproc-serial is initiated with guest_connected to
	 * false because port_fops_open expects this. Console ports are
	 * hooked up with an HVC console and is initialized with
	 * guest_connected to true.
	 */

	if (!port->guest_connected && !is_rproc_serial(port->portdev->vdev))
		klpp_discard_port_data(port);

	/* Send a SIGIO indicating new data in case the process asked for it */
	send_sigio_to_port(port);

	spin_unlock_irqrestore(&port->inbuf_lock, flags);

	wake_up_interruptible(&port->waitqueue);

	if (is_console_port(port) && hvc_poll(port->cons.hvc))
		hvc_kick();
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1190118.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "early_console_added", (void *)&klpe_early_console_added },
	{ "pending_free_dma_bufs", (void *)&klpe_pending_free_dma_bufs },
	{ "dma_bufs_lock", (void *)&klpe_dma_bufs_lock },
	{ "port_attribute_group", (void *)&klpe_port_attribute_group },
	{ "find_port_by_id", (void *)&klpe_find_port_by_id },
	{ "reclaim_consumed_buffers", (void *)&klpe_reclaim_consumed_buffers },
	{ "find_port_by_vq", (void *)&klpe_find_port_by_vq },
	{ "__send_control_msg", (void *)&klpe___send_control_msg },
	{ "add_inbuf", (void *)&klpe_add_inbuf },
	{ "resize_console", (void *)&klpe_resize_console },
	{ "init_port_console", (void *)&klpe_init_port_console },
	{ "add_port", (void *)&klpe_add_port },
	{ "unplug_port", (void *)&klpe_unplug_port },
};

int livepatch_bsc1190118_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
