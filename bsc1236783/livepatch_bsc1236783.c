/*
 * livepatch_bsc1236783
 *
 * Fix for CVE-2024-53104, bsc#1236783
 *
 *  Upstream commit:
 *  ecf2b43018da ("media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format")
 *
 *  SLE12-SP5 commit:
 *  5e374e6f596d3d5704dfd0efeab72dbdc91cc340
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  a0c98f3a2d23ab9fb6dc3d6c2c1c252ebdb95a27
 *
 *  SLE15-SP6 commit:
 *  a0907f284ed53dacbcc62e9b83d7b192cec7df9d
 *
 *  SLE MICRO-6-0 commit:
 *  a0907f284ed53dacbcc62e9b83d7b192cec7df9d
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_USB_VIDEO_CLASS)

#if !IS_MODULE(CONFIG_USB_VIDEO_CLASS)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/media/usb/uvc/uvc_driver.c */
#include <linux/atomic.h>
#include <linux/bits.h>

/* klp-ccp: from include/linux/gpio/consumer.h */
#define __LINUX_GPIO_CONSUMER_H

/* klp-ccp: from drivers/media/usb/uvc/uvc_driver.c */
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/usb/quirks.h>
#include <linux/usb/uvc.h>
#include <linux/videodev2.h>

/* klp-ccp: from include/linux/vmalloc.h */
#define _LINUX_VMALLOC_H

/* klp-ccp: from drivers/media/usb/uvc/uvc_driver.c */
#include <linux/wait.h>
#include <asm/unaligned.h>

#include <media/v4l2-common.h>

/* klp-ccp: from drivers/media/usb/uvc/uvcvideo.h */
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/usb.h>
#include <linux/usb/video.h>

#include <linux/videodev2.h>
#include <linux/workqueue.h>
#include <media/media-device.h>
#include <media/v4l2-device.h>

#include <media/v4l2-fh.h>
#include <media/videobuf2-v4l2.h>

#define UVC_TERM_INPUT			0x0000
#define UVC_TERM_OUTPUT			0x8000

#define UVC_ENTITY_TYPE(entity)		((entity)->type & 0x7fff)

#define UVC_URBS		5

#define UVC_MAX_PACKETS		32

#define UVC_QUIRK_RESTRICT_FRAME_RATE	0x00000200

#define UVC_QUIRK_FORCE_Y8		0x00000800
#define UVC_QUIRK_FORCE_BPP		0x00001000

#define UVC_FMT_FLAG_COMPRESSED		0x00000001
#define UVC_FMT_FLAG_STREAM		0x00000002

struct uvc_device;

struct uvc_entity {
	struct list_head list;		/* Entity as part of a UVC device. */
	struct list_head chain;		/* Entity as part of a video device chain. */
	unsigned int flags;

	/*
	 * Entities exposed by the UVC device use IDs 0-255, extra entities
	 * implemented by the driver (such as the GPIO entity) use IDs 256 and
	 * up.
	 */
	u16 id;
	u16 type;
	char name[64];
	u8 guid[16];

	/* Media controller-related fields. */
	struct video_device *vdev;
	struct v4l2_subdev subdev;
	unsigned int num_pads;
	unsigned int num_links;
	struct media_pad *pads;

	union {
		struct {
			u16 wObjectiveFocalLengthMin;
			u16 wObjectiveFocalLengthMax;
			u16 wOcularFocalLength;
			u8  bControlSize;
			u8  *bmControls;
		} camera;

		struct {
			u8  bControlSize;
			u8  *bmControls;
			u8  bTransportModeSize;
			u8  *bmTransportModes;
		} media;

		struct {
		} output;

		struct {
			u16 wMaxMultiplier;
			u8  bControlSize;
			u8  *bmControls;
			u8  bmVideoStandards;
		} processing;

		struct {
		} selector;

		struct {
			u8  bNumControls;
			u8  bControlSize;
			u8  *bmControls;
			u8  *bmControlsType;
		} extension;

		struct {
			u8  bControlSize;
			u8  *bmControls;
			struct gpio_desc *gpio_privacy;
			int irq;
		} gpio;
	};

	u8 bNrInPins;
	u8 *baSourceID;

	int (*get_info)(struct uvc_device *dev, struct uvc_entity *entity,
			u8 cs, u8 *caps);
	int (*get_cur)(struct uvc_device *dev, struct uvc_entity *entity,
		       u8 cs, void *data, u16 size);

	unsigned int ncontrols;
	struct uvc_control *controls;
};

struct uvc_frame {
	u8  bFrameIndex;
	u8  bmCapabilities;
	u16 wWidth;
	u16 wHeight;
	u32 dwMinBitRate;
	u32 dwMaxBitRate;
	u32 dwMaxVideoFrameBufferSize;
	u8  bFrameIntervalType;
	u32 dwDefaultFrameInterval;
	u32 *dwFrameInterval;
};

struct uvc_format {
	u8 type;
	u8 index;
	u8 bpp;
	enum v4l2_colorspace colorspace;
	enum v4l2_xfer_func xfer_func;
	enum v4l2_ycbcr_encoding ycbcr_enc;
	u32 fcc;
	u32 flags;

	unsigned int nframes;
	struct uvc_frame *frame;
};

struct uvc_streaming_header {
	u8 bNumFormats;
	u8 bEndpointAddress;
	u8 bTerminalLink;
	u8 bControlSize;
	u8 *bmaControls;
	/* The following fields are used by input headers only. */
	u8 bmInfo;
	u8 bStillCaptureMethod;
	u8 bTriggerSupport;
	u8 bTriggerUsage;
};

struct uvc_video_queue {
	struct vb2_queue queue;
	struct mutex mutex;			/* Protects queue */

	unsigned int flags;
	unsigned int buf_used;

	spinlock_t irqlock;			/* Protects irqqueue */
	struct list_head irqqueue;
};

struct uvc_stats_frame {
	unsigned int size;		/* Number of bytes captured */
	unsigned int first_data;	/* Index of the first non-empty packet */

	unsigned int nb_packets;	/* Number of packets */
	unsigned int nb_empty;		/* Number of empty packets */
	unsigned int nb_invalid;	/* Number of packets with an invalid header */
	unsigned int nb_errors;		/* Number of packets with the error bit set */

	unsigned int nb_pts;		/* Number of packets with a PTS timestamp */
	unsigned int nb_pts_diffs;	/* Number of PTS differences inside a frame */
	unsigned int last_pts_diff;	/* Index of the last PTS difference */
	bool has_initial_pts;		/* Whether the first non-empty packet has a PTS */
	bool has_early_pts;		/* Whether a PTS is present before the first non-empty packet */
	u32 pts;			/* PTS of the last packet */

	unsigned int nb_scr;		/* Number of packets with a SCR timestamp */
	unsigned int nb_scr_diffs;	/* Number of SCR.STC differences inside a frame */
	u16 scr_sof;			/* SCR.SOF of the last packet */
	u32 scr_stc;			/* SCR.STC of the last packet */
};

struct uvc_stats_stream {
	ktime_t start_ts;		/* Stream start timestamp */
	ktime_t stop_ts;		/* Stream stop timestamp */

	unsigned int nb_frames;		/* Number of frames */

	unsigned int nb_packets;	/* Number of packets */
	unsigned int nb_empty;		/* Number of empty packets */
	unsigned int nb_invalid;	/* Number of packets with an invalid header */
	unsigned int nb_errors;		/* Number of packets with the error bit set */

	unsigned int nb_pts_constant;	/* Number of frames with constant PTS */
	unsigned int nb_pts_early;	/* Number of frames with early PTS */
	unsigned int nb_pts_initial;	/* Number of frames with initial PTS */

	unsigned int nb_scr_count_ok;	/* Number of frames with at least one SCR per non empty packet */
	unsigned int nb_scr_diffs_ok;	/* Number of frames with varying SCR.STC */
	unsigned int scr_sof_count;	/* STC.SOF counter accumulated since stream start */
	unsigned int scr_sof;		/* STC.SOF of the last packet */
	unsigned int min_sof;		/* Minimum STC.SOF value */
	unsigned int max_sof;		/* Maximum STC.SOF value */
};

struct uvc_copy_op {
	struct uvc_buffer *buf;
	void *dst;
	const __u8 *src;
	size_t len;
};

struct uvc_urb {
	struct urb *urb;
	struct uvc_streaming *stream;

	char *buffer;
	dma_addr_t dma;
	struct sg_table *sgt;

	unsigned int async_operations;
	struct uvc_copy_op copy_operations[UVC_MAX_PACKETS];
	struct work_struct work;
};

struct uvc_streaming {
	struct list_head list;
	struct uvc_device *dev;
	struct video_device vdev;
	struct uvc_video_chain *chain;
	atomic_t active;

	struct usb_interface *intf;
	int intfnum;
	u16 maxpsize;

	struct uvc_streaming_header header;
	enum v4l2_buf_type type;

	unsigned int nformats;
	struct uvc_format *format;

	struct uvc_streaming_control ctrl;
	struct uvc_format *def_format;
	struct uvc_format *cur_format;
	struct uvc_frame *cur_frame;

	/*
	 * Protect access to ctrl, cur_format, cur_frame and hardware video
	 * probe control.
	 */
	struct mutex mutex;

	/* Buffers queue. */
	unsigned int frozen : 1;
	struct uvc_video_queue queue;
	struct workqueue_struct *async_wq;
	void (*decode)(struct uvc_urb *uvc_urb, struct uvc_buffer *buf,
		       struct uvc_buffer *meta_buf);

	struct {
		struct video_device vdev;
		struct uvc_video_queue queue;
		u32 format;
	} meta;

	/* Context data used by the bulk completion handler. */
	struct {
		u8 header[256];
		unsigned int header_size;
		int skip_payload;
		u32 payload_size;
		u32 max_payload_size;
	} bulk;

	struct uvc_urb uvc_urb[UVC_URBS];
	unsigned int urb_size;

	u32 sequence;
	u8 last_fid;

	/* debugfs */
	struct dentry *debugfs_dir;
	struct {
		struct uvc_stats_frame frame;
		struct uvc_stats_stream stream;
	} stats;

	/* Timestamps support. */
	struct uvc_clock {
		struct uvc_clock_sample {
			u32 dev_stc;
			u16 dev_sof;
			u16 host_sof;
			ktime_t host_time;
		} *samples;

		unsigned int head;
		unsigned int count;
		unsigned int size;

		u16 last_sof;
		u16 sof_offset;

		u8 last_scr[6];

		spinlock_t lock;
	} clock;
};

struct uvc_device {
	struct usb_device *udev;
	struct usb_interface *intf;
	unsigned long warnings;
	u32 quirks;
	int intfnum;
	char name[32];

	const struct uvc_device_info *info;

	struct mutex lock;		/* Protects users */
	unsigned int users;
	atomic_t nmappings;

#ifdef CONFIG_MEDIA_CONTROLLER
	struct media_device mdev;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct v4l2_device vdev;
	u16 uvc_version;
	u32 clock_frequency;

	struct list_head entities;
	struct list_head chains;

	/* Video Streaming interfaces */
	struct list_head streams;
	struct kref ref;

	/* Status Interrupt Endpoint */
	struct usb_host_endpoint *int_ep;
	struct urb *int_urb;
	struct uvc_status *status;
	bool flush_status;

	struct input_dev *input;
	char input_phys[64];

	struct uvc_ctrl_work {
		struct work_struct work;
		struct urb *urb;
		struct uvc_video_chain *chain;
		struct uvc_control *ctrl;
		const void *data;
	} async_ctrl;

	struct uvc_entity *gpio_unit;
};

struct uvc_driver {
	struct usb_driver driver;
};

#define UVC_DBG_DESCR		(1 << 1)

extern unsigned int uvc_dbg_param;

#define uvc_dbg(_dev, flag, fmt, ...)					\
do {									\
	if (uvc_dbg_param & UVC_DBG_##flag)				\
		dev_printk(KERN_DEBUG, &(_dev)->udev->dev, fmt,		\
			   ##__VA_ARGS__);				\
} while (0)

extern struct uvc_driver uvc_driver;

struct usb_host_endpoint *uvc_find_endpoint(struct usb_host_interface *alts,
					    u8 epaddr);
u16 uvc_endpoint_max_bpi(struct usb_device *dev, struct usb_host_endpoint *ep);

/* klp-ccp: from drivers/media/usb/uvc/uvc_driver.c */
extern unsigned int uvc_dbg_param;

struct usb_host_endpoint *uvc_find_endpoint(struct usb_host_interface *alts,
		u8 epaddr);

static enum v4l2_colorspace uvc_colorspace(const u8 primaries)
{
	static const enum v4l2_colorspace colorprimaries[] = {
		V4L2_COLORSPACE_SRGB,  /* Unspecified */
		V4L2_COLORSPACE_SRGB,
		V4L2_COLORSPACE_470_SYSTEM_M,
		V4L2_COLORSPACE_470_SYSTEM_BG,
		V4L2_COLORSPACE_SMPTE170M,
		V4L2_COLORSPACE_SMPTE240M,
	};

	if (primaries < ARRAY_SIZE(colorprimaries))
		return colorprimaries[primaries];

	return V4L2_COLORSPACE_SRGB;  /* Reserved */
}

static enum v4l2_xfer_func uvc_xfer_func(const u8 transfer_characteristics)
{
	/*
	 * V4L2 does not currently have definitions for all possible values of
	 * UVC transfer characteristics. If v4l2_xfer_func is extended with new
	 * values, the mapping below should be updated.
	 *
	 * Substitutions are taken from the mapping given for
	 * V4L2_XFER_FUNC_DEFAULT documented in videodev2.h.
	 */
	static const enum v4l2_xfer_func xfer_funcs[] = {
		V4L2_XFER_FUNC_DEFAULT,    /* Unspecified */
		V4L2_XFER_FUNC_709,
		V4L2_XFER_FUNC_709,        /* Substitution for BT.470-2 M */
		V4L2_XFER_FUNC_709,        /* Substitution for BT.470-2 B, G */
		V4L2_XFER_FUNC_709,        /* Substitution for SMPTE 170M */
		V4L2_XFER_FUNC_SMPTE240M,
		V4L2_XFER_FUNC_NONE,
		V4L2_XFER_FUNC_SRGB,
	};

	if (transfer_characteristics < ARRAY_SIZE(xfer_funcs))
		return xfer_funcs[transfer_characteristics];

	return V4L2_XFER_FUNC_DEFAULT;  /* Reserved */
}

static enum v4l2_ycbcr_encoding uvc_ycbcr_enc(const u8 matrix_coefficients)
{
	/*
	 * V4L2 does not currently have definitions for all possible values of
	 * UVC matrix coefficients. If v4l2_ycbcr_encoding is extended with new
	 * values, the mapping below should be updated.
	 *
	 * Substitutions are taken from the mapping given for
	 * V4L2_YCBCR_ENC_DEFAULT documented in videodev2.h.
	 *
	 * FCC is assumed to be close enough to 601.
	 */
	static const enum v4l2_ycbcr_encoding ycbcr_encs[] = {
		V4L2_YCBCR_ENC_DEFAULT,  /* Unspecified */
		V4L2_YCBCR_ENC_709,
		V4L2_YCBCR_ENC_601,      /* Substitution for FCC */
		V4L2_YCBCR_ENC_601,      /* Substitution for BT.470-2 B, G */
		V4L2_YCBCR_ENC_601,
		V4L2_YCBCR_ENC_SMPTE240M,
	};

	if (matrix_coefficients < ARRAY_SIZE(ycbcr_encs))
		return ycbcr_encs[matrix_coefficients];

	return V4L2_YCBCR_ENC_DEFAULT;  /* Reserved */
}

extern void uvc_stream_delete(struct uvc_streaming *stream);

static struct uvc_streaming *uvc_stream_new(struct uvc_device *dev,
					    struct usb_interface *intf)
{
	struct uvc_streaming *stream;

	stream = kzalloc(sizeof(*stream), GFP_KERNEL);
	if (stream == NULL)
		return NULL;

	mutex_init(&stream->mutex);

	stream->dev = dev;
	stream->intf = usb_get_intf(intf);
	stream->intfnum = intf->cur_altsetting->desc.bInterfaceNumber;

	/* Allocate a stream specific work queue for asynchronous tasks. */
	stream->async_wq = alloc_workqueue("uvcvideo", WQ_UNBOUND | WQ_HIGHPRI,
					   0);
	if (!stream->async_wq) {
		uvc_stream_delete(stream);
		return NULL;
	}

	return stream;
}

static int uvc_parse_format(struct uvc_device *dev,
	struct uvc_streaming *streaming, struct uvc_format *format,
	u32 **intervals, unsigned char *buffer, int buflen)
{
	struct usb_interface *intf = streaming->intf;
	struct usb_host_interface *alts = intf->cur_altsetting;
	const struct uvc_format_desc *fmtdesc;
	struct uvc_frame *frame;
	const unsigned char *start = buffer;
	unsigned int width_multiplier = 1;
	unsigned int interval;
	unsigned int i, n;
	u8 ftype;

	format->type = buffer[2];
	format->index = buffer[3];

	switch (buffer[2]) {
	case UVC_VS_FORMAT_UNCOMPRESSED:
	case UVC_VS_FORMAT_FRAME_BASED:
		n = buffer[2] == UVC_VS_FORMAT_UNCOMPRESSED ? 27 : 28;
		if (buflen < n) {
			uvc_dbg(dev, DESCR,
				"device %d videostreaming interface %d FORMAT error\n",
				dev->udev->devnum,
				alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		/* Find the format descriptor from its GUID. */
		fmtdesc = uvc_format_by_guid(&buffer[5]);

		if (!fmtdesc) {
			/*
			 * Unknown video formats are not fatal errors, the
			 * caller will skip this descriptor.
			 */
			dev_info(&streaming->intf->dev,
				 "Unknown video format %pUl\n", &buffer[5]);
			return 0;
		}

		format->fcc = fmtdesc->fcc;
		format->bpp = buffer[21];

		/*
		 * Some devices report a format that doesn't match what they
		 * really send.
		 */
		if (dev->quirks & UVC_QUIRK_FORCE_Y8) {
			if (format->fcc == V4L2_PIX_FMT_YUYV) {
				format->fcc = V4L2_PIX_FMT_GREY;
				format->bpp = 8;
				width_multiplier = 2;
			}
		}

		/* Some devices report bpp that doesn't match the format. */
		if (dev->quirks & UVC_QUIRK_FORCE_BPP) {
			const struct v4l2_format_info *info =
				v4l2_format_info(format->fcc);

			if (info) {
				unsigned int div = info->hdiv * info->vdiv;

				n = info->bpp[0] * div;
				for (i = 1; i < info->comp_planes; i++)
					n += info->bpp[i];

				format->bpp = DIV_ROUND_UP(8 * n, div);
			}
		}

		if (buffer[2] == UVC_VS_FORMAT_UNCOMPRESSED) {
			ftype = UVC_VS_FRAME_UNCOMPRESSED;
		} else {
			ftype = UVC_VS_FRAME_FRAME_BASED;
			if (buffer[27])
				format->flags = UVC_FMT_FLAG_COMPRESSED;
		}
		break;

	case UVC_VS_FORMAT_MJPEG:
		if (buflen < 11) {
			uvc_dbg(dev, DESCR,
				"device %d videostreaming interface %d FORMAT error\n",
				dev->udev->devnum,
				alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		format->fcc = V4L2_PIX_FMT_MJPEG;
		format->flags = UVC_FMT_FLAG_COMPRESSED;
		format->bpp = 0;
		ftype = UVC_VS_FRAME_MJPEG;
		break;

	case UVC_VS_FORMAT_DV:
		if (buflen < 9) {
			uvc_dbg(dev, DESCR,
				"device %d videostreaming interface %d FORMAT error\n",
				dev->udev->devnum,
				alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		if ((buffer[8] & 0x7f) > 2) {
			uvc_dbg(dev, DESCR,
				"device %d videostreaming interface %d: unknown DV format %u\n",
				dev->udev->devnum,
				alts->desc.bInterfaceNumber, buffer[8]);
			return -EINVAL;
		}

		format->fcc = V4L2_PIX_FMT_DV;
		format->flags = UVC_FMT_FLAG_COMPRESSED | UVC_FMT_FLAG_STREAM;
		format->bpp = 0;
		ftype = 0;

		/* Create a dummy frame descriptor. */
		frame = &format->frame[0];
		memset(&format->frame[0], 0, sizeof(format->frame[0]));
		frame->bFrameIntervalType = 1;
		frame->dwDefaultFrameInterval = 1;
		frame->dwFrameInterval = *intervals;
		*(*intervals)++ = 1;
		format->nframes = 1;
		break;

	case UVC_VS_FORMAT_MPEG2TS:
	case UVC_VS_FORMAT_STREAM_BASED:
		/* Not supported yet. */
	default:
		uvc_dbg(dev, DESCR,
			"device %d videostreaming interface %d unsupported format %u\n",
			dev->udev->devnum, alts->desc.bInterfaceNumber,
			buffer[2]);
		return -EINVAL;
	}

	uvc_dbg(dev, DESCR, "Found format %p4cc", &format->fcc);

	buflen -= buffer[0];
	buffer += buffer[0];

	/*
	 * Parse the frame descriptors. Only uncompressed, MJPEG and frame
	 * based formats have frame descriptors.
	 */
	while (ftype && buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE &&
	       buffer[2] == ftype) {
		frame = &format->frame[format->nframes];
		if (ftype != UVC_VS_FRAME_FRAME_BASED)
			n = buflen > 25 ? buffer[25] : 0;
		else
			n = buflen > 21 ? buffer[21] : 0;

		n = n ? n : 3;

		if (buflen < 26 + 4*n) {
			uvc_dbg(dev, DESCR,
				"device %d videostreaming interface %d FRAME error\n",
				dev->udev->devnum,
				alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		frame->bFrameIndex = buffer[3];
		frame->bmCapabilities = buffer[4];
		frame->wWidth = get_unaligned_le16(&buffer[5])
			      * width_multiplier;
		frame->wHeight = get_unaligned_le16(&buffer[7]);
		frame->dwMinBitRate = get_unaligned_le32(&buffer[9]);
		frame->dwMaxBitRate = get_unaligned_le32(&buffer[13]);
		if (ftype != UVC_VS_FRAME_FRAME_BASED) {
			frame->dwMaxVideoFrameBufferSize =
				get_unaligned_le32(&buffer[17]);
			frame->dwDefaultFrameInterval =
				get_unaligned_le32(&buffer[21]);
			frame->bFrameIntervalType = buffer[25];
		} else {
			frame->dwMaxVideoFrameBufferSize = 0;
			frame->dwDefaultFrameInterval =
				get_unaligned_le32(&buffer[17]);
			frame->bFrameIntervalType = buffer[21];
		}
		frame->dwFrameInterval = *intervals;

		/*
		 * Several UVC chipsets screw up dwMaxVideoFrameBufferSize
		 * completely. Observed behaviours range from setting the
		 * value to 1.1x the actual frame size to hardwiring the
		 * 16 low bits to 0. This results in a higher than necessary
		 * memory usage as well as a wrong image size information. For
		 * uncompressed formats this can be fixed by computing the
		 * value from the frame size.
		 */
		if (!(format->flags & UVC_FMT_FLAG_COMPRESSED))
			frame->dwMaxVideoFrameBufferSize = format->bpp
				* frame->wWidth * frame->wHeight / 8;

		/*
		 * Some bogus devices report dwMinFrameInterval equal to
		 * dwMaxFrameInterval and have dwFrameIntervalStep set to
		 * zero. Setting all null intervals to 1 fixes the problem and
		 * some other divisions by zero that could happen.
		 */
		for (i = 0; i < n; ++i) {
			interval = get_unaligned_le32(&buffer[26+4*i]);
			*(*intervals)++ = interval ? interval : 1;
		}

		/*
		 * Make sure that the default frame interval stays between
		 * the boundaries.
		 */
		n -= frame->bFrameIntervalType ? 1 : 2;
		frame->dwDefaultFrameInterval =
			min(frame->dwFrameInterval[n],
			    max(frame->dwFrameInterval[0],
				frame->dwDefaultFrameInterval));

		if (dev->quirks & UVC_QUIRK_RESTRICT_FRAME_RATE) {
			frame->bFrameIntervalType = 1;
			frame->dwFrameInterval[0] =
				frame->dwDefaultFrameInterval;
		}

		uvc_dbg(dev, DESCR, "- %ux%u (%u.%u fps)\n",
			frame->wWidth, frame->wHeight,
			10000000 / frame->dwDefaultFrameInterval,
			(100000000 / frame->dwDefaultFrameInterval) % 10);

		format->nframes++;
		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE &&
	    buffer[2] == UVC_VS_STILL_IMAGE_FRAME) {
		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE &&
	    buffer[2] == UVC_VS_COLORFORMAT) {
		if (buflen < 6) {
			uvc_dbg(dev, DESCR,
				"device %d videostreaming interface %d COLORFORMAT error\n",
				dev->udev->devnum,
				alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		format->colorspace = uvc_colorspace(buffer[3]);
		format->xfer_func = uvc_xfer_func(buffer[4]);
		format->ycbcr_enc = uvc_ycbcr_enc(buffer[5]);

		buflen -= buffer[0];
		buffer += buffer[0];
	} else {
		format->colorspace = V4L2_COLORSPACE_SRGB;
	}

	return buffer - start;
}

static int uvc_parse_streaming(struct uvc_device *dev,
	struct usb_interface *intf)
{
	struct uvc_streaming *streaming = NULL;
	struct uvc_format *format;
	struct uvc_frame *frame;
	struct usb_host_interface *alts = &intf->altsetting[0];
	unsigned char *_buffer, *buffer = alts->extra;
	int _buflen, buflen = alts->extralen;
	unsigned int nformats = 0, nframes = 0, nintervals = 0;
	unsigned int size, i, n, p;
	u32 *interval;
	u16 psize;
	int ret = -EINVAL;

	if (intf->cur_altsetting->desc.bInterfaceSubClass
		!= UVC_SC_VIDEOSTREAMING) {
		uvc_dbg(dev, DESCR,
			"device %d interface %d isn't a video streaming interface\n",
			dev->udev->devnum,
			intf->altsetting[0].desc.bInterfaceNumber);
		return -EINVAL;
	}

	if (usb_driver_claim_interface(&uvc_driver.driver, intf, dev)) {
		uvc_dbg(dev, DESCR,
			"device %d interface %d is already claimed\n",
			dev->udev->devnum,
			intf->altsetting[0].desc.bInterfaceNumber);
		return -EINVAL;
	}

	streaming = uvc_stream_new(dev, intf);
	if (streaming == NULL) {
		usb_driver_release_interface(&uvc_driver.driver, intf);
		return -ENOMEM;
	}

	/*
	 * The Pico iMage webcam has its class-specific interface descriptors
	 * after the endpoint descriptors.
	 */
	if (buflen == 0) {
		for (i = 0; i < alts->desc.bNumEndpoints; ++i) {
			struct usb_host_endpoint *ep = &alts->endpoint[i];

			if (ep->extralen == 0)
				continue;

			if (ep->extralen > 2 &&
			    ep->extra[1] == USB_DT_CS_INTERFACE) {
				uvc_dbg(dev, DESCR,
					"trying extra data from endpoint %u\n",
					i);
				buffer = alts->endpoint[i].extra;
				buflen = alts->endpoint[i].extralen;
				break;
			}
		}
	}

	/* Skip the standard interface descriptors. */
	while (buflen > 2 && buffer[1] != USB_DT_CS_INTERFACE) {
		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (buflen <= 2) {
		uvc_dbg(dev, DESCR,
			"no class-specific streaming interface descriptors found\n");
		goto error;
	}

	/* Parse the header descriptor. */
	switch (buffer[2]) {
	case UVC_VS_OUTPUT_HEADER:
		streaming->type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
		size = 9;
		break;

	case UVC_VS_INPUT_HEADER:
		streaming->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		size = 13;
		break;

	default:
		uvc_dbg(dev, DESCR,
			"device %d videostreaming interface %d HEADER descriptor not found\n",
			dev->udev->devnum, alts->desc.bInterfaceNumber);
		goto error;
	}

	p = buflen >= 4 ? buffer[3] : 0;
	n = buflen >= size ? buffer[size-1] : 0;

	if (buflen < size + p*n) {
		uvc_dbg(dev, DESCR,
			"device %d videostreaming interface %d HEADER descriptor is invalid\n",
			dev->udev->devnum, alts->desc.bInterfaceNumber);
		goto error;
	}

	streaming->header.bNumFormats = p;
	streaming->header.bEndpointAddress = buffer[6];
	if (buffer[2] == UVC_VS_INPUT_HEADER) {
		streaming->header.bmInfo = buffer[7];
		streaming->header.bTerminalLink = buffer[8];
		streaming->header.bStillCaptureMethod = buffer[9];
		streaming->header.bTriggerSupport = buffer[10];
		streaming->header.bTriggerUsage = buffer[11];
	} else {
		streaming->header.bTerminalLink = buffer[7];
	}
	streaming->header.bControlSize = n;

	streaming->header.bmaControls = kmemdup(&buffer[size], p * n,
						GFP_KERNEL);
	if (streaming->header.bmaControls == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	buflen -= buffer[0];
	buffer += buffer[0];

	_buffer = buffer;
	_buflen = buflen;

	/* Count the format and frame descriptors. */
	while (_buflen > 2 && _buffer[1] == USB_DT_CS_INTERFACE) {
		switch (_buffer[2]) {
		case UVC_VS_FORMAT_UNCOMPRESSED:
		case UVC_VS_FORMAT_MJPEG:
		case UVC_VS_FORMAT_FRAME_BASED:
			nformats++;
			break;

		case UVC_VS_FORMAT_DV:
			/*
			 * DV format has no frame descriptor. We will create a
			 * dummy frame descriptor with a dummy frame interval.
			 */
			nformats++;
			nframes++;
			nintervals++;
			break;

		case UVC_VS_FORMAT_MPEG2TS:
		case UVC_VS_FORMAT_STREAM_BASED:
			uvc_dbg(dev, DESCR,
				"device %d videostreaming interface %d FORMAT %u is not supported\n",
				dev->udev->devnum,
				alts->desc.bInterfaceNumber, _buffer[2]);
			break;

		case UVC_VS_FRAME_UNCOMPRESSED:
		case UVC_VS_FRAME_MJPEG:
			nframes++;
			if (_buflen > 25)
				nintervals += _buffer[25] ? _buffer[25] : 3;
			break;

		case UVC_VS_FRAME_FRAME_BASED:
			nframes++;
			if (_buflen > 21)
				nintervals += _buffer[21] ? _buffer[21] : 3;
			break;
		}

		_buflen -= _buffer[0];
		_buffer += _buffer[0];
	}

	if (nformats == 0) {
		uvc_dbg(dev, DESCR,
			"device %d videostreaming interface %d has no supported formats defined\n",
			dev->udev->devnum, alts->desc.bInterfaceNumber);
		goto error;
	}

	/*
	 * Allocate memory for the formats, the frames and the intervals,
	 * plus any required padding to guarantee that everything has the
	 * correct alignment.
	 */
	size = nformats * sizeof(*format);
	size = ALIGN(size, __alignof__(*frame)) + nframes * sizeof(*frame);
	size = ALIGN(size, __alignof__(*interval))
	     + nintervals * sizeof(*interval);

	format = kzalloc(size, GFP_KERNEL);
	if (!format) {
		ret = -ENOMEM;
		goto error;
	}

	frame = (void *)format + nformats * sizeof(*format);
	frame = PTR_ALIGN(frame, __alignof__(*frame));
	interval = (void *)frame + nframes * sizeof(*frame);
	interval = PTR_ALIGN(interval, __alignof__(*interval));

	streaming->format = format;
	streaming->nformats = 0;

	/* Parse the format descriptors. */
	while (buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE) {
		switch (buffer[2]) {
		case UVC_VS_FORMAT_UNCOMPRESSED:
		case UVC_VS_FORMAT_MJPEG:
		case UVC_VS_FORMAT_DV:
		case UVC_VS_FORMAT_FRAME_BASED:
			format->frame = frame;
			ret = uvc_parse_format(dev, streaming, format,
				&interval, buffer, buflen);
			if (ret < 0)
				goto error;
			if (!ret)
				break;

			streaming->nformats++;
			frame += format->nframes;
			format++;

			buflen -= ret;
			buffer += ret;
			continue;

		default:
			break;
		}

		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (buflen)
		uvc_dbg(dev, DESCR,
			"device %d videostreaming interface %d has %u bytes of trailing descriptor garbage\n",
			dev->udev->devnum, alts->desc.bInterfaceNumber, buflen);

	/* Parse the alternate settings to find the maximum bandwidth. */
	for (i = 0; i < intf->num_altsetting; ++i) {
		struct usb_host_endpoint *ep;

		alts = &intf->altsetting[i];
		ep = uvc_find_endpoint(alts,
				streaming->header.bEndpointAddress);
		if (ep == NULL)
			continue;
		psize = uvc_endpoint_max_bpi(dev->udev, ep);
		if (psize > streaming->maxpsize)
			streaming->maxpsize = psize;
	}

	list_add_tail(&streaming->list, &dev->streams);
	return 0;

error:
	usb_driver_release_interface(&uvc_driver.driver, intf);
	uvc_stream_delete(streaming);
	return ret;
}

extern struct uvc_entity *uvc_alloc_entity(u16 type, u16 id,
		unsigned int num_pads, unsigned int extra_size);

extern void uvc_entity_set_name(struct uvc_device *dev, struct uvc_entity *entity,
				const char *type_name, u8 string_id);

int klpp_uvc_parse_standard_control(struct uvc_device *dev,
	const unsigned char *buffer, int buflen)
{
	struct usb_device *udev = dev->udev;
	struct uvc_entity *unit, *term;
	struct usb_interface *intf;
	struct usb_host_interface *alts = dev->intf->cur_altsetting;
	unsigned int i, n, p, len;
	const char *type_name;
	u16 type;

	switch (buffer[2]) {
	case UVC_VC_HEADER:
		n = buflen >= 12 ? buffer[11] : 0;

		if (buflen < 12 + n) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d HEADER error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		dev->uvc_version = get_unaligned_le16(&buffer[3]);
		dev->clock_frequency = get_unaligned_le32(&buffer[7]);

		/* Parse all USB Video Streaming interfaces. */
		for (i = 0; i < n; ++i) {
			intf = usb_ifnum_to_if(udev, buffer[12+i]);
			if (intf == NULL) {
				uvc_dbg(dev, DESCR,
					"device %d interface %d doesn't exists\n",
					udev->devnum, i);
				continue;
			}

			uvc_parse_streaming(dev, intf);
		}
		break;

	case UVC_VC_INPUT_TERMINAL:
		if (buflen < 8) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d INPUT_TERMINAL error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		/*
		 * Reject invalid terminal types that would cause issues:
		 *
		 * - The high byte must be non-zero, otherwise it would be
		 *   confused with a unit.
		 *
		 * - Bit 15 must be 0, as we use it internally as a terminal
		 *   direction flag.
		 *
		 * Other unknown types are accepted.
		 */
		type = get_unaligned_le16(&buffer[4]);
		if ((type & 0x7f00) == 0 || (type & 0x8000) != 0) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d INPUT_TERMINAL %d has invalid type 0x%04x, skipping\n",
				udev->devnum, alts->desc.bInterfaceNumber,
				buffer[3], type);
			return 0;
		}

		n = 0;
		p = 0;
		len = 8;

		if (type == UVC_ITT_CAMERA) {
			n = buflen >= 15 ? buffer[14] : 0;
			len = 15;

		} else if (type == UVC_ITT_MEDIA_TRANSPORT_INPUT) {
			n = buflen >= 9 ? buffer[8] : 0;
			p = buflen >= 10 + n ? buffer[9+n] : 0;
			len = 10;
		}

		if (buflen < len + n + p) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d INPUT_TERMINAL error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		term = uvc_alloc_entity(type | UVC_TERM_INPUT, buffer[3],
					1, n + p);
		if (term == NULL)
			return -ENOMEM;

		if (UVC_ENTITY_TYPE(term) == UVC_ITT_CAMERA) {
			term->camera.bControlSize = n;
			term->camera.bmControls = (u8 *)term + sizeof(*term);
			term->camera.wObjectiveFocalLengthMin =
				get_unaligned_le16(&buffer[8]);
			term->camera.wObjectiveFocalLengthMax =
				get_unaligned_le16(&buffer[10]);
			term->camera.wOcularFocalLength =
				get_unaligned_le16(&buffer[12]);
			memcpy(term->camera.bmControls, &buffer[15], n);
		} else if (UVC_ENTITY_TYPE(term) ==
			   UVC_ITT_MEDIA_TRANSPORT_INPUT) {
			term->media.bControlSize = n;
			term->media.bmControls = (u8 *)term + sizeof(*term);
			term->media.bTransportModeSize = p;
			term->media.bmTransportModes = (u8 *)term
						     + sizeof(*term) + n;
			memcpy(term->media.bmControls, &buffer[9], n);
			memcpy(term->media.bmTransportModes, &buffer[10+n], p);
		}

		if (UVC_ENTITY_TYPE(term) == UVC_ITT_CAMERA)
			type_name = "Camera";
		else if (UVC_ENTITY_TYPE(term) == UVC_ITT_MEDIA_TRANSPORT_INPUT)
			type_name = "Media";
		else
			type_name = "Input";

		uvc_entity_set_name(dev, term, type_name, buffer[7]);

		list_add_tail(&term->list, &dev->entities);
		break;

	case UVC_VC_OUTPUT_TERMINAL:
		if (buflen < 9) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d OUTPUT_TERMINAL error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		/*
		 * Make sure the terminal type MSB is not null, otherwise it
		 * could be confused with a unit.
		 */
		type = get_unaligned_le16(&buffer[4]);
		if ((type & 0xff00) == 0) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d OUTPUT_TERMINAL %d has invalid type 0x%04x, skipping\n",
				udev->devnum, alts->desc.bInterfaceNumber,
				buffer[3], type);
			return 0;
		}

		term = uvc_alloc_entity(type | UVC_TERM_OUTPUT, buffer[3],
					1, 0);
		if (term == NULL)
			return -ENOMEM;

		memcpy(term->baSourceID, &buffer[7], 1);

		uvc_entity_set_name(dev, term, "Output", buffer[8]);

		list_add_tail(&term->list, &dev->entities);
		break;

	case UVC_VC_SELECTOR_UNIT:
		p = buflen >= 5 ? buffer[4] : 0;

		if (buflen < 5 || buflen < 6 + p) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d SELECTOR_UNIT error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		unit = uvc_alloc_entity(buffer[2], buffer[3], p + 1, 0);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->baSourceID, &buffer[5], p);

		uvc_entity_set_name(dev, unit, "Selector", buffer[5+p]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	case UVC_VC_PROCESSING_UNIT:
		n = buflen >= 8 ? buffer[7] : 0;
		p = dev->uvc_version >= 0x0110 ? 10 : 9;

		if (buflen < p + n) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d PROCESSING_UNIT error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		unit = uvc_alloc_entity(buffer[2], buffer[3], 2, n);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->baSourceID, &buffer[4], 1);
		unit->processing.wMaxMultiplier =
			get_unaligned_le16(&buffer[5]);
		unit->processing.bControlSize = buffer[7];
		unit->processing.bmControls = (u8 *)unit + sizeof(*unit);
		memcpy(unit->processing.bmControls, &buffer[8], n);
		if (dev->uvc_version >= 0x0110)
			unit->processing.bmVideoStandards = buffer[9+n];

		uvc_entity_set_name(dev, unit, "Processing", buffer[8+n]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	case UVC_VC_EXTENSION_UNIT:
		p = buflen >= 22 ? buffer[21] : 0;
		n = buflen >= 24 + p ? buffer[22+p] : 0;

		if (buflen < 24 + p + n) {
			uvc_dbg(dev, DESCR,
				"device %d videocontrol interface %d EXTENSION_UNIT error\n",
				udev->devnum, alts->desc.bInterfaceNumber);
			return -EINVAL;
		}

		unit = uvc_alloc_entity(buffer[2], buffer[3], p + 1, n);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->guid, &buffer[4], 16);
		unit->extension.bNumControls = buffer[20];
		memcpy(unit->baSourceID, &buffer[22], p);
		unit->extension.bControlSize = buffer[22+p];
		unit->extension.bmControls = (u8 *)unit + sizeof(*unit);
		memcpy(unit->extension.bmControls, &buffer[23+p], n);

		uvc_entity_set_name(dev, unit, "Extension", buffer[23+p+n]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	default:
		uvc_dbg(dev, DESCR,
			"Found an unknown CS_INTERFACE descriptor (%u)\n",
			buffer[2]);
		break;
	}

	return 0;
}

extern struct uvc_driver uvc_driver;


#include "livepatch_bsc1236783.h"
#include "linux/livepatch.h"

extern typeof(usb_driver_claim_interface) usb_driver_claim_interface
	 KLP_RELOC_SYMBOL(uvcvideo, usbcore, usb_driver_claim_interface);
extern typeof(usb_driver_release_interface) usb_driver_release_interface
	 KLP_RELOC_SYMBOL(uvcvideo, usbcore, usb_driver_release_interface);
extern typeof(usb_get_intf) usb_get_intf
	 KLP_RELOC_SYMBOL(uvcvideo, usbcore, usb_get_intf);
extern typeof(usb_ifnum_to_if) usb_ifnum_to_if
	 KLP_RELOC_SYMBOL(uvcvideo, usbcore, usb_ifnum_to_if);
extern typeof(uvc_alloc_entity) uvc_alloc_entity
	 KLP_RELOC_SYMBOL(uvcvideo, uvcvideo, uvc_alloc_entity);
extern typeof(uvc_dbg_param) uvc_dbg_param
	 KLP_RELOC_SYMBOL(uvcvideo, uvcvideo, uvc_dbg_param);
extern typeof(uvc_driver) uvc_driver
	 KLP_RELOC_SYMBOL(uvcvideo, uvcvideo, uvc_driver);
extern typeof(uvc_endpoint_max_bpi) uvc_endpoint_max_bpi
	 KLP_RELOC_SYMBOL(uvcvideo, uvcvideo, uvc_endpoint_max_bpi);
extern typeof(uvc_entity_set_name) uvc_entity_set_name
	 KLP_RELOC_SYMBOL(uvcvideo, uvcvideo, uvc_entity_set_name);
extern typeof(uvc_find_endpoint) uvc_find_endpoint
	 KLP_RELOC_SYMBOL(uvcvideo, uvcvideo, uvc_find_endpoint);
extern typeof(uvc_stream_delete) uvc_stream_delete
	 KLP_RELOC_SYMBOL(uvcvideo, uvcvideo, uvc_stream_delete);
extern typeof(uvc_format_by_guid) uvc_format_by_guid
	 KLP_RELOC_SYMBOL(uvcvideo, uvc, uvc_format_by_guid);
extern typeof(v4l2_format_info) v4l2_format_info
	 KLP_RELOC_SYMBOL(uvcvideo, videodev, v4l2_format_info);

#endif /* IS_ENABLED(CONFIG_USB_VIDEO_CLASS) */
