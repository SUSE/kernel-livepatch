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
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/usb.h>

/* klp-ccp: from include/linux/usb.h */
#ifdef __KERNEL__

static struct usb_interface *(*klpe_usb_get_intf)(struct usb_interface *intf);
static void (*klpe_usb_put_intf)(struct usb_interface *intf);

static int (*klpe_usb_driver_claim_interface)(struct usb_driver *driver,
			struct usb_interface *iface, void *priv);

static void (*klpe_usb_driver_release_interface)(struct usb_driver *driver,
			struct usb_interface *iface);

static struct usb_interface *(*klpe_usb_ifnum_to_if)(const struct usb_device *dev,
		unsigned ifnum);

static int (*klpe_usb_string)(struct usb_device *dev, int index,
	char *buf, size_t size);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif  /* __KERNEL__ */

/* klp-ccp: from drivers/media/usb/uvc/uvc_driver.c */
#include <linux/videodev2.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/version.h>
#include <asm/unaligned.h>

#include <media/v4l2-common.h>

/* klp-ccp: from drivers/media/usb/uvc/uvcvideo.h */
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/usb.h>
#include <linux/usb/video.h>

#include <linux/videodev2.h>

/* klp-ccp: from include/media/media-device.h */
#define _MEDIA_DEVICE_H

/* klp-ccp: from drivers/media/usb/uvc/uvcvideo.h */
#include <media/v4l2-device.h>

#include <media/v4l2-fh.h>
#include <media/videobuf2-v4l2.h>

#define UVC_TERM_INPUT			0x0000
#define UVC_TERM_OUTPUT			0x8000

#define UVC_ENTITY_TYPE(entity)		((entity)->type & 0x7fff)

#define UVC_URBS		5

#define UVC_QUIRK_RESTRICT_FRAME_RATE	0x00000200

#define UVC_QUIRK_FORCE_Y8		0x00000800

#define UVC_FMT_FLAG_COMPRESSED		0x00000001
#define UVC_FMT_FLAG_STREAM		0x00000002

struct uvc_format_desc {
	char *name;
	__u8 guid[16];
	__u32 fcc;
};

struct uvc_entity {
	struct list_head list;		/* Entity as part of a UVC device. */
	struct list_head chain;		/* Entity as part of a video device
					 * chain. */
	unsigned int flags;

	__u8 id;
	__u16 type;
	char name[64];

	/* Media controller-related fields. */
	struct video_device *vdev;
	struct v4l2_subdev subdev;
	unsigned int num_pads;
	unsigned int num_links;
	struct media_pad *pads;

	union {
		struct {
			__u16 wObjectiveFocalLengthMin;
			__u16 wObjectiveFocalLengthMax;
			__u16 wOcularFocalLength;
			__u8  bControlSize;
			__u8  *bmControls;
		} camera;

		struct {
			__u8  bControlSize;
			__u8  *bmControls;
			__u8  bTransportModeSize;
			__u8  *bmTransportModes;
		} media;

		struct {
		} output;

		struct {
			__u16 wMaxMultiplier;
			__u8  bControlSize;
			__u8  *bmControls;
			__u8  bmVideoStandards;
		} processing;

		struct {
		} selector;

		struct {
			__u8  guidExtensionCode[16];
			__u8  bNumControls;
			__u8  bControlSize;
			__u8  *bmControls;
			__u8  *bmControlsType;
		} extension;
	};

	__u8 bNrInPins;
	__u8 *baSourceID;

	unsigned int ncontrols;
	struct uvc_control *controls;
};

struct uvc_frame {
	__u8  bFrameIndex;
	__u8  bmCapabilities;
	__u16 wWidth;
	__u16 wHeight;
	__u32 dwMinBitRate;
	__u32 dwMaxBitRate;
	__u32 dwMaxVideoFrameBufferSize;
	__u8  bFrameIntervalType;
	__u32 dwDefaultFrameInterval;
	__u32 *dwFrameInterval;
};

struct uvc_format {
	__u8 type;
	__u8 index;
	__u8 bpp;
	__u8 colorspace;
	__u32 fcc;
	__u32 flags;

	char name[32];

	unsigned int nframes;
	struct uvc_frame *frame;
};

struct uvc_streaming_header {
	__u8 bNumFormats;
	__u8 bEndpointAddress;
	__u8 bTerminalLink;
	__u8 bControlSize;
	__u8 *bmaControls;
	/* The following fields are used by input headers only. */
	__u8 bmInfo;
	__u8 bStillCaptureMethod;
	__u8 bTriggerSupport;
	__u8 bTriggerUsage;
};

struct uvc_buffer;

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
	struct timespec start_ts;	/* Stream start timestamp */
	struct timespec stop_ts;	/* Stream stop timestamp */

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

struct uvc_streaming {
	struct list_head list;
	struct uvc_device *dev;
	struct video_device vdev;
	struct uvc_video_chain *chain;
	atomic_t active;

	struct usb_interface *intf;
	int intfnum;
	__u16 maxpsize;

	struct uvc_streaming_header header;
	enum v4l2_buf_type type;

	unsigned int nformats;
	struct uvc_format *format;

	struct uvc_streaming_control ctrl;
	struct uvc_format *def_format;
	struct uvc_format *cur_format;
	struct uvc_frame *cur_frame;

	/* Protect access to ctrl, cur_format, cur_frame and hardware video
	 * probe control.
	 */
	struct mutex mutex;

	/* Buffers queue. */
	unsigned int frozen : 1;
	struct uvc_video_queue queue;
	void (*decode) (struct urb *urb, struct uvc_streaming *video,
			struct uvc_buffer *buf);

	/* Context data used by the bulk completion handler. */
	struct {
		__u8 header[256];
		unsigned int header_size;
		int skip_payload;
		__u32 payload_size;
		__u32 max_payload_size;
	} bulk;

	struct urb *urb[UVC_URBS];
	char *urb_buffer[UVC_URBS];
	dma_addr_t urb_dma[UVC_URBS];
	unsigned int urb_size;

	__u32 sequence;
	__u8 last_fid;

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
			struct timespec host_ts;
			u16 host_sof;
		} *samples;

		unsigned int head;
		unsigned int count;
		unsigned int size;

		u16 last_sof;
		u16 sof_offset;

		spinlock_t lock;
	} clock;
};

struct uvc_device {
	struct usb_device *udev;
	struct usb_interface *intf;
	unsigned long warnings;
	__u32 quirks;
	int intfnum;
	char name[32];

	struct mutex lock;		/* Protects users */
	unsigned int users;
	atomic_t nmappings;

#ifdef CONFIG_MEDIA_CONTROLLER
#error "klp-ccp: non-taken branch"
#endif
	struct v4l2_device vdev;
	__u16 uvc_version;
	__u32 clock_frequency;

	struct list_head entities;
	struct list_head chains;

	/* Video Streaming interfaces */
	struct list_head streams;
	atomic_t nstreams;

	/* Status Interrupt Endpoint */
	struct usb_host_endpoint *int_ep;
	struct urb *int_urb;
	__u8 *status;
	struct input_dev *input;
	char input_phys[64];
};

struct uvc_driver {
	struct usb_driver driver;
};

static unsigned int (*klpe_uvc_trace_param);

#define uvc_printk(level, msg...) \
	printk(level "uvcvideo: " msg)

static struct uvc_driver (*klpe_uvc_driver);

static struct usb_host_endpoint *(*klpe_uvc_find_endpoint)(
		struct usb_host_interface *alts, __u8 epaddr);

static struct uvc_format_desc (*klpe_uvc_fmts)[32];

static struct uvc_format_desc *klpr_uvc_format_by_guid(const __u8 guid[16])
{
	unsigned int len = ARRAY_SIZE((*klpe_uvc_fmts));
	unsigned int i;

	for (i = 0; i < len; ++i) {
		if (memcmp(guid, (*klpe_uvc_fmts)[i].guid, 16) == 0)
			return &(*klpe_uvc_fmts)[i];
	}

	return NULL;
}

static __u32 uvc_colorspace(const __u8 primaries)
{
	static const __u8 colorprimaries[] = {
		0,
		V4L2_COLORSPACE_SRGB,
		V4L2_COLORSPACE_470_SYSTEM_M,
		V4L2_COLORSPACE_470_SYSTEM_BG,
		V4L2_COLORSPACE_SMPTE170M,
		V4L2_COLORSPACE_SMPTE240M,
	};

	if (primaries < ARRAY_SIZE(colorprimaries))
		return colorprimaries[primaries];

	return 0;
}

static int klpr_uvc_parse_format(struct uvc_device *dev,
	struct uvc_streaming *streaming, struct uvc_format *format,
	__u32 **intervals, unsigned char *buffer, int buflen)
{
	struct usb_interface *intf = streaming->intf;
	struct usb_host_interface *alts = intf->cur_altsetting;
	struct uvc_format_desc *fmtdesc;
	struct uvc_frame *frame;
	const unsigned char *start = buffer;
	unsigned int width_multiplier = 1;
	unsigned int interval;
	unsigned int i, n;
	__u8 ftype;

	format->type = buffer[2];
	format->index = buffer[3];

	switch (buffer[2]) {
	case UVC_VS_FORMAT_UNCOMPRESSED:
	case UVC_VS_FORMAT_FRAME_BASED:
		n = buffer[2] == UVC_VS_FORMAT_UNCOMPRESSED ? 27 : 28;
		if (buflen < n) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d FORMAT error\n", dev->udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		/* Find the format descriptor from its GUID. */
		fmtdesc = klpr_uvc_format_by_guid(&buffer[5]);

		if (fmtdesc != NULL) {
			strlcpy(format->name, fmtdesc->name,
				sizeof format->name);
			format->fcc = fmtdesc->fcc;
		} else {
			uvc_printk(KERN_INFO, "Unknown video format %pUl\n",
				&buffer[5]);
			snprintf(format->name, sizeof(format->name), "%pUl\n",
				&buffer[5]);
			format->fcc = 0;
		}

		format->bpp = buffer[21];

		/* Some devices report a format that doesn't match what they
		 * really send.
		 */
		if (dev->quirks & UVC_QUIRK_FORCE_Y8) {
			if (format->fcc == V4L2_PIX_FMT_YUYV) {
				strlcpy(format->name, "Greyscale 8-bit (Y8  )",
					sizeof(format->name));
				format->fcc = V4L2_PIX_FMT_GREY;
				format->bpp = 8;
				width_multiplier = 2;
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
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d FORMAT error\n", dev->udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		strlcpy(format->name, "MJPEG", sizeof format->name);
		format->fcc = V4L2_PIX_FMT_MJPEG;
		format->flags = UVC_FMT_FLAG_COMPRESSED;
		format->bpp = 0;
		ftype = UVC_VS_FRAME_MJPEG;
		break;

	case UVC_VS_FORMAT_DV:
		if (buflen < 9) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d FORMAT error\n", dev->udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		switch (buffer[8] & 0x7f) {
		case 0:
			strlcpy(format->name, "SD-DV", sizeof format->name);
			break;
		case 1:
			strlcpy(format->name, "SDL-DV", sizeof format->name);
			break;
		case 2:
			strlcpy(format->name, "HD-DV", sizeof format->name);
			break;
		default:
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d: unknown DV format %u\n", dev->udev->devnum, alts->desc.bInterfaceNumber, buffer[8]); } while (0);
			return -EINVAL;
		}

		strlcat(format->name, buffer[8] & (1 << 7) ? " 60Hz" : " 50Hz",
			sizeof format->name);

		format->fcc = V4L2_PIX_FMT_DV;
		format->flags = UVC_FMT_FLAG_COMPRESSED | UVC_FMT_FLAG_STREAM;
		format->bpp = 0;
		ftype = 0;

		/* Create a dummy frame descriptor. */
		frame = &format->frame[0];
		memset(&format->frame[0], 0, sizeof format->frame[0]);
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
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d unsupported format %u\n", dev->udev->devnum, alts->desc.bInterfaceNumber, buffer[2]); } while (0);
		return -EINVAL;
	}

	do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "Found format %s.\n", format->name); } while (0);

	buflen -= buffer[0];
	buffer += buffer[0];

	/* Parse the frame descriptors. Only uncompressed, MJPEG and frame
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
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d FRAME error\n", dev->udev->devnum, alts->desc.bInterfaceNumber); } while (0);
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

		/* Several UVC chipsets screw up dwMaxVideoFrameBufferSize
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

		/* Some bogus devices report dwMinFrameInterval equal to
		 * dwMaxFrameInterval and have dwFrameIntervalStep set to
		 * zero. Setting all null intervals to 1 fixes the problem and
		 * some other divisions by zero that could happen.
		 */
		for (i = 0; i < n; ++i) {
			interval = get_unaligned_le32(&buffer[26+4*i]);
			*(*intervals)++ = interval ? interval : 1;
		}

		/* Make sure that the default frame interval stays between
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

		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "- %ux%u (%u.%u fps)\n", frame->wWidth, frame->wHeight, 10000000/frame->dwDefaultFrameInterval, (100000000/frame->dwDefaultFrameInterval)%10); } while (0);

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
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d COLORFORMAT error\n", dev->udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		format->colorspace = uvc_colorspace(buffer[3]);

		buflen -= buffer[0];
		buffer += buffer[0];
	}

	return buffer - start;
}

static int klpr_uvc_parse_streaming(struct uvc_device *dev,
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
	__u32 *interval;
	__u16 psize;
	int ret = -EINVAL;

	if (intf->cur_altsetting->desc.bInterfaceSubClass
		!= UVC_SC_VIDEOSTREAMING) {
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d interface %d isn't a " "video streaming interface\n", dev->udev->devnum, intf->altsetting[0].desc.bInterfaceNumber); } while (0);
		return -EINVAL;
	}

	if ((*klpe_usb_driver_claim_interface)(&(*klpe_uvc_driver).driver, intf, dev)) {
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d interface %d is already " "claimed\n", dev->udev->devnum, intf->altsetting[0].desc.bInterfaceNumber); } while (0);
		return -EINVAL;
	}

	streaming = kzalloc(sizeof *streaming, GFP_KERNEL);
	if (streaming == NULL) {
		(*klpe_usb_driver_release_interface)(&(*klpe_uvc_driver).driver, intf);
		return -EINVAL;
	}

	mutex_init(&streaming->mutex);
	streaming->dev = dev;
	streaming->intf = (*klpe_usb_get_intf)(intf);
	streaming->intfnum = intf->cur_altsetting->desc.bInterfaceNumber;

	/* The Pico iMage webcam has its class-specific interface descriptors
	 * after the endpoint descriptors.
	 */
	if (buflen == 0) {
		for (i = 0; i < alts->desc.bNumEndpoints; ++i) {
			struct usb_host_endpoint *ep = &alts->endpoint[i];

			if (ep->extralen == 0)
				continue;

			if (ep->extralen > 2 &&
			    ep->extra[1] == USB_DT_CS_INTERFACE) {
				do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "trying extra data " "from endpoint %u.\n", i); } while (0);
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
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "no class-specific streaming " "interface descriptors found.\n"); } while (0);
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
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming interface " "%d HEADER descriptor not found.\n", dev->udev->devnum, alts->desc.bInterfaceNumber); } while (0);
		goto error;
	}

	p = buflen >= 4 ? buffer[3] : 0;
	n = buflen >= size ? buffer[size-1] : 0;

	if (buflen < size + p*n) {
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d HEADER descriptor is invalid.\n", dev->udev->devnum, alts->desc.bInterfaceNumber); } while (0);
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
			/* DV format has no frame descriptor. We will create a
			 * dummy frame descriptor with a dummy frame interval.
			 */
			nformats++;
			nframes++;
			nintervals++;
			break;

		case UVC_VS_FORMAT_MPEG2TS:
		case UVC_VS_FORMAT_STREAM_BASED:
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming " "interface %d FORMAT %u is not supported.\n", dev->udev->devnum, alts->desc.bInterfaceNumber, _buffer[2]); } while (0);
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
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming interface " "%d has no supported formats defined.\n", dev->udev->devnum, alts->desc.bInterfaceNumber); } while (0);
		goto error;
	}

	size = nformats * sizeof *format + nframes * sizeof *frame
	     + nintervals * sizeof *interval;
	format = kzalloc(size, GFP_KERNEL);
	if (format == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	frame = (struct uvc_frame *)&format[nformats];
	interval = (__u32 *)&frame[nframes];

	streaming->format = format;
	streaming->nformats = nformats;

	/* Parse the format descriptors. */
	while (buflen > 2 && buffer[1] == USB_DT_CS_INTERFACE) {
		switch (buffer[2]) {
		case UVC_VS_FORMAT_UNCOMPRESSED:
		case UVC_VS_FORMAT_MJPEG:
		case UVC_VS_FORMAT_DV:
		case UVC_VS_FORMAT_FRAME_BASED:
			format->frame = frame;
			ret = klpr_uvc_parse_format(dev, streaming, format,
				&interval, buffer, buflen);
			if (ret < 0)
				goto error;

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
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videostreaming interface " "%d has %u bytes of trailing descriptor garbage.\n", dev->udev->devnum, alts->desc.bInterfaceNumber, buflen); } while (0);

	/* Parse the alternate settings to find the maximum bandwidth. */
	for (i = 0; i < intf->num_altsetting; ++i) {
		struct usb_host_endpoint *ep;
		alts = &intf->altsetting[i];
		ep = (*klpe_uvc_find_endpoint)(alts,
				streaming->header.bEndpointAddress);
		if (ep == NULL)
			continue;

		psize = le16_to_cpu(ep->desc.wMaxPacketSize);
		psize = (psize & 0x07ff) * (1 + ((psize >> 11) & 3));
		if (psize > streaming->maxpsize)
			streaming->maxpsize = psize;
	}

	list_add_tail(&streaming->list, &dev->streams);
	return 0;

error:
	(*klpe_usb_driver_release_interface)(&(*klpe_uvc_driver).driver, intf);
	(*klpe_usb_put_intf)(intf);
	kfree(streaming->format);
	kfree(streaming->header.bmaControls);
	kfree(streaming);
	return ret;
}

static struct uvc_entity *(*klpe_uvc_alloc_entity)(u16 type, u8 id,
		unsigned int num_pads, unsigned int extra_size);

int klpp_uvc_parse_standard_control(struct uvc_device *dev,
	const unsigned char *buffer, int buflen)
{
	struct usb_device *udev = dev->udev;
	struct uvc_entity *unit, *term;
	struct usb_interface *intf;
	struct usb_host_interface *alts = dev->intf->cur_altsetting;
	unsigned int i, n, p, len;
	__u16 type;

	switch (buffer[2]) {
	case UVC_VC_HEADER:
		n = buflen >= 12 ? buffer[11] : 0;

		if (buflen < 12 + n) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d HEADER error\n", udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		dev->uvc_version = get_unaligned_le16(&buffer[3]);
		dev->clock_frequency = get_unaligned_le32(&buffer[7]);

		/* Parse all USB Video Streaming interfaces. */
		for (i = 0; i < n; ++i) {
			intf = (*klpe_usb_ifnum_to_if)(udev, buffer[12+i]);
			if (intf == NULL) {
				do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d " "interface %d doesn't exists\n", udev->devnum, i); } while (0);
				continue;
			}

			klpr_uvc_parse_streaming(dev, intf);
		}
		break;

	case UVC_VC_INPUT_TERMINAL:
		if (buflen < 8) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d INPUT_TERMINAL error\n", udev->devnum, alts->desc.bInterfaceNumber); } while (0);
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
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d INPUT_TERMINAL %d has invalid " "type 0x%04x, skipping\n", udev->devnum, alts->desc.bInterfaceNumber, buffer[3], type); } while (0);
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
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d INPUT_TERMINAL error\n", udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		term = (*klpe_uvc_alloc_entity)(type | UVC_TERM_INPUT, buffer[3],
					1, n + p);
		if (term == NULL)
			return -ENOMEM;

		if (UVC_ENTITY_TYPE(term) == UVC_ITT_CAMERA) {
			term->camera.bControlSize = n;
			term->camera.bmControls = (__u8 *)term + sizeof *term;
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
			term->media.bmControls = (__u8 *)term + sizeof *term;
			term->media.bTransportModeSize = p;
			term->media.bmTransportModes = (__u8 *)term
						     + sizeof *term + n;
			memcpy(term->media.bmControls, &buffer[9], n);
			memcpy(term->media.bmTransportModes, &buffer[10+n], p);
		}

		if (buffer[7] != 0)
			(*klpe_usb_string)(udev, buffer[7], term->name,
				   sizeof term->name);
		else if (UVC_ENTITY_TYPE(term) == UVC_ITT_CAMERA)
			sprintf(term->name, "Camera %u", buffer[3]);
		else if (UVC_ENTITY_TYPE(term) == UVC_ITT_MEDIA_TRANSPORT_INPUT)
			sprintf(term->name, "Media %u", buffer[3]);
		else
			sprintf(term->name, "Input %u", buffer[3]);

		list_add_tail(&term->list, &dev->entities);
		break;

	case UVC_VC_OUTPUT_TERMINAL:
		if (buflen < 9) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d OUTPUT_TERMINAL error\n", udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		/* Make sure the terminal type MSB is not null, otherwise it
		 * could be confused with a unit.
		 */
		type = get_unaligned_le16(&buffer[4]);
		if ((type & 0xff00) == 0) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d OUTPUT_TERMINAL %d has invalid " "type 0x%04x, skipping\n", udev->devnum, alts->desc.bInterfaceNumber, buffer[3], type); } while (0);
			return 0;
		}

		term = (*klpe_uvc_alloc_entity)(type | UVC_TERM_OUTPUT, buffer[3],
					1, 0);
		if (term == NULL)
			return -ENOMEM;

		memcpy(term->baSourceID, &buffer[7], 1);

		if (buffer[8] != 0)
			(*klpe_usb_string)(udev, buffer[8], term->name,
				   sizeof term->name);
		else
			sprintf(term->name, "Output %u", buffer[3]);

		list_add_tail(&term->list, &dev->entities);
		break;

	case UVC_VC_SELECTOR_UNIT:
		p = buflen >= 5 ? buffer[4] : 0;

		if (buflen < 5 || buflen < 6 + p) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d SELECTOR_UNIT error\n", udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		unit = (*klpe_uvc_alloc_entity)(buffer[2], buffer[3], p + 1, 0);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->baSourceID, &buffer[5], p);

		if (buffer[5+p] != 0)
			(*klpe_usb_string)(udev, buffer[5+p], unit->name,
				   sizeof unit->name);
		else
			sprintf(unit->name, "Selector %u", buffer[3]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	case UVC_VC_PROCESSING_UNIT:
		n = buflen >= 8 ? buffer[7] : 0;
		p = dev->uvc_version >= 0x0110 ? 10 : 9;

		if (buflen < p + n) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d PROCESSING_UNIT error\n", udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		unit = (*klpe_uvc_alloc_entity)(buffer[2], buffer[3], 2, n);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->baSourceID, &buffer[4], 1);
		unit->processing.wMaxMultiplier =
			get_unaligned_le16(&buffer[5]);
		unit->processing.bControlSize = buffer[7];
		unit->processing.bmControls = (__u8 *)unit + sizeof *unit;
		memcpy(unit->processing.bmControls, &buffer[8], n);
		if (dev->uvc_version >= 0x0110)
			unit->processing.bmVideoStandards = buffer[9+n];

		if (buffer[8+n] != 0)
			(*klpe_usb_string)(udev, buffer[8+n], unit->name,
				   sizeof unit->name);
		else
			sprintf(unit->name, "Processing %u", buffer[3]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	case UVC_VC_EXTENSION_UNIT:
		p = buflen >= 22 ? buffer[21] : 0;
		n = buflen >= 24 + p ? buffer[22+p] : 0;

		if (buflen < 24 + p + n) {
			do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "device %d videocontrol " "interface %d EXTENSION_UNIT error\n", udev->devnum, alts->desc.bInterfaceNumber); } while (0);
			return -EINVAL;
		}

		unit = (*klpe_uvc_alloc_entity)(buffer[2], buffer[3], p + 1, n);
		if (unit == NULL)
			return -ENOMEM;

		memcpy(unit->extension.guidExtensionCode, &buffer[4], 16);
		unit->extension.bNumControls = buffer[20];
		memcpy(unit->baSourceID, &buffer[22], p);
		unit->extension.bControlSize = buffer[22+p];
		unit->extension.bmControls = (__u8 *)unit + sizeof *unit;
		memcpy(unit->extension.bmControls, &buffer[23+p], n);

		if (buffer[23+p+n] != 0)
			(*klpe_usb_string)(udev, buffer[23+p+n], unit->name,
				   sizeof unit->name);
		else
			sprintf(unit->name, "Extension %u", buffer[3]);

		list_add_tail(&unit->list, &dev->entities);
		break;

	default:
		do { if ((*klpe_uvc_trace_param) & (1 << 1)) printk("\001" "7" "uvcvideo: " "Found an unknown CS_INTERFACE " "descriptor (%u)\n", buffer[2]); } while (0);
		break;
	}

	return 0;
}


#include "livepatch_bsc1236783.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "uvcvideo"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "usb_driver_claim_interface",
	  (void *)&klpe_usb_driver_claim_interface, "usbcore" },
	{ "usb_driver_release_interface",
	  (void *)&klpe_usb_driver_release_interface, "usbcore" },
	{ "usb_get_intf", (void *)&klpe_usb_get_intf, "usbcore" },
	{ "usb_ifnum_to_if", (void *)&klpe_usb_ifnum_to_if, "usbcore" },
	{ "usb_put_intf", (void *)&klpe_usb_put_intf, "usbcore" },
	{ "usb_string", (void *)&klpe_usb_string, "usbcore" },
	{ "uvc_alloc_entity", (void *)&klpe_uvc_alloc_entity, "uvcvideo" },
	{ "uvc_driver", (void *)&klpe_uvc_driver, "uvcvideo" },
	{ "uvc_find_endpoint", (void *)&klpe_uvc_find_endpoint, "uvcvideo" },
	{ "uvc_fmts", (void *)&klpe_uvc_fmts, "uvcvideo" },
	{ "uvc_trace_param", (void *)&klpe_uvc_trace_param, "uvcvideo" },
};

static int module_notify(struct notifier_block *nb,
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

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1236783_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1236783_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_USB_VIDEO_CLASS) */
