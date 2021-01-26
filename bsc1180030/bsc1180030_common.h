#ifndef BSC1180030_COMMON_H
#define BSC1180030_COMMON_H

#include <linux/device.h>
#include <linux/hid.h>

/* klp-ccp: from include/linux/hid.h */
static inline void klpp_hid_map_usage(struct hid_input *hidinput,
		struct hid_usage *usage, unsigned long **bit, int *max,
		__u8 type, __u16 c)
{
	struct input_dev *input = hidinput->input;
	/*
	 * Fix CVE-2020-0465
	 *  +2 lines
	 */
	unsigned long *bmap = NULL;
	unsigned int limit = 0;

	/*
	 * Fix CVE-2020-0465
	 *  -2 lines
	 */

	switch (type) {
	case EV_ABS:
		/*
		 * Fix CVE-2020-0465
		 *  -2 lines, +2 lines
		 */
		bmap = input->absbit;
		limit = ABS_MAX;
		break;
	case EV_REL:
		/*
		 * Fix CVE-2020-0465
		 *  -2 lines, +2 lines
		 */
		bmap = input->relbit;
		limit = REL_MAX;
		break;
	case EV_KEY:
		/*
		 * Fix CVE-2020-0465
		 *  -2 lines, +2 lines
		 */
		bmap = input->keybit;
		limit = KEY_MAX;
		break;
	case EV_LED:
		/*
		 * Fix CVE-2020-0465
		 *  -2 lines, +2 lines
		 */
		bmap = input->ledbit;
		limit = LED_MAX;
		break;
	}

	/*
	 * Fix CVE-2020-0465
	 *  +11 lines
	 */
	if (unlikely(c > limit || !bmap)) {
		pr_warn_ratelimited("%s: Invalid code %d type %d\n",
				    input->name, c, type);
		*bit = NULL;
		return;
	}

	usage->type = type;
	usage->code = c;
	*max = limit;
	*bit = bmap;
}

static inline void klpp_hid_map_usage_clear(struct hid_input *hidinput,
		struct hid_usage *usage, unsigned long **bit, int *max,
		__u8 type, __u16 c)
{
	klpp_hid_map_usage(hidinput, usage, bit, max, type, c);
	/*
	 * Fix CVE-2020-0465
	 *  -1 line, +2 lines
	 */
	if (*bit)
		clear_bit(usage->code, *bit);
}

#endif
