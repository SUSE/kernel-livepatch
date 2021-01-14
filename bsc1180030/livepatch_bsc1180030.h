#ifndef _LIVEPATCH_BSC1180030_H
#define _LIVEPATCH_BSC1180030_H

#if IS_ENABLED(CONFIG_HID_MULTITOUCH)

int livepatch_bsc1180030_init(void);
void livepatch_bsc1180030_cleanup(void);


struct hid_device;
struct hid_input;
struct hid_field;
struct hid_usage;

int klpp_mt_input_mapping(struct hid_device *hdev, struct hid_input *hi,
		struct hid_field *field, struct hid_usage *usage,
		unsigned long **bit, int *max);

#else /* !IS_ENABLED(CONFIG_HID_MULTITOUCH) */

static inline int livepatch_bsc1180030_init(void) { return 0; }

static inline void livepatch_bsc1180030_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_HID_MULTITOUCH) */
#endif /* _LIVEPATCH_BSC1180030_H */
