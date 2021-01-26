#ifndef _LIVEPATCH_BSC1180030_H
#define _LIVEPATCH_BSC1180030_H

#if IS_ENABLED(CONFIG_HID)

int livepatch_bsc1180030_hid_input_init(void);
static inline void livepatch_bsc1180030_hid_input_cleanup(void) {}

int livepatch_bsc1180030_hid_multitouch_init(void);
void livepatch_bsc1180030_hid_multitouch_cleanup(void);

int livepatch_bsc1180030_init(void);
void livepatch_bsc1180030_cleanup(void);


struct hid_input;
struct hid_field;
struct hid_usage;
struct hid_device;

void klpp_hidinput_configure_usage(struct hid_input *hidinput, struct hid_field *field,
				     struct hid_usage *usage);
int klpp_mt_input_mapping(struct hid_device *hdev, struct hid_input *hi,
		struct hid_field *field, struct hid_usage *usage,
		unsigned long **bit, int *max);

#else /* !IS_ENABLED(CONFIG_HID) */

static inline int livepatch_bsc1180030_init(void) { return 0; }

static inline void livepatch_bsc1180030_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_HID) */
#endif /* _LIVEPATCH_BSC1180030_H */
