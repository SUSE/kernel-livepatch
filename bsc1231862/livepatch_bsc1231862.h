#ifndef _LIVEPATCH_BSC1231862_H
#define _LIVEPATCH_BSC1231862_H

#if IS_ENABLED(CONFIG_ACPI)

int livepatch_bsc1231862_init(void);
static inline void livepatch_bsc1231862_cleanup(void) {}

struct acpi_device;

int klpp_acpi_device_setup_files(struct acpi_device *dev);

#else /* !IS_ENABLED(CONFIG_ACPI) */

static inline int livepatch_bsc1231862_init(void) { return 0; }
static inline void livepatch_bsc1231862_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_ACPI) */

#endif /* _LIVEPATCH_BSC1231862_H */
