#ifndef _LIVEPATCH_BSC1254451_H
#define _LIVEPATCH_BSC1254451_H

#if IS_ENABLED(CONFIG_ACPI_PROCESSOR)

int livepatch_bsc1254451_init(void);
static inline void livepatch_bsc1254451_cleanup(void) {}

struct acpi_processor;
int klpp_acpi_processor_get_lpi_info(struct acpi_processor *pr);

#else /* !IS_ENABLED(CONFIG_ACPI_PROCESSOR) */

static inline int livepatch_bsc1254451_init(void) { return 0; }
static inline void livepatch_bsc1254451_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_ACPI_PROCESSOR) */

#endif /* _LIVEPATCH_BSC1254451_H */
