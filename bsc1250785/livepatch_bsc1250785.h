#ifndef _LIVEPATCH_BSC1250785_H
#define _LIVEPATCH_BSC1250785_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_ACPI)

int livepatch_bsc1250785_init(void);
static inline void livepatch_bsc1250785_cleanup(void) {}

typedef u32 acpi_status;

struct acpi_walk_state;

acpi_status klpp_acpi_ut_copy_iobject_to_iobject(union acpi_operand_object *source_desc, union acpi_operand_object **dest_desc, struct acpi_walk_state *walk_state);

#else /* !IS_ENABLED(CONFIG_ACPI) */

static inline int livepatch_bsc1250785_init(void) { return 0; }
static inline void livepatch_bsc1250785_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_ACPI) */

#endif /* _LIVEPATCH_BSC1250785_H */
