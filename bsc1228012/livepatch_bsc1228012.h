#ifndef _LIVEPATCH_BSC1228012_H
#define _LIVEPATCH_BSC1228012_H

#if IS_ENABLED(CONFIG_SCSI_PM8001)

int livepatch_bsc1228012_init(void);
void livepatch_bsc1228012_cleanup(void);

int klpp_pm8001_abort_task(struct sas_task *task);
int klpp_pm8001_abort_task_set(struct domain_device *dev, u8 *lun);
int klpp_pm8001_clear_aca(struct domain_device *dev, u8 *lun);
int klpp_pm8001_clear_task_set(struct domain_device *dev, u8 *lun);
int klpp_pm8001_exec_internal_task_abort(struct pm8001_hba_info *pm8001_ha,
					 struct pm8001_device *pm8001_dev,
					 struct domain_device *dev, u32 flag,
					 u32 task_tag);
int klpp_pm8001_lu_reset(struct domain_device *dev, u8 *lun);
int klpp_pm8001_query_task(struct sas_task *task);
void klpp_pm8001_task_done(struct sas_task *task);
void klpp_pm8001_tmf_timedout(struct timer_list *t);

#else

static int livepatch_bsc1228012_init(void) { return 0; }
static void livepatch_bsc1228012_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SCSI_PM8001) */

#endif /* _LIVEPATCH_BSC1228012_H */
