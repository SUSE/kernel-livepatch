#ifndef _LIVEPATCH_BSC1215971_H
#define _LIVEPATCH_BSC1215971_H

int livepatch_bsc1215971_init(void);
void livepatch_bsc1215971_cleanup(void);

struct fs_context;
struct fs_parameter;

int klpp_smb3_fs_context_parse_param(struct fs_context *fc,
				      struct fs_parameter *param);

#endif /* _LIVEPATCH_BSC1215971_H */
