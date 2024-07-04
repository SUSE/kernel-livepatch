#ifndef _LIVEPATCH_BSC1223363_H
#define _LIVEPATCH_BSC1223363_H

int livepatch_bsc1223363_init(void);
void livepatch_bsc1223363_cleanup(void);

struct cifs_tcon;
struct cifs_sb_info;

void
klpp_smb3_qfs_tcon(const unsigned int xid, struct cifs_tcon *tcon,
	      struct cifs_sb_info *cifs_sb);

#endif /* _LIVEPATCH_BSC1223363_H */
