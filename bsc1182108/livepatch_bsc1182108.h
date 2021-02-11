#ifndef _LIVEPATCH_BSC1182108_H
#define _LIVEPATCH_BSC1182108_H

int livepatch_bsc1182108_init(void);
void livepatch_bsc1182108_cleanup(void);


struct page;
struct writeback_control;
struct nfs_pageio_descriptor;

int klpp_nfs_do_writepage(struct page *page, struct writeback_control *wbc,
			    struct nfs_pageio_descriptor *pgio);

#endif /* _LIVEPATCH_BSC1182108_H */
