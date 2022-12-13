#ifndef _LIVEPATCH_BSC1204424_H
#define _LIVEPATCH_BSC1204424_H

int livepatch_bsc1204424_init(void);
void livepatch_bsc1204424_cleanup(void);


struct nfp_cpp;

int klpp_nfp_cpp_read(struct nfp_cpp *cpp, u32 cpp_id,
		 unsigned long long address, void *kernel_vaddr, size_t length);
int klpp_nfp_cpp_write(struct nfp_cpp *cpp, u32 cpp_id,
		  unsigned long long address, const void *kernel_vaddr,
		  size_t length);

#endif /* _LIVEPATCH_BSC1204424_H */
