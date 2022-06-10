#ifndef _KLP_KALLSYMS_RELOCS
#define _KLP_KALLSYMS_RELOCS

struct klp_kallsyms_reloc
{
	const char *symname;
	void **addr;
	const char *objname;
	unsigned long sympos;
};

int klp_kallsyms_relocs_init(void);

int klp_resolve_kallsyms_relocs(struct klp_kallsyms_reloc *relocs,
				unsigned long count);

extern struct module *(*klpe_find_module)(const char *name);

#endif /* _KLP_KALLSYMS_RELOCS */
