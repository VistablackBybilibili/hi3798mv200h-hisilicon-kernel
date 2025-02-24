#include <linux/moduleloader.h>
#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/module.h>


int (*module_frob_sections)(Elf_Ehdr *hdr, Elf_Shdr *sechdrs, char *secstrings, struct module *mod);
EXPORT_SYMBOL(module_frob_sections);

int module_frob_arch_sections(Elf_Ehdr *hdr, Elf_Shdr *sechdrs, char *secstrings, struct module *mod)
{
	if (module_frob_sections) {
		int err = module_frob_sections(hdr, sechdrs, secstrings, mod);
		if (err < 0)
			return err;
	}
	return 0;
}