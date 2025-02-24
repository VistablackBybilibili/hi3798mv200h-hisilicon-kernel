#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <asm/io.h>

u32 bootlog_mem_addr = 0;
u32 bootlog_mem_size = 0;

static int bootlog_proc_show(struct seq_file *m, void *v)
{
	struct page **page_array = NULL;
	u32 i, parray_size = 0;
	unsigned char *vaddr = NULL;

	if (bootlog_mem_addr && bootlog_mem_size) {

		parray_size = bootlog_mem_size>>PAGE_SHIFT;

		page_array = vmalloc(sizeof(struct page) * parray_size);
		if(!page_array) {
			seq_printf(m, "%s\n", "error, failed to malloc page array!!!");
			return -1;
		}

		/* fill the page array */
		for(i=0; i <parray_size; i++) {
			page_array[i] = phys_to_page((phys_addr_t)bootlog_mem_addr + i * PAGE_SIZE);
		}

		vaddr = (unsigned char *)vmap(page_array, parray_size, VM_MAP, pgprot_noncached(PAGE_KERNEL));
		if(!vaddr) {
			seq_printf(m, "%s\n", "error, failed to remap bootlog mem!!!");
			vfree(page_array);
			return -1;
		}

		/* set the last byte to zero */
		vaddr[bootlog_mem_size-1] = 0;

		seq_printf(m, "%s\n", vaddr);

		/* free page_array and vaddr */
		vfree(page_array);
		vunmap(vaddr);
	}
	else
		seq_printf(m, "%s\n", "warnning: no bootlog be captured!!!");

	return 0;
}

static int bootlog_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, bootlog_proc_show, NULL);
}

static const struct file_operations bootlog_proc_fops = {
	.open		= bootlog_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_bootlog_init(void)
{
	proc_create("bootlog", 0, NULL, &bootlog_proc_fops);
	return 0;
}
fs_initcall(proc_bootlog_init);
