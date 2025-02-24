/******************************************************************************
 *  Copyright (C) 2018 Hisilicon Technologies CO.,LTD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Create By Cai Zhiying 2018.6.27
 *
******************************************************************************/

#include "reloc.h"
#include "fdt.h"
#include "mmu.h"

/*
 *                  <- 0x0000
 *
 *   _____________  <- (reloc_start - dtb_size) & ~7
 *  |     dtb     |
 *  |             |
 *  |_____________|
 *   _____________
 *  |  reloc.bin  |  <- reloc_start = (TEXT_OFFSET - 0x5000)
 *  |_____________|  <- _reloc_end
 *
 *   _____________  <- text_offset = 0x80000
 *  |    Image    |
 *  |             |
 *  |             |
 *  |             |
 *  |_____________|
 *
 *
 *
 *  |             |
 *  |             |
 *  |_____________|  <- sp, should alignment to 16byte
 *   _____________
 *  |             |  <- offset, any address.
 *  |  reloc.bin  |
 *  |             |
 *  | __________  |  <- (offset + image_start - reloc_start)
 *  | |        |  |
 *  | |        |  |
 *  | |  Image |  |
 *  | |        |  |
 *  |_|________|__|  <- (offset + image_end - reloc_start)
 *  | |        |  |  <- (offset + dtb_start - reloc_start), alignment with 4K
 *  | |   dtb  |  |
 *  | |________|  |
 *  |_____________|  <- (offset + dtb_start - reloc_start + dtb_size)
 *
 *   ______________  <- (offset + dtb_start - reloc_start + dtb_size + 8) & ~7
 *  |             |
 *  |  malloc     |  memory for decompress. (1M)
 *  |_____________|
 */

/*
 * Documentation/arm64/booting.txt
 * The device tree blob (dtb) must be placed on an 8-byte boundary and must
 * not exceed 2 megabytes in size. Since the dtb will be mapped cacheable
 * using blocks of up to 2 megabytes in size, it must not be placed within
 * any 2M region which must be mapped with any specific attributes.
 *
 * NOTE: versions prior to v4.2 also require that the DTB be placed within
 * the 512 MB region starting at text_offset bytes below the kernel Image.
 */
unsigned long relocate(char *offset, char *fdt)
{
	void *entry_kernel = (void *)(unsigned long)text_offset;
	void *entry_dtb = (void *)((reloc_start - dtb_size) & (~7ULL));
	unsigned int dtb_totalsize = 0;

	char *off_kernel = offset + (image_start - reloc_start);
	char *off_dtb = NULL;

	if(fdt) {
		off_dtb = fdt;
	} else {
		off_dtb = offset + (dtb_start - reloc_start);
	}

	putstr("\n\n");

	enable_mmu_el1();

	if ((unsigned long)entry_dtb > (unsigned long)entry_kernel)
		printf("reloc: dtb too large.\n");

	check_fdt((struct fdt_header *)off_dtb, dtb_size);

	dtb_totalsize = get_fdt_totalsize((struct fdt_header *)off_dtb);

	printf("DTB:    %08x %08x %08x\n",
		(unsigned long)off_dtb, (unsigned long)entry_dtb, dtb_totalsize);

	memmove(entry_dtb, off_dtb, dtb_totalsize);

	printf("Kernel: %08x %08x %08x\n", (unsigned long)off_kernel,
		(unsigned long)entry_kernel, (image_end - image_start));

#ifdef CONFIG_ARM64_KERNEL_COMPRESS
	decompress_kernel((unsigned char *)off_kernel, image_end - image_start, entry_kernel,
		((unsigned long)offset + dtb_start - reloc_start + dtb_size + 8) & ~7ULL);
#else
	memmove(entry_kernel, off_kernel, image_end - image_start);
	putstr("booting the arm64 kernel.\n");
#endif
	flush_icache_all();

	return (unsigned long)entry_dtb;
}
