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
 * Create By Cai Zhiying 2018.6.29
 *
******************************************************************************/

#include "fdt.h"
#include "reloc.h"

void putstr(const char *s);

void fdt_error(char *x)
{
	putstr("\n\n");
	putstr(x);
	putstr("\n\n -- System halted");

	while(1);	/* Halt */
}

int check_fdt(struct fdt_header *fdt, unsigned int dtb_size)
{
	if (fdt32_to_cpu(fdt->magic) != FDT_MAGIC) {
		fdt_error("reloc: bad dtb magic.");
	}

	return 0;
}

int get_fdt_totalsize(struct fdt_header *fdt)
{
	if (fdt32_to_cpu(fdt->magic) != FDT_MAGIC) {
		fdt_error("reloc: bad dtb magic.");
	}

	return fdt32_to_cpu(fdt->totalsize);
}