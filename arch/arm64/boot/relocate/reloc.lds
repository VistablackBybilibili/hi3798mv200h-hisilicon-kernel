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

OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS
{
	.text : {
		__reloc_start = .;
		arch/arm64/boot/relocate/start.o (.text)
		*(.text)
	}

	. = ALIGN(4);
	.rodata : { *(SORT_BY_ALIGNMENT(SORT_BY_NAME(.rodata*))) }

	. = ALIGN(4);
	.data : { *(.data)  }

	. = ALIGN(4);
	__bss_start = .;
	.bss : { *(.bss) }
	. = ALIGN(4);
	__bss_end = .;

	. = ALIGN(4);
	__reloc_end = .;

	ASSERT(((__reloc_end - __reloc_start) < 0x5000), "reloc.bin out of range!")

	.image_data : { *(.image_data)  }

	. = ALIGN(4);
	__dtb_start = .;

	__reloc_total = __dtb_start - __reloc_start;
}
