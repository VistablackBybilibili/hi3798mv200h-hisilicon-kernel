################################################################################
#    Copyright (C) 2014 Hisilicon STB Development Dept
#    All rights reserved.
#####
#    Create by Cai Zhiyong
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#    http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
################################################################################

OBJS	=
OBJS	+= start.o reloc.o uart_p101x.o image_data.o printf.o fdt.o \
	mmu.o cache.o

OBJS	+= utils.o
CFLAGS_utils.o := -Os

ifeq ($(CONFIG_ARM64_KERNEL_COMPRESS),y)
OBJS	+= decompress.o
endif

compress-$(CONFIG_KERNEL_GZIP) = gzip
compress-$(CONFIG_KERNEL_LZO)  = lzo
compress-$(CONFIG_KERNEL_LZMA) = lzma
compress-$(CONFIG_KERNEL_XZ)   = xzkern
compress-$(CONFIG_KERNEL_LZ4)  = lz4

clean-files	+=

CONFIG_GCOV_KERNEL	:=
CONFIG_UBSAN		:=
CONFIG_KCOV		:=
CONFIG_KASAN		:=

KBUILD_CFLAGS := -D__KERNEL__ -Wall -Wundef -fno-common -std=gnu89 \
		 -mgeneral-regs-only -Wno-unused-but-set-variable  \
		 -fno-delete-null-pointer-checks -mlittle-endian -O2 \
		 -Wno-pointer-sign -Werror

ccflags-y := -fpic -fno-builtin -mstrict-align

AFLAGS_start.o := -DTEXT_OFFSET=$(TEXT_OFFSET)   \
	-DDTB_SIZE=$(shell ls -l $(DTB_OBJS) | awk '{print $$5}')

$(obj)/start.o: $(DTB_OBJS) $(IMAGE)

CFLAGS_uart_p101x.o := -DDEBUG_UART_BASE=$(CONFIG_HISI_DEBUG_UART_PHYS)

$(obj)/uart_p101x.o: $(DTB_OBJS) $(IMAGE)

$(obj)/image_data.o: $(obj)/image_data

$(obj)/image_data: $(IMAGE) FORCE
ifeq ($(CONFIG_ARM64_KERNEL_COMPRESS),y)
	$(call if_changed,$(compress-y))
else
	cp -f $< $@
endif

RELOC_SIZE := 0x5000

RELOC_TEXT_OFFSET := $(shell /bin/bash -c 'printf "0x%08x" \
	$$[$(TEXT_OFFSET) - $(RELOC_SIZE)]')

LDFLAGS_reloc.elf += -Ttext $(RELOC_TEXT_OFFSET) -e _start
LDFLAGS_reloc.elf += -p --no-undefined -X -T

$(obj)/reloc.elf: $(obj)/reloc.lds $(addprefix $(obj)/,$(OBJS)) FORCE
	$(call if_changed,ld)

OBJCOPYFLAGS_reloc.bin :=-O binary -R .note -R .note.gnu.build-id -R .comment -S

$(obj)/reloc.bin: $(obj)/reloc.elf $(IMAGE) $(DTB_OBJS)
	$(call if_changed,objcopy)
	$(Q)(SZ=$(shell $(CROSS_COMPILE)readelf -s $< | grep "__reloc_total" | awk '{print $$2}'); \
		dd if=$@ of=$@T bs=$$(echo $$((16#$${SZ}))) count=1 conv=sync 2>/dev/null)
	$(Q)mv -f $@T $@
