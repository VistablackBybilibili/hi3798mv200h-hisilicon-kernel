/******************************************************************************
 *  Copyright (C) 2014 Hisilicon Technologies CO.,LTD.
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
 * Create By Hisilicon 2017.5.12
 *
 ******************************************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/syscore_ops.h>
#include <linux/hisilicon/platform.h>

//#define __DUMP_REG
//#define CONFIG_REG_DEBUG

extern char *boot_bootreg;

void __iomem *reg_base_fmc = NULL;
void __iomem *reg_base_peri_ctrl = NULL;
void __iomem *_io_base_virt = NULL;
unsigned long _io_virt_to_phys_offset = 0;

#define REG_MODULE_HEAD_SIZE 2
#define REG_LEN_SIZE         2
#define REG_BASE_SIZE        3
#define REG_CFG_LEN_SIZE     2
#define REG_FMT_SIZE         3
#define REG_TABLE_END_FLAG   0
#define REG_OFFSET_POS       10
#define REG_MAX_LENGTH       8192
#define REG_VERSION_V120     0x30323176  /* v120 */

/* Boot mode */
#define BOOT_MODE_SPINAND               0x4
#define BOOT_MODE_EMMC                  0x3
#define BOOT_MODE_NAND                  0x1
#define BOOT_MODE_SPI                   0x0

#define REG_BASE_FMC                    0xF9950000
#define REG_FMC_CFG						0x0
#define REG_START_MODE                  0x0000
#define NORMAL_BOOTMODE_OFFSET          9
#define NORMAL_BOOTMODE_MASK            7

#define PLAT_IO_BASE_PHYS				(0xF8000000)
#define PLAT_IO_SIZE					(0x02000000)

#define AUTH_SUCCESS					(0x3CA5965A)
#define AUTH_FAILURE					(0xC35A69A5)

typedef unsigned int u32;

union reg_module_head {
	struct {
		unsigned char ca_flag : 1;     /* whether execute when ca chip */
		unsigned char normal_flag : 1; /* whether execute when normal(no-ca) chip */
		unsigned char wakeup_flag : 1; /* whether execute when wakeup from standby */
		unsigned char boot_flag : 1;   /* whether execute when power on */
		unsigned char module_type : 4; /* module type, like: spi,nand...  */
	} member;
	unsigned char val;
};

union reg_format {
	struct {
		/* byte 0 */
		unsigned char rw_flag : 1;     /* read or write: 0-write; 1-read */
		unsigned char reserve : 1;
		unsigned char offset : 6;      /* real offset = (offset << 2)*/

		/* byte 1 */
		unsigned char bit_off : 5;     /* bit offset of read/write */
		unsigned char val_len : 3;     /* byte length of val to be read/write: 0-0; 1~3 - 1~3byte; */

		/* byte 2 */
		unsigned char bit_num : 5;     /* bit num of read/write, real bit number = bit_num + 1 */
		unsigned char delay_len : 3;   /* byte length of delay: 0-endless; 1~3 - 1~3byte; */
	} member;
	unsigned char val[3];
};

typedef union
{
	struct
	{
		u32 op_mode                 :1;    //[0]
		u32 flash_sel               :2;    //[2:1]
		u32 page_size               :2;    //[4:3]
		u32 ecc_type                :3;    //[7:5]
		u32 block_size              :2;    //[9:8]
		u32 spi_nor_addr_mode       :1;    //[10]
		u32 spi_nand_sel            :2;    //[12:11]
		u32 nf_mode                 :3;    //[15:13]
		u32 reserved                :16;   //[31:16]
	} bits;
	u32 u32;
} FMC_CFG_U;

/* PERI ctrl register definition */
typedef union
{
	struct
	{
		u32 reserved_0              : 9; //[8:0]
		u32 boot_sel                : 3; //[11:9]
		u32 reserved_1              : 8; //[19:12]
		u32 romboot_sel             : 1; //[20]
		u32 reserved_2              : 2; //[22:21]
		u32 jtag_sel_in             : 1; //[23]
		u32 usb_boot                : 1; //[24]
		u32 sdio_pu_en_in_lock      : 1; //[25]
		u32 flash_boot_in           : 1; //[26]
		u32 reserved_3              : 5; //[31:27]
	} bits;
	u32 u32;
} PERI_START_MODE_U;            //0x0 START_MODE

enum mod_type {
	MOD_TYPE_NORMAL = 0,
	MOD_TYPE_SPI = 1,
	MOD_TYPE_NAND = 2,
	MOD_TYPE_EMMC = 3,
	MOD_TYPE_SYNCNAND = 4,
	MOD_TYPE_SD = 4,
	MOD_TYPE_BUTT,
};

/*****************************************************************************/
struct reg_filter
{
	unsigned int offset;
	unsigned int mask;
};

struct module_filter
{
	unsigned int baseaddr;
	struct reg_filter *filter;
};

struct reg_checklist_t
{
	struct module_filter *module_list;
	unsigned int module_count;
	struct reg_filter *other;
};

/*****************************************************************************/
static inline void delay(unsigned int cnt)
{
	while (cnt--)
		__asm__ __volatile__("nop");
}

/*****************************************************************************/

unsigned int boottype2modtype(unsigned int boot_type)
{
	int i, size;
	FMC_CFG_U un_fmc_cfg;
	unsigned int array[][2] = {
		{BOOT_MODE_SPI, MOD_TYPE_SPI},
		{BOOT_MODE_NAND, MOD_TYPE_NAND},
		{BOOT_MODE_EMMC, MOD_TYPE_EMMC},
		{BOOT_MODE_SPINAND, MOD_TYPE_SPI},
	};

	size = sizeof(array) / sizeof((array)[0]);

	for (i = 0; i < size; i++) {
		if (boot_type == BOOT_MODE_NAND) {
			un_fmc_cfg.u32 = readl((void __iomem *)(REG_BASE_FMC +  _io_virt_to_phys_offset + REG_FMC_CFG));
			if (un_fmc_cfg.bits.nf_mode == 0) {
				return MOD_TYPE_NAND;
			} else
			      return MOD_TYPE_SYNCNAND;
		}

		if (array[i][0] == boot_type)
		      return array[i][1];
	}

	return MOD_TYPE_NORMAL;
}

/******************************************************************************/

int get_boot_mode(void)
{
	int boot_media;

	/* read from pin */
	boot_media = readl((void __iomem *)reg_base_peri_ctrl + REG_START_MODE);
	boot_media = ((boot_media >> NORMAL_BOOTMODE_OFFSET)
		& NORMAL_BOOTMODE_MASK);

	return boot_media;
}

/*****************************************************************************/

int regaddr_is_valid(unsigned int regaddr, unsigned int *bitmask,
			struct reg_checklist_t *checklist)
{
	unsigned int base = regaddr & 0xfffff000;
	struct reg_filter *filter = 0;
	struct module_filter *module_list = checklist->module_list;
	unsigned int i = 0;
	volatile unsigned int tmp_regaddr;

	*bitmask = 0x0;

	if ((regaddr & 0xfffff000) == 0xf8a31000) {
		*bitmask = 0x0;
		return AUTH_FAILURE;
	}

	if (((regaddr & 0xffff0000) == 0xf8a30000)
	     || ((regaddr & 0xfffff000) == 0xf8a21000)) {
		tmp_regaddr = regaddr;

		if (((tmp_regaddr & 0xffff0000) != 0xf8a30000)
		     && ((tmp_regaddr & 0xfffff000) != 0xf8a21000)) {
			BUG();
		}

		*bitmask = 0xffffffff;
		return AUTH_SUCCESS;
	}

	for(i = 0; i < checklist->module_count; i++) {
		if (module_list->filter == 0)
		      break;

		if(base == module_list->baseaddr) {
			filter = module_list->filter;
			break;
		}
		module_list++;
	}

	if(!filter) {
		filter = checklist->other;
		base = 0;
	}

	for(i = 0; filter[i].mask; i++) {
		if(regaddr == (base + filter[i].offset)) {
			tmp_regaddr = regaddr;

			if(tmp_regaddr != (base + filter[i].offset)) {
				BUG();
			}

			*bitmask = filter[i].mask;
			return AUTH_SUCCESS;
		}
	}

	return AUTH_FAILURE;
}

static void reg_read_write(unsigned int addr,
			unsigned int val,
			unsigned int wait,
			union reg_format *reg,
			unsigned int bitmask)
{
	unsigned int tmp_val;
	unsigned int bit_num = reg->member.bit_num + 1;
	unsigned int regmask;

#ifdef CONFIG_REG_DEBUG
	printk(KERN_DEBUG "r/w 0x%X addr 0x%X bn 0x%X bo 0x%X v 0x%X d 0x%X\n",
			reg->member.rw_flag, addr, reg->member.bit_num, reg->member.bit_off, val, wait);
#endif

	if (reg->member.rw_flag) { /* read */
		/* if wait == 0, then wait endless */
		if (!wait)
		      wait = 120000000; //1s for 1.2G

		do {
			tmp_val = readl((void __iomem *)(uintptr_t)addr);
			if (bit_num != 32) {
				tmp_val >>= reg->member.bit_off;
				tmp_val &= ((1<<bit_num)-1);
			}

			/* timeout */
			if (0 == wait--)
			      break;

			delay(1);
		} while (tmp_val != val);

		if (tmp_val != val) {
			printk("Warning: read reg: 0x%x fail.\n", addr);
		}

	} else { /* write */
		if (bit_num < 32) {
			regmask = ((1<<bit_num)-1)<<reg->member.bit_off;
		} else {
			regmask = 0xffffffff;
		}
		regmask &= bitmask;
		regmask &= bitmask;
		regmask &= bitmask;
		tmp_val = readl((void __iomem *)(uintptr_t)addr);
		tmp_val &= ~(regmask);
		val = tmp_val | ((val << reg->member.bit_off) & regmask);
		writel(val, (void __iomem *)(uintptr_t)addr);

		delay(wait);
	}
}
/*****************************************************************************/

static void reg_parse_register(unsigned char *buf, unsigned int base, int length)
{
	unsigned char *pbuf = buf;
	union reg_format reg;
	unsigned int reg_addr;
	unsigned int val, delay;
	unsigned int bitmask = 0;
	struct reg_checklist_t reg_checklist;
	struct reg_filter sysctrl[] = {
					{0x0, 0xffffffff},
					{0x44, 0x071c77ff},
					{0x48, 0xffffffff},
					{0x58, 0xffffffff},
					{0x5c, 0x00007000},
					{0x8c, 0xffffffff},
					{0x94, 0x80000000},
					{0x98, 0xffffffff},
					{0xa8, 0xffff00ff},
					{0xac, 0xffff00ff},
					{0xc4, 0xffffffff},
					{0xc8, 0xffffffff},
					{0xd0, 0xffffffff},
					{0xf4, 0x00000001},
					{0xf00, 0xffffffff},
					{0, 0}
				};
		struct reg_filter peri_ctrl[] = {
					{0x8, 0x0000f863},
					{0x44, 0xffffffff},
					{0x48, 0xffffffff},
					{0x4c, 0xffffffff},
					{0x50, 0xffffffff},
					{0x54, 0xffffffff},
					{0x58, 0xffffffff},
					{0x5c, 0xffffffff},
					{0x60, 0xffffffff},
					{0x11c, 0x00000070},
					{0, 0}
				};

		struct reg_filter crg[] = {
					{0x0, 0xffffffff},
					{0x4, 0xffffffff},
					{0x8, 0xffffffff},
					{0xc, 0xffffffff},
					{0x10, 0xffffffff},
					{0x14, 0xffffffff},
					{0x20, 0xffffffff},
					{0x24, 0xffffffff},
					{0x28, 0xffffffff},
					{0x2c, 0xffffffff},
					{0x30, 0xffffffff},
					{0x34, 0xffffffff},
					{0x38, 0xffffffff},
					{0x3c, 0xffffffff},
					{0x48, 0xffffffff},
					{0x58, 0xffffffff},
					{0x6c, 0xffffffff},
					{0x70, 0xffffffff},
					{0x74, 0xffffffff},
					{0x78, 0xffffffff},
					{0x7c, 0xffffffff},
					{0x84, 0xffffffff},
					{0x88, 0xffffffff},
					{0x8c, 0xffffffff},
					{0x90, 0xffffffff},
					{0x94, 0xffffffff},
					{0x9c, 0xffffffff},
					{0xa0, 0xffffffff},
					{0xa8, 0xffffffff},
					{0xb0, 0xffffffff},
					{0xc8, 0xffffffff},
					{0xcc, 0xffffffff},
					{0xd0, 0xffffffff},
					{0xd4, 0xffffffff},
					{0xd8, 0xffffffff},
					{0xf0, 0xffffffff},
					{0xfc, 0xffffffff},
					{0x10c, 0xffffffff},
					{0x110, 0xffffffff},
					{0x114, 0xffffffff},
					{0x118, 0xffffffff},
					{0x11c, 0xffffffff},
					{0x128, 0xffffffff},
					{0x12c, 0xffffffff},
					{0x130, 0xffffffff},
					{0x134, 0xffffffff},
					{0x13c, 0xffffffff},
					{0x140, 0xffffffff},
					{0x144, 0xffffffff},
					{0x148, 0xffffffff},
					{0x188, 0xffffffff},
					{0x18c, 0xffffffff},
					{0x28c, 0xffffffff},
					{0x32c, 0xffffffff},
					{0x330, 0xffffffff},
					{0x334, 0xffffffff},
					{0x33c, 0xffffffff},
					{0x348, 0xffffffff},
					{0x34c, 0xffffffff},
					{0x378, 0xffffffff},
					{0x388, 0xffffffff},
					{0x38c, 0xffffffff},
					{0x390, 0xffffffff},
					{0, 0}
				};
		struct reg_filter pmc[] = {
					{0x18, 0xffffffff},
					{0x1c, 0xffffffff},
					{0x20, 0xffffffff},
					{0x24, 0xffffffff},
					{0, 0}
				};

		struct reg_filter others[] = {
					{0xf984300c, 0x000000e0},	//MAC_IF_STAT_CTRL0.phy_select
					{0, 0}
				};

		struct module_filter modulelist[] = {
					{0xF8000000, sysctrl},
					{0xF8A20000, peri_ctrl},
					{0xF8A22000, crg},
					{0xF8A23000, pmc},
					{0, 0},
				};

	while (pbuf < (buf + length)) {
		reg.val[0] = pbuf[0];
		reg.val[1] = pbuf[1];
		reg.val[2] = pbuf[2];
		pbuf += REG_FMT_SIZE;

		val = delay = 0;

		if (reg.member.val_len > 4) {
			BUG();
		}

		while (reg.member.val_len--)
		      val = (val << 8) | (*pbuf++);

		if (reg.member.delay_len > 4) {
			BUG();
		}

		while (reg.member.delay_len--)
		      delay = (delay << 8) | (*pbuf++);

		if (pbuf > (buf + length)) {
			BUG();
		}

		reg_addr = base + (reg.member.offset << 2);

		reg_checklist.module_list = modulelist;
		reg_checklist.module_count = sizeof(modulelist)/sizeof(struct module_filter);
		reg_checklist.other = others;

		bitmask = 0;
		if (regaddr_is_valid(reg_addr, &bitmask, &reg_checklist) == AUTH_SUCCESS) {
			continue;
		}

		bitmask = 0xFFFFFFFF;

		reg_read_write(reg_addr + _io_virt_to_phys_offset , val, delay, &reg, bitmask);
	}

	if (pbuf != (buf + length)) {
		BUG();
	}

}
/*****************************************************************************/

static void reg_parse_group(unsigned char *buf, int length)
{
	unsigned int base;
	int regcfg_len;
	unsigned char *pbuf = buf;

	while (pbuf < (buf + length)) {
		base = (pbuf[0]<<24) | (pbuf[1]<<16) | (pbuf[2]<<8);
		regcfg_len = (pbuf[3]<<8) | pbuf[4];

		pbuf += REG_BASE_SIZE + REG_CFG_LEN_SIZE;
		if ((pbuf + regcfg_len) <= (buf + length)) {
			reg_parse_register(pbuf, base, regcfg_len);
		}

		pbuf += regcfg_len;
	}

	if (pbuf != (buf + length)) {
		BUG();
	}
}

/*****************************************************************************/
static void reg_show_info(unsigned int regbase)
{
	printk("\nReg Version:  ");
	printk((char *)(uintptr_t)(regbase + 0x4));

	printk("\nReg Time:     ");
	printk((char *)(uintptr_t)(regbase + 0xc));

	printk("\nReg Name:     ");
	printk((char *)(uintptr_t)(regbase + 0x20));
	printk("\n\n");
}

/*****************************************************************************/

void init_reg(unsigned int base, unsigned int pm, unsigned int which)
{
#define CONFIG_EXTKEY_AREA_LEN          0x220
#define CONFIG_EXTKEY_AREA_SIG_LEN      0x100
	unsigned int regbase = base + CONFIG_EXTKEY_AREA_LEN + CONFIG_EXTKEY_AREA_SIG_LEN;
	unsigned int pm_flag = 0;
	unsigned int ca_flag = 1;
	unsigned int module_type;
	union reg_module_head head;
	int length = 0;
	unsigned short offset = *(unsigned short *)(uintptr_t)(regbase + REG_OFFSET_POS);
	unsigned char *regbuf = (unsigned char *)(uintptr_t)(regbase + offset);
	int boot_mode;

	reg_show_info(regbase);

	boot_mode = get_boot_mode();
	module_type = boottype2modtype(boot_mode);

#ifdef __DUMP_REG
	{
		unsigned int reg_len = *((unsigned int *)boot_bootreg);

		printk("boot_mode=%X, module_type=%X, reg_len = %X\n",boot_mode, module_type, reg_len);
		reg_len = 0x1000;
		printk(KERN_INFO "-----------Boot Reg-------------");
		print_hex_dump(KERN_INFO, " ", DUMP_PREFIX_OFFSET, 16, 4,
					(unsigned int *)(uintptr_t)regbase, reg_len, true);
		printk(KERN_INFO "--------------End---------------");
	}
#endif

	while ((REG_TABLE_END_FLAG != (*(unsigned int *)regbuf)) && (length < REG_MAX_LENGTH)) {
		length = (regbuf[2]<<8) | regbuf[3];
		if (length >= REG_MAX_LENGTH) {
		      BUG();
		}

		head.val = regbuf[1];
		regbuf += REG_MODULE_HEAD_SIZE + REG_LEN_SIZE;
		if ((!head.member.module_type) || (head.member.module_type == module_type)) {
			if ((head.member.boot_flag & (!pm_flag)) || (head.member.wakeup_flag & pm_flag))
			      if ((head.member.normal_flag & (!ca_flag)) || (head.member.ca_flag & ca_flag)) {
				      reg_parse_group(regbuf, length);
			      }
		}

		length = (length + 3) & (~3);
		regbuf += length;
	}
}
/*****************************************************************************/

void bootreg_resume(void)
{
	int reg_len = 0;

	reg_len = *((u32 *)boot_bootreg);
	if(!reg_len) {
		printk("Reg information invalid !!!\n");
		return;
	}

	printk("\nBootreg resume...");

	reg_base_peri_ctrl = ioremap_nocache(REG_BASE_PERI_CTRL, PAGE_SIZE);
	BUG_ON(!reg_base_peri_ctrl);

	_io_base_virt = ioremap_nocache(PLAT_IO_BASE_PHYS, PLAT_IO_SIZE);
	BUG_ON(!_io_base_virt);

	BUG_ON((ulong)_io_base_virt < PLAT_IO_BASE_PHYS);
	_io_virt_to_phys_offset = (unsigned long)_io_base_virt - PLAT_IO_BASE_PHYS;

	init_reg((u32)(uintptr_t)(boot_bootreg + 4), 0, 0);

	iounmap(reg_base_peri_ctrl);
	iounmap(_io_base_virt);

	printk("done!!!\n");

}

static struct syscore_ops bootreg_pm_syscore_ops = {
	.suspend	= NULL,
	.resume		= bootreg_resume,
};

static int __init bootreg_init(void)
{
	printk(KERN_INFO "Register bootreg syscore ops\n");
	register_syscore_ops(&bootreg_pm_syscore_ops);

	return 0;
}

early_initcall(bootreg_init);
