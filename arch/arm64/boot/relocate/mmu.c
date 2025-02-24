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
 * Create By Cai Zhiying 2018.7.2
 *
******************************************************************************/

#include "reloc.h"
#include "mmu.h"

/******************************************************************************/
#define ATTR_IWBWA_OWBWA_NTR_INDEX     0x0
#define ATTR_IWBWA_OWBWA_NTR           (0xff)
#define MAIR_ATTR_SET(attr, index)     (attr << (index << 3))

#define TCR_SH_INNER_SHAREABLE         (0x3 << 12)
#define TCR_RGN_OUTER_WBA              (0x1 << 10)
#define TCR_RGN_INNER_WBA              (0x1 << 8)
#define TCR_TG1_4K                     (0x2ULL << 30)
#define TCR_EPD1_DISABLE               (1 << 23)
#define TCR_T0SZ_BIT(bit)              ((64 - (bit)) << 0)
#define TCR_T1SZ_BIT(bit)              ((64 - (bit)) << 16)

#define SCTLR_M_BIT                    (1 << 0)

#define SCTLR_A_BIT                    (1 << 1)
#define SCTLR_C_BIT                    (1 << 2)
#define SCTLR_SA_BIT                   (1 << 3)
#define SCTLR_I_BIT                    (1 << 12)
#define SCTLR_WXN_BIT                  (1 << 19)
#define SCTLR_EE_BIT                   (1 << 25)

static unsigned long l1_ttb0[4] __attribute__((__aligned__(32))) = {
	0x0ULL      /* 0 - 1G */
	| (1 << 10) /* AF */
	| (3 << 8)  /* ISH */
	| 0x01      /* Block */
	,

	0x40000000ULL /* 1G - 2G */
	| (1 << 10)   /* AF */
	| (3 << 8)    /* ISH */
	| 0x01        /* Block */
	,

	0x80000000ULL /* 2G-3G */
	| (1 << 10)   /* AF */
	| (3 << 8)    /* ISH */
	| 0x01        /* Block */
	,

	0xC0000000ULL /* 3G-4G */
	| (1 << 10)   /* AF */
	| (1 << 2)    /* AttrIndex=1 */
	| 0x01        /* Block */
};

static unsigned long l1_ttb1[4] __attribute__((__aligned__(32))) = {
	0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL,
};

void enable_mmu_el1(void)
{
	unsigned long mair, tcr;
	unsigned int sctlr;

	mair = MAIR_ATTR_SET(ATTR_IWBWA_OWBWA_NTR, ATTR_IWBWA_OWBWA_NTR_INDEX);
	asm volatile("msr	mair_el1, %0" : : "r" (mair));

	asm volatile("tlbi	vmalle1");

	tcr = TCR_SH_INNER_SHAREABLE |
		TCR_RGN_OUTER_WBA |
		TCR_RGN_INNER_WBA |
		TCR_TG1_4K |
		TCR_EPD1_DISABLE |
		TCR_T0SZ_BIT(32) |
		TCR_T1SZ_BIT(32);
	asm volatile("msr	tcr_el1, %0" : : "r" (tcr));

	asm volatile("msr	ttbr0_el1, %0" : : "r" (l1_ttb0));
	asm volatile("msr	ttbr1_el1, %0" : : "r" (l1_ttb1));

	asm volatile("dsb	sy\n"
		     "isb");

	asm volatile("mrs	%0, sctlr_el1": "=r" (sctlr));
	sctlr |= SCTLR_M_BIT | SCTLR_I_BIT | SCTLR_C_BIT;
	asm volatile("msr	sctlr_el1, %0" : : "r" (sctlr));

	asm volatile("isb");
}

void disable_mmu_el1(void)
{
	unsigned int sctlr;

	asm volatile("mrs	%0, sctlr_el1": "=r" (sctlr));

	sctlr &= ~(SCTLR_M_BIT | SCTLR_I_BIT | SCTLR_C_BIT);

	asm volatile("msr	sctlr_el1, %0" : : "r" (sctlr));

	asm volatile("isb");

}

void flush_icache_all(void)
{
	asm volatile("ic	ialluis");
	asm volatile("dsb	ish");
	asm volatile("isb");
}

