
/*
 * devfreq clock for utgard GPUs
 *
 * Copyright (c) <2011-2015> HiSilicon Technologies Co., Ltd.
 *              http://www.hisilicon.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <dt-bindings/clock/hi3798mv310-clock.h>
#include <linux/hikapi.h>

#include <linux/of.h>
#include <linux/of_address.h>
#include "clk-hisi.h"

#define CLOCK_ERROR_INFO() \
	printk("error: func = %s, line = %d\n", __FUNCTION__, __LINE__);

#define CLOCK_DEBUG 0

typedef enum
{
	CRG_REG_ADDR_SOFTRESET = 0x00d4,
	CRG_REG_ADDR_LOWPOWER = 0x0124
}crg_register_addr;

typedef enum
{
	CRG_REG_MASK_ENABLE = 0x1,
	CRG_REG_MASK_ENABLE_PP0 = (0x1 << 8),
	CRG_REG_MASK_ENABLE_PP1 = (0x1 << 9),
	CRG_REG_MASK_ENABLE_PP2 = (0x1 << 10),
	CRG_REG_MASK_ENABLE_PP3 = (0x1 << 11),

	CRG_REG_MASK_RESET = (0x1 << 4),
	CRG_REG_MASK_FREQ_SEL = 0x7,

	CRG_REG_MASK_BEGIN_CFG_BYPASS = (0x1 << 9),
	CRG_REG_MASK_SW_BEGIN_CFG = (0x1 << 10)
}crg_register_mask;

struct pll_table {
	unsigned long rate;
	int value;
};

static struct pll_table gpu_pll_table[] = {
	{200000000, 0x7},
	{300000000, 0x4},
	{400000000, 0x1},
	{480000000, 0x6},
	{540000000, 0x0},
	{675000000, 0x5},
	{860000000, 0x2}
};


static int CLOCK_MAX_FREQ_NUM = (sizeof(gpu_pll_table)/sizeof(gpu_pll_table[0]));

/************ private function ************/

static void hisi_gpu_clk_on(struct clk_hw *hw)
{
	unsigned int value;
	struct hiclk_hw *clock = to_hiclk_hw(hw);

	value = readl(clock->peri_crg_base + CRG_REG_ADDR_SOFTRESET);
	value |= CRG_REG_MASK_ENABLE | CRG_REG_MASK_ENABLE_PP0 | CRG_REG_MASK_ENABLE_PP1;
	writel(value, clock->peri_crg_base + CRG_REG_ADDR_SOFTRESET);

	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_on@\n");
}

static void hisi_gpu_clk_off(struct clk_hw *hw)
{
	unsigned int value;
	struct hiclk_hw *clock = to_hiclk_hw(hw);

	value = readl(clock->peri_crg_base + CRG_REG_ADDR_SOFTRESET);
	value &= ~(CRG_REG_MASK_ENABLE | CRG_REG_MASK_ENABLE_PP0 | CRG_REG_MASK_ENABLE_PP1);
	writel(value, clock->peri_crg_base + CRG_REG_ADDR_SOFTRESET);

	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_off@\n");
}

static void hisi_gpu_clk_reset(struct clk_hw *hw)
{
	unsigned int value;
	struct hiclk_hw *clock = to_hiclk_hw(hw);

	/* reset */
	value = readl(clock->peri_crg_base + CRG_REG_ADDR_SOFTRESET);
	value |= CRG_REG_MASK_RESET;
	writel(value, clock->peri_crg_base + CRG_REG_ADDR_SOFTRESET);

	udelay(1);

	/* cancel reset */
	value &= ~CRG_REG_MASK_RESET;
	writel(value, clock->peri_crg_base + CRG_REG_ADDR_SOFTRESET);

	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_reset@\n");
}

static int hisi_gpu_clk_get_index(unsigned int rate)
{
	int index;

	for (index = 0; index < CLOCK_MAX_FREQ_NUM; index++) {
		if (gpu_pll_table[index].rate == rate) {
			/*if(CLOCK_DEBUG)
				printk("hisi_gpu_clk_get_index@ index = %d\n", index);*/

			return index;
		}
	}

	CLOCK_ERROR_INFO();

	return -1;
}

static unsigned long hisi_gpu_clk_get_rate(struct clk_hw *hw)
{
	unsigned int i, value;
	struct hiclk_hw *clock = to_hiclk_hw(hw);

	value = readl(clock->peri_crg_base + CRG_REG_ADDR_LOWPOWER);
	value &= CRG_REG_MASK_FREQ_SEL;

	for (i = 0; i < CLOCK_MAX_FREQ_NUM; i++) {
		if (gpu_pll_table[i].value == value) {
			if (CLOCK_DEBUG)
				printk("hisi_gpu_clk_get_rate@ Freq = %ld\n", gpu_pll_table[i].rate);

			return gpu_pll_table[i].rate;
		}
	}

	CLOCK_ERROR_INFO();

	return 0;
}

/************ plugin function ************/

static int hisi_gpu_clk_prepare(struct clk_hw *hw)
{
	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_prepare@\n");

	return 0;
}


static void hisi_gpu_clk_unprepare(struct clk_hw *hw)
{
	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_unprepare@\n");
}

static int hisi_gpu_clk_enable(struct clk_hw *hw)
{
	hisi_gpu_clk_on(hw);

	hisi_gpu_clk_reset(hw);

	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_enable@\n");

	return 0;
}


static void hisi_gpu_clk_disable(struct clk_hw *hw)
{
	hisi_gpu_clk_off(hw);

	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_disable@\n");
}

static int hisi_gpu_clk_set_rate(struct clk_hw *hw, unsigned long rate, unsigned long parent_rate)
{
	unsigned int crg_value, index;
	unsigned long old_rate;
	struct hiclk_hw *clock = to_hiclk_hw(hw);

	index = hisi_gpu_clk_get_index(rate);

	if (-1 == index) {
		CLOCK_ERROR_INFO();
		return -1;
	}

	old_rate = clock->rate;

	crg_value = readl(clock->peri_crg_base + CRG_REG_ADDR_LOWPOWER);

	crg_value &= ~CRG_REG_MASK_FREQ_SEL;
	crg_value |= CRG_REG_MASK_BEGIN_CFG_BYPASS;
	crg_value &= ~CRG_REG_MASK_SW_BEGIN_CFG;
	crg_value |= gpu_pll_table[index].value;

	writel(crg_value, clock->peri_crg_base + CRG_REG_ADDR_LOWPOWER);

	crg_value |= CRG_REG_MASK_SW_BEGIN_CFG;

	writel(crg_value, clock->peri_crg_base + CRG_REG_ADDR_LOWPOWER);

	clock->rate = rate;

	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_set_rate@ cur = %lu, next = %lu\n", old_rate, rate);

	return 0;
}

static unsigned long hisi_gpu_clk_recalc_rate(struct clk_hw *hw, unsigned long parent_rate)
{
	struct hiclk_hw *clock = to_hiclk_hw(hw);
	unsigned long rate = hisi_gpu_clk_get_rate(hw);

	if (0 == rate) {
		CLOCK_ERROR_INFO();
		return -1;
	}

	clock->rate = rate;

	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_recalc_rate@ Freq = %ld\n", rate);

	return rate;
}

static long hisi_gpu_clk_round_rate(struct clk_hw *hw, unsigned long rate, unsigned long *parent_rate)
{
	if (CLOCK_DEBUG)
		printk("hisi_gpu_clk_round_rate@ next = %lu\n", rate);

	return rate;
}

struct clk_ops clk_ops_higpu = {
	.prepare = hisi_gpu_clk_prepare,
	.unprepare = hisi_gpu_clk_unprepare,
	.enable = hisi_gpu_clk_enable,
	.disable = hisi_gpu_clk_disable,
	.set_rate = hisi_gpu_clk_set_rate,
	.recalc_rate = hisi_gpu_clk_recalc_rate,
	.round_rate = hisi_gpu_clk_round_rate,
};

