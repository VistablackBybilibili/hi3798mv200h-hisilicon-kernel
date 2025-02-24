
/*
 * devfreq regulator for utgard GPUs
 *
 * Copyright (c) <2011-2015> HiSilicon Technologies Co., Ltd.
 *              http://www.hisilicon.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define DRVNAME "gpu-regulator-driver"
#define REGNAME "Hisilicon GPU Regulator"
#define pr_fmt(fmt) DRVNAME ": " fmt

#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>
#include <asm/delay.h>

#define REGULATOR_ERROR_INFO() \
	printk("error: func = %s, line = %d\n", __FUNCTION__, __LINE__);

#define REGULATOR_DEBUG 0

#define REGULATOR_STEP 5
#define REGULATOR_OFFSET (1<<17)
#define REGULATOR_BASE 0x000100DD
#define REGULATOR_VMIN 700
#define REGULATOR_VMAX 1250

#define REG_HPM			0xf8000098
#define REG_PWM			0xf8a2301c

#define REG_LINE0		0xf8000f0c
#define REG_LINE1		0xf8000f08
#define REG_MAX			0xf80000c4
#define REG_TEMP		0xf80000b4
#define REG_OTP			0xf8000f1c

/* Max voltage can be configured */
#define MAX_VOLT		1185

#define REGULATOR_GPU 0
#define REGULATOR_CPU 1

struct hisi_gpu_regulator {
	struct regulator_desc desc;
	struct regulator_dev *regdev;
	void __iomem *base;
	int min_uV;
	int max_uV;
};

static unsigned int HPM = 0;

/* 0: gpu voltage
     1: cpu voltage */
static unsigned int voltage[2];

/* 0: line 0 parameters, for lower frequency
     1: line 1 parameters, for higher frequency */
static unsigned int ratio[2];
static unsigned int offset[2];
static unsigned int maxvolt[2];

/* 0: compensate for temperature
     1: compensate for OTP */
static unsigned int compensate[2];;

static void *iomem_pwm = NULL;
static void *iomem_temp = NULL;
static void *iomem_otp = NULL;

static DEFINE_MUTEX(regulator_mutex);

/* To get the core hpm and core voltage */
static void hisi_regulator_core_init(void)
{
	int i;
	void *iomem_line0 = ioremap_nocache(REG_LINE0, 0x1000);
	void *iomem_max = ioremap_nocache(REG_MAX, 0x1000);
	void *iomem_hpm = ioremap_nocache(REG_HPM, 0x1000);

	iomem_temp = ioremap_nocache(REG_TEMP, 0x1000);
	iomem_otp = ioremap_nocache(REG_OTP, 0x1000);

	/* get cpu-gpu voltage */
	for (i = 0; i < 2; i++) {
		voltage[i] = REGULATOR_VMAX - (readl(iomem_pwm) - REGULATOR_BASE) * REGULATOR_STEP / REGULATOR_OFFSET;
	}

	/* every board has only one hpm */
	HPM = (readl(iomem_hpm) & 0x3ff);

	/* parameters for line */
	for (i = 0; i < 2; i++) {
		ratio[i]   = (readl(iomem_line0 - i*4) & 0xffff0000) >> 16;
		offset[i]  = (readl(iomem_line0 - i*4) & 0x0000ffff);
		maxvolt[i] = (readl(iomem_max) & (0xffff0000 >> (i*16))) >> ((1-i)*16);
	}

	/* compensate for temperature and OTP */
	for (i = 0; i < 2; i++) {
		compensate[i] = readl(i ? iomem_otp : iomem_temp);
	}

	iounmap(iomem_line0);
	iounmap(iomem_max);
	iounmap(iomem_hpm);

	return;
}

/* GPU/CPU/Core had a common power domain, should give consideration to each other */
int hisi_regulator_set_voltage(int type, int volt)
{
	unsigned int value, real_volt;

	mutex_lock(&regulator_mutex);

	switch (type) {
		case REGULATOR_GPU:
		case REGULATOR_CPU:
			voltage[type] = volt;
			break;

		default:
			REGULATOR_ERROR_INFO();
			mutex_unlock(&regulator_mutex);
			return -EINVAL;
	}

	real_volt = (voltage[0] > voltage[1]) ? voltage[0] : voltage[1];

	real_volt = (real_volt > MAX_VOLT) ? MAX_VOLT : real_volt;

	value = REGULATOR_BASE + ((REGULATOR_VMAX - real_volt) / REGULATOR_STEP) * REGULATOR_OFFSET;
	writel(value, iomem_pwm);

	mutex_unlock(&regulator_mutex);

	return real_volt;
}
EXPORT_SYMBOL(hisi_regulator_set_voltage);

static int hisi_gpu_regulator_get_voltage(struct regulator_dev *regdev)
{
	struct hisi_gpu_regulator *regulator = rdev_get_drvdata(regdev);

	unsigned int vmax = REGULATOR_VMAX;
	unsigned int vmin = REGULATOR_VMIN;
	unsigned int step = REGULATOR_STEP;
	unsigned int base = REGULATOR_BASE;
	unsigned int offset = REGULATOR_OFFSET;
	unsigned int volt, value;

	value = readl(regulator->base);

	volt = vmax - (value - base)*step/offset;

	if ((volt < vmin) || (volt > vmax)) {
		REGULATOR_ERROR_INFO();
		return -EINVAL;
	}

	if (REGULATOR_DEBUG)
		printk("hisi_gpu_regulator_get_voltage@ Volt = %d\n", volt);

	return volt*1000;
}

static int hisi_gpu_regulator_set_voltage(struct regulator_dev *regdev, int min_uV, int max_uV, unsigned *selector)
{
#define BOUNDARY 540000

	unsigned int freq = min_uV;
	unsigned int volt;

	/* compute the gpu voltage, based on gpu frequency and HPM */
	int i = (freq > BOUNDARY) ? 1 : 0;

	volt = offset[i] - (ratio[i] * HPM) / 1000;
	volt = (volt > maxvolt[i]) ? maxvolt[i] : volt;

	/* compensate for temperature */
	compensate[0] = readl(iomem_temp);
	if (compensate[0] == 0x33333333) {
		volt += 50;
	}

	/* compensate for OTP */
	compensate[1] = readl(iomem_otp);
	volt += (compensate[1] & 0xff);

	if (volt >= REGULATOR_VMIN && volt <= REGULATOR_VMAX) {
		volt = hisi_regulator_set_voltage(REGULATOR_GPU, volt);
	} else {
		REGULATOR_ERROR_INFO();
		return -EINVAL;
	}

	udelay(1000);

	if (REGULATOR_DEBUG)
		printk("hisi_gpu_regulator_set_voltage@ Volt = %d\n", volt);

	return 0;
}

static struct regulator_ops hisi_gpu_regulator_ops = {
	.get_voltage = hisi_gpu_regulator_get_voltage,
	.set_voltage = hisi_gpu_regulator_set_voltage,
};

static int hisi_regulator_probe(struct platform_device *pdev)
{
	struct hisi_gpu_regulator *regulator = NULL;
	struct regulator_init_data *init_data = NULL;
	struct regulator_config config = {0};
	struct resource *res = NULL;
	char *pname = NULL;

	regulator = devm_kzalloc(&pdev->dev, sizeof(*regulator), GFP_KERNEL);

	if (!regulator) {
		REGULATOR_ERROR_INFO();
		return -ENOMEM;
	}

	pname = REGNAME;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, pname);
	if (!res) {
		REGULATOR_ERROR_INFO();
		return -ENODEV;
	}

	regulator->base = devm_ioremap_nocache(&pdev->dev, res->start, resource_size(res));
	if (!regulator->base) {
		devm_kfree(&pdev->dev, regulator);
		REGULATOR_ERROR_INFO();
		return -ENOMEM;
	}

	iomem_pwm = (void __iomem *)regulator->base;

	regulator->desc.name = dev_name(&pdev->dev);
	regulator->desc.type = REGULATOR_VOLTAGE;
	regulator->desc.owner = THIS_MODULE;
	regulator->desc.continuous_voltage_range = true;

	init_data = of_get_regulator_init_data(&pdev->dev, pdev->dev.of_node, &regulator->desc);
	if (!init_data) {
		devm_iounmap(&pdev->dev, regulator->base);
		devm_kfree(&pdev->dev, regulator);
		REGULATOR_ERROR_INFO();
		return -EINVAL;
	}

	init_data->constraints.apply_uV = 0;
	regulator->min_uV = init_data->constraints.min_uV;
	regulator->max_uV = init_data->constraints.max_uV;

	if (regulator->min_uV >= regulator->max_uV) {
		devm_iounmap(&pdev->dev, regulator->base);
		devm_kfree(&pdev->dev, regulator);
		REGULATOR_ERROR_INFO();
		return -EINVAL;
	}

	regulator->desc.ops = &hisi_gpu_regulator_ops;

	config.dev = &pdev->dev;
	config.init_data = init_data;
	config.driver_data = regulator;
	config.of_node = pdev->dev.of_node;

	regulator->regdev = devm_regulator_register(&pdev->dev, &regulator->desc, &config);
	if (IS_ERR(regulator->regdev)) {
		devm_iounmap(&pdev->dev, regulator->base);
		devm_kfree(&pdev->dev, regulator);
		REGULATOR_ERROR_INFO();
		return PTR_ERR(regulator->regdev);
	}

	platform_set_drvdata(pdev, regulator);

	hisi_regulator_core_init();

	if (REGULATOR_DEBUG)
		printk("hisi_regulator_probe@\n");

	return 0;
}

static const struct of_device_id hisi_regulator_of_match[] = {
	{ .compatible = "hisilicon,hi3798mv310-volt", },
	{ }
};

static struct platform_driver hisi_regulator_driver = {
	.probe = hisi_regulator_probe,
	.driver = {
		.name = DRVNAME,
		.owner = THIS_MODULE,
		.of_match_table = hisi_regulator_of_match,
	},
};

module_platform_driver(hisi_regulator_driver);

MODULE_AUTHOR("Hisilicon GPU Team");
MODULE_DESCRIPTION("Hisilicon GPU Regulator");
MODULE_LICENSE("GPLv2");
MODULE_ALIAS("Hisilicon GPU Regulator");
