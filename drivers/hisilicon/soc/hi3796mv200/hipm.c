#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pm.h>
#include <linux/suspend.h>
#include <asm/memory.h>
#include <linux/delay.h>
#include <linux/suspend.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/kmemleak.h>
#include <linux/device.h>
#include <linux/irqchip/arm-gic.h>
#include <mach/hardware.h>
#include <linux/hikapi.h>
#include <asm/suspend.h>
#include <asm/bug.h>
#include <asm/io.h>
#include <asm/types.h>

#define ACPU_SUSPEND_FIRMWARE_ADDR  0xFFFF8000
#define ACPU_SUSPEND_FIRMWARE_SIZE  0x2000

void __iomem *hi_sc_virtbase = NULL;
void __iomem *hi_acpu_suspend_firmware_virt = NULL;
unsigned long hi_acpu_suspend_firmware_phys = ACPU_SUSPEND_FIRMWARE_ADDR;

/**/
#define MCU_START_CTRL  0xf840f000      /* mcu start control */
#define OTP_IDWORD_ADDR 0xf8ab0060      /* OTP shadow register to indicate if it is advca chipset */
#define OTP_CA_ID_WORD  0x6EDBE953
#define MAILBOX_BASE_ADDR 0xf9a39000


void __iomem *hi_uart_virtbase = NULL;
extern void *hi_otp_idword_addr;
extern void *hi_mcu_start_ctrl;
extern void *hi_mailbox_base_addr;

asmlinkage int hi_pm_sleep(unsigned long arg);

int (* hi_load_suspend_firmware)(void *sram_addr, int length) = NULL;
EXPORT_SYMBOL(hi_load_suspend_firmware);

/*****************************************************************************/

static int hi_pm_suspend(void)
{
	int ret = 0;

#ifndef CONFIG_TEE
	if (hi_acpu_suspend_firmware_virt == NULL) {
		hi_acpu_suspend_firmware_virt = ioremap(hi_acpu_suspend_firmware_phys,
			ACPU_SUSPEND_FIRMWARE_SIZE);
	}

	BUG_ON(hi_load_suspend_firmware == NULL);

	if (hi_load_suspend_firmware != NULL) {
		hi_load_suspend_firmware(hi_acpu_suspend_firmware_virt, ACPU_SUSPEND_FIRMWARE_SIZE);
	}
#endif

	ret = cpu_suspend(0, hi_pm_sleep);

	return ret;
}

static int hi_pm_enter(suspend_state_t state)
{
	int ret = 0;
	switch (state) {
	case PM_SUSPEND_STANDBY:
	case PM_SUSPEND_MEM:
		ret = hi_pm_suspend();
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

int hi_pm_valid(suspend_state_t state)
{
	return 1;
}

static const struct platform_suspend_ops hi_pm_ops = {
	.enter = hi_pm_enter,
	.valid = hi_pm_valid,
};
/*****************************************************************************/

static int __init hi_pm_init(void)
{
	hi_sc_virtbase = (void __iomem *)IO_ADDRESS(REG_BASE_SCTL);
	hi_uart_virtbase = (void __iomem *)IO_ADDRESS(REG_BASE_UART0);

	hi_mcu_start_ctrl = (void __iomem *)ioremap_nocache(MCU_START_CTRL, 0x1000);
	hi_mailbox_base_addr = (void __iomem *)ioremap_nocache(MAILBOX_BASE_ADDR, 0x1000);

	hi_otp_idword_addr = (void __iomem *)ioremap_nocache(OTP_IDWORD_ADDR, 0x1000);
	suspend_set_ops(&hi_pm_ops);

	return 0;
}

module_init(hi_pm_init);
