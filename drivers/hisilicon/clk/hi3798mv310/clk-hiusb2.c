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
 * Create By Liu Hui 2015.06.23
 *
******************************************************************************/

#include <linux/delay.h>
#include <dt-bindings/clock/hi3798mv200-clock.h>
#include <linux/hikapi.h>

#include "clk-hisi.h"

/******************************************************************************/
#define PERI_CTRL_USB3                 (0x12c)

#define USB2_2P_SS_WORD_IF_I            BIT(0)
#define USB2_2P_SS_ENA_INCR16_I         BIT(9)

#define USB2_BUS_CKEN                   BIT(0)
#define USB2_OHCI48M_CKEN               BIT(1)
#define USB2_OHCI12M_CKEN               BIT(2)
#define USB2_OTG_UTMI_CKEN              BIT(3)
#define USB2_HST_PHY_CKEN               BIT(4)
#define USB2_UTMI0_CKEN                 BIT(5)
#define USB2_UTMI1_CKEN                 BIT(6)
#define USB2_UTMI2_CKEN                 BIT(7)
#define USB2_BUS_SRST_REQ               BIT(12)
#define USB2_UTMI0_SRST_REQ             BIT(13)
#define USB2_UTMI1_SRST_REQ             BIT(14)
#define USB2_UTMI2_SRST_REQ             BIT(15)
#define USB2_HST_PHY_SYST_REQ           BIT(16)
#define USB2_OTG_PHY_SYST_REQ           BIT(17)
#define USB2_PHY01_CLK_SEL              BIT(19)

#define USB2_PHY01_REF_CKEN             BIT(0)
#define USB2_PHY2_REF_CKEN              BIT(2)
#define USB2_PHY01_SRST_REQ             BIT(4)
#define USB2_PHY2_SRST_REQ              BIT(6)
#define USB2_PHY01_SRST_TREQ0           BIT(8)
#define USB2_PHY01_SRST_TREQ1           BIT(9)
#define USB2_PHY2_SRST_TREQ             BIT(10)
#define USB2_PHY01_REFCLK_SEL           BIT(12)
#define USB2_PHY2_REFCLK_SEL            BIT(14)
#define USB2_PHY01_TEST_SRST_REQ        BIT(15)
#define USB2_PHY2_TEST_SRST_REQ         BIT(16)

#define REG_PHY_CLK                    (0x18)
#define PHY_CLK_VALUE                  (0x5)

#define USB2_PHY01_REGBASE             0xf9865000
#define USB2_PHY2_REGBASE              0xf9960000

#define USB2_PORT1_REGBASE             0x400

static u32 get_usbphy_chiptrim(void)
{
	u32 chiptrim_usbphy = 0;
	int ret;
	struct device_node *chiptrim_node;

	chiptrim_node = of_find_node_by_path("chiptrim");
	if (!chiptrim_node)
		return 0;

	ret = of_property_read_u32(chiptrim_node, "chiptrim2", &chiptrim_usbphy);
	if (ret) {
		pr_err("%s,%d: chiptrim2 property not found\n",
			__func__, __LINE__);
		return 0;
	}

	/* chiptrim_usbphy config */
	chiptrim_usbphy <<= 2;
	chiptrim_usbphy &= 0x7C;  //bit[6:2]
	return chiptrim_usbphy;
}

/******************************************************************************/

static atomic_t dev_open_cnt = {
	.counter = 0,
};
/******************************************************************************/

static void inno_phy_config(struct hiclk_hw *clk)
{
	int reg, chiptrim_usbphy = 0;
	void __iomem *regbase = ioremap_nocache(USB2_PHY01_REGBASE, 0x1000);
	if (!regbase) {
		printk("ioremap ehci regbase failed.\n");
		return;
	}

	/* config phy clk output */
	writel(PHY_CLK_VALUE, regbase + REG_PHY_CLK);

	/*HS eye height tuning 0x02[6:4]
	*3'b101:425mV
	*/
	writel(0x5c, regbase + 0x08);
	writel(0x5c, regbase + 0x408);
	udelay(20);

	/*pre-emphasis tuning 0x00[2:0]
	*3'b100:enable pre-emphasis in non-chirp state
	*/
	writel(0x1c, regbase + 0x0);
	writel(0x1c, regbase + 0x400);
	udelay(20);

	/*Tx HS pre_emphasize strength configure 0x05[4:2]
	*3'b001
	*/
	writel(0x84, regbase + 0x14);
	writel(0x84, regbase + 0x414);
	udelay(20);

	/*HOST disconnects detection trigger point 0x04[7:4]
	4'b1101:625mV
	*/
	writel(0xd7, regbase + 0x10);
	writel(0xd7, regbase + 0x410);
	udelay(20);

	/*HS chirp mode amplitude increasing register 0x1f[6]
	*1'b1
	*/
	writel(0x68, regbase + 0x7c);
	writel(0x68, regbase + 0x47c);
	udelay(20);

	chiptrim_usbphy = get_usbphy_chiptrim();

	if ((chiptrim_usbphy>=0x3c) && (chiptrim_usbphy<=0x70)) {
		/* 2xport port0 */
		reg = readl(regbase + 0x00c);
		reg &= ~0x7C;
		reg |= chiptrim_usbphy;
		writel(reg, regbase + 0x00c);
		udelay(20);

		/* 2xport port1 */
		reg = readl(regbase + 0x40c);
		reg &= ~0x7C;
		reg |= chiptrim_usbphy;
		writel(reg, regbase + 0x40c);
		udelay(20);
	}

	iounmap(regbase);
	regbase = NULL;

	/*2 port phy config*/
	regbase = ioremap_nocache(USB2_PHY2_REGBASE, 0x1000);
	if (!regbase) {
		printk("ioremap ehci regbase failed.\n");
		return;
	}

	/* config phy clk output */
	writel(PHY_CLK_VALUE, regbase + REG_PHY_CLK);

	writel(0x5c, regbase + 0x08);
	udelay(20);

	writel(0x1c, regbase + 0x0);
	udelay(20);

	writel(0x84, regbase + 0x14);
	udelay(20);

	writel(0xd7, regbase + 0x10);
	udelay(20);

	writel(0xe8, regbase + 0x7c);
	udelay(20);

	if ((chiptrim_usbphy>=0x3c) && (chiptrim_usbphy<=0x70)) {
		reg = readl(regbase + 0x00c);
		reg &= ~0x7C;
		reg |= chiptrim_usbphy;
		writel(reg, regbase + 0x00c);
		udelay(20);
	}

	iounmap(regbase);
	regbase = NULL;
}
/******************************************************************************/

static int hiclk_enable_usb2(struct clk_hw *hw)
{
	u32 reg;
	struct hiclk_hw *clk = to_hiclk_hw(hw);

	if (atomic_add_return(1, &dev_open_cnt) == 1) {

		/* reset controller bus/utmi/roothub  */
		reg = readl(clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		reg |= (USB2_BUS_SRST_REQ
			| USB2_UTMI0_SRST_REQ
			| USB2_UTMI1_SRST_REQ
			| USB2_UTMI2_SRST_REQ
			| USB2_HST_PHY_SYST_REQ
			| USB2_OTG_PHY_SYST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		udelay(200);

		/* reset phy por/utmi */
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg |= (USB2_PHY01_SRST_REQ
			| USB2_PHY01_SRST_TREQ0
			| USB2_PHY01_SRST_TREQ1
			| USB2_PHY2_SRST_REQ
			| USB2_PHY2_SRST_TREQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(200);

		reg = readl(clk->peri_ctrl_base + PERI_CTRL_USB3);
		reg &= ~(USB2_2P_SS_WORD_IF_I);
		reg &= ~(USB2_2P_SS_ENA_INCR16_I);
		writel(reg, clk->peri_ctrl_base + PERI_CTRL_USB3);
		udelay(100);

		/* open ref clk */
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg |= (USB2_PHY01_REF_CKEN
			| USB2_PHY2_REF_CKEN);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(300);

		/* cancel power on reset */
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg &= ~(USB2_PHY01_SRST_REQ
			| USB2_PHY2_SRST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(500);

		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg &= ~(USB2_PHY01_TEST_SRST_REQ
			| USB2_PHY2_TEST_SRST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(200);

		inno_phy_config(clk);

		/* cancel port reset 
		* delay 2ms for waiting comp circuit stable
		*/
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg &= ~(USB2_PHY01_SRST_TREQ0
			| USB2_PHY01_SRST_TREQ1
			| USB2_PHY2_SRST_TREQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		mdelay(2);

		/* open controller clk */
		reg = readl(clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		reg |= (USB2_BUS_CKEN
			| USB2_OHCI48M_CKEN
			| USB2_OHCI12M_CKEN
			| USB2_OTG_UTMI_CKEN
			| USB2_HST_PHY_CKEN
			| USB2_UTMI0_CKEN
			| USB2_UTMI1_CKEN
			| USB2_UTMI2_CKEN);
		writel(reg, clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		udelay(200);

		/* cancel control reset */
		reg = readl(clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		reg &= ~(USB2_BUS_SRST_REQ
			| USB2_UTMI0_SRST_REQ
			| USB2_UTMI1_SRST_REQ
			| USB2_UTMI2_SRST_REQ
			| USB2_HST_PHY_SYST_REQ
			| USB2_OTG_PHY_SYST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		udelay(200);
	}

	return 0;
}
/******************************************************************************/

static void hiclk_disable_usb2(struct clk_hw *hw)
{
	u32 reg;
	struct hiclk_hw *clk = to_hiclk_hw(hw);

	if (atomic_sub_return(1, &dev_open_cnt) == 0) {

		reg = readl(clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		reg |= (USB2_BUS_SRST_REQ
			| USB2_UTMI0_SRST_REQ
			| USB2_UTMI1_SRST_REQ
			| USB2_UTMI2_SRST_REQ
			| USB2_HST_PHY_SYST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		udelay(200);

		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg |= (USB2_PHY01_SRST_REQ
			| USB2_PHY2_SRST_REQ
			| USB2_PHY01_SRST_TREQ1
			| USB2_PHY01_SRST_TREQ0
			| USB2_PHY2_SRST_TREQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(100);
	}
}
/******************************************************************************/

struct clk_ops clk_ops_hiusb2 = {
	.enable = hiclk_enable_usb2,
	.disable = hiclk_disable_usb2,
};
