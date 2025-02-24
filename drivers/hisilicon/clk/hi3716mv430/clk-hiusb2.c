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
#include <dt-bindings/clock/hi3716mv430-clock.h>
#include <linux/hikapi.h>

#include "clk-hisi.h"

/******************************************************************************/
#define PERI_CTRL_USB3                  (0x12c)

#define USB2_2P_SS_WORD_IF_I            BIT(0)
#define USB2_2P_SS_ENA_INCR16_I         BIT(9)

#define USB2_BUS_CKEN                   BIT(0)
#define USB2_OHCI48M_CKEN               BIT(1)
#define USB2_OHCI12M_CKEN               BIT(2)
#define USB2_HST_PHY_CKEN               BIT(4)
#define USB2_UTMI0_CKEN                 BIT(5)
#define USB2_UTMI1_CKEN                 BIT(6)
#define USB2_BUS_SRST_REQ               BIT(12)
#define USB2_UTMI0_SRST_REQ             BIT(13)
#define USB2_UTMI1_SRST_REQ             BIT(14)
#define USB2_HST_PHY_SYST_REQ           BIT(16)

#define USB2_PHY01_REF_CKEN             BIT(0)
#define USB2_PHY01_SRST_REQ             BIT(4)
#define USB2_PHY0_SRST_TREQ             BIT(8)
#define USB2_PHY1_SRST_TREQ             BIT(9)
#define USB2_PHY01_REFCLK_SEL           BIT(12)
#define USB2_PHY01_TEST_SRST_REQ        BIT(15)

#define USB2_PHY01_REGBASE              0xf9865000

#define REG_BASE_OTP 			0xF8AB0000
#define REG_OTP_USB_TRIM		0x032C
#define REG_MASK_OTP_USB_TRIM		GENMASK(15, 0)
/******************************************************************************/

struct hisi_priv {
	void __iomem    *base_otp;
	void __iomem    *base_2p_phy;
	void __iomem    *peri_usb2phy0;
	void __iomem    *peri_usb2phy1;
};

static struct hisi_priv hisi_usb2 = {
	.base_otp = NULL,
	.base_2p_phy = NULL,
	.peri_usb2phy0 = NULL,
	.peri_usb2phy1 = NULL,
};

static atomic_t dev_open_cnt = {
	.counter = 0,
};
/******************************************************************************/

static u32 get_usbphy_chiptrim(void)
{
	u32  chiptrim_usbphy;
	void __iomem *otp_chiptrim  = hisi_usb2.base_otp;

	/* chiptrim_usbphy config */
	chiptrim_usbphy = readl(otp_chiptrim + REG_OTP_USB_TRIM);
	chiptrim_usbphy <<= 2;
	chiptrim_usbphy &= 0x7C;

	return chiptrim_usbphy;
}
/******************************************************************************/

static void inno_phy_config_2p(struct hiclk_hw *clk)
{
	void __iomem *regbase = hisi_usb2.base_2p_phy;
	int reg, chiptrim_usbphy = 0;
	if (!regbase) {
		printk("ioremap ehci regbase failed.\n");
		return;
	}

	/* 2.HS eye height tuning 0x02[6:4]=3b'110 : 437.5mV */
	writel(0x6c, regbase + 0x08);
	writel(0x6c, regbase + 0x408);
	udelay(20);

	/* 3.pre-emphasis tuning 0x00[2:0]=3b'111 : always enable pre-emphasis */
	writel(0x1f, regbase );
	writel(0x1f, regbase + 0x400);
	udelay(20);

	/* 4.pre-emphasis strength 0x05[4:2]=3b'000 */
	writel(0x80, regbase + 0x14);
	writel(0x80, regbase + 0x414);
	udelay(20);

	/* 5.HS driver slew rate tunning 0x1d[3:1]=3'111 */
	writel(0x1e, regbase + 0x74);
	writel(0x1e, regbase + 0x474);
	udelay(20);

	/* 6.HOST disconnects detection trigger point 0x04[7:4]=4b'1101: 625mV */
	writel(0xd7, regbase + 0x10);
	writel(0xd7, regbase + 0x410);
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

	writel(0x5, regbase + 0x18);
	udelay(100);
}
/******************************************************************************/

static int hiclk_prepare_usb2(struct clk_hw *hw)
{
	if(!hisi_usb2.base_otp)
		hisi_usb2.base_otp = ioremap_nocache(REG_BASE_OTP, 0x1000);
	if(!hisi_usb2.base_2p_phy)
		hisi_usb2.base_2p_phy = ioremap_nocache(USB2_PHY01_REGBASE, 0x1000);
	return 0;
}
/******************************************************************************/

static void hiclk_unprepare_usb2(struct clk_hw *hw)
{

	if(hisi_usb2.base_otp)
		iounmap(hisi_usb2.base_otp);
	if(hisi_usb2.base_2p_phy)
		iounmap(hisi_usb2.base_2p_phy);

	hisi_usb2.base_otp = NULL;
	hisi_usb2.base_2p_phy = NULL;
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
			| USB2_HST_PHY_SYST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		udelay(100);

		/* reset phy por/utmi */
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg |= (USB2_PHY01_TEST_SRST_REQ
		| USB2_PHY01_SRST_REQ
		| USB2_PHY0_SRST_TREQ
		| USB2_PHY1_SRST_TREQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(100);

		reg = readl(clk->peri_ctrl_base + PERI_CTRL_USB3);
		reg &= ~(USB2_2P_SS_WORD_IF_I);
		reg &= ~(USB2_2P_SS_ENA_INCR16_I);
		writel(reg, clk->peri_ctrl_base + PERI_CTRL_USB3);
		udelay(100);

		/* open ref clk */
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg |= (USB2_PHY01_REF_CKEN);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(100);
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg &= ~(USB2_PHY01_TEST_SRST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(100);

		/* cancel power on reset */
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg &= ~(USB2_PHY01_SRST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		mdelay(2);

		inno_phy_config_2p(clk);

//		config_ufsphy_chiptrim();

		/* cancel port reset 
		* delay 2ms for waiting comp circuit stable
		*/
		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg &= ~(USB2_PHY0_SRST_TREQ | USB2_PHY1_SRST_TREQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(100);

		/* open controller clk */
		reg = readl(clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		reg |= (USB2_BUS_CKEN
			| USB2_OHCI48M_CKEN
			| USB2_OHCI12M_CKEN
			| USB2_HST_PHY_CKEN
			| USB2_UTMI0_CKEN
			| USB2_UTMI1_CKEN);
		writel(reg, clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		udelay(100);
		
		/* cancel control reset */
		reg = readl(clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		reg &= ~(USB2_BUS_SRST_REQ
			| USB2_UTMI0_SRST_REQ
			| USB2_UTMI1_SRST_REQ
			| USB2_HST_PHY_SYST_REQ);
		writel(reg, clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		udelay(100);
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
		reg &= ~(USB2_BUS_CKEN
			| USB2_HST_PHY_CKEN
			| USB2_UTMI0_CKEN
			| USB2_UTMI1_CKEN);
		writel(reg, clk->peri_crg_base + PERI_CRG46_USB2CTRL);
		udelay(100);

		reg = readl(clk->peri_crg_base + PERI_CRG47_USB2PHY);
		reg |= (USB2_PHY01_TEST_SRST_REQ
			| USB2_PHY01_SRST_REQ
			| USB2_PHY0_SRST_TREQ
			| USB2_PHY1_SRST_TREQ);
		writel(reg, clk->peri_crg_base + PERI_CRG47_USB2PHY);
		udelay(100);
	}
}
/******************************************************************************/

struct clk_ops clk_ops_hiusb2 = {
	.prepare = hiclk_prepare_usb2,
	.unprepare = hiclk_unprepare_usb2,
	.enable = hiclk_enable_usb2,
	.disable = hiclk_disable_usb2,
};
