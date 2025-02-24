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

#define UART_DR				0x00
#define UART_RSR			0x04
#define UART_FR				0x18
#define UART_FR_TXFF			(1 << 5)
#define UART_RF_RXFE			(1 << 4)

#define UART_IBRD			0x24
#define UART_FBRD			0x28
#define UART_LCR_H			0x2C
#define UART_LCR_H_8BIT			(3 << 5)
#define UART_LCR_H_FIFO_EN		(1 << 4)

#define UART_CR				0x30
#define UART_CR_EN			(1 << 0)
#define UART_CR_SEND_EN			(1 << 8)
#define UART_CR_REV_EN			(1 << 9)

#define readl(_addr) \
	({unsigned int __v = *(volatile unsigned int *)(_addr); asm("dsb sy"); __v;})
#define writel(_value, _addr) \
	({asm("dsb sy"); *(volatile unsigned int *)(_addr) = (unsigned int)(_value);})

/******************************************************************************/

static void pl01x_putc(char c)
{
	/* Wait until there is space in the FIFO */
	while (readl(DEBUG_UART_BASE + UART_FR) & UART_FR_TXFF);

	/* Send the character */
	writel(c, DEBUG_UART_BASE + UART_DR);
}
/******************************************************************************/

void putc(const char c)
{
	if (c == '\n')
		pl01x_putc('\r');
	pl01x_putc(c);
}
/******************************************************************************/

void putstr(const char *s)
{
	while (*s != '\0')
		putc(*s++);
}
