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

.globl _start
_start:
	bl	__start

. = 0x04
.globl image_start
image_start:
	.word __image_start

. = 0x8
.globl image_end
image_end:
	.word __image_end

. = 0xc
.globl dtb_start
dtb_start:
	.word __dtb_start

. = 0x10
.globl dtb_size
dtb_size:
	.word DTB_SIZE

.globl reloc_start
reloc_start:
	.word __reloc_start

_reloc_end:
	.word __reloc_end

.align 4
.globl text_offset
text_offset:
	.word TEXT_OFFSET

.align 4
_reloc_reloc:
	.word __reloc_reloc

.align 4
_bss_start:
	.word __bss_start

.align 4
_bss_end:
	.word __bss_end

.align 4
__start:
	stur	wzr,[x20,#0x7c]
	adr	x9, _start
	bic	x8, x9, #0xf
	mov	sp, x8
	mov	x21, x0

	stp	x0, x1, [sp, #-64]!
	stp	x2, x3, [sp, #16 * 1]
	stp	x4, x5, [sp, #16 * 2]
	stp	x6, x7, [sp, #16 * 3]

	ldr	w0, reloc_start
	ldr	w2, _reloc_end
	sub	x2, x2, x0
	mov	x1, x9
	bl	memcpy

	ldr	w0, _reloc_reloc
	br	x0
__reloc_reloc:
	/* clean .bss section */
	ldr	w0, _bss_start
	ldr	w1, _bss_end
memset_loop:
	str	xzr, [x0], #8
	cmp	x0, x1
	b.mi	memset_loop

	mov	x0, x9
	mov	x1, x21
	bl	relocate
	mov	x8, x0

	ldp	x6, x7, [sp, #16 * 3]
	ldp	x4, x5, [sp, #16 * 2]
	ldp	x3, x2, [sp, #16 * 1]
	ldp	x0, x1, [sp], #64

	mov	x0, x8
	ldr	w30, text_offset

	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr

	ret

/******************************************************************************/

.align 4
memcpy:
	add	x2, x2, x0
memcpy_loop:

	ldp	x3, x4, [x1], #16
	ldp	x5, x6, [x1], #16

	stp	x3, x4, [x0], #16
	stp	x5, x6, [x0], #16

	cmp	x0, x2
	b.mi	memcpy_loop

	ret
