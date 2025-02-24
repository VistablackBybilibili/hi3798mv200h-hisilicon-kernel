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

#ifndef RELOCH
#define RELOCH

typedef signed char                   int8;
typedef signed short                  int16;
typedef signed int                    int32;
typedef signed long long              int64;

typedef unsigned char                 uint8;
typedef unsigned short                uint16;
typedef unsigned int                  uint32;
typedef unsigned long long            uint64;

typedef unsigned char                 u_char;
typedef unsigned int                  u_int;
typedef unsigned short                u_short;
typedef unsigned long                 u_long;

typedef uint32                        size_t;
typedef uint32                        ssize_t;
typedef uint32                        uintmax_t;
typedef int32                         intmax_t;
typedef int32                         ptrdiff_t;
typedef uint32                        uintptr_t;
typedef int64                         quad_t;
typedef uint64                        u_quad_t;

extern char const hex2ascii_data[];
#define hex2ascii(hex) (hex2ascii_data[hex])

#define imax(_a, _b) ((_a) > (_b) ? (_a) : (_b))

#define toupper(c) ((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

#define NULL (void *)0

extern unsigned int image_start;
extern unsigned int image_end;
extern unsigned int dtb_start;
extern unsigned int dtb_size;
extern unsigned int reloc_start;
extern unsigned int text_offset;

void putc(const char c);
void putstr(const char *s);
uint32 strnlen(const char *s, uint32 len);
void *memmove(void *dest, const void *src, unsigned int size);

#include <stdarg.h>

int printf(const char *cfmt, ...);

#ifdef CONFIG_ARM64_KERNEL_COMPRESS
void decompress_kernel(unsigned char *from, int sz_from, unsigned char *to,
		       unsigned long malloc_start);
#endif

#endif