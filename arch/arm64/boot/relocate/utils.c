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

#include "reloc.h"

char const hex2ascii_data[] = "0123456789abcdefghijklmnopqrstuvwxyz";

void *memcpy(void *__dest, const void *__src, unsigned int __n)
{
	int i = 0;
	unsigned char *d = (unsigned char *)__dest, *s = (unsigned char *)__src;

	for (i = __n >> 3; i > 0; i--) {
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1 << 2) {
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1 << 1) {
		*d++ = *s++;
		*d++ = *s++;
	}

	if (__n & 1)
		*d++ = *s++;

	return __dest;
}

void *memmove(void *__dest, const void *__src, unsigned int count)
{
	unsigned char *d = __dest;
	const unsigned char *s = __src;

	if (__dest == __src)
		return __dest;

	if (__dest < __src)
		return memcpy(__dest, __src, count);

	while (count--)
		d[count] = s[count];
	return __dest;
}

unsigned int strlen(const char *s)
{
	const char *sc = s;

	while (*sc != '\0')
		sc++;
	return sc - s;
}

unsigned int strnlen(const char *s, unsigned int count)
{
	const char *sc;

	for (sc = s; count-- && *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}

int memcmp(const void *cs, const void *ct, unsigned int count)
{
	const unsigned char *su1 = cs, *su2 = ct, *end = su1 + count;
	int res = 0;

	while (su1 < end) {
		res = *su1++ - *su2++;
		if (res)
			break;
	}
	return res;
}

int strcmp(const char *cs, const char *ct)
{
	unsigned char c1, c2;
	int res = 0;

	do {
		c1 = *cs++;
		c2 = *ct++;
		res = c1 - c2;
		if (res)
			break;
	} while (c1);
	return res;
}

void *memchr(const void *s, int c, unsigned int count)
{
	const unsigned char *p = s;

	while (count--)
		if ((unsigned char)c == *p++)
			return (void *)(p - 1);
	return NULL;
}

char *strchr(const char *s, int c)
{
	while (*s != (char)c)
		if (*s++ == '\0')
			return NULL;
	return (char *)s;
}

void *memset(void *s, int c, unsigned int count)
{
	char *xs = s;
	while (count--)
		*xs++ = c;
	return s;
}

void __memzero(void *s, unsigned int count)
{
	memset(s, 0, count);
}
