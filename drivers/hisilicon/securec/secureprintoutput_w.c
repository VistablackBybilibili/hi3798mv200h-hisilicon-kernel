/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description:
 *             by defining corresponding macro for UNICODE string and including
 *             "output.inl", this file generates real underlying function used by
 *             printf family API.
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */

#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#ifdef _CRTIMP_ALTERNATIVE
#undef _CRTIMP_ALTERNATIVE
#endif
#define _CRTIMP_ALTERNATIVE     /* comment microsoft *_s function */
#ifdef __STDC_WANT_SECURE_LIB__
#undef __STDC_WANT_SECURE_LIB__
#endif
#define __STDC_WANT_SECURE_LIB__ 0
#endif

/* if some platforms don't have wchar.h, dont't include it */
#if !(defined(SECUREC_VXWORKS_PLATFORM))
/* This header file is placed below secinput.h, which will cause tool alarm,
 * but if there is no macro above, it will cause compiling alarm
 */
#include <wchar.h>
#endif
#include "secureprintoutput.h"

#ifndef WEOF
#define WEOF ((wchar_t)-1)
#endif

#ifndef SECUREC_FOR_WCHAR
#define SECUREC_FOR_WCHAR
#endif

typedef wchar_t SecChar;
#define SECUREC_CHAR(x) L ## x
#define SECUREC_WRITE_CHAR       SecWriteCharW
#define SECUREC_WRITE_MULTI_CHAR SecWriteMultiCharW
#define SECUREC_WRITE_STRING     SecWriteStringW

/* put a wchar to output stream */
/* LSD change "unsigned short" to wchar_t */
/*
 * Output a wide character into the SecPrintfStream structure
 */
static wchar_t SecPutCharW(wchar_t ch, SecPrintfStream *f)
{
    wchar_t wcRet = 0;
    if (((f)->count -= (int)sizeof(wchar_t)) >= 0) {
        *(wchar_t *)(void *)(f->cur) = ch;
        f->cur += sizeof(wchar_t);
        wcRet = ch;
    } else {
        wcRet = (wchar_t)WEOF;
    }
    return wcRet;
}

/*
 * Output a wide character into the SecPrintfStream structure, returns the number of characters written
 */
static void SecWriteCharW(wchar_t ch, SecPrintfStream *f, int *pnumwritten)
{
    if (SecPutCharW(ch, f) == (wchar_t)WEOF) {
        *pnumwritten = -1;
    } else {
        ++(*pnumwritten);
    }
}

/*
 * Output multiple wide character into the SecPrintfStream structure,  returns the number of characters written
 */
static void SecWriteMultiCharW(wchar_t ch, int num, SecPrintfStream *f, int *pnumwritten)
{
    int count = num;
    while (count-- > 0) {
        SecWriteCharW(ch, f, pnumwritten);
        if (*pnumwritten == -1) {
            break;
        }
    }
}

/*
 * Output a wide string into the SecPrintfStream structure,  returns the number of characters written
 */
static void SecWriteStringW(const wchar_t *string, int len, SecPrintfStream *f, int *pnumwritten)
{
    const wchar_t *str = string;
    int count = len;
    while (count-- > 0) {
        SecWriteCharW(*str++, f, pnumwritten);
        if (*pnumwritten == -1) {
            break;
        }
    }
}

#include "output.inl"

