/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description:
 *             define macro, enum, data struct, and declare internal used function
 *             prototype, which is used by output.inl, secureprintoutput_w.c and
 *             secureprintoutput_a.c.
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */

#ifndef __SECUREPRINTOUTPUT_H__E950DA2C_902F_4B15_BECD_948E99090D9C
#define __SECUREPRINTOUTPUT_H__E950DA2C_902F_4B15_BECD_948E99090D9C
#include "securecutil.h"

/* flag definitions */
/* Using macros instead of enumerations is because some of the enumerated types under the compiler are 16bit. */
#define SECUREC_FLAG_SIGN           0x00001U
#define SECUREC_FLAG_SIGN_SPACE     0x00002U
#define SECUREC_FLAG_LEFT           0x00004U
#define SECUREC_FLAG_LEADZERO       0x00008U
#define SECUREC_FLAG_LONG           0x00010U
#define SECUREC_FLAG_SHORT          0x00020U
#define SECUREC_FLAG_SIGNED         0x00040U
#define SECUREC_FLAG_ALTERNATE      0x00080U
#define SECUREC_FLAG_NEGATIVE       0x00100U
#define SECUREC_FLAG_FORCE_OCTAL    0x00200U
#define SECUREC_FLAG_LONG_DOUBLE    0x00400U
#define SECUREC_FLAG_WIDECHAR       0x00800U
#define SECUREC_FLAG_LONGLONG       0x01000U
#define SECUREC_FLAG_CHAR           0x02000U
#define SECUREC_FLAG_POINTER        0x04000U
#define SECUREC_FLAG_I64            0x08000U
#define SECUREC_FLAG_PTRDIFF        0x10000U
#define SECUREC_FLAG_SIZE           0x20000U
#ifdef  SECUREC_COMPATIBLE_LINUX_FORMAT
#define SECUREC_FLAG_INTMAX         0x40000U
#endif

/* state definitions */
typedef enum {
    STAT_NORMAL,
    STAT_PERCENT,
    STAT_FLAG,
    STAT_WIDTH,
    STAT_DOT,
    STAT_PRECIS,
    STAT_SIZE,
    STAT_TYPE,
    STAT_INVALID
} SecFmtState;
#ifndef SECUREC_BUFFER_SIZE
#ifdef SECUREC_STACK_SIZE_LESS_THAN_1K
/* SECUREC_BUFFER_SIZE Can not be less than 23 ,
 * the length of the octal representation of 64-bit integers with zero lead
 */
#define SECUREC_BUFFER_SIZE    256
#else
#define SECUREC_BUFFER_SIZE    512
#endif
#endif
#if SECUREC_BUFFER_SIZE < 23
#error SECUREC_BUFFER_SIZE Can not be less than 23
#endif

#define SECUREC_MAX_PRECISION  SECUREC_BUFFER_SIZE
/* max. # bytes in multibyte char  ,see MB_LEN_MAX */
#define SECUREC_MB_LEN 16

#ifdef __cplusplus
extern "C" {
#endif
    extern int SecOutputS(SecPrintfStream *stream, const char *cformat, va_list argList);
#if SECUREC_IN_KERNEL == 0
    extern int SecOutputSW(SecPrintfStream *stream, const wchar_t *cformat, va_list argList);
#endif

#ifdef __cplusplus
}
#endif

#endif


