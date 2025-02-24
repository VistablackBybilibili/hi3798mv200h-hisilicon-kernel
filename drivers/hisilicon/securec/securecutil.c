/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description:
 *             provides internal functions used by this library, such as memory
 *             copy and memory move. Besides, include some helper function for
 *             printf family API, such as SecVsnprintfImpl, SECUREC_PUTC
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */

/* Avoid duplicate header files,not include securecutil.h */
#include "secureprintoutput.h"

#if defined(ANDROID) && SECUREC_IN_KERNEL == 0
#include <wchar.h>
/*
 * Convert wide characters to narrow multi-bytes
 */
int wctomb(char *s, wchar_t wc)
{
    return wcrtomb(s, wc, NULL);
}

/*
 * Converting narrow multi-byte characters to wide characters
 */
int mbtowc(wchar_t *pwc, const char *s, size_t n)
{
    return mbrtowc(pwc, s, n, NULL);
}
#endif

/* high Num << 8 | num of SPC Ver */
#define SECUREC_C_VERSION     (0x5 << 8)
#define SECUREC_SPC_VERSION   (6)
#define SECUREC_VERSION_STR   "Huawei Secure C V100R001C01SPC006B002"

/* SPC verNumber<->verStr like:
 * 0X201<->C01
 * 0X202<->SPC001   Redefine numbers after this version
 * 0X502<->SPC002
 * 0X503<->SPC003
 * ...
 * 0X50a<->SPC010
 * 0X50b<->SPC011
 * ...
 */
/* CP  verNumber<->verStr like:
 * 0X601<->CP0001
 * 0X602<->CP0002
 * ...
 */
void getHwSecureCVersion(char *verStr, int bufSize, unsigned short *verNumber)
{
    if (verStr != NULL && bufSize > 0) {
        /* In order to reduce product integration code size use memcpy_s instead of strcpy_s.  */
        if (memcpy_s(verStr, (size_t)(unsigned int)bufSize, SECUREC_VERSION_STR, sizeof(SECUREC_VERSION_STR)) != EOK) {
            *verStr = '\0';
        }
    }

    if (verNumber != NULL) {
        *verNumber = (unsigned short)(SECUREC_C_VERSION | SECUREC_SPC_VERSION);
    }
    return;
}

#if SECUREC_IN_KERNEL
EXPORT_SYMBOL(getHwSecureCVersion);
#endif

#if SECUREC_IN_KERNEL == 0 || defined(SECUREC_WANT_SPRINTF)

#if SECUREC_IN_KERNEL
#ifndef EOF
#define EOF  (-1)
#endif
#endif

/* put a char to output */
#define SECUREC_PUTC(c, outStream)    ((--(outStream)->count >= 0) ? ((*(outStream)->cur++ = (char)(c)) & 0xff) : EOF)
/* to clear e835 */
#define SECUREC_PUTC_ZERO(outStream)    ((--(outStream)->count >= 0) ? ((*(outStream)->cur++ = (char)('\0'))) : EOF)

int SecPutWcharStrEndingZero(SecPrintfStream *str, int zeroNum)
{
    int succeed = 0;
    int i = 0;

    while (i < zeroNum && (SECUREC_PUTC_ZERO(str) != EOF)) {
        ++i;
    }
    if (i == zeroNum) {
        succeed = 1;
    }
    return succeed;
}
/*
 * Performance optimizationSec
 */
int SecVsnprintfImpl(char *string, size_t count, const char *format, va_list argList)
{
    SecPrintfStream str;
    int retVal;

    str.count = (int)count; /* this count include \0 character, Must be greater than zero */
    str.cur = string;

    retVal = SecOutputS(&str, format, argList);
    if ((retVal >= 0) && (SECUREC_PUTC_ZERO(&str) != EOF)) {
        return retVal;
    } else if (str.count < 0) {
        /* the buffer was too small; we return truncation */
        string[count - 1] = '\0';
        return SECUREC_PRINTF_TRUNCATE;
    }
    string[0] = '\0'; /* empty the dest strDest */
    return -1;
}

/*
 * Sec write Wide character
 */
void SecWriteMultiChar(char ch, int num, SecPrintfStream *f, int *pnumwritten)
{
    int count = num;
    while (count-- > 0) {
        if (SECUREC_PUTC(ch, f) == EOF) {
            *pnumwritten = -1;
            break;
        } else {
            ++(*pnumwritten);
        }
    }
}

/*
 * Sec write string function
 */
void SecWriteString(const char *string, int len, SecPrintfStream *f, int *pnumwritten)
{
    const char *str = string;
    int count = len;
    while (count-- > 0) {
        if (SECUREC_PUTC(*str, f) == EOF) {
            *pnumwritten = -1;
            break;
        } else {
            ++(*pnumwritten);
            ++str;
        }
    }
}
#endif

/* Following function "U64Div32" realized the operation of division between an unsigned 64-bits
 *     number and an unsigned 32-bits number.
 * these codes are contributed by Dopra team in syslib.
 */
#if defined(SECUREC_VXWORKS_VERSION_5_4)

#define SECUREC_MAX_SHIFT_NUM           32
#define SECUREC_MASK_BIT_ALL            0xFFFFFFFF
#define SECUREC_MASK_BIT_32             0x80000000
#define SECUREC_MASK_BIT_01             0x00000001
#define SECUREC_MASK_HI_NBITS(x)        (SECUREC_MASK_BIT_ALL << (SECUREC_MAX_SHIFT_NUM - (x)))

typedef enum {
    SEC_BIT64_GREAT,
    SEC_BIT64_EQUAL,
    SEC_BIT64_LESS
} SecCompareResult;

/*
 * Sec BigInt (64 bit) subtraction
 */
static void SecBigIntSub(SecUnsignedInt32 *aHi, SecUnsignedInt32 *aLo, const SecUnsignedInt32 bHi,
                         const SecUnsignedInt32 bLo)
{
    if (*aLo < bLo) {
        *aHi -= (bHi + 1);
    } else {
        *aHi -= (bHi);
    }
    *aLo -= bLo;
}

/*
 * Sec BigInt compare function
 */
static SecCompareResult SecBigIntCompare(const SecUnsignedInt32 aHi, const SecUnsignedInt32 aLo,
                                         const SecUnsignedInt32 bHi, const SecUnsignedInt32 bLo)
{
    if (aHi > bHi) {
        return SEC_BIT64_GREAT;
    } else if ((aHi == bHi) && (aLo > bLo)) {
        return SEC_BIT64_GREAT;
    } else if ((aHi == bHi) && (aLo == bLo)) {
        return SEC_BIT64_EQUAL;
    } else {
        return SEC_BIT64_LESS;
    }
}

/*
 * bigint (64 bit) division operation function
 */
static void SecU64Div64Ret(SecUnsignedInt32 tmpQuoHi, SecUnsignedInt32 tmpQuoLo,
                           SecUnsignedInt32 tmpDividendHi, SecUnsignedInt32 tmpDividendLo,
                           SecUnsignedInt32 *pQuotientHigh, SecUnsignedInt32 *pQuotientLow,
                           SecUnsignedInt32 *pRemainderHigh, SecUnsignedInt32 *pRemainderLow)
{
    *pQuotientHigh = tmpQuoHi;
    *pQuotientLow = tmpQuoLo;

    if ((pRemainderHigh != NULL)
        && (pRemainderLow != NULL)) {
        *pRemainderHigh = tmpDividendHi;
        *pRemainderLow = tmpDividendLo;
    }
    return;
}

/*
 * bigint (64 bit) division operation function
 */
static int SecU64Div64(SecUnsignedInt32 dividendHigh, SecUnsignedInt32 dividendLow,
                       SecUnsignedInt32 divisorHigh, SecUnsignedInt32 divisorLow,
                       SecUnsignedInt32 *pQuotientHigh, SecUnsignedInt32 *pQuotientLow,
                       SecUnsignedInt32 *pRemainderHigh, SecUnsignedInt32 *pRemainderLow)
{
    signed char scShiftNumHi = 0;
    signed char scShiftNumLo = 0;
    SecUnsignedInt32 tmpQuoHi;
    SecUnsignedInt32 tmpQuoLo;
    SecUnsignedInt32 tmpDividendHi;
    SecUnsignedInt32 tmpDividendLo;
    SecUnsignedInt32 tmpDivisorHi;
    SecUnsignedInt32 tmpDivisorLo;
    SecCompareResult tmpResult;

    if ((pQuotientHigh == NULL) || (pQuotientLow == NULL)) {
        return -1;
    }

    if (divisorHigh == 0) {
        if (divisorLow == 0) {
            return -1;
        } else if (divisorLow == 1) {
            *pQuotientHigh = dividendHigh;
            *pQuotientLow = dividendLow;

            if (pRemainderHigh != NULL && pRemainderLow != NULL) {
                *pRemainderHigh = 0;
                *pRemainderLow = 0;
            }

            return 0;
        }
    }

    tmpQuoHi = tmpQuoLo = 0;
    tmpDividendHi = dividendHigh;
    tmpDividendLo = dividendLow;

    /* if divisor is larger than dividend, quotient equals to zero,
     * remainder equals to dividends */
    tmpResult = SecBigIntCompare(dividendHigh, dividendLow, divisorHigh, divisorLow);

    if (tmpResult == SEC_BIT64_LESS) {
        SecU64Div64Ret(tmpQuoHi, tmpQuoLo,
                       tmpDividendHi, tmpDividendLo, pQuotientHigh, pQuotientLow, pRemainderHigh, pRemainderLow);
        return 0;
    } else if (tmpResult == SEC_BIT64_EQUAL) {
        *pQuotientHigh = 0;
        *pQuotientLow = 1;

        if ((pRemainderHigh != NULL) && (pRemainderLow != NULL)) {
            *pRemainderHigh = 0;
            *pRemainderLow = 0;
        }

        return 0;
    }

    /* get shift number to implement divide arithmetic */
    if (divisorHigh > 0) {
        for (scShiftNumHi = 0; scShiftNumHi < SECUREC_MAX_SHIFT_NUM; scShiftNumHi++) {
            if ((divisorHigh << (SecUnsignedInt32)(unsigned char)scShiftNumHi) & SECUREC_MASK_BIT_32) {
                break;
            }
        }
    } else {
        for (scShiftNumLo = 0; scShiftNumLo < SECUREC_MAX_SHIFT_NUM; scShiftNumLo++) {
            if ((divisorLow << scShiftNumLo) & SECUREC_MASK_BIT_32) {
                break;
            }
        }
    }

    /* divisor's high 32 bits doesn't equal to zero */
    if (divisorHigh > 0) {
        for (; scShiftNumHi >= 0; scShiftNumHi--) {

            if (scShiftNumHi == 0) {
                tmpDivisorHi = divisorHigh;
            } else {
                tmpDivisorHi = (divisorHigh << (SecUnsignedInt32)(unsigned char)scShiftNumHi)
                    | (divisorLow >> (SECUREC_MAX_SHIFT_NUM - scShiftNumHi));
            }

            tmpDivisorLo = divisorLow << (SecUnsignedInt32)(unsigned char)scShiftNumHi;

            tmpResult = SecBigIntCompare(tmpDividendHi, tmpDividendLo, tmpDivisorHi, tmpDivisorLo);

            if (tmpResult != SEC_BIT64_LESS) {
                SecBigIntSub(&tmpDividendHi, &tmpDividendLo, tmpDivisorHi, tmpDivisorLo);

                tmpQuoLo |= (SecUnsignedInt32)(1 << (SecUnsignedInt32)(unsigned char)scShiftNumHi);

                if ((tmpDividendHi == 0) && (tmpDividendLo == 0)) {
                    SecU64Div64Ret(tmpQuoHi, tmpQuoLo,
                                   tmpDividendHi, tmpDividendLo,
                                   pQuotientHigh, pQuotientLow, pRemainderHigh, pRemainderLow);
                    return 0;
                }
            }
            if (scShiftNumHi == 0) {
                break;
            }
        }

    } else {
        /* divisor's high 32 bits equals to zero */
        scShiftNumHi = scShiftNumLo;

        for (; scShiftNumHi >= 0; scShiftNumHi--) {
            tmpDivisorHi = divisorLow << (SecUnsignedInt32)(unsigned char)scShiftNumHi;
            tmpResult = SecBigIntCompare(tmpDividendHi, tmpDividendLo, tmpDivisorHi, 0);

            if (tmpResult != SEC_BIT64_LESS) {
                SecUnsignedInt32 tmp = 0;
                SecBigIntSub(&tmpDividendHi, &tmpDividendLo, tmpDivisorHi, tmp);

                tmpQuoHi |= (SecUnsignedInt32)(1 << (SecUnsignedInt32)(unsigned char)scShiftNumHi);

                if ((tmpDividendHi == 0) && (tmpDividendLo == 0)) {
                    SecU64Div64Ret(tmpQuoHi, tmpQuoLo, tmpDividendHi, tmpDividendLo,
                                   pQuotientHigh, pQuotientLow, pRemainderHigh, pRemainderLow);
                    return 0;
                }
            }
            if (scShiftNumHi == 0) {
                break;
            }
        }

        for (scShiftNumHi = SECUREC_MAX_SHIFT_NUM - 1; scShiftNumHi >= 0; scShiftNumHi--) {
            if (scShiftNumHi == 0) {
                tmpDivisorHi = 0;
            } else {
                tmpDivisorHi = divisorLow >> (SECUREC_MAX_SHIFT_NUM - scShiftNumHi);
            }

            tmpDivisorLo = divisorLow << (SecUnsignedInt32)(unsigned char)scShiftNumHi;

            tmpResult = SecBigIntCompare(tmpDividendHi, tmpDividendLo, tmpDivisorHi, tmpDivisorLo);

            if (tmpResult != SEC_BIT64_LESS) {
                SecBigIntSub(&tmpDividendHi, &tmpDividendLo, tmpDivisorHi, tmpDivisorLo);

                tmpQuoLo |= (SecUnsignedInt32)(1 << (SecUnsignedInt32)(unsigned char)scShiftNumHi);

                if ((tmpDividendHi == 0) && (tmpDividendLo == 0)) {
                    SecU64Div64Ret(tmpQuoHi, tmpQuoLo, tmpDividendHi, tmpDividendLo,
                                   pQuotientHigh, pQuotientLow, pRemainderHigh, pRemainderLow);
                    return 0;
                }
            }
            if (scShiftNumHi == 0) {
                break;
            }
        }

    }

    SecU64Div64Ret(tmpQuoHi, tmpQuoLo,
                   tmpDividendHi, tmpDividendLo, pQuotientHigh, pQuotientLow, pRemainderHigh, pRemainderLow);
    return 0;
}

/*
 * 64-bit divided by 32-bit operation
 */
int SecU64Div32(SecUnsignedInt32 dividendHigh, SecUnsignedInt32 dividendLow, SecUnsignedInt32 divisor,
                SecUnsignedInt32 *pQuotientHigh, SecUnsignedInt32 *pQuotientLow, SecUnsignedInt32 *puiRemainder)
{
    SecUnsignedInt32 tmpRemainderHi = 0;
    SecUnsignedInt32 tmpRemainderLo = 0;
    SecUnsignedInt32 tmpDividendHigh = dividendHigh;
    SecUnsignedInt32 tmpDividendLow = dividendLow;
    SecUnsignedInt32 tmpDivisor = divisor;
    int ret;

    if ((pQuotientHigh == NULL) || (pQuotientLow == NULL) || tmpDivisor == 0 || puiRemainder == NULL) {
        return -1;
    }

    tmpDividendHigh &= SECUREC_MASK_BIT_ALL;
    tmpDividendLow &= SECUREC_MASK_BIT_ALL;
    tmpDivisor &= SECUREC_MASK_BIT_ALL;
    *pQuotientHigh = 0;
    *pQuotientLow = 0;
    *puiRemainder = 0;

    ret = SecU64Div64(tmpDividendHigh,
                      tmpDividendLow, 0, tmpDivisor, pQuotientHigh, pQuotientLow, &tmpRemainderHi, &tmpRemainderLo);
    if (ret != 0) {
        return ret;
    }

    if (tmpRemainderHi != 0) {
        return -1;
    }
    *puiRemainder = tmpRemainderLo;

    return 0;
}
#endif

