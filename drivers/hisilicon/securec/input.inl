/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description:
 *           used by secureinput_a.c and secureinput_w.c to include. This file
 *           provides a template function for ANSI and UNICODE compiling by
 *           different type definition. The functions of SecInputS or
 *           SecInputSW provides internal implementation for scanf family
 *           API, such as sscanf_s, fscanf_s.
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */
/* [Standardize-exceptions] Use unsafe function: Performance-sensitive
 * [reason] Always used in the performance critical path,
 *          and sufficient input validation is performed before calling
 */

#ifndef __INPUT_INL__5D13A042_DC3F_4ED9_A8D1_882811274C27
#define __INPUT_INL__5D13A042_DC3F_4ED9_A8D1_882811274C27

#if SECUREC_IN_KERNEL
#include <linux/ctype.h>
#ifndef EOF
#define EOF  (-1)
#endif
#else
#if !defined(SECUREC_SYSAPI4VXWORKS) && !defined(SECUREC_CTYPE_MACRO_ADAPT)
#include <ctype.h>
#ifdef SECUREC_FOR_WCHAR
#include <wctype.h>             /* for iswspace */
#endif
#endif
#endif

#define SECUREC_NUM_WIDTH_SHORT       0
#define SECUREC_NUM_WIDTH_INT         1
#define SECUREC_NUM_WIDTH_LONG        2
#define SECUREC_NUM_WIDTH_LONG_LONG   3 /* also long double */

#define SECUREC_BUF_EXT_MUL (2)
#define SECUREC_BUFFERED_BLOK_SIZE 1024

#if SECUREC_ENABLE_SCANF_FLOAT
#if defined(ANDROID) || defined(SECUREC_SYSAPI4VXWORKS)
#define SECUREC_DECIMAL_POINT_PTR  "."
#else
#include <locale.h>             /* if this file NOT exist, you can remove it */
#define SECUREC_DECIMAL_POINT_PTR (localeconv()->decimal_point)
#endif
#endif

#if defined(SECUREC_VXWORKS_PLATFORM) && !defined(va_copy) && !defined(__va_copy)
/* the name is the same as system macro. */
#define __va_copy(d, s) do { \
    size_t size_of_d = (size_t)sizeof(d); \
    size_t size_of_s = (size_t)sizeof(s); \
    if (size_of_d != size_of_s) { \
        (void)memcpy((d), (s), sizeof(va_list)); \
    } else { \
        (void)memcpy(&(d), &(s), sizeof(va_list)); \
    } \
} SECUREC_WHILE_ZERO
#endif

#define SECUREC_MUL_SIXTEEN(number)             ((number) << 4)
#define SECUREC_MUL_EIGHT(number)               ((number) << 3)
#define SECUREC_MUL_TEN(x)                      ((((x) << 2) + (x)) << 1)
#define SECUREC_MULTI_BYTE_MAX_LEN               (6)
#define SECUREC_INT_MAX_DIV_TEN                  21474836

#define SECUREC_FLAG_I32_LEN                     (2)
#define SECUREC_FLAG_I64_LEN                     (2)
/* Record a flag for each bit */
#define SECUREC_BRACKET_INDEX(x)                 ((x) >> 3)
#define SECUREC_BRACKET_VALUE(x)                 ((unsigned char)(1 << ((x) & 7)))

/* Compatibility macro name cannot be modifie */
#ifndef UNALIGNED
#if !(defined(_M_IA64)) && !(defined(_M_AMD64))
#define UNALIGNED
#else
#define UNALIGNED __unaligned
#endif
#endif

#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
#define SECUREC_MAX_64BITS_VALUE                18446744073709551615ULL
#define SECUREC_MAX_64BITS_VALUE_DIV_TEN        1844674407370955161ULL
#define SECUREC_MAX_64BITS_VALUE_CUT_LAST_DIGIT 18446744073709551610ULL
#define SECUREC_MIN_64BITS_NEG_VALUE            9223372036854775808ULL
#define SECUREC_MAX_64BITS_POS_VALUE            9223372036854775807ULL
#define SECUREC_MIN_32BITS_NEG_VALUE            2147483648ULL
#define SECUREC_MAX_32BITS_POS_VALUE            2147483647ULL
#define SECUREC_MAX_32BITS_VALUE                4294967295ULL
#define SECUREC_MAX_32BITS_VALUE_INC            4294967296ULL
#define SECUREC_MAX_32BITS_VALUE_DIV_TEN        429496729ULL
#define SECUREC_LONG_BIT_NUM                    ((unsigned int)(sizeof(long) << 3U))

#define SECUREC_LONG_HEX_BEYOND_MAX(number)     (((number) >> (SECUREC_LONG_BIT_NUM - 4U)) > 0)
#define SECUREC_LONG_OCTAL_BEYOND_MAX(number)   (((number) >> (SECUREC_LONG_BIT_NUM - 3U)) > 0)

#define SECUREC_QWORD_HEX_BEYOND_MAX(number)     (((number) >> (64U - 4U)) > 0)
#define SECUREC_QWORD_OCTAL_BEYOND_MAX(number)   (((number) >> (64U - 3U)) > 0)

#define SECUREC_LP64_BIT_WIDTH                   64
#define SECUREC_LP32_BIT_WIDTH                   32

#endif

#define SECUREC_CHAR(x) (x)
#define SECUREC_BRACE ('{')     /* [ to { */

#ifdef SECUREC_FOR_WCHAR
#define SECUREC_SCANF_BRACKET_CONDITION(comChr, ch, bracketTable, tableMask) ((comChr) == SECUREC_BRACE && \
    (bracketTable) != NULL && \
    (((bracketTable)[((unsigned int)(int)(ch) & SECUREC_CHAR_MASK) >> 3] ^ (tableMask)) & (1 << ((ch) & 7))))
#else
#define SECUREC_SCANF_BRACKET_CONDITION(comChr, ch, bracketTable, tableMask) ((comChr) == SECUREC_BRACE && \
    (((bracketTable)[((unsigned char)(ch) & 0xff) >> 3] ^ (tableMask)) & (1 << ((ch) & 7))))
#endif
#define SECUREC_SCANF_STRING_CONDITION(comChr, ch) ((comChr) == SECUREC_CHAR('s') && \
    (!((ch) >= SECUREC_CHAR('\t') && (ch) <= SECUREC_CHAR('\r')) && (ch) != SECUREC_CHAR(' ')))

#ifdef SECUREC_FOR_WCHAR
#define SECUREC_EOF WEOF
#define SECUREC_MB_LEN 16       /* max. # bytes in multibyte char  ,see MB_LEN_MAX */
#define SECUREC_GET_CHAR() (++charCount, SecGetCharW(stream))
/* un get char marco do not set char count ,The reason is to avoid warning that variables are not used */
#define SECUREC_UN_GET_CHAR(chr) (--charCount, SecUnGetCharW((chr), stream))
#define SECUREC_IS_DIGIT(chr) (!((chr) & 0xff00) && isdigit(((chr) & 0x00ff)))
#define SECUREC_IS_XDIGIT(chr) (!((chr) & 0xff00) && isxdigit(((chr) & 0x00ff)))
static void SecUnGetCharW(SecInt chr, SecFileStream *str);
static SecInt SecGetCharW(SecFileStream *str);
#else
#define SECUREC_EOF EOF
#define SECUREC_GET_CHAR() (++charCount, SecGetChar(stream))
#define SECUREC_UN_GET_CHAR(chr) (--charCount, SecUnGetChar((chr), stream))
#define SECUREC_IS_DIGIT(chr) isdigit((unsigned char)(chr) & 0x00ff)
#define SECUREC_IS_XDIGIT(chr) isxdigit((unsigned char)(chr) & 0x00ff)
static SecInt SecGetChar(SecFileStream *str);
static void SecUnGetChar(SecInt chr, SecFileStream *str);
#endif

#define SECUREC_SKIP_SPACE_CHAR() SecSkipSpaceChar(&charCount, stream)

static SecInt SecSkipSpaceChar(int *, SecFileStream *);

typedef struct {
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
    int beyondMax;
#endif
    SecUnsignedInt64 number64;
    unsigned long number;
    int negative;
} SecNumberSpce;

/*
 * Determine if it is a 64-bit pointer  function
 */
static int SecIs64BitPtr(const size_t sizeOfVoidStar)
{
    /* point size is 4 or 8 , Under the 64 bit system, the value not 0 */
    /* to clear e778 */
    return (int)(sizeOfVoidStar & sizeof(SecInt64));
}

#if SECUREC_ENABLE_SCANF_FLOAT
/*
 * Check float point character  function
 */
static int SecCheckFloatDecPoint(const SecChar decPointer)
{
    /* don't support multi-language decimal point */
    if (decPointer == SECUREC_CHAR('.')) {
        return 1;
    }
    return 0;
}

/*
 * Convert a floating point string to a floating point number
 */
static void SecAssignFloat(const char *floatStr, const int numberWidth, void *argument)
{
    char *endPtr = NULL;
    double d;
#if SECUREC_SUPPORT_STRTOLD
    if (numberWidth == SECUREC_NUM_WIDTH_LONG_LONG) {
        long double d2 = strtold(floatStr, &endPtr);
        *(long double UNALIGNED *)argument = d2;
        return;
    }
#endif
    d = strtod(floatStr, &endPtr);
    if (numberWidth > SECUREC_NUM_WIDTH_INT) {
        *(double UNALIGNED *)argument = (double)d;
    } else {
        *(float UNALIGNED *)argument = (float)d;
    }
}

#ifdef SECUREC_FOR_WCHAR
/*
 * Convert a floating point wchar string to a floating point number
 * Success  ret 0
 */
static int SecAssignFloatW(const SecChar *floatStr, const size_t floatStrSize, const int numberWidth, void *argument)
{
    /* convert float string */
    size_t mbsLen;
    size_t tempFloatStrLen = (size_t)(floatStrSize + 1) * sizeof(wchar_t);
    char *tempFloatStr = (char *)SECUREC_MALLOC(tempFloatStrLen);

    if (tempFloatStr == NULL) {
        return -1;
    }
    tempFloatStr[0] = '\0';
    SECUREC_MASK_MSVC_CRT_WARNING
    mbsLen = wcstombs(tempFloatStr, floatStr, tempFloatStrLen - 1);
    SECUREC_END_MASK_MSVC_CRT_WARNING
    if (mbsLen != (size_t)-1) {
        tempFloatStr[mbsLen] = '\0';
        SecAssignFloat(tempFloatStr, numberWidth, argument);
    } else {
        SECUREC_FREE(tempFloatStr);
        return -1;
    }
    SECUREC_FREE(tempFloatStr);
    return 0;
}
#endif
/*
 *   Splice floating point string
 *   on error ret 0
 */
static int SecUpdateFloatString(size_t usedLen,
                                size_t *floatStrSize,
                                SecChar **floatStr, const SecChar *floatStrBuf, SecChar **allocFlag)
{
    if (usedLen != (*floatStrSize)) {
        return 1;
    }

    if ((*floatStr) == floatStrBuf) {
        /* add 1 to clear ZERO LENGTH ALLOCATIONS warning */
        size_t oriBufSize = (*floatStrSize) * (SECUREC_BUF_EXT_MUL * sizeof(SecChar)) + 1;
        void *tmpPointer = (void *)SECUREC_MALLOC(oriBufSize);
        if (tmpPointer == NULL) {
            return 0;
        }
        if (memcpy_s(tmpPointer, oriBufSize, (*floatStr), (*floatStrSize) * sizeof(SecChar)) != EOK) {
            SECUREC_FREE(tmpPointer);   /* This is a dead code, just to meet the coding requirements */
            return 0;
        }
        (*floatStr) = (SecChar *) (tmpPointer);
        (*allocFlag) = (SecChar *) (tmpPointer); /* use to clear free on stack warning */
        (*floatStrSize) *= SECUREC_BUF_EXT_MUL; /* this is OK, oriBufSize plus 1 just clear warning */
        return 1;
    } else {
        /* LSD 2014.3.6 fix, replace realloc to malloc to avoid heap injection */
        size_t oriBufSize = (*floatStrSize) * sizeof(SecChar);
        size_t nextSize = (oriBufSize * SECUREC_BUF_EXT_MUL) + 1; /* add 1 to clear satic check tool warning */
        /* Prevents integer overflow when calculating the wide character length.
         * The maximum length of SECUREC_INT_MAX_DIV_TEN is enough
         */
        if (nextSize <= SECUREC_INT_MAX_DIV_TEN) {
            void *tmpPointer = (void *)SECUREC_MALLOC(nextSize);
            if (tmpPointer == NULL) {
                return 0;
            }
            if (memcpy_s(tmpPointer, nextSize, (*floatStr), oriBufSize) != EOK) {
                SECUREC_FREE(tmpPointer);   /* This is a dead code, just to meet the coding requirements */
                return 0;
            }
            if (memset_s((*floatStr), oriBufSize, 0, oriBufSize) != EOK) {
                SECUREC_FREE(tmpPointer);   /* This is a dead code, just to meet the coding requirements */
                return 0;
            }
            SECUREC_FREE((*floatStr));

            (*floatStr) = (SecChar *) (tmpPointer);
            (*allocFlag) = (SecChar *) (tmpPointer);    /* use to clear free on stack warning */
            (*floatStrSize) *= SECUREC_BUF_EXT_MUL; /* this is OK, oriBufSize plus 1 just clear warning */
            return 1;
        }
    }
    return 0;
}

#endif

#ifndef SECUREC_FOR_WCHAR

/* LSD only multi-bytes string need isleadbyte() function */
static int SecIsleadbyte(SecInt ch)
{
    unsigned int c = (unsigned int)ch;
#if !(defined(_MSC_VER) || defined(_INC_WCTYPE))
    return (int)(c & 0x80);
#else
    return (int)isleadbyte((int)(c & 0xff));
#endif
}

#endif

/*
 *  Parsing whether it is a wide character
 */
static void SecUpdateWcharFlagByType(const SecUnsignedChar ch, signed char *isWChar)
{
#if defined(SECUREC_FOR_WCHAR) && (defined(SECUREC_COMPATIBLE_WIN_FORMAT))
    signed char flagForUpperType = -1;
    signed char flagForLowerType = 1;
#else
    signed char flagForUpperType = 1;
    signed char flagForLowerType = -1;
#endif

    if ((*isWChar) == 0) {
        if ((ch == SECUREC_CHAR('C')) || (ch == SECUREC_CHAR('S'))) {
            (*isWChar) = flagForUpperType;
        } else {
            (*isWChar) = flagForLowerType;
        }
    }
    return;
}

#define SECUREC_FLOAT_BUFSIZE (309 + 40)  /* digits in max.dp value + slop */
#ifdef SECUREC_FOR_WCHAR
#define SECUREC_BRACKET_TABLE_SIZE    (32 * 256)
#else
#define SECUREC_BRACKET_TABLE_SIZE    (32)
#endif

#ifdef SECUREC_FOR_WCHAR
#define SECUREC_GETC fgetwc
#define SECUREC_UN_GETC ungetwc
#define SECUREC_CHAR_MASK 0xffff
#else
#define SECUREC_GETC fgetc
#define SECUREC_UN_GETC ungetc
#define SECUREC_CHAR_MASK 0xff
#endif

/* LSD 2014 1 24 add to protect NULL pointer access */
#define SECUREC_CHECK_INPUT_ADDR(p) do { \
    if ((p) == NULL) { \
        paraIsNull = 1; \
        goto ERR_RET; \
    } \
} SECUREC_WHILE_ZERO

#ifdef SECUREC_FOR_WCHAR
/*
 *  Clean up the first %s %c buffer to zero for wchar version
 */
void SecClearDestBufW(const wchar_t *buffer, const wchar_t *cformat, va_list argList)
#else
/*
 *  Clean up the first %s %c buffer to zero for char version
 */
void SecClearDestBuf(const char *buffer, const char *cformat, va_list argList)
#endif
{
    const SecUnsignedChar *fmt = (const SecUnsignedChar *)cformat;
    void *pDestBuf = NULL;
    va_list argListSave;        /* backup for argList value, this variable don't need initialized */
    size_t bufSize = 0;
    int spec = 0;
    signed char isWChar = 0;
    char doneFlag = 0;

    if (fmt != NULL) {
        while (*fmt) {
            if (*fmt == SECUREC_CHAR('%')) {
                doneFlag = 0;
                isWChar = 0;

                while (doneFlag == 0) {
                    spec = (int)(unsigned char)(*(++fmt));

                    if (SECUREC_IS_DIGIT((SecUnsignedChar)spec)) {
                        continue;
                    } else if (spec == SECUREC_CHAR('h')) {
                        isWChar = -1;
                        continue;
                    } else if (spec == SECUREC_CHAR('l') || spec == SECUREC_CHAR('w')) {
                        isWChar = 1;
                        continue;
                    }
                    doneFlag = 1;
                }

                /* if no  l or h flag */
                SecUpdateWcharFlagByType(*fmt, &isWChar);

                spec = (unsigned char)(*fmt) | (SECUREC_CHAR('a') - SECUREC_CHAR('A'));

                if (!(spec == SECUREC_CHAR('c') || spec == SECUREC_CHAR('s') || spec == SECUREC_BRACE)) {
                    return;     /* first argument is not a string type */
                }

                if ((buffer != NULL) && (*buffer != SECUREC_CHAR('\0')) && (spec != SECUREC_CHAR('s'))) {
                    /* when buffer not empty just clear %s.
                     * example call sscanf by  argment of (" \n", "%s", str, sizeof(str))
                     */
                    return;
                }

                if (spec == SECUREC_BRACE) {
#if !(defined(SECUREC_COMPATIBLE_WIN_FORMAT))
                    if (*fmt == SECUREC_CHAR('{')) {
                        return;
                    }
#endif
                    ++fmt;

                    if (*fmt == SECUREC_CHAR('^')) {
                        ++fmt;
                    }

                    if (*fmt == SECUREC_CHAR(']')) {
                        ++fmt;
                    }

                    while ((*fmt != SECUREC_CHAR('\0')) && (*fmt != SECUREC_CHAR(']'))) {
                        ++fmt;
                    }
                    if (*fmt == SECUREC_CHAR('\0')) {
                        return; /* trunc'd format string */
                    }
                }

                (void)memset(&argListSave, 0, sizeof(argListSave)); /* to clear e530 argListSave not initialized */
#if defined(va_copy)
                va_copy(argListSave, argList);
#elif defined(__va_copy)        /* for vxworks */
                __va_copy(argListSave, argList);
#else
                argListSave = argList;
#endif
                pDestBuf = (void *)va_arg(argListSave, void *);
                /* Get the next argument - size of the array in characters */
                bufSize = ((size_t)(va_arg(argListSave, size_t))) & 0xFFFFFFFFUL;

                va_end(argListSave);
                /* to clear e438 last value assigned not used , the compiler will optimize this code */
                (void)argListSave;

                if (bufSize == 0 || bufSize > SECUREC_STRING_MAX_LEN || pDestBuf == NULL) {
                    return;
                }

                *(char *)pDestBuf = '\0';

                if (isWChar > 0 && bufSize >= sizeof(wchar_t)) {
                    *(wchar_t UNALIGNED *)pDestBuf = L'\0';
                }

                return;
            }
            ++fmt;              /* skip to next char */
        }
    }
    return;
}

/*
 *  Assign number  to output buffer
 */
static void SecAssignNumber(const int numberWidth, const unsigned long number, void *argPtr)
{
    if (numberWidth > SECUREC_NUM_WIDTH_INT) {
        /* take number as unsigned number */
        *(long UNALIGNED *)argPtr = (long)number;
    } else if (numberWidth == SECUREC_NUM_WIDTH_INT) {
        *(int UNALIGNED *)argPtr = (int)number;
    } else if (numberWidth == SECUREC_NUM_WIDTH_SHORT) {
        /* take number as unsigned number */
        *(short UNALIGNED *)argPtr = (short)number;
    } else {  /* < 0 for hh format modifier */
        /* take number as unsigned number */
        *(char UNALIGNED *)argPtr = (char)number;
    }
}

#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
/*
 *  Judge the long bit width
 */
static int SecIsLongBitEqual(const int bitNum)
{
    return (unsigned int)bitNum == SECUREC_LONG_BIT_NUM;
}
#endif
/*
 * Convert hexadecimal characters to decimal offsets relative to '0'
 */
static SecInt SecHexOffsetByZeroChar(const SecInt ch)
{
    /* use isdigt Causing tool false alarms */
    return (SecInt)((ch >= '0' && ch <= '9') ? (unsigned char)ch :
            ((((unsigned char)ch | (unsigned char)('a' - 'A')) - ('a')) + 10 + '0'));
}

/*
 * Parse 32-bit integer formatted input
 */
static char SecDecodeNumber(const int comChr, const SecInt ch, SecNumberSpce *spec)
{
    char doneFlag = 0;
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
    unsigned long decimalEdge = SECUREC_MAX_32BITS_VALUE_DIV_TEN;
#endif
    if (comChr == SECUREC_CHAR('x') || comChr == SECUREC_CHAR('p')) {
        if (SECUREC_IS_XDIGIT(ch)) {
            SecInt ch2;
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
            if (SECUREC_LONG_HEX_BEYOND_MAX(spec->number)) {
                spec->beyondMax = 1;
            }
#endif
            spec->number = SECUREC_MUL_SIXTEEN(spec->number);
            ch2 = SecHexOffsetByZeroChar(ch);
            spec->number += (unsigned long)((SecUnsignedInt)ch2 - SECUREC_CHAR('0'));
        } else {
            doneFlag = 1;
        }
    } else if (SECUREC_IS_DIGIT(ch)) {
        if (comChr == SECUREC_CHAR('o')) {
            if (ch < SECUREC_CHAR('8')) {
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
                if (SECUREC_LONG_OCTAL_BEYOND_MAX(spec->number)) {
                    spec->beyondMax = 1;
                }
#endif
                spec->number = SECUREC_MUL_EIGHT(spec->number);
                spec->number += (unsigned long)((SecUnsignedInt)ch - SECUREC_CHAR('0'));
            } else {
                doneFlag = 1;
            }
        } else { /* comChr is 'd' */
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
#ifdef SECUREC_ON_64BITS
            if (SecIsLongBitEqual(SECUREC_LP64_BIT_WIDTH)) {
                decimalEdge = (unsigned long)SECUREC_MAX_64BITS_VALUE_DIV_TEN;
            }
#else
            if (SecIsLongBitEqual(SECUREC_LP32_BIT_WIDTH)) {
                decimalEdge = SECUREC_MAX_32BITS_VALUE_DIV_TEN;
            }
#endif
            if (spec->number > decimalEdge) {
                spec->beyondMax = 1;
            }
#endif
            spec->number = SECUREC_MUL_TEN(spec->number);
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
            if (spec->number == SECUREC_MUL_TEN(decimalEdge)) {
                SecUnsignedInt64 number64As = (unsigned long)SECUREC_MAX_64BITS_VALUE - spec->number;
                if (number64As < (SecUnsignedInt64)((SecUnsignedInt)ch - SECUREC_CHAR('0'))) {
                    spec->beyondMax = 1;
                }
            }
#endif
            spec->number += (unsigned long)((SecUnsignedInt)ch - SECUREC_CHAR('0'));
        }
    } else {
        doneFlag = 1;
    }
    return doneFlag;
}

/*
 * Complete the final 32-bit integer formatted input
 */
static void SecFinishNumber(const int comChr, const int numberWidth, SecNumberSpce *spec)
{

#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
    if (spec->negative != 0) {
        if (numberWidth == SECUREC_NUM_WIDTH_INT) {
            if ((comChr == SECUREC_CHAR('d')) || (comChr == SECUREC_CHAR('i'))) {
#ifdef SECUREC_ON_64BITS
                if (SecIsLongBitEqual(SECUREC_LP64_BIT_WIDTH)) {
                    if ((spec->number > SECUREC_MIN_64BITS_NEG_VALUE)) {
                        spec->number = 0;
                    } else {
                        spec->number = (unsigned int)(-(int)spec->number);
                    }
                }
#else
                if (SecIsLongBitEqual(SECUREC_LP32_BIT_WIDTH)) {
                    if ((spec->number > SECUREC_MIN_32BITS_NEG_VALUE)) {
                        spec->number = SECUREC_MIN_32BITS_NEG_VALUE;
                    } else {
                        spec->number = (unsigned int)(-(int)spec->number);
                    }
                }
#endif
                if (spec->beyondMax) {
#ifdef SECUREC_ON_64BITS
                    if (SecIsLongBitEqual(SECUREC_LP64_BIT_WIDTH)) {
                        spec->number = 0;
                    }
#else
                    if (SecIsLongBitEqual(SECUREC_LP32_BIT_WIDTH)) {
                        spec->number = SECUREC_MIN_32BITS_NEG_VALUE;
                    }
#endif
                }
            } else {            /* o, u, x, X ,p */
#ifdef SECUREC_ON_64BITS
                if (spec->number > SECUREC_MAX_32BITS_VALUE_INC) {
                    spec->number = SECUREC_MAX_32BITS_VALUE;
                } else {
                    spec->number = (unsigned int)(-(int)spec->number);
                }
#else
                spec->number = (unsigned int)(-(int)spec->number);
#endif
                if (spec->beyondMax) {
                    spec->number |= (unsigned long)0xffffffffffffffffULL;
                }
            }
        } else {
            if ((comChr == SECUREC_CHAR('d')) || (comChr == SECUREC_CHAR('i'))) {
                if (spec->number > (unsigned long)(1ULL << (SECUREC_LONG_BIT_NUM - 1))) {
                    spec->number = (unsigned long)(1ULL << (SECUREC_LONG_BIT_NUM - 1));
                } else {
                    spec->number = (unsigned long)(-(long)spec->number);
                }
            } else {
                spec->number = (unsigned long)(-(long)spec->number);
                if (spec->beyondMax) {
                    spec->number |= (unsigned long)0xffffffffffffffffULL;
                }
            }
        }
        if ((comChr == SECUREC_CHAR('d')) || (comChr == SECUREC_CHAR('i'))) {
            if (((spec->beyondMax) && (numberWidth < SECUREC_NUM_WIDTH_SHORT)) ||
                ((spec->beyondMax) && (numberWidth == SECUREC_NUM_WIDTH_SHORT)) ||
                ((spec->beyondMax) && (numberWidth == SECUREC_NUM_WIDTH_INT) &&
                (SecIsLongBitEqual(SECUREC_LP64_BIT_WIDTH)))) {
                spec->number = 0;
            }
            if ((spec->beyondMax) && (numberWidth == SECUREC_NUM_WIDTH_LONG)) {
                spec->number = ((unsigned long)(1UL << (SECUREC_LONG_BIT_NUM - 1)));
            }
        } else {                /* o, u, x, X, p */
            if (spec->beyondMax) {
                spec->number |= (unsigned long)0xffffffffffffffffULL;
            }
        }
    } else {
        if (numberWidth == SECUREC_NUM_WIDTH_INT) {
            if ((comChr == SECUREC_CHAR('d')) || (comChr == SECUREC_CHAR('i'))) {
#ifdef SECUREC_ON_64BITS
                if (SecIsLongBitEqual(SECUREC_LP64_BIT_WIDTH)) {
                    if (spec->number > SECUREC_MAX_64BITS_POS_VALUE) {
                        spec->number |= (unsigned long)0xffffffffffffffffULL;
                    }
                }
                if ((spec->beyondMax) && (SecIsLongBitEqual(SECUREC_LP64_BIT_WIDTH))) {
                    spec->number |= (unsigned long)0xffffffffffffffffULL;
                }
#else
                if (SecIsLongBitEqual(SECUREC_LP32_BIT_WIDTH)) {
                    if (spec->number > SECUREC_MAX_32BITS_POS_VALUE) {
                        spec->number = SECUREC_MAX_32BITS_POS_VALUE;
                    }
                }
                if ((spec->beyondMax) && (SecIsLongBitEqual(SECUREC_LP32_BIT_WIDTH))) {
                    spec->number = SECUREC_MAX_32BITS_POS_VALUE;
                }
#endif
            } else {            /* o,u,x,X,p */
                if (spec->beyondMax) {
                    spec->number = SECUREC_MAX_32BITS_VALUE;
                }
            }

        } else {
            if ((comChr == SECUREC_CHAR('d')) || (comChr == SECUREC_CHAR('i'))) {
                if (spec->number > ((unsigned long)(1UL << (SECUREC_LONG_BIT_NUM - 1)) - 1)) {
                    spec->number = ((unsigned long)(1UL << (SECUREC_LONG_BIT_NUM - 1)) - 1);
                }
                if (((spec->beyondMax) && (numberWidth < SECUREC_NUM_WIDTH_SHORT)) ||
                    ((spec->beyondMax) && (numberWidth == SECUREC_NUM_WIDTH_SHORT))) {
                    spec->number |= (unsigned long)0xffffffffffffffffULL;
                }
                if ((spec->beyondMax) && (numberWidth == SECUREC_NUM_WIDTH_LONG)) {
                    spec->number = ((unsigned long)(1UL << (SECUREC_LONG_BIT_NUM - 1)) - 1);
                }
            } else {
                if (spec->beyondMax) {
                    spec->number |= (unsigned long)0xffffffffffffffffULL;
                }
            }
        }
    }
#else
    if (spec->negative != 0) {
#if defined(__hpux)
        if (comChr != SECUREC_CHAR('p')) {
            spec->number = (unsigned long)(-(long)spec->number);
        }
#else
        spec->number = (unsigned long)(-(long)spec->number);
#endif
    }
#endif

    (void)numberWidth;          /* clear compile warnig */
    (void)comChr;               /* clear compile warnig */
    return;
}

/*
 * Parse 64-bit integer formatted input
 */
static char SecDecodeNumber64(const int comChr, const SecInt ch, SecNumberSpce *spec)
{
    char doneFlag = 0;

    if (comChr == SECUREC_CHAR('x') || comChr == SECUREC_CHAR('p')) {
        if (SECUREC_IS_XDIGIT(ch)) {
            SecInt ch2;
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
            if (SECUREC_QWORD_HEX_BEYOND_MAX(spec->number64)) {
                spec->beyondMax = 1;
            }
#endif
            spec->number64 = SECUREC_MUL_SIXTEEN(spec->number64);
            ch2 = SecHexOffsetByZeroChar(ch);
            spec->number64 += (SecUnsignedInt64)((SecUnsignedInt)ch2 - SECUREC_CHAR('0'));
        } else {
            doneFlag = 1;
        }
    } else if (SECUREC_IS_DIGIT(ch)) {
        if (comChr == SECUREC_CHAR('o')) {
            if (ch < SECUREC_CHAR('8')) {
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
                if (SECUREC_QWORD_OCTAL_BEYOND_MAX(spec->number64)) {
                    spec->beyondMax = 1;
                }
#endif
                spec->number64 = SECUREC_MUL_EIGHT(spec->number64);
                spec->number64 += (SecUnsignedInt64)((SecUnsignedInt)ch - SECUREC_CHAR('0'));
            } else {
                doneFlag = 1;
            }
        } else { /* comChr is d */
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
            if (spec->number64 > SECUREC_MAX_64BITS_VALUE_DIV_TEN) {
                spec->beyondMax = 1;
            }
#endif
            spec->number64 = SECUREC_MUL_TEN(spec->number64);
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
            if (spec->number64 == SECUREC_MAX_64BITS_VALUE_CUT_LAST_DIGIT) {
                SecUnsignedInt64 number64As = SECUREC_MAX_64BITS_VALUE - spec->number64;
                if (number64As < (SecUnsignedInt64)((SecUnsignedInt)ch - SECUREC_CHAR('0'))) {
                    spec->beyondMax = 1;
                }
            }
#endif
            spec->number64 += (SecUnsignedInt64)((SecUnsignedInt)ch - SECUREC_CHAR('0'));
        }

    } else {
        doneFlag = 1;
    }

    return doneFlag;
}

/*
 * Complete the final 64-bit integer formatted input
 */
static void SecFinishNumber64(const int comChr, SecNumberSpce *spec)
{
#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
    if (spec->negative != 0) {
        if (comChr == (SECUREC_CHAR('d')) || (comChr == SECUREC_CHAR('i'))) {
            if (spec->number64 > SECUREC_MIN_64BITS_NEG_VALUE) {
                spec->number64 = SECUREC_MIN_64BITS_NEG_VALUE;
            } else {
                spec->number64 = (SecUnsignedInt64)(-(SecInt64)spec->number64);
            }
            if (spec->beyondMax) {
                spec->number64 = SECUREC_MIN_64BITS_NEG_VALUE;
            }
        } else {                /* o, u, x, X, p */
            spec->number64 = (SecUnsignedInt64)(-(SecInt64)spec->number64);
            if (spec->beyondMax) {
                spec->number64 = SECUREC_MAX_64BITS_VALUE;
            }
        }
    } else {
        if ((comChr == SECUREC_CHAR('d')) || (comChr == SECUREC_CHAR('i'))) {
            if (spec->number64 > SECUREC_MAX_64BITS_POS_VALUE) {
                spec->number64 = SECUREC_MAX_64BITS_POS_VALUE;
            }
            if (spec->beyondMax) {
                spec->number64 = SECUREC_MAX_64BITS_POS_VALUE;
            }
        } else {
            if (spec->beyondMax) {
                spec->number64 = SECUREC_MAX_64BITS_VALUE;
            }
        }
    }
#else
    if (spec->negative != 0) {
#if defined(__hpux)
        if (comChr != SECUREC_CHAR('p')) {
            spec->number64 = (SecUnsignedInt64)(-(SecInt64)spec->number64);
        }
#else
        spec->number64 = (SecUnsignedInt64)(-(SecInt64)spec->number64);
#endif
    }
#endif
    (void)comChr;               /* clear compile warnig */
    return;
}

#if SECUREC_ENABLE_SCANF_FILE

/*
 *  Adjust the pointer position of the file stream
 */
static void SecSeekStream(SecFileStream *stream)
{
    if ((stream->count == 0) && feof(stream->pf)) {
        /* file pointer at the end of file, don't need to seek back */
        stream->base[0] = '\0';
        return;
    }
    /* LSD seek to original position, bug fix 2014 1 21 */
    if (fseek(stream->pf, stream->oriFilePos, SEEK_SET)) {
        /* seek failed, ignore it */
        stream->oriFilePos = 0;
        return;
    }

    if (stream->fileRealRead > 0) { /* LSD bug fix. when file reach to EOF, don't seek back */
#if (defined(SECUREC_COMPATIBLE_WIN_FORMAT))
        int loops;
        for (loops = 0; loops < (stream->fileRealRead / SECUREC_BUFFERED_BLOK_SIZE); ++loops) {
            if (fread(stream->base, (size_t)1, (size_t)SECUREC_BUFFERED_BLOK_SIZE,
                stream->pf) != SECUREC_BUFFERED_BLOK_SIZE) {
                break;
            }
        }
        if ((stream->fileRealRead % SECUREC_BUFFERED_BLOK_SIZE) != 0) {
            size_t ret = fread(stream->base, (size_t)((unsigned int)stream->fileRealRead % SECUREC_BUFFERED_BLOK_SIZE),
                               (size_t)1, stream->pf);
            if ((ret == 1 || ret == 0) && (ftell(stream->pf) < stream->oriFilePos + stream->fileRealRead)) {
                (void)fseek(stream->pf, stream->oriFilePos + stream->fileRealRead, SEEK_SET);
            }
        }

#else
        /* in linux like system */
        if (fseek(stream->pf, stream->oriFilePos + stream->fileRealRead, SEEK_SET)) {
            /* seek failed, ignore it */
            stream->oriFilePos = 0;
        }
#endif
    }

    return;
}

/*
 *  Adjust the pointer position of the file stream and free memory
 */
static void SecAdjustStream(SecFileStream *stream)
{
    if (stream != NULL && (stream->flag & SECUREC_FILE_STREAM_FLAG) && stream->base != NULL) {
        SecSeekStream(stream);
        SECUREC_FREE(stream->base);
        stream->base = NULL;
    }
    return;
}
#endif

#ifdef SECUREC_FOR_WCHAR
/*
 *  Formatting input core functions for wchar version.Called by a function such as vsscanf_s
 */
int SecInputSW(SecFileStream *stream, const wchar_t *cformat, va_list argList)
#else
/*
 * Formatting input core functions for char version.Called by a function such as vswscanf_s
 */
int SecInputS(SecFileStream *stream, const char *cformat, va_list argList)
#endif
{
    const SecUnsignedChar *format = (const SecUnsignedChar *)cformat;
    size_t arrayWidth = 0;
#ifdef SECUREC_FOR_WCHAR
    unsigned char *bracketTable = NULL;
#else
    unsigned char bracketTable[SECUREC_BRACKET_TABLE_SIZE] = { 0 };
#endif

#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
    SecNumberSpce numberSpec = { 0, 0, 0, 0 };
#else
    SecNumberSpce numberSpec = { 0, 0, 0 };
#endif

    void *argPtr = NULL; /* points to receiving data addr */
    void *startPtr = NULL;
    SecInt ch = 0;
    int charCount;
    int comChr = 0;
    int oriComChr = 0;
    int doneCount;
    int started = 0;
    int width = 0;
    int widthSet = 0;
    int errNoMem = 0;
    int formatError = 0;
    int paraIsNull = 0;
    int numberWidth;    /* 0 = SHORT, 1 = int, > 1  long or L_DOUBLE */
    int isInt64Arg;         /* 1 for 64-bit integer, 0 otherwise */
    va_list argListSave;        /* backup for argList value, this variable don't need initialized */

#if defined(va_copy) || defined(__va_copy)
    int argListBeenCopied = 0;
#endif

#if SECUREC_ENABLE_SCANF_FLOAT
    SecChar floatStrBuffer[SECUREC_FLOAT_BUFSIZE + 1];
    SecChar *pFloatStr = floatStrBuffer;
    SecChar *pAllocatedFloatStr = NULL;
    size_t floatStrSize = sizeof(floatStrBuffer) / sizeof(floatStrBuffer[0]);
    size_t floatStrUsedLen;
    SecChar decimal;
#endif

    SecUnsignedChar expCh;
    SecUnsignedChar last;
    SecUnsignedChar prevChar;
    signed char isWChar;     /* -1/0 not wchar, 1 for wchar */
    unsigned char tableMask;
    char suppress;
    char match;
    char doneFlag;

    doneCount = 0;
    charCount = 0;
    match = 0;
    (void)memset(&argListSave, 0, sizeof(argListSave));

    while (format != NULL && *format) {
#ifdef SECUREC_FOR_WCHAR
        /* int to wint_t clear  e571 */
        if (iswspace((wint_t)(int)(*format))) {
#else
        if (isspace((SecUnsignedChar)(*format))) {
#endif

            SecUnsignedChar tch;
            /* eat all space chars and put fist no space char backup */
            SECUREC_UN_GET_CHAR(SECUREC_SKIP_SPACE_CHAR());
            do {
                tch = (SecUnsignedChar)(*(++format));
#ifdef SECUREC_FOR_WCHAR
                /* int to wint_t clear  e571 */
            } while (iswspace((wint_t)(int)tch));
#else
            } while (isspace(tch));
#endif

            continue;
        }

        if (*format == SECUREC_CHAR('%')) {
            numberWidth = SECUREC_NUM_WIDTH_INT;    /* 0 = SHORT, 1 = int, > 1  long or L_DOUBLE */
            isInt64Arg = 0;         /* 1 for 64-bit integer, 0 otherwise */
            numberSpec.number = 0;
            numberSpec.negative = 0;
            prevChar = 0;
            width = 0;
            widthSet = 0;
            started = 0;
            arrayWidth = 0;
            errNoMem = 0;
            doneFlag = 0;
            suppress = 0;
            tableMask = 0;
            isWChar = 0;

#if (defined(SECUREC_COMPATIBLE_LINUX_FORMAT) && !(defined(SECUREC_ON_UNIX)))
            numberSpec.beyondMax = 0;
#endif

            numberSpec.number64 = 0;

            while (doneFlag == 0) {
                comChr = (int)(unsigned char)(*(++format));
                if (SECUREC_IS_DIGIT((SecUnsignedChar)comChr)) {
                    widthSet = 1;
                    if (width > SECUREC_INT_MAX_DIV_TEN) {
                        formatError = 1;
                        goto ERR_RET;
                    }
                    width = (int)SECUREC_MUL_TEN((unsigned int)width) +
                                    (unsigned char)(comChr - SECUREC_CHAR('0'));
                } else {
                    switch (comChr) {
                        case SECUREC_CHAR('F'):    /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('N'):
                            break;
                        case SECUREC_CHAR('h'):
                            --numberWidth;  /* h for SHORT , hh for CHAR */
                            isWChar = -1;
                            break;
#ifdef SECUREC_COMPATIBLE_LINUX_FORMAT
                        case SECUREC_CHAR('j'):
                            numberWidth = SECUREC_NUM_WIDTH_LONG_LONG;  /* intmax_t or uintmax_t */
                            isInt64Arg = 1;
                            break;
                        case SECUREC_CHAR('t'):    /* fall-through */ /* FALLTHRU */
#endif
                        case SECUREC_CHAR('z'):
#ifdef SECUREC_ON_64BITS
                            numberWidth = SECUREC_NUM_WIDTH_LONG_LONG;
                            isInt64Arg = 1;
#else
                            numberWidth = SECUREC_NUM_WIDTH_LONG;
#endif
                            break;
                        case SECUREC_CHAR('L'):    /* long double */ /* fall-through */ /* FALLTHRU */
                        case SECUREC_CHAR('q'):
                            numberWidth = SECUREC_NUM_WIDTH_LONG_LONG;
                            isInt64Arg = 1;
                            break;
                        case SECUREC_CHAR('l'):
                            if (*(format + 1) == SECUREC_CHAR('l')) {
                                isInt64Arg = 1;
                                numberWidth = SECUREC_NUM_WIDTH_LONG_LONG;
                                ++format;
                            } else {
                                numberWidth = SECUREC_NUM_WIDTH_LONG;
#ifdef SECUREC_ON_64BITS
#if !(defined(SECUREC_COMPATIBLE_WIN_FORMAT))  /* on window 64 system sizeof long is 32bit */
                                isInt64Arg = 1;
#endif
#endif
                                isWChar = 1;
                            }
                            break;
                        case SECUREC_CHAR('w'):
                            isWChar = 1;
                            break;

                        case SECUREC_CHAR('*'):
                            suppress = 1;
                            break;

                        case SECUREC_CHAR('I'):
                            if ((*(format + 1) == SECUREC_CHAR('6')) &&
                                (*(format + 2) == SECUREC_CHAR('4'))) {
                                isInt64Arg = 1;
                                format += SECUREC_FLAG_I64_LEN;
                                break;
                            } else if ((*(format + 1) == SECUREC_CHAR('3')) &&
                                        (*(format + 2) == SECUREC_CHAR('2'))) {
                                format += SECUREC_FLAG_I32_LEN;
                                break;
                            } else if ((*(format + 1) == SECUREC_CHAR('d')) ||
                                        (*(format + 1) == SECUREC_CHAR('i')) ||
                                        (*(format + 1) == SECUREC_CHAR('o')) ||
                                        (*(format + 1) == SECUREC_CHAR('x')) ||
                                        (*(format + 1) == SECUREC_CHAR('X'))) {
                                isInt64Arg = SecIs64BitPtr(sizeof(void *));
                                break;
                            }
                            isInt64Arg = SecIs64BitPtr(sizeof(void *));
                            doneFlag = 1;
                            break;
                        default:
                            doneFlag = 1;
                            break;
                    }           /* end of switch (comChr) ... */
                }
            }

            if (suppress == 0) {
                /* LSD change, for gcc compile Assign argList to   argListSave */
#if defined(va_copy)
                va_copy(argListSave, argList);
#elif defined(__va_copy)        /* for vxworks */
                __va_copy(argListSave, argList);
#else
                argListSave = argList;
#endif
                argPtr = (void *)va_arg(argList, void *);
                SECUREC_CHECK_INPUT_ADDR(argPtr);
            } else {
                /* "argPtr = NULL" is safe, in supress mode we don't use argPtr to store data */
                argPtr = NULL;  /* doesn't matter what value we use here - we're only using it as a flag */
            }

            doneFlag = 0;

            SecUpdateWcharFlagByType(*format, &isWChar);

            comChr = (unsigned char)(*format) | (SECUREC_CHAR('a') - SECUREC_CHAR('A')); /* to lowercase */

            if (comChr != SECUREC_CHAR('n')) {
                if (comChr != SECUREC_CHAR('c') && comChr != SECUREC_BRACE) {
                    ch = SECUREC_SKIP_SPACE_CHAR();
                } else {
                    ch = SECUREC_GET_CHAR();
                }
            }

            if (comChr != SECUREC_CHAR('n')) {
                if (ch == SECUREC_EOF) {
                    goto ERR_RET;
                }
            }

            if (widthSet == 0 || width != 0) {
                if (suppress == 0 && (comChr == SECUREC_CHAR('c') ||
                    comChr == SECUREC_CHAR('s') ||
                    comChr == SECUREC_BRACE)) {

#if defined(va_copy)
                    va_copy(argList, argListSave);
                    va_end(argListSave);
                    argListBeenCopied = 1;
#elif defined(__va_copy)        /* for vxworks */
                    __va_copy(argList, argListSave);
                    va_end(argListSave);
                    argListBeenCopied = 1;
#else
                    argList = argListSave;
#endif
                    argPtr = (void *)va_arg(argList, void *);
                    SECUREC_CHECK_INPUT_ADDR(argPtr);

#if defined(va_copy)
                    va_copy(argListSave, argList);
#elif defined(__va_copy)        /* for vxworks */
                    __va_copy(argListSave, argList);
#else
                    argListSave = argList;
#endif
                    /* Get the next argument - size of the array in characters */
#ifdef SECUREC_ON_64BITS
                    arrayWidth = ((size_t)(va_arg(argList, size_t))) & 0xFFFFFFFFUL;
#else /* !SECUREC_ON_64BITS */
                    arrayWidth = (size_t)va_arg(argList, size_t);
#endif

                    if (arrayWidth < 1) {

                        if (isWChar > 0) {
                            *(wchar_t UNALIGNED *)argPtr = L'\0';
                        } else {
                            *(char *)argPtr = '\0';
                        }

                        goto ERR_RET;
                    }

                    /* LSD add string maxi width protection */
                    if (isWChar > 0) {
                        if (arrayWidth > SECUREC_WCHAR_STRING_MAX_LEN) {
                            goto ERR_RET;
                        }
                    } else {
                        /* for char *buffer */
                        if (arrayWidth > SECUREC_STRING_MAX_LEN) {
                            goto ERR_RET;
                        }
                    }

                }

                oriComChr = comChr;

                switch (comChr) {
                    case SECUREC_CHAR('c'):
                        /* also case 'C' */ /* fall-through */ /* FALLTHRU */
                    case SECUREC_CHAR('s'):
                        /* also case 'S': */ /* fall-through */ /* FALLTHRU */
                    case SECUREC_BRACE:
                        if (comChr == 'c') {
                            if (widthSet == 0) {
                                widthSet = 1;
                                width = 1;
                            }
                        } else if (comChr == 's') {
                            /* empty */
                        } else {    /* for [ */
                            const SecUnsignedChar *bracketFmtPtr = (const SecUnsignedChar *)(format);
#if !(defined(SECUREC_COMPATIBLE_WIN_FORMAT))
                            if (*format == SECUREC_CHAR('{')) {
                                goto ERR_RET;
                            }
#endif
                            /* for building "table" data */
                            ++bracketFmtPtr;

                            if (*bracketFmtPtr == SECUREC_CHAR('^')) {
                                ++bracketFmtPtr;
                                tableMask = (unsigned char)0xff;
                            }

                            /* malloc  when  first %[ is meet  for wchar version */
#ifdef SECUREC_FOR_WCHAR
                            if (bracketTable == NULL) {
                                /* LSD the table will be freed after ERR_RET label of this function */
                                bracketTable = (unsigned char *)SECUREC_MALLOC(SECUREC_BRACKET_TABLE_SIZE);
                                if (bracketTable == NULL) {
                                    goto ERR_RET;
                                }
                            }
#endif
                            (void)memset(bracketTable, 0, (size_t)SECUREC_BRACKET_TABLE_SIZE);

                            if (*bracketFmtPtr == SECUREC_CHAR(']')) {
                                prevChar = SECUREC_CHAR(']');
                                ++bracketFmtPtr;

                                bracketTable[SECUREC_BRACKET_INDEX(SECUREC_CHAR(']'))] = \
                                    SECUREC_BRACKET_VALUE(SECUREC_CHAR(']'));

                            }

                            while (*bracketFmtPtr != SECUREC_CHAR('\0') && *bracketFmtPtr != SECUREC_CHAR(']')) {
                                unsigned int tmpIndex;  /* to clear warning */
                                expCh = *bracketFmtPtr++;

                                if (expCh != SECUREC_CHAR('-') || !prevChar ||  /* first char */
                                    *bracketFmtPtr == SECUREC_CHAR(']')) {  /* last char */
                                    prevChar = expCh;
                                    /* only supports  wide characters with a maximum length of two bytes */
                                    tmpIndex = (unsigned int)(int)expCh & SECUREC_CHAR_MASK;
                                    /* Do not use    |= optimize this code, it will cause compiling warning */
                                    bracketTable[SECUREC_BRACKET_INDEX(tmpIndex)] = \
                                        (unsigned char)(bracketTable[SECUREC_BRACKET_INDEX(tmpIndex)] | \
                                        SECUREC_BRACKET_VALUE(tmpIndex));
                                } else {
                                    /* for %[a-z] */
                                    expCh = *bracketFmtPtr++;   /* get end of range */

                                    if (prevChar < expCh) { /* %[a-z] */
                                        last = expCh;
                                    } else {

#if (defined(SECUREC_COMPATIBLE_WIN_FORMAT))
                                        /* %[z-a] */
                                        last = prevChar;
                                        prevChar = expCh;
#else
                                        prevChar = expCh;
                                        /* only supports  wide characters with a maximum length of two bytes */
                                        tmpIndex = (unsigned int)(int)expCh & SECUREC_CHAR_MASK;
                                        bracketTable[SECUREC_BRACKET_INDEX('-')] |= SECUREC_BRACKET_VALUE('-');
                                        bracketTable[SECUREC_BRACKET_INDEX(tmpIndex)] = \
                                            (unsigned char)(bracketTable[SECUREC_BRACKET_INDEX(tmpIndex)] |
                                            SECUREC_BRACKET_VALUE(tmpIndex));
                                        continue;
#endif
                                    }
                                    /* format %[a-\xff] last is 0xFF, condition (rnch <= last) cause dead loop */
                                    for (expCh = prevChar; expCh < last; ++expCh) {
                                        /* only supports  wide characters with a maximum length of two bytes */
                                        tmpIndex = (unsigned int)(int)expCh & SECUREC_CHAR_MASK;
                                        bracketTable[SECUREC_BRACKET_INDEX(tmpIndex)] = \
                                            (unsigned char)(bracketTable[SECUREC_BRACKET_INDEX(tmpIndex)] |
                                            SECUREC_BRACKET_VALUE(tmpIndex));
                                    }
                                    /* only supports  wide characters with a maximum length of two bytes */
                                    tmpIndex = (unsigned int)(int)last & SECUREC_CHAR_MASK;
                                    bracketTable[SECUREC_BRACKET_INDEX(tmpIndex)] = \
                                        (unsigned char)(bracketTable[SECUREC_BRACKET_INDEX(tmpIndex)] |
                                        SECUREC_BRACKET_VALUE(tmpIndex));
                                    prevChar = 0;
                                }
                            }

                            if (*bracketFmtPtr == SECUREC_CHAR('\0')) {
                                if (arrayWidth >= sizeof(SecChar) && argPtr) {
                                    *(SecChar *) argPtr = SECUREC_CHAR('\0');
                                }
                                goto ERR_RET;   /* trunc'd format string */
                            }
                            format = bracketFmtPtr;
                        }
                        /* scanset completed.  Now read string */
                        startPtr = argPtr;

                        SECUREC_UN_GET_CHAR(ch);

                        /* One element is needed for '\0' for %s & %[ */
                        if (comChr != SECUREC_CHAR('c')) {
                            --arrayWidth;
                        }
                        while (widthSet == 0 || width-- != 0) {

                            ch = SECUREC_GET_CHAR();
                            /* char  condition or string condition and bracket condition.
                             * only supports  wide characters with a maximum length of two bytes
                             */
                            if ((ch != SECUREC_EOF) && (comChr == SECUREC_CHAR('c') ||
                                SECUREC_SCANF_STRING_CONDITION(comChr, ch) ||
                                SECUREC_SCANF_BRACKET_CONDITION(comChr, ch, bracketTable, tableMask))) {
                                if (suppress == 0) {
                                    if (arrayWidth == 0) {
                                        errNoMem = 1; /* We have exhausted the user's buffer */
                                        break;
                                    }
                                    SECUREC_CHECK_INPUT_ADDR(argPtr);
#ifdef SECUREC_FOR_WCHAR
                                    if (isWChar > 0) {
                                        *(wchar_t UNALIGNED *)argPtr = (wchar_t)ch;
                                        argPtr = (wchar_t *)argPtr + 1;
                                        --arrayWidth;
                                    } else {
#if SECUREC_HAVE_WCTOMB
                                        int temp = 0;
                                        if (arrayWidth >= ((size_t)MB_CUR_MAX)) {
                                            SECUREC_MASK_MSVC_CRT_WARNING
                                            temp = wctomb((char *)argPtr, (wchar_t)ch);
                                            SECUREC_END_MASK_MSVC_CRT_WARNING
                                        } else {
                                            char tmpBuf[SECUREC_MB_LEN + 1];
                                            SECUREC_MASK_MSVC_CRT_WARNING temp = wctomb(tmpBuf, (wchar_t)ch);
                                            SECUREC_END_MASK_MSVC_CRT_WARNING
                                            if (temp > 0 && ((size_t)(unsigned int)temp) > arrayWidth) {
                                                errNoMem = 1;
                                                break;
                                            }
                                            if (temp > 0 && ((size_t)(unsigned int)temp) <= sizeof(tmpBuf)) {
                                                if (EOK != memcpy_s(argPtr, arrayWidth,
                                                                    tmpBuf, (size_t)(unsigned int)temp)) {
                                                    errNoMem = 1;
                                                    break;
                                                }
                                            }
                                        }
                                        if (temp > 0) {
                                            /* if wctomb  error, then ignore character */
                                            argPtr = (char *)argPtr + temp;
                                            arrayWidth -= (size_t)(unsigned int)temp;
                                        }
#else
                                        errNoMem = 1;
                                        break;
#endif
                                    }
#else

                                    if (isWChar > 0) {
                                        wchar_t tempWChar = L'?';   /* set default char as ? */
#if SECUREC_HAVE_MBTOWC
                                        char temp[SECUREC_MULTI_BYTE_MAX_LEN + 1];
                                        temp[0] = (char)ch;
                                        temp[1] = '\0';
#if defined(SECUREC_COMPATIBLE_WIN_FORMAT)
                                        if (SecIsleadbyte(ch)) {
                                            temp[1] = (char)SECUREC_GET_CHAR();
                                            temp[2] = '\0';
                                        }
                                        if (mbtowc(&tempWChar, temp, sizeof(temp)) <= 0) {
                                            /* no string termination error for tool */
                                            tempWChar = L'?';
                                        }
#else
                                        if (SecIsleadbyte(ch)) {
                                            int convRes = 0;
                                            int di = 1;
                                            /* in Linux like system, the string is encoded in UTF-8 */
                                            while (di < (int)MB_CUR_MAX && di < SECUREC_MULTI_BYTE_MAX_LEN) {
                                                temp[di++] = (char)SECUREC_GET_CHAR();
                                                temp[di] = '\0';
                                                convRes = mbtowc(&tempWChar, temp, sizeof(temp));
                                                if (convRes > 0) {
                                                    break;  /* convert succeed */
                                                }
                                            }
                                            if (convRes <= 0) {
                                                tempWChar = L'?';
                                            }
                                        } else {
                                            if (mbtowc(&tempWChar, temp, sizeof(temp)) <= 0) {
                                                /* no string termination error for tool */
                                                tempWChar = L'?';
                                            }
                                        }
#endif
#endif /* SECUREC_HAVE_MBTOWC */
                                        *(wchar_t UNALIGNED *)argPtr = tempWChar;
                                        /* just copy L'?' if mbtowc fails, errno is set by mbtowc */
                                        argPtr = (wchar_t *)argPtr + 1;
                                        --arrayWidth;

                                     } else {
                                        *(char *)argPtr = (char)ch;
                                        argPtr = (char *)argPtr + 1;
                                        --arrayWidth;
                                     }
#endif
                                } else {
                                    /* suppress */
                                    /* this is OK, Used to identify processed data for %* ,
                                     * use size_t just  clear e613
                                     */
                                    startPtr = (SecChar *) (size_t)1 + (size_t)argPtr;
                                }
                            } else {
                                SECUREC_UN_GET_CHAR(ch);
                                break;
                            }
                        }

                        if (errNoMem != 0) {
                            /* In case of error, blank out the input buffer */
                            if (isWChar > 0) {
                                if (startPtr != NULL) {
                                    *(wchar_t UNALIGNED *)startPtr = 0;
                                }
                            } else {
                                if (startPtr != NULL) {
                                    *(char *)startPtr = 0;
                                }
                            }

                            goto ERR_RET;
                        }

                        if (startPtr != argPtr) {
                            if (suppress == 0) {

                                SECUREC_CHECK_INPUT_ADDR(argPtr);

                                if (comChr != 'c') {
                                    /* null-terminate strings */
                                    if (isWChar > 0) {
                                        *(wchar_t UNALIGNED *)argPtr = L'\0';
                                    } else {
                                        *(char *)argPtr = '\0';
                                    }
                                }
                                ++doneCount;
                            }

                        } else {
                            goto ERR_RET;
                        }

                        break;
                    case SECUREC_CHAR('p'):
                        /* make %hp same as %p */
                        numberWidth = SECUREC_NUM_WIDTH_INT;
#ifdef SECUREC_ON_64BITS
                        isInt64Arg = 1;
#endif
                        /* fall-through */
                        /* FALLTHRU */
                    case SECUREC_CHAR('o'):    /* fall-through */ /* FALLTHRU */
                    case SECUREC_CHAR('u'):    /* fall-through */ /* FALLTHRU */
                    case SECUREC_CHAR('d'):    /* fall-through */ /* FALLTHRU */
                    case SECUREC_CHAR('i'):    /* fall-through */ /* FALLTHRU */
                    case SECUREC_CHAR('x'):
                        if (ch == SECUREC_CHAR('+') || ch == SECUREC_CHAR('-')) {
                            if (ch == SECUREC_CHAR('-')) {
                                numberSpec.negative = 1;
                            }
                            if (--width == 0 && widthSet != 0) {
                                doneFlag = 1;
                            } else {
                                ch = SECUREC_GET_CHAR();
                            }
                        }

                        if (comChr == SECUREC_CHAR('x') || comChr == SECUREC_CHAR('i')) {
                            if (comChr == SECUREC_CHAR('i')) {
                                /* i could be d, o, or x, use d as default */
                                comChr = SECUREC_CHAR('d');
                            }
                            if (ch == SECUREC_CHAR('0')) {
                                ch = SECUREC_GET_CHAR();
                                if ((SecChar)(ch) == SECUREC_CHAR('x') || (SecChar)ch == SECUREC_CHAR('X')) {
                                    ch = SECUREC_GET_CHAR();
                                    if (widthSet != 0) {
                                        width -= 2; /* Subtract the length of "0x" */
                                        if (width < 1) {
                                            doneFlag = 1;
                                        }
                                    }
                                    comChr = SECUREC_CHAR('x');
                                } else {
                                    started = 1;
                                    if (comChr != SECUREC_CHAR('x')) {
                                        if (widthSet != 0 && --width == 0) {
                                            doneFlag = 1;
                                        }
                                        comChr = SECUREC_CHAR('o');
                                    } else {
                                        SECUREC_UN_GET_CHAR(ch);
                                        ch = SECUREC_CHAR('0');
                                    }
                                }
                            }
                        }

                        /* scanNumber: */
                        if (isInt64Arg != 0) {
                            while (doneFlag == 0) {
                                /* decode ch to number64 */
                                doneFlag = SecDecodeNumber64(comChr, ch, &numberSpec);
                                if (doneFlag == 0) {
                                    started = 1;
                                    if (widthSet != 0 && --width == 0) {
                                        doneFlag = 1;
                                    } else {
                                        ch = SECUREC_GET_CHAR();
                                    }
                                } else {
                                    SECUREC_UN_GET_CHAR(ch);
                                }
                            }

                            /* Handling integer negative numbers and beyond max */

                            SecFinishNumber64(oriComChr, &numberSpec);

                        }
                        /* do not use else , Otherwise, the vxworks55 arm926ej compiler will crash. */
                        if (isInt64Arg == 0) {
                            while (doneFlag == 0) {
                                /* decode ch to number */
                                doneFlag = SecDecodeNumber(comChr, ch, &numberSpec);
                                if (doneFlag == 0) {
                                    started = 1;
                                    if (widthSet != 0 && --width == 0) {
                                        doneFlag = 1;
                                    } else {
                                        ch = SECUREC_GET_CHAR();
                                    }
                                } else {
                                    SECUREC_UN_GET_CHAR(ch);
                                }
                            }

                            /* Handling integer negative numbers and beyond max */

                            SecFinishNumber(oriComChr, numberWidth, &numberSpec);

                        }

                        if (comChr == SECUREC_CHAR('F')) {  /* expected ':' in long pointer */
                            started = 0;
                        }

                        if (started != 0) {
                            if (suppress == 0) {
                                SECUREC_CHECK_INPUT_ADDR(argPtr);

                                if (isInt64Arg != 0) {
#if defined(SECUREC_VXWORKS_PLATFORM)
                                    /* take number64 as unsigned number */
                                    *(SecInt64 UNALIGNED *)argPtr = *(SecUnsignedInt64 *)(&numberSpec.number64);
#else
                                    /* take number64 as unsigned number */
                                    *(SecInt64 UNALIGNED *)argPtr = (SecInt64)numberSpec.number64;
#endif
                                } else {
                                    SecAssignNumber(numberWidth, numberSpec.number, argPtr);
                                }
                                ++doneCount;
                            }
                            /* remove blank else */
                        } else {
                            goto ERR_RET;
                        }
                        break;

                    case SECUREC_CHAR('n'):    /* char count */
                        if (suppress == 0) {
                            SECUREC_CHECK_INPUT_ADDR(argPtr);
                            SecAssignNumber(numberWidth, (unsigned long)(unsigned int)charCount, argPtr);
                        }
                        break;

                    case SECUREC_CHAR('e'):    /* fall-through */ /* FALLTHRU */
                    case SECUREC_CHAR('f'):    /* fall-through */ /* FALLTHRU */
                    case SECUREC_CHAR('g'):    /* scan a float */
#if SECUREC_ENABLE_SCANF_FLOAT
                        floatStrUsedLen = 0;

                        if (ch == SECUREC_CHAR('-')) {
                            pFloatStr[floatStrUsedLen++] = SECUREC_CHAR('-');
                            --width;
                            ch = SECUREC_GET_CHAR();

                        } else if (ch == SECUREC_CHAR('+')) {
                            --width;
                            ch = SECUREC_GET_CHAR();
                        }

                        if (widthSet == 0) {    /* must care width */
                            width = -1;
                        }

                        /* now get integral part */
                        while (SECUREC_IS_DIGIT(ch) && width-- != 0) {
                            started = 1;
                            pFloatStr[floatStrUsedLen++] = (SecChar)ch;    /* ch must be '0' - '9' */
                            if (SecUpdateFloatString(floatStrUsedLen,
                                    &floatStrSize, &pFloatStr, floatStrBuffer, &pAllocatedFloatStr) == 0) {
                                goto ERR_RET;
                            }
                            ch = SECUREC_GET_CHAR();
                        }

#ifdef SECUREC_FOR_WCHAR
                        /* convert decimal point(.) to wide-char */
                        decimal = L'.';
#if SECUREC_HAVE_MBTOWC

                        if (mbtowc(&decimal, SECUREC_DECIMAL_POINT_PTR, (size_t)MB_CUR_MAX) <= 0) {
                            decimal = L'.';
                        }
#endif
#else
                        decimal = *SECUREC_DECIMAL_POINT_PTR;   /* if locale.h NOT exist, let decimal = '.' */
#endif

                        if (SecCheckFloatDecPoint(decimal) != 1) {
                            goto ERR_RET;
                        }

                        /* now check for decimal */
                        if (decimal == (char)ch && width-- != 0) {
                            ch = SECUREC_GET_CHAR();
                            pFloatStr[floatStrUsedLen++] = decimal;
                            if (SecUpdateFloatString(floatStrUsedLen,
                                         &floatStrSize, &pFloatStr, floatStrBuffer, &pAllocatedFloatStr) == 0) {
                                goto ERR_RET;
                            }
                            while (SECUREC_IS_DIGIT(ch) && width-- != 0) {
                                started = 1;
                                pFloatStr[floatStrUsedLen++] = (SecChar)ch;
                                if (SecUpdateFloatString(floatStrUsedLen,
                                         &floatStrSize,
                                         &pFloatStr, floatStrBuffer, &pAllocatedFloatStr) == 0) {
                                    goto ERR_RET;
                                }
                                ch = SECUREC_GET_CHAR();
                            }
                        }

                        /* now check for exponent */

                        if (started != 0 && (ch == SECUREC_CHAR('e') || ch == SECUREC_CHAR('E')) && width-- != 0) {
                            pFloatStr[floatStrUsedLen++] = SECUREC_CHAR('e');
                            if (SecUpdateFloatString(floatStrUsedLen,
                                     &floatStrSize, &pFloatStr, floatStrBuffer, &pAllocatedFloatStr) == 0) {
                                goto ERR_RET;
                            }

                            ch = SECUREC_GET_CHAR();
                            if (ch == SECUREC_CHAR('+') || ch == SECUREC_CHAR('-')) {
                                if (ch == SECUREC_CHAR('-')) {

                                    pFloatStr[floatStrUsedLen++] = SECUREC_CHAR('-');
                                    if (SecUpdateFloatString(floatStrUsedLen,
                                             &floatStrSize,
                                             &pFloatStr, floatStrBuffer, &pAllocatedFloatStr) == 0) {
                                        goto ERR_RET;
                                    }
                                }

                                if (width != 0) {
                                    ch = SECUREC_GET_CHAR();
                                    --width;
                                }
                            }

                            while (SECUREC_IS_DIGIT(ch) && width-- != 0) {
                                pFloatStr[floatStrUsedLen++] = (SecChar)ch;
                                if (SecUpdateFloatString(floatStrUsedLen,
                                         &floatStrSize,
                                         &pFloatStr, floatStrBuffer, &pAllocatedFloatStr) == 0) {
                                    goto ERR_RET;
                                }
                                ch = SECUREC_GET_CHAR();
                            }

                        }

                        SECUREC_UN_GET_CHAR(ch);

                        if (started != 0) {
                            if (suppress == 0) {
                                SECUREC_CHECK_INPUT_ADDR(argPtr);

                                /* Make sure  have a string terminator */
                                pFloatStr[floatStrUsedLen] = SECUREC_CHAR('\0');
#ifdef SECUREC_FOR_WCHAR
                                if (SecAssignFloatW(pFloatStr, floatStrSize, numberWidth, argPtr) != 0) {
                                    goto ERR_RET;
                                }
#else
                                SecAssignFloat(pFloatStr, numberWidth, argPtr);
#endif
                                ++doneCount;
                            }
                            /* remove blank else */ /* NULL */
                        } else {
                            goto ERR_RET;
                        }
                        break;
#else /* SECUREC_ENABLE_SCANF_FLOAT */
                        goto ERR_RET;
#endif
                    default:
                        if ((int)(*format) != (int)ch) {
                            SECUREC_UN_GET_CHAR(ch);
                            /* to clear e438 last value assigned not used , the compiler will optimize this code */
                            (void)charCount;
                            formatError = 1;
                            goto ERR_RET;
                        } else {
                            --match;
                        }

                        if (suppress == 0) {
#if defined(va_copy)
                            va_copy(argList, argListSave);
                            argListBeenCopied = 1;
                            va_end(argListSave);
#elif defined(__va_copy)        /* for vxworks */
                            __va_copy(argList, argListSave);
                            argListBeenCopied = 1;
                            va_end(argListSave);
#else
                            argList = argListSave;
#endif
                        }
                }

                ++match;

            } else {
                /* 0 width in format */
                SECUREC_UN_GET_CHAR(ch);
                /* to clear e438 last value assigned not used , the compiler will optimize this code */
                (void)charCount;
                goto ERR_RET;
            }

            ++format;
        } else {
            ch = SECUREC_GET_CHAR();
            if ((int)(*format++) != (int)(ch)) {
                SECUREC_UN_GET_CHAR(ch);
                /* to clear e438 last value assigned not used , the compiler will optimize this code */
                (void)charCount;
                goto ERR_RET;
            }
#ifndef SECUREC_FOR_WCHAR
            /* The purpose of type conversion is to avoid warnings */
            if (SecIsleadbyte(ch)) {
#if SECUREC_HAVE_MBTOWC
                char temp[SECUREC_MULTI_BYTE_MAX_LEN];
                wchar_t tempWChar = L'\0';
                int ch2 = SECUREC_GET_CHAR();

                if ((int)(*format++) != (ch2)) {
                    SECUREC_UN_GET_CHAR(ch2);   /* LSD in console mode, ungetc twice will cause problem */
                    SECUREC_UN_GET_CHAR(ch);
                    /* to clear e438 last value assigned not used , the compiler will optimize this code */
                    (void)charCount;
                    goto ERR_RET;
                }
                if (MB_CUR_MAX > SECUREC_UTF8_MIN_LEN &&
                    (((unsigned char)ch & SECUREC_UTF8_LEAD_1ST) == SECUREC_UTF8_LEAD_1ST) &&
                    (((unsigned char)ch2 & SECUREC_UTF8_LEAD_2ND) == SECUREC_UTF8_LEAD_2ND)) {
                    /* this char is very likely to be a UTF-8 char */
                    int ch3 = SECUREC_GET_CHAR();
                    temp[0] = (char)ch;
                    temp[1] = (char)ch2;
                    temp[2] = (char)ch3;
                    temp[3] = '\0';

                    if (mbtowc(&tempWChar, temp, sizeof(temp)) > 0) {
                        /* succeed */
                        if ((int)(*format++) != (int)ch3) {
                            SECUREC_UN_GET_CHAR(ch3);
                            /* to clear e438 last value assigned not used , the compiler will optimize this code */
                            (void)charCount;
                            goto ERR_RET;
                        }
                        --charCount;
                    } else {
                        SECUREC_UN_GET_CHAR(ch3);
                    }
                }
                --charCount;    /* only count as one character read */
#else
                SECUREC_UN_GET_CHAR(ch);
                /* to clear e438 last value assigned not used , the compiler will optimize this code */
                (void)charCount;
                goto ERR_RET;
#endif
            }
#endif /* SECUREC_FOR_WCHAR */
        }

        if ((ch == SECUREC_EOF) && ((*format != SECUREC_CHAR('%')) || (*(format + 1) != SECUREC_CHAR('n')))) {
            break;
        }

    }

ERR_RET:
#ifdef SECUREC_FOR_WCHAR
    if (bracketTable != NULL) {
        SECUREC_FREE(bracketTable);
        bracketTable = NULL;
        (void)bracketTable; /* to clear e438 last value assigned not used , the compiler will optimize this code */
    }
#endif

#if defined(va_copy) || defined(__va_copy)
    if (argListBeenCopied != 0) {
        va_end(argList);
        (void)argList; /* to clear e438 last value assigned not used , the compiler will optimize this code */
    }
#endif
    va_end(argListSave);
    (void)argListSave; /* to clear e438 last value assigned not used , the compiler will optimize this code */

#if SECUREC_ENABLE_SCANF_FLOAT
    /* LSD 2014.3.6 add, clear the stack data */
    if (memset_s(floatStrBuffer, sizeof(floatStrBuffer), 0, sizeof(floatStrBuffer)) != EOK) {
        doneCount = 0;          /* This is a dead code, just to meet the coding requirements */
    }
    if (pAllocatedFloatStr != NULL) {
        /* pFloatStr can be alloced in SecUpdateFloatString function, clear and free it */
        if (memset_s(pAllocatedFloatStr, floatStrSize * sizeof(SecChar), 0, floatStrSize * sizeof(SecChar)) != EOK) {
            doneCount = 0;      /* This is a dead code, just to meet the coding requirements */
        }
        SECUREC_FREE(pAllocatedFloatStr);
        pAllocatedFloatStr = NULL;
        (void)pAllocatedFloatStr; /* to clear e438, the compiler will optimize this code */
    }
#endif

#if SECUREC_ENABLE_SCANF_FILE
    SecAdjustStream(stream);
#endif

    if (ch == SECUREC_EOF) {
        return ((doneCount || match) ? doneCount : EOF);
    } else if (formatError != 0 || paraIsNull != 0) {
        /* Invalid Input Format or parameter */
        return SECUREC_SCANF_ERROR_PARA;
    }

    return doneCount;
}

#if SECUREC_ENABLE_SCANF_FILE

/*
 *  Get char  from stdin or buffer
 */
static SecInt SecGetCharFromStdin(const SecFileStream *str)
{
    SecInt ch;
#if defined(SECUREC_NO_STD_UNGETC)
    if (str->fUnget == 1) {
        ch = (SecInt) str->lastChar;
        str->fUnget = 0;
    } else {
        ch = SECUREC_GETC(str->pf);
        str->lastChar = (unsigned int)ch;
    }
#else
    ch = SECUREC_GETC(str->pf);
#endif
    return ch;
}

/*
 *  Get char  from file stream or buffer
 */
static SecInt SecGetCharFromFile(SecFileStream *str)
{
    int firstReadOnFile = 0;
    /* load file to buffer */
    if (str->base == NULL) {
        str->base = (char *)SECUREC_MALLOC(SECUREC_BUFFERED_BLOK_SIZE + 1);
        if (str->base == NULL) {
            return SECUREC_EOF;
        }
        str->base[SECUREC_BUFFERED_BLOK_SIZE] = '\0';   /* for tool Warning string null */
    }
    /* LSD add 2014.3.21 */
    if (str->oriFilePos == SECUREC_UNINITIALIZED_FILE_POS) {
        str->oriFilePos = ftell(str->pf);   /* save original file read position */
        firstReadOnFile = 1;
    }
    str->count = (int)fread(str->base, (size_t)1, (size_t)SECUREC_BUFFERED_BLOK_SIZE, str->pf);
    str->base[SECUREC_BUFFERED_BLOK_SIZE] = '\0';   /* for tool Warning string null */
    if (str->count == 0 || str->count > SECUREC_BUFFERED_BLOK_SIZE) {
        return SECUREC_EOF;
    }
    str->cur = str->base;
    str->flag |= SECUREC_LOAD_FILE_TO_MEM_FLAG;
    if (firstReadOnFile != 0) {
#ifdef SECUREC_FOR_WCHAR
        if (str->count > 1 &&
            (((unsigned char)(str->base[0]) == 0xFFU && (unsigned char)(str->base[1]) == 0xFEU) ||
            ((unsigned char)(str->base[0]) == 0xFEU && (unsigned char)(str->base[1]) == 0xFFU))) {
            /* it's BOM header, UNICODE little endian */
            str->count -= SECUREC_BOM_HEADER_SIZE;
            if (memmove_s(str->base, (size_t)SECUREC_BUFFERED_BLOK_SIZE,
                          str->base + SECUREC_BOM_HEADER_SIZE, (size_t)(unsigned int)str->count) != EOK) {
                return SECUREC_EOF;
            }

            if (str->count % (int)sizeof(SecChar)) {
                /* the str->count must be a  multiple of  sizeof(SecChar),
                 * otherwise this function will return SECUREC_EOF when read the last character
                 */
                int ret = (int)fread(str->base + str->count, (size_t)1,
                                     (size_t)SECUREC_BOM_HEADER_SIZE, str->pf);
                if (ret > 0 && ret <= SECUREC_BUFFERED_BLOK_SIZE) {
                    str->count += ret;
                }
            }
        }

#else
        if (str->count > 2 &&
            (unsigned char)(str->base[0]) == SECUREC_UTF8_BOM_HEADER_1ST &&
            (unsigned char)(str->base[1]) == SECUREC_UTF8_BOM_HEADER_2ND &&
            (unsigned char)(str->base[2]) == SECUREC_UTF8_BOM_HEADER_3RD) {
            /* it's BOM header,  little endian */
            str->count -= SECUREC_UTF8_BOM_HEADER_SIZE;
            str->cur += SECUREC_UTF8_BOM_HEADER_SIZE;
        }
#endif
    }
    /* just return no EOF */
    return 0;
}
#endif

#ifdef SECUREC_FOR_WCHAR
/*
 *  Get char  for wchar version
 */
static SecInt SecGetCharW(SecFileStream *str)
#else
/*
 *  Get char  for wchar version
 */
static SecInt SecGetChar(SecFileStream *str)
#endif
{
    SecInt ch = 0;

    do {
#if SECUREC_ENABLE_SCANF_FILE

        if ((str->flag & SECUREC_FROM_STDIN_FLAG) > 0) {
            ch = SecGetCharFromStdin(str);
            break;
        } else if ((str->flag & SECUREC_FILE_STREAM_FLAG) > 0 && str->count == 0) {
            ch = SecGetCharFromFile(str);
            if (ch == SECUREC_EOF) {
                break;
            }
        }
#endif /* SECUREC_ENABLE_SCANF_FILE */

        if ((str->flag & SECUREC_MEM_STR_FLAG) > 0 || (str->flag & SECUREC_LOAD_FILE_TO_MEM_FLAG) > 0) {
            /* according  wchar_t has two bytes */
            ch = (SecInt)((str->count -= (int)sizeof(SecChar)) >= 0 ? \
                          (SecInt)(SECUREC_CHAR_MASK & *((const SecChar *)(const void *)str->cur)) : SECUREC_EOF);
            str->cur += sizeof(SecChar);
        }
        /* use break in do-while to skip some code */
    } SECUREC_WHILE_ZERO;

    if (ch != SECUREC_EOF && (str->flag & SECUREC_FILE_STREAM_FLAG) > 0 && str->base) {
        str->fileRealRead += (int)sizeof(SecChar);
    }
    return ch;

}

/*
 *  Unget Public realizatio char  for wchar and char version
 */
static void SecUnGetCharImpl(SecInt chr, SecFileStream *str)
{
    if ((str->flag & SECUREC_FROM_STDIN_FLAG) > 0) {
#if SECUREC_ENABLE_SCANF_FILE
#if defined(SECUREC_NO_STD_UNGETC)
        str->lastChar = (unsigned int)chr;
        str->fUnget = 1;
#else
        (void)SECUREC_UN_GETC(chr, str->pf);
#endif
#else
        (void)chr; /* to clear e438 last value assigned not used , the compiler will optimize this code */
#endif
    } else if ((str->flag & SECUREC_MEM_STR_FLAG) || (str->flag & SECUREC_LOAD_FILE_TO_MEM_FLAG) > 0) {
        if (str->cur > str->base) {
            str->cur -= sizeof(SecChar);
            str->count += (int)sizeof(SecChar);
        }
    }

    if ((str->flag & SECUREC_FILE_STREAM_FLAG) > 0 && str->base) {
        /* LSD fix, change from -- str->fileRealRead to str->fileRealRead -= sizeof(SecChar). 2014.2.21 */
        str->fileRealRead -= (int)sizeof(SecChar);
    }
}

#ifdef SECUREC_FOR_WCHAR
/*
 *  Unget char  for wchar version
 */
static void SecUnGetCharW(SecInt chr, SecFileStream *str)
#else
/*
 *  Unget char  for char version
 */
static void SecUnGetChar(SecInt chr, SecFileStream *str)
#endif
{
    if (chr != SECUREC_EOF) {
        SecUnGetCharImpl(chr, str);
    }
}

/*
 *  Skip space char by isspace
 */
static SecInt SecSkipSpaceChar(int *counter, SecFileStream *fileptr)
{
    SecInt ch;

    do {
        ++(*counter);
#ifdef SECUREC_FOR_WCHAR
        ch = SecGetCharW(fileptr);
#else
        ch = SecGetChar(fileptr);
#endif
        if (ch == SECUREC_EOF) {
            break;
        }
    }
#ifdef SECUREC_FOR_WCHAR
    while (iswspace((wint_t) ch));
#else
    while (isspace((SecUnsignedChar)ch));
#endif
    return ch;
}

#endif /* __INPUT_INL__5D13A042_DC3F_4ED9_A8D1_882811274C27 */

