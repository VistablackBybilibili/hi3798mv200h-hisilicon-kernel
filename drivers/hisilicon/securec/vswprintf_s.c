/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description: vswprintf_s  function
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */

#include "secureprintoutput.h"

/*
 * Wide character formatted output implementation
 */
static int SecVswprintfImpl(wchar_t *string, size_t sizeInWchar, const wchar_t *format, va_list argList)
{
    SecPrintfStream str;
    int retVal; /* If initialization causes  e838 */

    str.cur = (char *)string;
    /* this count include \0 character, Must be greater than zero */
    str.count = (int)(sizeInWchar * sizeof(wchar_t));

    retVal = SecOutputSW(&str, format, argList);
    if ((retVal >= 0) && SecPutWcharStrEndingZero(&str, (int)sizeof(wchar_t))) {
        return (retVal);
    } else if (str.count < 0) {
        /* the buffer was too small; we return truncation */
        string[sizeInWchar - 1] = L'\0';
        return SECUREC_PRINTF_TRUNCATE;
    }
    string[0] = L'\0';
    return -1;
}

/*******************************************************************************
 * <FUNCTION DESCRIPTION>
 *    The  vswprintf_s  function  is  the  wide-character  equivalent  of the vsprintf_s function
 *
 * <INPUT PARAMETERS>
 *    strDest                  Storage location for the output.
 *    destMax                Size of strDest
 *    format                  Format specification.
 *    argList                   pointer to list of arguments
 *
 * <OUTPUT PARAMETERS>
 *    strDest                 is updated
 *
 * <RETURN VALUE>
 *    return  the number of wide characters stored in strDest, not  counting the terminating null wide character.
 *    return -1  if an error occurred.
 *
 * If there is a runtime-constraint violation, strDest[0] will be set to the '\0' when strDest and destMax valid
 *******************************************************************************
 */
int vswprintf_s(wchar_t *strDest, size_t destMax, const wchar_t *format, va_list argList)
{
    int retVal;               /* If initialization causes  e838 */

    if (format == NULL || strDest == NULL || destMax == 0 || destMax > (SECUREC_WCHAR_STRING_MAX_LEN)) {
        if (strDest != NULL && destMax > 0) {
            strDest[0] = '\0';
        }
        SECUREC_ERROR_INVALID_PARAMTER("vswprintf_s");
        return -1;
    }

    retVal = SecVswprintfImpl(strDest, destMax, format, argList);

    if (retVal < 0) {
        strDest[0] = '\0';
        if (retVal == SECUREC_PRINTF_TRUNCATE) {
            /* Buffer too small */
            SECUREC_ERROR_INVALID_RANGE("vswprintf_s");
        }
        SECUREC_ERROR_INVALID_PARAMTER("vswprintf_s");
        return -1;
    }

    return retVal;
}


