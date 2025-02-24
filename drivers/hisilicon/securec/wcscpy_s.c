/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description: wcscpy_s  function
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */

#include "securecutil.h"

static errno_t SecDoWcscpy(wchar_t *strDest, size_t destMax, const wchar_t *strSrc)
{
    wchar_t *tmpDest = strDest;
    const wchar_t *tmpSrc = strSrc;
    size_t maxSize = destMax;
    SECUREC_IN_REGISTER const wchar_t *overlapGuard = NULL;

    if (tmpDest < tmpSrc) {
        overlapGuard = tmpSrc;
        while ((*(tmpDest++) = *(tmpSrc++)) != '\0' && --maxSize > 0) {
            if (tmpDest == overlapGuard) {
                strDest[0] = '\0';
                SECUREC_ERROR_BUFFER_OVERLAP("wcscpy_s");
                return EOVERLAP_AND_RESET;
            }
        }
    } else {
        overlapGuard = tmpDest;
        while ((*(tmpDest++) = *(tmpSrc++)) != '\0' && --maxSize > 0) {
            if (tmpSrc == overlapGuard) {
                strDest[0] = '\0';
                SECUREC_ERROR_BUFFER_OVERLAP("wcscpy_s");
                return EOVERLAP_AND_RESET;
            }
        }
    }

    if (maxSize == 0) {
        strDest[0] = '\0';
        SECUREC_ERROR_INVALID_RANGE("wcscpy_s");
        return ERANGE_AND_RESET;
    }
    return EOK;
}

/*******************************************************************************
 * <FUNCTION DESCRIPTION>
 *   The wcscpy_s function copies the wide string pointed to by strSrc
 *   (including theterminating null wide character) into the array pointed to by strDest

 * <INPUT PARAMETERS>
 *    strDest               Destination string buffer
 *    destMax               Size of the destination string buffer.
 *    strSrc                Null-terminated source string buffer.
 *
 * <OUTPUT PARAMETERS>      
 *    strDest               is updated.
 *                          
 * <RETURN VALUE>           
 *    EOK                   Success
 *    EINVAL                strDest is  NULL and destMax != 0 and destMax <= SECUREC_WCHAR_STRING_MAX_LEN
 *    EINVAL_AND_RESET      strDest != NULL and strSrc is NULLL and destMax != 0
 *                          and destMax <= SECUREC_WCHAR_STRING_MAX_LEN
 *    ERANGE                destMax > SECUREC_WCHAR_STRING_MAX_LEN or destMax is 0
 *    ERANGE_AND_RESET      destMax <= length of strSrc and strDest != strSrc
 *                          and strDest != NULL and strSrc != NULL and destMax != 0
 *                          and destMax <= SECUREC_WCHAR_STRING_MAX_LEN and not overlap
 *    EOVERLAP_AND_RESET    dest buffer and source buffer are overlapped and destMax != 0
 *                          and destMax <= SECUREC_WCHAR_STRING_MAX_LEN
 *                          and strDest != NULL and strSrc !=NULL and strDest != strSrc
 *
 *    If there is a runtime-constraint violation, strDest[0] will be set to the '\0' when strDest and destMax valid
 *******************************************************************************
 */
errno_t wcscpy_s(wchar_t *strDest, size_t destMax, const wchar_t *strSrc)
{
    if (destMax == 0 || destMax > SECUREC_WCHAR_STRING_MAX_LEN) {
        SECUREC_ERROR_INVALID_RANGE("wcscpy_s");
        return ERANGE;
    }
    if (strDest == NULL || strSrc == NULL) {
        SECUREC_ERROR_INVALID_PARAMTER("wcscpy_s");
        if (strDest != NULL) {
            strDest[0] = L'\0';
            return EINVAL_AND_RESET;
        }

        return EINVAL;
    }
    if (strDest == strSrc) {
        return EOK;
    }
    return SecDoWcscpy(strDest, destMax, strSrc);
}


