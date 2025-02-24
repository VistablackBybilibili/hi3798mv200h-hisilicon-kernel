/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description:
 *             by defining data type for UNICODE string and including "input.inl",
 *             this file generates real underlying function used by scanf family
 *             API.
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */

#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#ifdef __STDC_WANT_SECURE_LIB__
#undef __STDC_WANT_SECURE_LIB__
#endif
#ifdef _CRTIMP_ALTERNATIVE
#undef _CRTIMP_ALTERNATIVE
#endif
/* The order of adjustment is to eliminate alarm of Duplicate Block */
#define __STDC_WANT_SECURE_LIB__ 0
#define _CRTIMP_ALTERNATIVE     /* comment microsoft *_s function */
#endif

/* if some platforms don't have wchar.h, dont't include it */
#if !(defined(SECUREC_VXWORKS_PLATFORM))
/* This header file is placed below secinput.h, which will cause tool alarm,
 * but  If there is no macro above, it will cause compiling alarm
 */
#include <wchar.h>
#endif
#include "secinput.h"

#ifndef SECUREC_FOR_WCHAR
#define SECUREC_FOR_WCHAR
#endif

#ifndef WEOF
#define WEOF ((wchar_t)(-1))
#endif

#if defined(SECUREC_VXWORKS_PLATFORM) && !defined(__WINT_TYPE__)
typedef wchar_t wint_t;
#endif

typedef wint_t SecInt;
typedef wint_t SecUnsignedInt;
typedef wchar_t SecChar;
typedef wchar_t SecUnsignedChar;

#include "input.inl"

