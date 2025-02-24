/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description:
 *             by defining data type for ANSI string and including "input.inl",
 *             this file generates real underlying function used by scanf family
 *             API.
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */

#include "secinput.h"

#ifdef SECUREC_FOR_WCHAR
#undef SECUREC_FOR_WCHAR
#endif

typedef char SecChar;
typedef unsigned char SecUnsignedChar;
typedef int SecInt;
typedef unsigned int SecUnsignedInt;

#include "input.inl"


