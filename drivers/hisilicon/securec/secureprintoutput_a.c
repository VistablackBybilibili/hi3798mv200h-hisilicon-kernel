/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description:
 *             by defining corresponding macro for ANSI string and including
 *             "output.inl", this file generates real underlying function used by
 *             printf family API.
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */
#include "secureprintoutput.h"

#ifdef SECUREC_FOR_WCHAR
#undef SECUREC_FOR_WCHAR
#endif

typedef char SecChar;
#define SECUREC_CHAR(x) x

#define SECUREC_WRITE_MULTI_CHAR  SecWriteMultiChar
#define SECUREC_WRITE_STRING      SecWriteString

#include "output.inl"

