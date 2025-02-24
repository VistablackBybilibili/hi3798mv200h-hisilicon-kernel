/*******************************************************************************
 * Copyright @ Huawei Technologies Co., Ltd. 2014-2018. All rights reserved.
 * Description: strtok_s  function
 * Author: lishunda
 * Create: 2014-02-25
 ********************************************************************************
 */

#include "securec.h"

/*
 * Find beginning of token (skip over leading delimiters).Note that
 * there is no token if this loop sets string to point to the terminal null.
 */
static char *SecFindBegin(char *strToken, const char *strDelimit)
{
    char *token = strToken;
    while (*token != 0) {
        const char *ctl = strDelimit;
        while (*ctl != 0 && *ctl != *token) {
            ++ctl;
        }

        if (*ctl == 0) {        /* don't find any delimiter in string header, break the loop */
            break;
        }
        ++token;
    }
    return token;
}

/*
 * Find rest of token
 */
static char *SecFindRest(char *strToken, const char *strDelimit)
{

    /* Find the rest of the token. If it is not the end of the string,
     * put a null there.
     */
    char *token = strToken;
    while (*token != 0) {
        const char *ctl = strDelimit;
        while (*ctl != 0 && *ctl != *token) {
            ++ctl;
        }
        if (*ctl != 0) {        /* find a delimiter */
            *token++ = 0;       /* set string termintor */
            break;
        }
        ++token;
    }
    return token;
}

/*
 * Find the final position pointer
 */
static char *SecUpdateToken(char *strToken, const char *strDelimit, char **context)
{
    /* point to updated position */
    char *token = SecFindRest(strToken, strDelimit);

    /* record string position for next search in the context */
    *context = token;

    /* Determine if a token has been found. */
    if (token == strToken) {
        return NULL;
    }
    return strToken;
}

/*******************************************************************************
 * <FUNCTION DESCRIPTION>
 *    The  strtok_s  function parses a string into a sequence of tokens,
 *    On the first call to strtok_s the string to be parsed should be specified in strToken.
 *    In each subsequent call that should parse the same string, strToken should be NULL
 *
 * <INPUT PARAMETERS>
 *    strToken            String containing token or tokens.
 *    strDelimit          Set of delimiter characters.
 *    context             Used to store position information between calls
 *                             to strtok_s
 *
 * <OUTPUT PARAMETERS>
 *   context               is updated
 * <RETURN VALUE>
 *    Returns a pointer to the next token found in strToken.
 *    They return NULL when no more tokens are found.
 *    Each call modifies strToken by substituting a NULL character for the first
 *    delimiter that occurs after the returned token.
 *
 *    return value        condition
 *    NULL                context is NULL, strDelimit is NULL, strToken is NULL
 *                        and  (*context) is  NULL, or no token is found.
 *******************************************************************************
 */
char *strtok_s(char *strToken, const char *strDelimit, char **context)
{
    char *orgToken = strToken;
    /* validate delimiter and string context */
    if (context == NULL || strDelimit == NULL) {
        return NULL;
    }

    /* valid input string and string pointer from where to search */
    if (orgToken == NULL && (*context) == NULL) {
        return NULL;
    }

    /* If string is null, continue searching from previous string position stored in context */
    if (orgToken == NULL) {
        orgToken = *context;
    }

    orgToken = SecFindBegin(orgToken, strDelimit);

    return SecUpdateToken(orgToken, strDelimit, context);
}

