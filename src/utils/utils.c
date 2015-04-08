/******************************************************************************/
/* General utility functions.                                                 */
/*                                                                            */
/* Copyright 2015 Jim Buller                                                  */
/*                                                                            */
/* Licensed under the Apache License, Version 2.0 (the "License");            */
/* you may not use this file except in compliance with the License.           */
/* You may obtain a copy of the License at                                    */
/*                                                                            */
/*     http://www.apache.org/licenses/LICENSE-2.0                             */
/*                                                                            */
/* Unless required by applicable law or agreed to in writing, software        */
/* distributed under the License is distributed on an "AS IS" BASIS,          */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   */
/* See the License for the specific language governing permissions and        */
/* limitations under the License.                                             */
/******************************************************************************/

/***************************************************************************//**
 * @file utils.c
 * @brief General utility functions. 
 *
 * General utility functions used throughout, largely output related.
 ******************************************************************************/
#include "utils.h"
#include "global.h"

#define MAX_OUT_LINE_LEN 512 /*!< Maximum output line length.      */
#define HEX_CHAR_LEN       3 /*!< A single (null terminated) char. */

/******************************************************************************/
/* Forward declarations.                                                      */
/******************************************************************************/
static int8_t utils_xtod(char c);

/******************************************************************************/
/* Global functions.                                                          */
/******************************************************************************/

/***************************************************************************//**
 * Returns current software version.
 *
 * @return The current Software Version.
 ******************************************************************************/
char *softwareVersion(void)
{
    return SOFTWARE_VERSION;
} /* softwareVersion */

/***************************************************************************//**
 * Outputs a hash value to the specified log-type.
 *
 * @param[in]  log_type  One of ERROR, LOG, INFO, DEBUG.
 * @param[in]  section  The code section that called this, to identify where in 
 *                      the code this log state ment has been called from.
 * @param[in]  text     Some preceeding text for the message.
 * @param[in]  pad      Pad for the output line of the hash.
 * @param[in]  hash     The hash we want to output. 
 * @param[in]  hash_len The length of the hash.
 ******************************************************************************/
void utils_displayHash(
    const uint8_t   log_type, 
    const char     *section, 
    const char     *text, 
    const uint8_t   pad, 
    const char     *hash, 
    const uint16_t  hash_len) 
{
    uint16_t        c_count = 0;
    uint16_t        p_count = 0;

    char line[MAX_OUT_LINE_LEN];
    char hex[HEX_CHAR_LEN];

    memset(line, 0, sizeof(line));
    memset(hex,  0, sizeof(hex));

    if (text != NULL) {
        switch (log_type) {
            case ES_LOGGING_ERROR : {
                ES_ERROR("%s%*s", section, pad, text);
                break;
            }
            case ES_LOGGING_LOG   : {
                ES_LOG("%s%*s",   section, pad, text);
                break;
            }
            case ES_LOGGING_INFO  : {
                ES_INFO("%s%*s",  section, pad, text);
                break;
            }
            case ES_LOGGING_DEBUG : {
                ES_DEBUG("%s%*s", section, pad, text);
                break;
            }
            default    : {
                ES_ERROR("%s:%s:%d - Attempt to display Hash, but no valid log type specified!",
                         __FILE__, __FUNCTION__, __LINE__);
                return;
            }
        }
    }

    strcpy(line, section);
    for (p_count = 0; p_count < pad; p_count++) { 
        strcat(line, " ");
    }

    for (c_count=0; c_count <= hash_len; c_count++) {
        if (((c_count != 0) && ((c_count%16)==0)) || (c_count == hash_len)) { 
            switch (log_type) {
                case ES_LOGGING_ERROR : {
                    ES_ERROR("%s", line);
                    break;
                }
                case ES_LOGGING_LOG   : {
                    ES_LOG("%s",   line);
                    break;
                }
                case ES_LOGGING_INFO  : {
                    ES_INFO("%s",  line);
                    break;
                }
                case ES_LOGGING_DEBUG : {
                    ES_DEBUG("%s", line);
                    break;
                }
                default    : {
                    ES_ERROR("%s:%s:%d - Attempt to display Hash, but no valid log type specified!",
                         __FILE__, __FUNCTION__, __LINE__);
                }
            }
            memset(line, 0, sizeof(line));
            strcpy(line, section);
            for (p_count = 0; p_count < pad; p_count++) { strcat(line, " "); }
        }
        else {
            if ((c_count != 0) && ((c_count%4)==0)) {
                strcat(line, " ");
            }
        }
        if (c_count < hash_len) {
            sprintf(hex, "%X%X", ((hash[c_count] & 0xf0) >> 4), hash[c_count] & 0x0f);
            strcat(line, hex);
        }
    }

    memset(line, 0, sizeof(line));
    memset(hex,  0, sizeof(hex));
} /* utils_displayHash */

/***************************************************************************//**
 * Outputs an OpenSSL BN value to the specified log-type.
 *
 * @param[in]  log_type  One of ERROR, LOG, INFO, DEBUG.
 * @param[in]  section  The code section that called this, to identify where in 
 *                      the code this log state ment has been called from.
 * @param[in]  text     Some preceeding text for the message.
 * @param[in]  pad      Pad for the output line of the hash.
 * @param[in]  val      The Bignum value to output.
 ******************************************************************************/
void utils_BNdump(
    const uint8_t  log_type, 
    const char    *section,
    const char    *text,
    const uint8_t  pad,
    const BIGNUM  *val) 
{
    char     *bn_as_hex_str = NULL;
    uint16_t  len           = 0;
    uint16_t  c_count       = 0;
    uint16_t  p_count       = 0;
    char      line[MAX_OUT_LINE_LEN];
    char      hex[HEX_CHAR_LEN-1];
   
    if (text != NULL) {
        switch (log_type) {
            case ES_LOGGING_ERROR : {
                ES_ERROR("%s%*s", section, pad, text); 
                break;
            }
            case ES_LOGGING_LOG   : {
                ES_LOG("%s%*s",   section, pad, text); 
                break;
            }
            case ES_LOGGING_INFO  : {
                ES_INFO("%s%*s",  section, pad, text); 
                break;
            }
            case ES_LOGGING_DEBUG : {
                ES_DEBUG("%s%*s", section, pad, text); 
                break;
            }
            default    : {
                ES_ERROR("%s", "Attempted display of BN, but no valid log type specified");
                if (bn_as_hex_str != NULL) { 
                    free(bn_as_hex_str);
                }
                return;
            }
        }
    }
    if (val == NULL) {
        strcpy(line, section);
        strcat(line, "No BIGNUM supplied to BN dump.");
        switch (log_type) {
            case ES_LOGGING_ERROR : {
                ES_ERROR("%s", line); 
                break;
            }
            case ES_LOGGING_LOG   : {
                ES_LOG("%s",   line); 
                break;
            }
            case ES_LOGGING_INFO  : {
                ES_INFO("%s",  line); 
                break;
            }
            case ES_LOGGING_DEBUG : {
                ES_DEBUG("%s", line);
                break;
            }
            default    : {
                ES_ERROR("%s", "Attempt display of BN, but no valid log type specified");
            }
        }
    }
    else {
        bn_as_hex_str = BN_bn2hex(val);
        len = strlen(bn_as_hex_str);
        strcpy(line, section);
        for (p_count = 0; p_count < pad; p_count++) { strcat(line, " "); }
        for (c_count = 0; c_count <= len; c_count++) {
            if (((c_count != 0) && ((c_count%32)==0)) || (c_count == len)) {
                switch (log_type) {
                    case ES_LOGGING_ERROR : {
                        ES_ERROR("%s", line); 
                        break;
                    }
                    case ES_LOGGING_LOG   : {
                        ES_LOG("%s",   line); 
                        break;
                    }
                    case ES_LOGGING_INFO  : {
                        ES_INFO("%s",  line); 
                        break;
                    }
                    case ES_LOGGING_DEBUG : {
                        ES_DEBUG("%s", line); 
                        break;
                    }
                    default    : {
                        ES_ERROR("%s", "Attempt display display BIGNUM, but no log valid log type specified");
                    }
                }
                memset(line, 0, sizeof(line)); 
                strcpy(line, section);
                for (p_count = 0; p_count < pad; p_count++) { strcat(line, " "); }
            }
            else {
                if ((c_count != 0) && ((c_count%8)==0)) {
                    strcat(line, " ");
                }
            }
            sprintf(hex, "%c", bn_as_hex_str[c_count]);
            strcat(line, hex);
        }
    }
    if (bn_as_hex_str != NULL) {
        free(bn_as_hex_str);
    }
    memset(line, 0, sizeof(line)); 
    memset(hex,  0, sizeof(hex)); 
} /* utils_BNdump */

/***************************************************************************//**
 * Outputs the coordinates of the specified point on the specified curve to the 
 * specified log-type.
 *
 * @param[in]  log_type  One of ERROR, LOG, INFO, DEBUG.
 * @param[in]  section  The code section that called this, to identify where in 
 *                      the code this log state ment has been called from.
 * @param[in]  text     Some preceeding text for the message.
 * @param[in]  pad      Pad for the output line of the hash.
 * @param[in]  group    The Curve.
 * @param[in]  point    The Point.
 ******************************************************************************/
void utils_displayAffineCoordinates(
    const uint8_t   log_type,
    const char     *section, 
    const char     *text, 
    const uint8_t   pad, 
    const EC_GROUP *group, 
    const EC_POINT *point) 
{
    /* Create BN context for faster calculations. */
    BN_CTX *bn_ctx = BN_CTX_new();

    BIGNUM *x      = BN_new();
    BIGNUM *y      = BN_new();

    EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bn_ctx);

    switch (log_type) {
         case ES_LOGGING_ERROR : {
             if (text != NULL) ES_ERROR("%s%s", section, text);
             utils_BNdump(log_type, section, "x:", pad, x);
             utils_BNdump(log_type, section, "y:", pad, y);
             break;
         }
         case ES_LOGGING_LOG   : {
             if (text != NULL) ES_LOG("%s%s", section, text);
             utils_BNdump(log_type, section, "x:", pad, x);
             utils_BNdump(log_type, section, "y:", pad, y);
             break;
         }
         case ES_LOGGING_INFO  : {
             if (text != NULL) ES_INFO("%s%s", section, text);
             utils_BNdump(log_type, section, "x:", pad, x);
             utils_BNdump(log_type, section, "y:", pad, y);
             break;
         }
         case ES_LOGGING_DEBUG : {
             if (text != NULL) ES_DEBUG("%s%s", section, text);
             utils_BNdump(log_type, section, "x:", pad, x);
             utils_BNdump(log_type, section, "y:", pad, y);
             break;
         }
         default    : {
             ES_ERROR("%s", "Attempt display Affine Co-ordinates, but no valid log type specified");
         }
    }

    BN_clear_free(x);
    BN_clear_free(y);

    BN_CTX_free(bn_ctx);

} /* utils_displayAffineCoordinates */

/***************************************************************************//**
 * Outputs an octet string to the specified log-type. The octet string is output
 * in a 'pretty' fashion i.e. 4 byte space and 16 byte line separators.
 *
 * @param[in]  log_type One of ERROR, LOG, INFO, DEBUG.
 * @param[in]  section  The code section that called this, to identify where in 
 *                      the code this log state ment has been called from.
 * @param[in]  text     Some preceeding text for the message.
 * @param[in]  pad      Pad for the output line of the hash.
 * @param[in]  oStr     The octet string.
 * @param[in]  oStr_len The octet string length.
 ******************************************************************************/
void utils_printFormattedOctetString(
    const uint8_t        log_type,
    const char          *section,
    const char          *text,
    const uint8_t        pad,
    const uint8_t       *oStr,
    const size_t         oStr_len) {

    unsigned int  loop = 0;
    char          out_line[MAX_OUT_LINE_LEN];
    memset(out_line, 0, MAX_OUT_LINE_LEN);

    if (oStr == NULL) {
        return;
    }

    strcpy(out_line, section);
    if (text != NULL) {
        switch (log_type) {
            case ES_LOGGING_ERROR : {
                ES_ERROR("%s%*s", section, pad, text); break;
            }
            case ES_LOGGING_LOG   : {
                ES_LOG("%s%*s",   section, pad, text); break;
            }
            case ES_LOGGING_INFO  : {
                ES_INFO("%s%*s",  section, pad, text); break;
            }
            case ES_LOGGING_DEBUG : {
                ES_DEBUG("%s%*s", section, pad, text); break;
            }
            default    : {
                ES_ERROR("%s",    "No log_type specified");
                return;
            }
        }
    }

    memset(out_line, 0, MAX_OUT_LINE_LEN);
    strcpy(out_line, section);
    sprintf(&out_line[strlen(out_line)], "%*s", pad, " ");
    for (loop=0; loop < oStr_len; loop++) {
        if ((loop%16)==0) {
            if ((loop/16) > 0) { /* Not first empty line */
                sprintf(&out_line[strlen(out_line)], "%*s", pad, "");
                if (out_line[0] != 0x0) {
                    switch (log_type) {
                        case ES_LOGGING_ERROR : {
                            ES_ERROR("%s", out_line); break;
                        }
                        case ES_LOGGING_LOG   : {
                            ES_LOG("%s", out_line);   break;
                        }
                        case ES_LOGGING_INFO  : {
                            ES_INFO("%s", out_line);  break;
                        }
                        case ES_LOGGING_DEBUG : {
                            ES_DEBUG("%s", out_line); break;
                        }
                        default    : {
                            ES_ERROR("%s",    "No log_type specified");
                            return;
                        }
                    }
                }

                memset(out_line, 0, MAX_OUT_LINE_LEN);
                strcpy(out_line, section);
                sprintf(&out_line[strlen(out_line)], "%*s", pad, " ");
            }
        }
        else {
            if ((loop%4)==0) {
               sprintf(&out_line[strlen(out_line)], " ");
            }
        }

        sprintf(&out_line[strlen(out_line)], "%X%X", 
                (((oStr[loop])&0xf0)>>4), 
                (oStr[loop])&0x0f);

    }
    switch (log_type) {
        case ES_LOGGING_ERROR : {
            ES_ERROR("%s", out_line); break;
        }
        case ES_LOGGING_LOG   : {
            ES_LOG("%s", out_line);   break;
        }
        case ES_LOGGING_INFO  : {
            ES_INFO("%s", out_line);  break;
        }
        case ES_LOGGING_DEBUG : {
            ES_DEBUG("%s", out_line); break;
        }
        default    : {
            ES_ERROR("%s",    "No log_type specified");
            return;
        }
    }

    memset(out_line, 0, MAX_OUT_LINE_LEN);

} /* utils_printFormattedOctetString*/

/***************************************************************************//**
 * Convert a hex string e.g. where F0 would be two bytes 0x46, 0x30 to an octet 
 * string 0xF0. 
 *
 * @param[in]  xStr         The input hex string.
 * @param[in]  required_len The required octet string length, so it can be 
 *                          padded.
 * @param[in]  oStr         The output octet string.
 * @param[in]  oStr_len     The output octet string length.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short utils_convertHexStringToOctetString(
    const char    *xStr, 
    const size_t   required_len, /* For padding */
    uint8_t      **oStr, 
    size_t        *oStr_len) 
{
    uint8_t        ret_val = ES_FAILURE;
    uint16_t       charCount = 0;
    int16_t        loop      = 0;
    short          hoFlag    = 1;
    uint8_t        c         = 0;
    uint8_t        lo        = 0;

    /* Check parameters */
    if (xStr != NULL) {
        if (*oStr != NULL) {
            ES_ERROR("%s:%s:%d - Error passed reference for octet string is not null!",
                  __FILE__, __FUNCTION__, __LINE__);
        }
        else {
            /* Only interested in 0-9, A-F, a-f. no spaces, padding or anything
             * else.
             */ 
            for (loop=0, loop=0; loop < (strlen(xStr)); loop++) {
                if ((c = utils_xtod(xStr[loop])) != -1 ) { 
                    /* Not 0-9, a-f, A-F */
                    *oStr_len+=1;
                }
            }

            if (*oStr_len == 0) {
                /* Not necessaily an error case, there just might not be hex 
                 * characters in the string.
                 *
                 * oStr will be NULL.
                 */
                ret_val = ES_SUCCESS;
            }
            else {
                *oStr_len = required_len;
    
                if ((*oStr = calloc(1, required_len+1)) != NULL) {
                    charCount = 0;
                    lo        = 0;
                    hoFlag    = 0;
                    charCount = required_len;
                    for (loop = strlen(xStr)-1; loop >= 0; loop--) {
                        if ((c = utils_xtod(xStr[loop])) != -1 ) { 
                            /* Not 0-9, a-f, A-F */
                            if (hoFlag) {
                                (*oStr)[charCount]  = (c * 16)+lo;
                                hoFlag = 0;
                            }
                            else {
                                lo     = c;
                                hoFlag = 1;
                                charCount--;

                                /* If it the last digit and lo make sure
                                 * it's output.
                                 */
                                if (loop == 0) { 
                                    (*oStr)[charCount]  = c;
                                }
                            }
                        }
                    }
                    ret_val = ES_SUCCESS;
                }
                else {
                    ES_ERROR("%s:%s:%d - Error calloc failed!",
                              __FILE__, __FUNCTION__, __LINE__);
                }
            }
        }
    }
    return ret_val;
} /* user_convertHexStringToOctetString */

/***************************************************************************//**
 * Outputs an MS identifier that conforms to date|NULL|id|NULL as date.id
 *
 * Obviously, if you try and print the identifier without this, you'll only see 
 * the date part.
 *
 * @param[in]  log_type One of ERROR, LOG, INFO, DEBUG.
 * @param[in]  section  The code section that called this, to identify where in 
 *                      the code this log state ment has been called from.
 * @param[in]  text     Some preceeding text for the message.
 * @param[in]  pad      Pad for the output line of the hash.
 * @param[in]  id       The identifier .
 * @param[in]  id_len   The identifier length.
 ******************************************************************************/
void utils_printUserId(
    const uint8_t        log_type,
    const char          *section,
    const char          *text,
    const uint8_t        pad,
    const uint8_t       *id,
    const size_t         id_len) 
{
    unsigned int  loop = 0;
    char          out_line[MAX_OUT_LINE_LEN];

    memset(out_line, 0, MAX_OUT_LINE_LEN);

    if (id == NULL) {
        return;
    }

    strcpy(out_line, section);
    if (text != NULL) {
        switch (log_type) {
            case ES_LOGGING_ERROR : {
                ES_ERROR("%s%*s", section, pad, text);
                break;
            }
            case ES_LOGGING_LOG   : {
                ES_LOG("%s%*s",   section, pad, text);
                break;
            }
            case ES_LOGGING_INFO  : {
                ES_INFO("%s%*s",  section, pad, text);
                break;
            }
            case ES_LOGGING_DEBUG : {
                ES_DEBUG("%s%*s", section, pad, text);
                break;
            }
            default    : {
                ES_ERROR("%s",    "No log_type specified");
                return;
            }
        }
    }

    memset(out_line, 0, MAX_OUT_LINE_LEN);
    strcpy(out_line, section);
    sprintf(&out_line[strlen(out_line)], "%*s", pad, " ");
    for (loop=0; loop < id_len; loop++) {
        if (id[loop] == 0x0) {
            sprintf(&out_line[strlen(out_line)], ".");
        }
        else {
            sprintf(&out_line[strlen(out_line)], "%c", id[loop]);
        }
    }

    /* Output any remainder less than a complete line */
    if (out_line[0] != 0x0) {
        switch (log_type) {
            case ES_LOGGING_ERROR : {
                ES_ERROR("%s", out_line);
                break;
            }
            case ES_LOGGING_LOG   : {
                ES_LOG("%s", out_line);
                break;
            }
            case ES_LOGGING_INFO  : {
                ES_INFO("%s", out_line);
                break;
            }
            case ES_LOGGING_DEBUG : {
                ES_DEBUG("%s", out_line);
                break;
            }
            default    : {
                ES_ERROR("%s",    "No log_type specified");
                return;
            }
        }
    }

} /* utils_printUserId */

/******************************************************************************/
/* Internal functions not to be called externally.                            */
/******************************************************************************/

/***************************************************************************//**
 * Convert a hex digit to decimal.
 *
 * @param[in] c The character.
 *
 * @return A decimal 0..15 or -1 on failure.
 ******************************************************************************/
static int8_t utils_xtod(char c) {
    if ((c>='0') && (c<='9')) {
        return c-'0';
    }
    if ((c>='A') && (c<='F')) {
        return c-'A'+10;
    }
    if ((c>='a') && (c<='f')) {
        return c-'a'+10;
    }
    
    return c=-1;
} /* utils_xtod */

/******************************************************************************/
/*                                END OF FILE                                 */
/******************************************************************************/
