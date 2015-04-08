/******************************************************************************/
/* Logging.                                                                   */
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
 * @file log.h
 * @brief Logging. 
 ******************************************************************************/
#ifndef __ES_LOG__
#define __ES_LOG__

#ifdef __cplusplus
extern "C" {
#endif

#include "utils.h"

#define ES_MAX_LOG_LINE 1024 /*!< Maximum log output line length. */

#define ES_OUTPUT_DEBUG /*!< Comment this line out to disable DEBUG output at 
                         *   compilation. 
                         */

/***************************************************************************//**
 * Log type identifiers.
 ******************************************************************************/
enum logType_e {
   ES_LOGGING_ERROR = 1,
   ES_LOGGING_LOG   = 2,
   ES_LOGGING_INFO  = 3,
   ES_LOGGING_DEBUG = 4
}; 

/***************************************************************************//**
 * Output ERROR message.
 *
 * @param[in] a_format The output format.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_ERROR(a_format, vargs...) { \
    char outBuff_a[ES_MAX_LOG_LINE]; \
    snprintf(outBuff_a, sizeof(outBuff_a), a_format, ## vargs); \
    fprintf(stdout, "ES ERROR: %s\n", outBuff_a); \
    }

/***************************************************************************//**
 * Output LOG message.
 *
 * @param[in] a_format The output format.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_LOG(a_format, vargs...) { \
    char outBuff_a[ES_MAX_LOG_LINE]; \
    snprintf(outBuff_a, sizeof(outBuff_a), a_format, ## vargs); \
    fprintf(stdout, "ES LOG: %s\n", outBuff_a); \
    }

/***************************************************************************//**
 * Output INFO message.
 *
 * @param[in] a_format The output format.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_INFO(a_format, vargs...) { \
    char outBuff_a[ES_MAX_LOG_LINE]; \
    snprintf(outBuff_a, sizeof(outBuff_a), a_format, ## vargs); \
    fprintf(stdout, "ES INFO: %s\n", outBuff_a); \
    }

/* Only allow debug messages when DEBUG flag is set */
#ifdef ES_OUTPUT_DEBUG
/***************************************************************************//**
 * Output DEBUG message.
 *
 * @param[in] a_format The output format.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_DEBUG(a_format, vargs...) { \
    char outBuff_a[ES_MAX_LOG_LINE]; \
    snprintf(outBuff_a, sizeof(outBuff_a), a_format, ## vargs); \
    fprintf(stdout, "ES DEBUG: %s\n", outBuff_a); \
    }
#else
#define ES_DEBUG(section, vargs...)  {}
#endif

/***************************************************************************//**
 * Output HASH as a DEBUG message.
 *
 * @param[in] section  The code section the call to output came from.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_DEBUG_DISPLAY_HASH(section, vargs...) { \
    utils_displayHash(ES_LOGGING_DEBUG, section, ## vargs); \
    }

/***************************************************************************//**
 * Output BIGNUM as a DEBUG message.
 *
 * @param[in] section  The code section the call to output came from.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_DEBUG_DISPLAY_BN(section, vargs...) { \
    utils_BNdump(ES_LOGGING_DEBUG, section, ## vargs); \
    }

/***************************************************************************//**
 * Output Affine Coordinates as a DEBUG message.
 *
 * @param[in] section  The code section the call to output came from.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_DEBUG_DISPLAY_AFFINE_COORDS(section, vargs...) { \
    utils_displayAffineCoordinates(ES_LOGGING_DEBUG, section, ## vargs); \
    }

/***************************************************************************//**
 * Output Octet String in formatted fashion as a DEBUG message.
 *
 * @param[in] section  The code section the call to output came from.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(section, vargs...) { \
    utils_printFormattedOctetString(ES_LOGGING_DEBUG, section,  ## vargs); \
    }

/***************************************************************************//**
 * Output Octet String in formatted fashion as a INFO message.
 *
 * @param[in] section  The code section the call to output came from.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_INFO_PRINT_FORMATTED_OCTET_STRING(section, vargs...) { \
    utils_printFormattedOctetString(ES_LOGGING_INFO, section,  ## vargs); \
    }

/***************************************************************************//**
 * Output User-ID as a DEBUG message.
 *
 * @param[in] section  The code section the call to output came from.
 * @param[in] vargs    A list of arguments to output.
 ******************************************************************************/
#define ES_DEBUG_PRINT_ID(section, vargs...) { \
    utils_printUserId(ES_LOGGING_DEBUG, section,  ## vargs); \
    }

#ifdef __cplusplus
}
#endif
#endif /* __ES_LOG__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
