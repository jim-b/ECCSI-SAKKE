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
 * @file utils.h
 * @brief General utility functions. 
 *
 * General utility functions used throughout, largely output related.
 ******************************************************************************/
#ifndef __ES_UTILS__
#define __ES_UTILS__

#ifdef __cplusplus
extern "C" {
#endif
    
#include <stdint.h>
#include <string.h>
#include <openssl/bn.h> 
#include <openssl/ec.h> 

#include "log.h" 

/***************************************************************************//**
 * Returns current software version.
 ******************************************************************************/
char *softwareVersion(void);

/*******************************************************************************
 * Outputs a hash value to the specified log-type.
 ******************************************************************************/
void utils_displayHash(
    const uint8_t   log_type, 
    const char     *section, 
    const char     *text, 
    const uint8_t   pad, 
    const char     *hash, 
    const uint16_t  len);

/*******************************************************************************
 * Outputs an OpenSSL BN value to the specified log-type.
 ******************************************************************************/
void utils_BNdump(
    const uint8_t  log_type, 
    const char    *section, 
    const char    *text, 
    const uint8_t  pad, 
    const BIGNUM  *val);

/*******************************************************************************
 * Outputs the coordinates of the specified point on the specified curve to the 
 * specified log-type.
 ******************************************************************************/
void utils_displayAffineCoordinates(
    const uint8_t   log_type,
    const char     *section,
    const char     *text,
    const uint8_t   pad,
    const EC_GROUP *group,
    const EC_POINT *point);

/*******************************************************************************
 * Outputs an octet string to the specified log-type. The octet string is output
 * in a 'pretty' fashion i.e. 4 byte space and 16 byte line separators.
 ******************************************************************************/
void utils_printFormattedOctetString(
    const uint8_t  log_type,
    const char    *section,
    const char    *text,
    const uint8_t  pad,
    const uint8_t *oStr,
    const size_t   oStr_len);

/*******************************************************************************
 * Convert a hex string e.g. where F0 would be two bytes 0x46, 0x30 to an octet 
 * string 0xF0. 
 ******************************************************************************/
short utils_convertHexStringToOctetString(
    const char    *hexString,
    const size_t   requiredLength,
    uint8_t      **octetString,
    size_t        *octetStringLength);

/*******************************************************************************
 * Outputs an MS identifier that conforms to date|NULL|id|NULL as date.id
 ******************************************************************************/
void utils_printUserId(
    const uint8_t  log_type,
    const char    *section,
    const char    *text,
    const uint8_t  pad,
    const uint8_t *id,
    const size_t   id_len);

#ifdef __cplusplus
}
#endif
#endif /* __ES_UTILS__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
