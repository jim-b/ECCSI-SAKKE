/******************************************************************************/
/* SAKKE  - Described in RFC6508                                              */
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
 * @file sakke.h
 * @brief Provides the functionality in support of RFC 6508, SAKKE.
 ******************************************************************************/
#ifndef __ES_SAKKE__
#define __ES_SAKKE__

#ifdef __cplusplus
extern "C" {
#endif
    
#include <stdlib.h>
#include <openssl/ec.h>   /* for ECC  */
#include <openssl/sha.h>  /* for hash */
#include <openssl/bn.h>   /* for hash */

/*******************************************************************************
 * Create SAKKE encapsulated data. This includes SSV (Shared Secret Value).
 * Described in RFC6508 Section 6.2.1.
 ******************************************************************************/
uint8_t sakke_generateSakkeEncapsulatedData(
    uint8_t       **encapsulated_data,
    size_t         *encapsulated_data_len,
    const uint8_t  *user_id,
    const size_t    user_id_len,
    const uint8_t  *community,
    const uint8_t  *ssv,
    const size_t    ssv_len);

/*******************************************************************************
 * Extract SSV (Shared Secret Value) from SED( Sakke Encapsulated Data).
 * Described in Section 6.2.2 of RFC 6508.
 ******************************************************************************/
uint8_t sakke_extractSharedSecret(
    const uint8_t  *SED,
    const size_t    SEDLength,
    const uint8_t  *userId,
    const size_t    userIdLength,
    const uint8_t  *community,
    uint8_t        **ssv,
    size_t          *ssvLength);

/*******************************************************************************
 * Validates the RSK provided by the KMS for use by this user.
 * See Section 6.1.2 (para 2) of RFC6508.
 ******************************************************************************/
uint8_t sakke_validateRSK(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    const uint8_t *RSK,
    const size_t   RSK_len);

#ifdef __cplusplus
}
#endif
#endif /* __ES_SAKKE__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
