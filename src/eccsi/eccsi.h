/******************************************************************************/
/* ECCSI (Eliptic Curve based Certificateless Signatures for Identity-Based   */
/* Encryption).                                                               */
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
 * @file eccsi.h
 * @brief ECCSI (RFC 6507).
 ******************************************************************************/
#ifndef __ES_ECCSI__
#define __ES_ECCSI__

#ifdef __cplusplus
extern "C" {
#endif
    
#include "mikeySakkeParameters.h"
#include "communityParameters.h"
#include "userParameters.h"

/*******************************************************************************
 * Create an ECCSI signature for the specified message.
 ******************************************************************************/
uint8_t eccsi_sign(
    const uint8_t  *message,
    const size_t    message_len,
    const uint8_t  *user_id,
    const size_t    user_id_len,
    const uint8_t  *community,
    const uint8_t  *j_random,
    const size_t    j_random_len,
    uint8_t       **signature,
    size_t         *signature_len);

/*******************************************************************************
 * Verifies an ECCSI signature following the Actions described in section 5.2.2
 * of RFC 6507.
 ******************************************************************************/
uint8_t eccsi_verify(
    const uint8_t  *message,
    const size_t    message_len,
    const uint8_t  *signature,
    const size_t    signature_len,
    const uint8_t  *userId,
    const size_t    userIdLength,
    const uint8_t  *community);

/*******************************************************************************
 * Validate a received (from KMS) SSK (RFC 6507 Section 5.1.2)
 ******************************************************************************/
uint8_t eccsi_validateSSK(
    const uint8_t  *user_id,
    const size_t    user_id_len,
    const uint8_t  *community,
    const uint8_t  *SSK,
    const size_t    SSK_len,
    const uint8_t  *KPAK,
    const size_t    KPAK_len,
    const uint8_t  *PVT,
    const size_t    PVT_len,
    uint8_t       **hash,
    size_t         *hash_len);

/*******************************************************************************
 * Compute HS = hash( G || KPAK || ID || PVT )
 * 
 * Used internally for client side. i.e. if you're a developer you don't need 
 * this for client development, you only need the 'sign', 'verify' and 
 * 'validate' functions above. 
 *
 * It is only declared here for use by the (demo) KMS code (a separate project)
 * when that links to this library. 
 ******************************************************************************/
uint8_t computeHS(
    const uint8_t  *community_G,    const size_t community_G_len,
    const uint8_t  *community_KPAK, const size_t community_KPAK_len,
    const uint8_t  *user_id,        const size_t user_id_len,
    const uint8_t  *user_PVT,       const size_t user_PVT_len,
    uint8_t       **hash_result);

#ifdef __cplusplus
}
#endif
#endif /* __ES_ECCSI__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
