/******************************************************************************/
/* Community Parameters                                                       */
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
 * @file communityParameters.h
 * @brief Storage of Mikey Sakke Community data.
 ******************************************************************************/
#ifndef __ES_COMMUNITY_PARAMETERS_STORAGE__
#define __ES_COMMUNITY_PARAMETERS_STORAGE__

#ifdef __cplusplus
extern "C" {
#endif
    
#include <openssl/ec.h>  /* for ECC */

#include "utils.h"

/*******************************************************************************
 * Initialise Mikey-Sakke Community storage.
 ******************************************************************************/
short community_initStorage();

/*******************************************************************************
 * Delete non file storagei community data.
 ******************************************************************************/
void community_deleteStorage();

/*******************************************************************************
 * Returns the number of currently stored communities.
 ******************************************************************************/
uint8_t community_count();

/*******************************************************************************
 * Returns an unsorted CSV (Comma Separated Value) list of currently stored
 * community names.
 *
 * It is expected this function may be useful at the application level to
 * list supported communities.
 *
 * Callers of this function are responsible for freeing the storage.
 ******************************************************************************/
uint8_t *community_list();

/*******************************************************************************
 * Does the specified community exist?
 ******************************************************************************/
short community_exists(
    const uint8_t *community);

/*******************************************************************************
 * Stores a new community and associated Mikey Sakke data.
 ******************************************************************************/
uint8_t community_store(
    uint8_t  *version,           /* Optional */
    uint8_t  *cert_uri,          /* Optional */
    uint8_t  *kms_uri,           /* Mandatory AKA community. */
    uint8_t  *issuer,            /* Optional */
    uint8_t  *valid_from,        /* Optional */
    uint8_t  *valid_to,          /* Optional */
    short     revoked,           /* Optional */
    uint8_t  *user_id_format,    /* Optional RFC indicates this as optional. */
    uint8_t  *pub_enc_key,       /* Mandatory AKA 'Z'. */
    size_t    pub_enc_key_len,   /* Mandatory 'Z' Length/ */
    uint8_t  *pub_auth_key,      /* Mandatory AKA 'KPAK'. */
    size_t    pub_auth_key_len,  /* Mandatory 'KPAK' length. */
    uint8_t  *kms_domain_list);  /* Optional */

/*******************************************************************************
 * Remove the specified community.
 ******************************************************************************/
short community_remove(
    const uint8_t *community);

/*******************************************************************************
 * Remove all stored communities.
 ******************************************************************************/
short community_deleteAllCommunities();

/******************************************************************************/
/* GLOBAL PARAMETERS (HARD CODED in specs.)                                   */
/******************************************************************************/

/*******************************************************************************
 * Get the commnunity 'n' value. 'n' is a security parameter; the size of 
 * symetric key in bits to be exchanged by SAKKE.
 *
 * Defined RFC 6507 Section 4.1
 ******************************************************************************/
uint16_t community_get_n(void);

/*******************************************************************************
 * Get the commnunity 'N' value. 'N' is the number of octets used to represent
 * 'r' and 's' in signatures. Also the number of octets output by the hash 
 * function.
 *
 * Defined RFC 6507 Section 4.1
 ******************************************************************************/
uint16_t community_get_N(void);

/*******************************************************************************
 * Get the commnunity 'p' value. 'p' is a prime number of size 'n' bits. the 
 * finite field with 'p' elements is denoted F_p.
 *
 * Defined RFC 6507 Section 4.1
 ******************************************************************************/
BIGNUM *community_get_p(void);

/*******************************************************************************
 * Get the NIST P256 Curve. 
 ******************************************************************************/
EC_GROUP *community_get_NIST_P256_Curve(void);

/*******************************************************************************
 * Get the commnunity 'q' value. The prime 'q' is defined to be the order of G 
 * in E over F_p.
 *
 * Defined RFC 6507 Section 4.1
 ******************************************************************************/
BIGNUM *community_getq_bn(void);

/*******************************************************************************
 * Get the commnunity 'G' value. 'G' is a point on the elliptic curve 'E' that 
 * generates the subgroup of order 'q'.
 *
 * Defined RFC 6507 Section 4.1
 ******************************************************************************/
short community_getG_string(
    uint8_t        **G,
    size_t          *G_len);

/*******************************************************************************
 * Get the community 'G' as a point.
 ******************************************************************************/
EC_POINT *community_getG_point(void);

/******************************************************************************/
/* COMMUNITY PARAMETERS (SUPPLIED BY KMS)                                     */
/******************************************************************************/

/*******************************************************************************
 * Get the Mikey-Sakke parameter set. Initially only 1.
 *
 * Note! Potential problem future i.e. one community supporting multiple 
 * parameter sets? Would peers even know which to use/ is it even passed P2P?
 *
 * According to secure chorus docs - not supplied, assumd to be 1... always. 
 ******************************************************************************/
uint8_t community_get_paramSet( 
    const uint8_t   *community);

/*******************************************************************************
 * Get the commnunity 'KPAK' value. KMS Public Authentication Key - the root of 
 * trust for authentication.
 *
 * Defined RFC 6507 Section 4.2
 ******************************************************************************/
short community_getKPAK_string(
     const uint8_t  *community,
     uint8_t       **KPAK,
     size_t         *KPAK_len);

/*******************************************************************************
 * Get the community 'KPAK' as a point.
 ******************************************************************************/
EC_POINT *community_getKPAK_point(
    const uint8_t   *community);

/*******************************************************************************
 * Get the community 'Z' as a point.
 ******************************************************************************/
EC_POINT *community_getZ_point(
    const uint8_t   *community);

/******************************************************************************/
/* Output.                                                                    */
/******************************************************************************/

/*******************************************************************************
 * Output the KMS certificate (AKA community parameter set) for the specified 
 * community.
 ******************************************************************************/
void community_outputKMSCertificate(
    uint8_t *community);

#ifdef __cplusplus
}
#endif
#endif /* __ES_COMMUNITY_PARAMETERS_STORAGE__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
