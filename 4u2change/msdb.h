/******************************************************************************/
/* Generic Data Handling                                                      */
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
 * @file msdb.h
 * @brief Generic Data Handling
 *
 * This header file describes the access functions that are required by the
 * ECCSI/ SAKKE crypto code to a back end storage mechanism.
 * <P>
 * This <b>EXAMPLE</b> code implements this interface, storing the data in flat 
 * file format. However, it is very simple and not intended for product, just as
 * a simple exemplar. The storage implentation code itself isn't particularly
 * pretty and I haven't spent much time on it because I'd expect it to be
 * replaced by others (i.e. YOU), depending on what you want this storage to
 * be.
 * <P>
 * Implementors are free to implement the back end storage mechanism in
 * whatever way they see fit. However, it MUST comply with the interface/ API
 * defined in THIS header file for it to work.
 * <P>
 * The actual storage mechanism chosen to store this (Mikey-Sakke) key
 * material will largely depend upon the implemntation architecture and
 * target platform  and may be:
 * <PRE>
 *     One of a variety of databases e.g.:
 *         MYSQL/ SQLcipher
 *         PostGres
 *         Oracle
 *         LDAP etc
 *     or, something more novel perhaps (depending on product/ platform) :
 *         RFID/ NFC card/ Yubi key/ SD card, or hardware tag
 *     or, something else entirely I haven't considered yet.
 * </PRE>
 * Data used by the ECCSI/ SAKKE code consists of 3 parts:
 * <PRE>
 *     1) Mikey-Sakke parameter set (NOT managed by this API)
 *        There is presently only one set and this is hard coded in this
 *        code.
 *     2) Community (managed by this API)
 *        In Secure Chorus parlance the KMS certificate. Refer to Secure
 *        Chorus documentation.
 *     3) User (managed by this API)
 *        A User within a community. A user may be in several communities.
 * </PRE>
 * In short these actions (i.e. what YOU must implement for your chosen
 * storage mechanism) are:
 * <PRE>
 *     Community:
 *         msdb_communityAdd
 *         msdb_communityExists
 *         msdb_communityDelete
 *         msdb_communityPurge
 *         msdb_communityList
 *         msdb_communityCount<br>
 *       Attributes as defined by Secure Chorus...
 *         msdb_communityGetVersion
 *         msdb_communityGetCertUri
 *         msdb_communityGetKmsUri
 *         msdb_communityGetIssuer
 *         msdb_communityGetValidFrom
 *         msdb_communityGetValidTo
 *         msdb_communityGetRevoked
 *         msdb_communityGetUserIDFormat
 *         msdb_communityGetPubEncKey (Z)
 *         msdb_communityGetPubAuthKey (KPAK)
 *         msdb_communityGetUserKmsDomainList
 *     User:
 *         msdb_userAdd
 *         msdb_userExists
 *         msdb_userDelete
 *         msdb_userPurge
 *         msdb_userList
 *         msdb_userCount
 *         msdb_userGetSSK
 *         msdb_userGetRSK
 *         msdb_userGetHash
 *         msdb_userGetPVT
 * </PRE>
 ******************************************************************************/
#ifndef __ES_ECCSI_SAKKE_DATA_STORAGE_H__
#define __ES_ECCSI_SAKKE_DATA_STORAGE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MSDB_MAX_LOG_LINE 1024       /*!< The maximum length for log output. */

/* Matches ES_TRUE/ ES_FALSE */
#ifndef MSDB_TRUE
#define MSDB_TRUE 1                  /*!< MSDB value for true  */
#endif
#ifndef MSDB_FALSE
#define MSDB_FALSE (!MSDB_TRUE)      /*!< MSDB value for false */
#endif

/* Matches ES_FAILURE/ ES_SUCCESS*/
#ifndef MSDB_FAILURE_
#define MSDB_FAILURE 1               /*!< MSDB value for failure */
#endif
#ifndef MSDB_SUCCESS
#define MSDB_SUCCESS (!MSDB_FAILURE) /*!< MSDB value for success */
#endif

#define STORAGE_ROOT       "." /*!< The root directory location for data 
                                *   storage.
                                */
#define STORAGE_DIRECTORY  STORAGE_ROOT"/storage"  /*!< The storage directory.*/

/***************************************************************************//**
 * MSDB Error Macro - output passed error string
 */
#define MSDB_ERROR(a_format, vargs...) { \
    char outBuff_a[MSDB_MAX_LOG_LINE]; \
    snprintf(outBuff_a, sizeof(outBuff_a), a_format, ## vargs); \
    fprintf(stdout, "MSDB ERROR: %s\n", outBuff_a); \
    }

/******************************************************************************/
/* Community Data Accessor Functions.                                         */
/******************************************************************************/

/* Management */

/*******************************************************************************
 * Add KMS certificate data for a new KMS (community). If the kms_uri 
 * (community) name exists the storage is deleted first.
 ******************************************************************************/
short msdb_communityAdd(
    const uint8_t *version,
    const uint8_t *cert_uri, /* AKA community */
    const uint8_t *kms_uri, 
    const uint8_t *issuer,
    const uint8_t *valid_from,
    const uint8_t *valid_to,
    const short    revoked,
    const uint8_t *user_id_format, /* Optional */
    const uint8_t *pub_enc_key,
    const size_t   pub_enc_key_len,
    const uint8_t *pub_auth_key,
    const size_t   pub_auth_key_len,
    const uint8_t *kms_domain_list);

/*******************************************************************************
 * Check whether the specified community exists.
 ******************************************************************************/
short    msdb_communityExists(
    const uint8_t *community);

/*******************************************************************************
 * Delete specified community.
 ******************************************************************************/
short    msdb_communityDelete(
    const uint8_t *community);

/*******************************************************************************
 * Delete all (purge) stored communities.
 ******************************************************************************/
short    msdb_communityPurge();

/*******************************************************************************
 * Get a comma separated list of stored communities.
 ******************************************************************************/
uint8_t *msdb_communityList();

/*******************************************************************************
 * The number of stored communities.
 ******************************************************************************/
uint16_t msdb_communityCount();

/* Get Attributes */

/*******************************************************************************
 * Get the stored version for the specified community.
 ******************************************************************************/
short msdb_communityGetVersion(
    const uint8_t *community,
    uint8_t       *version);

/*******************************************************************************
 * Get the stored CertUri for the specified community.
 ******************************************************************************/
short msdb_communityGetCertUri(
    const uint8_t *community,
    uint8_t       *cert_uri);

/*******************************************************************************
 * Get the stored KmUri for the specified community.
 ******************************************************************************/
short msdb_communityGetKmsUri(
    const uint8_t *community,
    uint8_t       *kms_uri);

/*******************************************************************************
 * Get the stored Issuer for the specified community.
 ******************************************************************************/
short msdb_communityGetIssuer(
    const uint8_t *community,
    uint8_t       *issuer);

/*******************************************************************************
 * Get the stored ValidFrom for the specified community.
 ******************************************************************************/
short msdb_communityGetValidFrom(
    const uint8_t *community,
    uint8_t       *valid_from);

/*******************************************************************************
 * Get the stored ValidTo for the specified community.
 ******************************************************************************/
short msdb_communityGetValidTo(
    const uint8_t *community,
    uint8_t       *valid_to);

/*******************************************************************************
 * Get the stored Revoked indicator for the specified community.
 ******************************************************************************/
short msdb_communityGetRevoked(
    const uint8_t *community,
    short         *revoked);

/* Optional */

/*******************************************************************************
 * Get the stored UserIdFormat for the specified community.
 ******************************************************************************/
short msdb_communityGetUserIDFormat(
    const uint8_t *community,
    uint8_t       *user_id_format);

/*******************************************************************************
 * Get the stored PubEncKey (Z) for the specified community.
 ******************************************************************************/
short msdb_communityGetPubEncKey(
    const uint8_t *community,
    uint8_t       *Z);

/*******************************************************************************
 * Get the stored PubAuthKey (KPAK) for the specified community.
 ******************************************************************************/
short msdb_communityGetPubAuthKey(
    const uint8_t *community,
    uint8_t       *KPAK);

/*******************************************************************************
 * Get the stored KmsDomainList for the specified community.
 ******************************************************************************/
short msdb_communityGetKmsDomainList(
    const uint8_t *community,
    uint8_t       *domain_list);

/******************************************************************************/
/*                                   USER                                     */
/******************************************************************************/

/*******************************************************************************
 * Add a user to the user store.
 *
 * If the user exists already that data entry is deleted first.
 ******************************************************************************/
uint8_t msdb_userAdd(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    const uint8_t *ssk,
    const size_t   ssk_len,
    const uint8_t *rsk,
    const size_t   rsk_len,
    const uint8_t *hash,
    const size_t   hash_len,
    const uint8_t *pvt,
    const size_t   pvt_len);

/*******************************************************************************
 * Check whether the specified user exists.
 ******************************************************************************/
short    msdb_userExists(
    const uint8_t *user,
    const size_t   user_len,
    const uint8_t *community);

/*******************************************************************************
 * Delete a specified user within a community.
 ******************************************************************************/
short    msdb_userDelete(
    const uint8_t *user,
    const size_t   user_len,
    const uint8_t *community);

/*******************************************************************************
 * Delete all (purge) stored users.
 ******************************************************************************/
short    msdb_userPurge();

/*******************************************************************************
 * Get a comma separated list of stored users.
 ******************************************************************************/
uint8_t *msdb_userList();

/*******************************************************************************
 * Get the number of stored users.
 ******************************************************************************/
uint16_t msdb_userCount();

/*******************************************************************************
 * Get a specified user's SSK (Secret Signing Key).
 ******************************************************************************/
short    msdb_userGetSSK(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    uint8_t       *ssk);

/*******************************************************************************
 * Get a specified user's RSK (Receiver Secret Key).
 ******************************************************************************/
short    msdb_userGetRSK(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    uint8_t       *rsk);

/*******************************************************************************
 * Get a specified user's Hash.
 ******************************************************************************/
short    msdb_userGetHash(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    uint8_t       *hash);

/*******************************************************************************
 * Get a specified user's PVT (Public Validation Token).
 ******************************************************************************/
short    msdb_userGetPVT(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    uint8_t       *pvt);

#ifdef __cplusplus
}
#endif
#endif /* __ES_ECCSI_SAKKE_DATA_STORAGE_H__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
