/******************************************************************************/
/* Storage of user parameters                                                 */
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
 * @file userParameters.c
 * @brief Storage of Mikey Sakke User data.
 *
 * <PRE>
 * Provides :
 *     Flat file storage for Mikey Sakke user parameters.
 * </PRE>
 * Can handle multiple users.
 ******************************************************************************/
#include "log.h"
#include "userParameters.h"
#include "mikeySakkeParameters.h"
#include "communityParameters.h"
#include "msdb.h"
#include "sakke.h"
#include "eccsi.h"
#include "global.h"

#define ES_USER_PARAM_SECTION_NAME "(ES-USER-PARAMS)   " /*!< Section name 
                                                          *   output 
                                                          */
#define USER_MAX_SSK_STR_LEN   65 /*!< Maximum SSK length as a string 
                                   *   SSK|NULL 
                                   */
#define USER_MAX_RSK_STR_LEN  515 /*!< Maximum RSK length as a string
                                   *   04|RSK|NULL
                                   */
#define USER_MAX_HASH_STR_LEN  65 /*!< Maximum HASHlength as a string 
                                   *   HASH|NULL 
                                   */
#define USER_MAX_PVT_STR_LEN  131 /*!< Maximum PVT length as a string 
                                   *   04|PVT|NULL 
                                   */

/***************************************************************************//**
 * Checks the user ID/ Community data and the key material supplied by the KMS
 * (SSK, RSK and PVT). Note there are specific checks for SSK (RFC 6507 Section 
 * 5.1.2)and RSK (RFC6508 6.1.2 para 2). A call is then made to the msdb API 
 * in order to store the user data. 
 *
 * Validation of the SSK results in a hash that is also stored for subsequent 
 * use in calculations.
 *
 * @param[in] id_date   Date  part 'id' string.
 * @param[in] id_uri    ID part of 'id'.
 * @param[in] community community string.
 * @param[in] SSK       SSK (Secret Signing Key) string, from KMS.
 * @param[in] SSK_len   SSK (Secret Signing Key) octet string length.
 * @param[in] RSK       RSK (Receiver Secret Key) octet string, from KMS.
 * @param[in] RSK_len   RSK (Receiver Secret Key) octet string length.
 * @param[in] PVT       PVT (Public Validation Token) octet string, from KMS.
 * @param[in] PVT_len   PVT (Public Validation Token) octet string length.
 *
 * @return ES_SUCCESS, ES_FAILURE (internal failure), or, 
 *         ES_SAKKE_ERROR_RSK_VALIDATION_FAILED, or,
 *         ES_ECCSI_ERROR_SSK_VALIDATION_FAILED.
 ******************************************************************************/
short user_store(
    const uint8_t *id_date,
    const uint8_t *id_uri,
    const uint8_t *community,
    const uint8_t *SSK,
    const size_t   SSK_len,
    const uint8_t *RSK,
    const size_t   RSK_len,
    const uint8_t *PVT,
    const size_t   PVT_len)
{
    uint8_t  ret_val     = ES_FAILURE;
    uint8_t  tmp_res     = ES_FAILURE;

    uint8_t *user_id     = NULL;
    size_t   user_id_len = 0;
    uint8_t *hash        = NULL;
    size_t   hash_len    = 0;
    uint8_t *KPAK        = NULL;
    size_t   KPAK_len    = 0;

    /* Check parameters. */
    if (NULL == id_date) {
        ES_ERROR("%s", "User Storage Store User, 'ID date' value is NULL!");
    } else if (NULL == id_uri) {
        ES_ERROR("%s", "User Storage Store User, 'ID uri' value is NULL!");
    } else if (NULL == community ) {
        ES_ERROR("%s", "User Storage Store User, 'community' is NULL!");
    } /* The community MUST already exist in order to get KPAK. */
    else if (!community_exists(community)) {
        ES_ERROR("User Storage Store User, 'community' <%s> does not exist!", community);
    } else if (NULL == SSK) {
        ES_ERROR("%s", "User Storage Store User, 'SSK' value is NULL!");
    } else if (NULL == RSK) {
        ES_ERROR("%s", "User Storage Store User, 'RSK' value is NULL!");
    } else if (NULL == PVT) {
        ES_ERROR("%s", "User Storage Store User, 'PVT' value is NULL!");
    } else {
        /* Create a User-ID string in the correct format. */
        user_id_len = strlen((char *)id_date) + strlen((char *)id_uri) + 2;
                      /* 2 is for NULL separator plus NULL termninal as 
                       * per RFC 6507 Appendix A, Page 13, 'ID'.
                       */
        if (!(user_id = calloc(1, user_id_len))) { 
            ES_ERROR("%s", "User Storage Store User, could not allocate space for User Id!");
        }
        else {
            strcpy((char *)user_id, (char *)id_date);
            strcat((char *)user_id+strlen((char *)user_id)+1, (char *)id_uri);

            /* Validate the RSK. */
            if ((tmp_res = sakke_validateRSK(user_id, user_id_len, community, 
                                             RSK, RSK_len))) {
                if (tmp_res != ES_SAKKE_ERROR_RSK_VALIDATION_FAILED) {
                    ES_ERROR("%s", "User Storage Store User, RSK validation failed!");
                    ret_val = ES_SAKKE_ERROR_RSK_VALIDATION_FAILED;
                }
                else { /* Some other failure, check error log. */
                    ES_ERROR("%s", "User Storage Store User, RSK validation internal failure, check error log!");
                }
            }
            else {
                /*ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ES_USER_PARAM_SECTION_NAME,
                 *     "    SSK:",  6, SSK, SSK_len);
                 *ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ES_USER_PARAM_SECTION_NAME,
                 *     "    KPAK:", 6, KPAK, KPAK_len);
                 *ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ES_USER_PARAM_SECTION_NAME,
                 *     "    PVT:",  6, PVT, PVT_len);
                 */

                /* KPAK - Retrieve (Octet String) from the Community storage. */
                if (community_getKPAK_string(community, &KPAK, &KPAK_len)) {
                    ES_ERROR("User Storage Store User, unable to retrieve 'KPAK' for community <%s>!",
                             community);
                } else if (eccsi_validateSSK(
                               user_id, user_id_len, community,
                               SSK,     SSK_len,  
                               KPAK,    KPAK_len,
                               PVT,     PVT_len,                     
                               &hash,  &hash_len)) { /* Validate SSK. */
                    ES_ERROR("%s", "User Storage Store User, SSK validation failed!");
                    ret_val = ES_ECCSI_ERROR_SSK_VALIDATION_FAILED;
                }
                else {
                    /* Calculated Hash. */
                    ES_DEBUG_DISPLAY_HASH(ES_USER_PARAM_SECTION_NAME,
                        "    Calculated HASH:", 6, (char *)hash, hash_len);

                    /* Save User data. */
                    if (msdb_userAdd(
                           user_id, user_id_len,
                           community,
                           SSK,     SSK_len,
                           RSK,     RSK_len,
                           hash,    hash_len,
                           PVT,     PVT_len)) {
                        ES_ERROR("%s", "User Storage Store User, failed to store user!");
                    }
                    else {
                        ret_val = ES_SUCCESS;
                    }
                }
            }
        }
    } 
    if (NULL != KPAK) {
        memset(KPAK, 0, KPAK_len);
        free(KPAK);
        KPAK_len= 0;
    }
    if (NULL != hash) {
        memset(hash, 0, hash_len);
        free(hash);
        hash_len = 0;
    }
    if (NULL != user_id) {
        memset(user_id, 0, user_id_len);
        free(user_id);
        user_id_len = 0;
    }

    return ret_val;
} /* user_store */

/***************************************************************************//**
 * Remove user account identified by community and user_id from storage 
 * structure.
 *
 * @param[in] user_id       Octet string pointer of the 'user_id'.
 * @param[in] user_id_len   Length of 'user_id' octet string.
 * @param[in] community     Octet string of the 'community'.
 *
 * @return ES_SUCCESS or ES_FAILURE.
 ******************************************************************************/
short user_remove(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    return msdb_userDelete(user_id, user_id_len, community);
} /* user_remove */

/***************************************************************************//**
 * Indicates whether the specified community+user_id combination is stored. 
 *
 * @return ES_TRUE or ES_FALSE.
 ******************************************************************************/
short user_exists(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    return msdb_userExists(user_id, user_id_len, community);
} /* user_exists */

/***************************************************************************//**
 * Get user PVT (Public Validation Token) octet string if stored.
 *
 * @param[in]  user_id       Octet string of the 'user_id'.
 * @param[in]  user_id_len   Length of 'user_id' octet string.
 * @param[in]  community     Octet string of the 'community'.
 * @param[out] PVT           Result PVT octet string for the user.
 * @param[out] PVT_len       Length of PVT result octet string for the user.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short user_getPVT(
    const uint8_t  *user_id,
    const size_t    user_id_len,
    const uint8_t  *community, 
    uint8_t       **PVT,
    size_t         *PVT_len) {

    short ret_val = ES_FAILURE;

    uint8_t pvt[USER_MAX_PVT_STR_LEN];
    size_t  pvt_len = 0;

    /* Check parameters. */
    if (NULL == user_id) {
        ES_ERROR("%s", "User Storage Get PVT, 'user ID' value not specified!");
    } else if (user_id_len == 0) {
        ES_ERROR("%s", "User Storage Get PVT, 'user ID' length is 0!");
    } else if (NULL == community) {
        ES_ERROR("%s", "User Storage Get PVT, 'community' value not specified!");
    } else {
        if (!msdb_userGetPVT(user_id, user_id_len, community, (uint8_t *)&pvt)) {
            pvt_len =  strlen((char *)pvt);
            utils_convertHexStringToOctetString(
                (char *)pvt, pvt_len/2, /* Padded */ PVT, PVT_len);
            ret_val = ES_SUCCESS;
        }
    }

    return ret_val;
} /* user_getPVT */

/***************************************************************************//**
 * Get user PVT (Public Validation Token) x-coordinate value if stored.
 *
 * @param[in] user_id       Octet string of the 'user_id'.
 * @param[in] user_id_len   Length of 'user_id' octet string.
 * @param[in] community     Octet string of the 'community'.
 *
 * @return Pointer to the stored PVTx value or NULL.
 ******************************************************************************/
BIGNUM *user_getPVTx(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    BIGNUM  *pvtx = NULL;
    uint8_t  pvt[130];
    uint8_t  pvt_x[65];

    /* Check parameters. */
    if (NULL == user_id) {
        ES_ERROR("%s", "User Storage Get PVTx, 'user ID' value not specified!");
    } else if (user_id_len == 0) {
        ES_ERROR("%s", "User Storage Get PVTx, 'user ID' length is 0!");
    } else if (NULL == community) {
        ES_ERROR("%s", "User Storage Get PVTx, 'community' value not specified!");
    } else {
        memset(pvt,   0, sizeof(pvt));
        memset(pvt_x, 0, sizeof(pvt_x));
        if (!msdb_userGetPVT(user_id, user_id_len, community, (uint8_t *)&pvt)) {
            /* Returns full 04+PVTx+PVTy hex string. */
            memcpy(pvt_x, pvt+2, 64);
            BN_hex2bn(&pvtx, (char *)pvt_x);
        }
    }

    memset(pvt,   0, sizeof(pvt));
    memset(pvt_x, 0, sizeof(pvt_x));

    return pvtx;

} /* user_getPVTx */

/***************************************************************************//**
 * Get user PVT (Public Validation Token) y-coordinate value if stored.
 *
 * @param[in] user_id       Octet string of the 'user_id'.
 * @param[in] user_id_len   Length of 'user_id' octet string.
 * @param[in] community     Octet string of the 'community'.
 *
 * @return Pointer to the stored PVTy value or NULL.
 ******************************************************************************/
BIGNUM *user_getPVTy(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    BIGNUM  *pvty = NULL;
    uint8_t  pvt[130];
    uint8_t  pvt_y[65];

    /* Check parameters. */
    if (NULL == user_id) {
        ES_ERROR("%s", "User Storage Get PVTy, 'user ID' value not specified!");
    } else if (user_id_len == 0) {
        ES_ERROR("%s", "User Storage Get PVTy, 'user ID' length is 0!");
    } else if (NULL == community) {
        ES_ERROR("%s", "User Storage Get PVTy, 'community' value not specified!");
    }
    else {
        memset(pvt,   0, sizeof(pvt));
        memset(pvt_y, 0, sizeof(pvt_y));
        if (!msdb_userGetPVT(user_id, user_id_len, community, (uint8_t *)&pvt)) {
            /* Returns full 04+PVTx+PVTy hex string. */
            memcpy(pvt_y, pvt+66, 64);
            BN_hex2bn(&pvty, (char *)pvt_y);
        }
    }

    memset(pvt,   0, sizeof(pvt));
    memset(pvt_y, 0, sizeof(pvt_y));

    return pvty;

} /* user_getPVTy */

/***************************************************************************//**
 * Get user SSK (Secret Signing Key) value if stored.
 *
 * @param[in] user_id       Octet string of the 'user_id'.
 * @param[in] user_id_len   Length of 'user_id' octet string.
 * @param[in] community     Octet string of the 'community'.
 *
 * @return Pointer to the stored SSK value or NULL.
 ******************************************************************************/
BIGNUM *user_getSSK(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    BIGNUM  *ssk_bn = NULL;
    uint8_t  ssk[USER_MAX_SSK_STR_LEN];

    /* Check parameters. */
    if (NULL == user_id) {
        ES_ERROR("%s", "User Storage Get SSK, 'user ID' value not specified!");
    } else if (user_id_len == 0) {
        ES_ERROR("%s", "User Storage Get SSK, 'user ID' length is 0!");
    } else if (NULL == community) {
        ES_ERROR("%s", "User Storage Get SSK, 'community' value not specified!");
    } else {
        memset(ssk, 0, sizeof(ssk));
        if (!msdb_userGetSSK(user_id, user_id_len,
                             community, ssk)) {
            BN_hex2bn(&ssk_bn, (char *)ssk);
        }
    }
 
    memset(ssk, 0, sizeof(ssk));

    return ssk_bn;
} /* user_getSSK */

/***************************************************************************//**
 * Get user Hash value if stored.
 *
 * @param[in] user_id       Octet string of the 'user_id'.
 * @param[in] user_id_len   Length of 'user_id' octet string.
 * @param[in] community     Octet string of the 'community'.
 *
 * @return Pointer to the stored hash value or NULL.
 ******************************************************************************/
BIGNUM *user_getHash(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    BIGNUM  *hash_bn = NULL;
    uint8_t  hash[USER_MAX_HASH_STR_LEN];

    /* Check parameters. */
    if (NULL == user_id) {
        ES_ERROR("%s", "User Storage Get Hash, 'user ID' value not specified!");
    } else if (user_id_len == 0) {
        ES_ERROR("%s", "User Storage Get Hash, 'user ID' length is 0!");
    } else if (NULL == community) {
        ES_ERROR("%s", "User Storage Get Hash, 'community' value not specified!");
    } else {
        memset(hash, 0, sizeof(hash));
        if (!msdb_userGetHash(user_id, user_id_len,
                             community, hash)) {
            BN_hex2bn(&hash_bn, (char *)hash);
        }
    }

    memset(hash, 0, sizeof(hash));

    return hash_bn;

} /* user_getHash */

/***************************************************************************//**
 * Get user RSK as point.
 *
 * @param[in] user_id       Octet string of the 'user_id'.
 * @param[in] user_id_len   Length of 'user_id' octet string.
 * @param[in] community     Octet string of the 'community'.
 *
 * @return A pointer to the RSK point on success, NULL on failure.
 ******************************************************************************/
EC_POINT *user_getRSKpoint(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    EC_GROUP *ms_curve = NULL;
    EC_POINT *RSKpoint = NULL;
    uint8_t   RSK[USER_MAX_RSK_STR_LEN];
    size_t    RSK_len  = 0;
    uint8_t  *RSKx     = NULL;
    uint8_t  *RSKy     = NULL;
    BIGNUM   *RSK_x    = NULL;
    BIGNUM   *RSK_y    = NULL;

    /* Check parameters. */
    if (NULL == user_id) {
        ES_ERROR("%s", "User Storage Get RSK Point, 'user ID' value not specified!");
    } else if (user_id_len == 0) {
        ES_ERROR("%s", "User Storage Get RSK Point, 'user ID' length is 0!");
    } else if (NULL == community) {
        ES_ERROR("%s", "User Storage Get RSK Point, 'community' value not specified!");
    } else {
        memset(RSK, 0, sizeof(RSK));

        if (!msdb_userGetRSK(user_id, user_id_len, community, (uint8_t *)&RSK)) {
            if (!(RSK_len = strlen((char *)RSK))) {
                ES_ERROR("%s", "User Storage Get RSK Point, length is 0!");
            } else if (!(RSKx = calloc(1, (RSK_len/2)))) {
                ES_ERROR("%s", "User Storage Get RSK Point, could not allocate space for RSKx!");
            } else if (!(RSKy = calloc(1, (RSK_len/2)))) {
                ES_ERROR("%s", "User Storage Get RSK Point, could not allocate space for RSKy!");
            }
            else {
                snprintf((char *)RSKx, ((RSK_len-2)/2)+1, "%s", RSK+2);
                snprintf((char *)RSKy, ((RSK_len-2)/2)+1, "%s", RSK+2+((RSK_len-2)/2));

                if (!BN_hex2bn(&RSK_x,  (char *)RSKx)) {
                    ES_ERROR("%s", "User Storage Get RSK Point, could create RSKx BN!");
                } else if (!BN_hex2bn(&RSK_y,  (char *)RSKy)) {
                    ES_ERROR("%s", "User Storage Get RSK Point, could create RSKy BN!");
                } else if (!(ms_curve = ms_getParameter_E(1))) {
                    ES_ERROR("%s", "User Storage Get RSK Point, error retrieving 'E' Curve!");
                } else if (!(RSKpoint = EC_POINT_new(ms_curve))) {
                    ES_ERROR("%s", "Community Storage Get RSK Point, failed to create RSK point!");
                } else if (!EC_POINT_set_affine_coordinates_GFp(ms_curve,
                             RSKpoint, RSK_x, RSK_y, NULL)) {
                    ES_ERROR("%s", "Community Storage Get RSK Point, failed to set RSK coordinates!");
                }
                /*   ES_DEBUG_DISPLAY_AFFINE_COORDS(ES_COMMUNITY_SECTION_NAME,
                 *       "   RSK:", 8, ms_curve, RSK_point);
                 */
            }
        }
    }
    if (NULL != RSKx) {
        memset(RSKx, 0, strlen((char *)RSKx));
        free(RSKx);
    }
    if (NULL != RSKy) {
        memset(RSKy, 0, strlen((char *)RSKy));
        free(RSKy);
    }
    memset(RSK, 0, sizeof(RSK));
    BN_clear_free(RSK_x);
    BN_clear_free(RSK_y);

    return RSKpoint;
} /* user_get_RSK_point */

/***************************************************************************//**
 * Delete all user parameter sets. 
 *
 * @return Success '0' or Failure '1'.
 ******************************************************************************/
short user_deleteAllUserAccounts() {
    return msdb_userPurge();
} /* user_deleteAllUserAccounts */

/***************************************************************************//**
 * Returns an unsorted CSV (comma separated value) list of currently stored
 * user account names.
 *
 * Note! Callers of this function are responsible for freeing the space
 * allocated to the list returned.
 *
 * @return A CSV list of users.
 ******************************************************************************/
uint8_t *user_list() {
    return msdb_userList();
} /* user_list*/

/* Future maybe - users by community */

/***************************************************************************//**
 * Outputs parameter set data for the identified user. Only used when running 
 * in debug mode.
 *
 * @param[in] user_id       Octet string of the 'user_id'.
 * @param[in] user_id_len   Length of 'user_id' octet string.
 * @param[in] community     Octet string of the 'community'.
 ******************************************************************************/
void user_outputParameterSet(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
#ifdef ES_OUTPUT_DEBUG
    uint8_t value[ES_MAX_ATTR_LEN];

    ES_DEBUG("%s    Mikey Sakke User Data", ES_USER_PARAM_SECTION_NAME);
    ES_DEBUG("%s    =====================", ES_USER_PARAM_SECTION_NAME);

    memset(value, 0, sizeof(value));
    if (!msdb_userGetSSK(user_id, user_id_len, community, (uint8_t *)&value)) {
        ES_DEBUG("%s        SSK:       <%s>", ES_USER_PARAM_SECTION_NAME, 
                 value);
    } else {
        ES_DEBUG("%s        SSK:      could not be retrieved", 
                 ES_USER_PARAM_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_userGetRSK(user_id, user_id_len, community, (uint8_t *)&value)) {
        ES_DEBUG("%s        RSK:       <%s>", ES_USER_PARAM_SECTION_NAME, value);
    } else {
        ES_DEBUG("%s        RSK:       could not be retrieved", 
                 ES_USER_PARAM_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_userGetHash(user_id, user_id_len, community, (uint8_t *)&value)) {
        ES_DEBUG("%s        HASH:      <%s>", ES_USER_PARAM_SECTION_NAME, 
                 value);
    } else {
        ES_DEBUG("%s        HASH:      could not be retrieved", 
                 ES_USER_PARAM_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_userGetPVT(user_id, user_id_len, community, (uint8_t *)&value)) {
        ES_DEBUG("%s        PVT:       <%s>", ES_USER_PARAM_SECTION_NAME, 
                 value);
    } else {
        ES_DEBUG("%s        PVT:       could not be retrieved", 
                 ES_USER_PARAM_SECTION_NAME);
    }
    memset(value, 0, sizeof(value));

#endif /* ES_OUTPUT_DEBUG */
} /* user_outputParameterSet */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
