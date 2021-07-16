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
 * @file communityParameters.c
 * @brief Storage of Mikey Sakke Community data.
 *
 * <PRE>
 * Provides :
 *     In memory storage and access functions for Mikey Sakke community
 *     parameters.
 *     File storage for Mikey Sakke community parameters.
 * </PRE>
 *
 * Handles multiple communities accessed by community name.
 * <BR>
 * Implements a flat file storage for Mikey Sakke community parameters.
 ******************************************************************************/
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "communityParameters.h"
#include "mikeySakkeParameters.h"
#include "global.h"

#include "msdb.h"
#include "log.h"

/* Max values. */
#define COMMUNITY_MAX_KPAK_STR_LEN 131 /*!< Maximum KPAK length as a string 
                                        *   04|KPAK|NULL 
                                        */
#define COMMUNITY_MAX_Z_STR_LEN    515 /*!< Maximum Z length as a string
                                        *   04|Z|NULL
                                        */

/* A section name for LOG output */
#define ES_COMMUNITY_SECTION_NAME "(ES-COMMUNITY)   "/*!< Section name output */

/* Global (hard-coded) parameters */
#define COMMUNITY_n 256 /*!< RFC 6507 Section 4.1 and Appendix A page 13.
                         *   A security parameter; the size in bits of
                         *   the prime 'p' over which elliptic curve 
                         *   cryptography is to be performed.
                         */

#define COMMUNITY_N  32 /*!< RFC 6507 Appendix A. 
                         *   The number of octets used to represent 
                         *   fields 'r' and 's' in signatures. Also 
                         *   the number of octets output by the hash 
                         *   function. 
                         */

#define COMMUNITY_p  "FFFFFFFF" "00000001" "00000000" "00000000"\
                    "00000000" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF"
                        /*!< RFC 6507 Section 4.1 and Appendix A page 13.
                         *   A prime number of size 'n' bits. The finite 
                         *   field with 'p' elements is denoted 'F_p'. 
                         */

#define COMMUNITY_B "5AC635D8" "AA3A93E7" "B3EBBD55" "769886BC"\
                    "651D06B0" "CC53B0F6" "3BCE3C3E" "27D2604B"
                        /*!< RFC 6507 Section 4.1 and Appendix A page 13.
                         *   An element of F_p, where 'E' is denoted by 
                         *   the formula y^2 = x^3 - 3*x + B modulo p.
                         *
                         *   Note! 'E' is named NIST_P256_Curve here to avoid 
                         *   confusion with Mikey-Sakke 'E' (RFC 6509) where
                         *   'p' differs, see mikeySakkParameters.c.
                         */

#define COMMUNITY_G "04"\
                    "6B17D1F2" "E12C4247" "F8BCE6E5" "63A440F2"\
                    "77037D81" "2DEB33A0" "F4A13945" "D898C296"\
                    "4FE342E2" "FE1A7F9B" "8EE7EB4A" "7C0F9E16"\
                    "2BCE3357" "6B315ECE" "CBB64068" "37BF51F5"
                        /*!< RFC 6507 Section 4.1 and Appendix A page 13.
                         *   A point on elliptic curve 'E' that generates the
                         *   subgroup of order 'q'.
                         *
                         *   Note! 'E' is named NIST_P256_Curve here to avoid 
                         *   confusion with Mikey-Sakke 'E' (RFC 6509) where
                         *   'p' differs, see mikeySakkParameters.c.
                         */

#define COMMUNITY_q "FFFFFFFF" "00000000" "FFFFFFFF" "FFFFFFFF"\
                    "BCE6FAAD" "A7179E84" "F3B9CAC2" "FC632551"
                        /*!< RFC 6507 Section 4.1 and Appendix A page 13.
                         *   The prime 'q' is defined to be the order of 'G' 
                         *   in 'E' over 'F_p'.
                         *
                         *   Note! 'E' is named NIST_P256_Curve here to avoid 
                         *   confusion with Mikey-Sakke 'E' (RFC 6509) where
                         *   'p' differs, see mikeySakkParameters.c.
                         */

/* Global */
static BIGNUM        *p_bn;            /*!<  A BIGNUM of 'p' above. */
/*static BIGNUM      *a_bn; - Not needed other than to create NIST curve. */
/*static BIGNUM      *B_bn; - Not needed other than to create NIST curve. */
static BIGNUM        *q_bn;            /*!<  A BIGNUM of 'q' above. */

static uint8_t       *G_string;        /*!< A padded octet string for 'G'.   */
static size_t         G_string_len;    /*!< The octet string length for 'G'. */
static EC_POINT      *G_point;         /*!< The EC_POINT G on curve 'E'.     
i                                       *
                                        *   Note! 'E' is named NIST_P256_Curve 
                                        *   here to avoid confusion with 
                                        *   Mikey-Sakke 'E' (RFC 6509) where
                                        *   'p' differs, see 
                                        *   mikeySakkParameters.c.
                                        */

static EC_GROUP      *NIST_P256_Curve; /*!< The NIST P256 Curve.    */

/***************************************************************************//**
 * Initialise Mikey-Sakke Community storage.
 *
 * @return ES_SUCCESS or ES_FAILURE 
 ******************************************************************************/
short community_initStorage() {
    uint8_t error_encountered = ES_FALSE;
    uint8_t ret_val           = ES_FAILURE;

    /* BIGNUM */
    BIGNUM  *a_bn     = NULL;
    BIGNUM  *B_bn     = NULL;
    BIGNUM  *Gx_bn    = NULL;
    BIGNUM  *Gy_bn    = NULL;

    uint8_t *Gx       = NULL;
    uint8_t *Gy       = NULL;
    uint16_t tmp_glen = 0;

    /*************************************************************************/
    /* Init.                                                                 */
    /*************************************************************************/
    /* Hard coded values. */
    if (!BN_hex2bn(&p_bn, COMMUNITY_p)) {
        ES_ERROR("%s", "Community Storage Init, could not create 'p' BN!");
        error_encountered = ES_TRUE;
    } else if (!BN_dec2bn(&a_bn, "-3l")) { /* Coefficient of x */
        ES_ERROR("%s", "Community Storage Init, could not create 'a' BN!");
        error_encountered = ES_TRUE;
    } else if (!BN_hex2bn(&B_bn, COMMUNITY_B)) {
        ES_ERROR("%s", "Community Storage Init, could not create 'B' BN!");
        error_encountered = ES_TRUE;
    } else if (!(NIST_P256_Curve = EC_GROUP_new_curve_GFp(p_bn, a_bn, B_bn, NULL))) {
        ES_ERROR("%s", "Community Storage Init, error creating NIST_P256_Curve!");
        error_encountered = ES_TRUE;
    }

    if (!error_encountered) {
        /* 'G' octet string */
        if (utils_convertHexStringToOctetString((char *)COMMUNITY_G,
            strlen((char *)COMMUNITY_G)/2, /*Padded*/ &G_string, &G_string_len)) {
            error_encountered = ES_TRUE;
        }
    }

    if (!error_encountered) {
        if (!(tmp_glen = strlen(COMMUNITY_G))) {
            ES_ERROR("%s", "Community Storage Init, length is 0!");
        } 

        /* We don't need to include the '04' start, hence the 2 offset. */
        else {
	    // Switched to strdup as GCC 7+ whinges unnecessarrily about snprintf.
	    // IMHO if you specify the length and that is less than the target 
	    // location then that should be sufficient.
            Gx = (uint8_t *)strndup(COMMUNITY_G+2, (tmp_glen-2)/2);   
            Gy = (uint8_t *)strndup(COMMUNITY_G+2+((tmp_glen-2)/2), (tmp_glen-2)/2);   

            if (!BN_hex2bn(&Gx_bn,  (char *)Gx)) {
                ES_ERROR("%s", "Community Storage Init, could create Gx BN!");
            } else if (!BN_hex2bn(&Gy_bn,  (char *)Gy)) {
                ES_ERROR("%s", "Community Storage Init, could create Gy BN!");
            } else if (!(G_point = EC_POINT_new(NIST_P256_Curve))) {
                ES_ERROR("%s", "Community Storage Init, failed to create G point!");
            } else if (!EC_POINT_set_affine_coordinates(NIST_P256_Curve, 
                         G_point, Gx_bn, Gy_bn, NULL)) {
                ES_ERROR("%s", "Community Storage Init, failed to set 'G' coordinates!");
            }
            /*   ES_DEBUG_DISPLAY_AFFINE_COORDS(ES_COMMUNITY_SECTION_NAME,
             *       "   G:", 8, NIST_P256_Curve, G_point);
             */
        }
    }

    if (!error_encountered) {
        if (!BN_hex2bn(&q_bn,  COMMUNITY_q)) {
            ES_ERROR("%s", "Community Storage Init, could create 'q' BN!");
        }
        else {
            ret_val = ES_SUCCESS;
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    BN_clear_free(a_bn); /* Used to create curve then not used again. */
    BN_clear_free(B_bn); /* Used to create curve then not used again. */
    BN_clear_free(Gx_bn);
    BN_clear_free(Gy_bn);
    if (NULL != Gx) {
        free(Gx);
    }
    if (NULL != Gy) {
        free(Gy);
    }

    /* NOTE! KPAK and Z vary and are stored individually for each community. */

    return ret_val;
} /* community_initStorage */

/***************************************************************************//**
 * Delete all non file storage community (global) data.
 ******************************************************************************/
void community_deleteStorage() {
    if (p_bn != NULL) {
        BN_clear_free(p_bn);
    }
    if (q_bn != NULL) {
        BN_clear_free(q_bn);
    }
    if (G_point != NULL) {
        EC_POINT_clear_free(G_point);
    }
    if (NIST_P256_Curve != NULL) {
        EC_GROUP_clear_free(NIST_P256_Curve);
    }

    if (NULL != G_string) {
        memset(G_string, 0, G_string_len);
        free(G_string);
    }

} /* community_deleteStorage */

/***************************************************************************//**
 * Stores a new community and associated Mikey Sakke data.
 *
 * Note! Descriptions from Secure Chorus 'KMS Protocol Specification'.
 *
 * @param[in]  version          (Attribute) The version number of the 
 *                              certificate type(1.0.0).
 * @param[in]  cert_uri         The URI of the Certificate (this object). 
 * @param[in]  kms_uri          The URI of the KMS which issued the Certificate.
 * @param[in]  issuer           String describing the issuing entity.
 * @param[in]  valid_from       Date from which the Certificate may be used.
 * @param[in]  valid_to         Date at which the Certificate expires.
 * @param[in]  revoked          A Boolean value defining whether a Certificate  
 *                              has been revoked.
 * @param[in]  user_id_format   A string denoting how MIKEY-SAKKE UserIDs should 
 *                              be constructed. See Section A.4.3. This field is 
 *                              optional.
 * @param[in]  pub_enc_key      The SAKKE Public Key 'Z', as defined in [SAKKE]. 
 *                              This is an OCTET STRING encoding of an elliptic 
 *                              curve point as defined in Section 2.2 of 
 *                              [RFC5480].
 * @param[in]  pub_enc_key_len  The SAKKE Public Key 'Z' length.
 * @param[in]  pub_auth_key     The ECCSI Public Key, 'KPAK' as defined in 
 *                              [ECCSI]. This is an OCTET STRING encoding of an 
 *                              elliptic curve point as defined in Section 2.2  
 *                              of [RFC5480].
 * @param[in]  pub_auth_key_len The ECCSI Public Key length.
 * @param[in]  kms_domain_list  List of domains which the KMS manages
 *
 * @return ES_SUCCESS or ES_FAILURE (where MSDB_SUCCESS or MSDB_FAILURE 
 *         returned from the call to msdb_communityAdd match).
 ******************************************************************************/
uint8_t community_store(
    uint8_t  *version,
    uint8_t  *cert_uri,
    uint8_t  *kms_uri,        /* AKA community. */
    uint8_t  *issuer,
    uint8_t  *valid_from,
    uint8_t  *valid_to,
    short     revoked,
    uint8_t  *user_id_format, /* Optional. */
    uint8_t  *pub_enc_key,    /* AKA 'Z'. */
    size_t    pub_enc_key_len,
    uint8_t  *pub_auth_key,   /* AKA 'KPAK'. */
    size_t    pub_auth_key_len,
    uint8_t  *kms_domain_list) {

    return msdb_communityAdd(
               version,
               cert_uri,       /* AKA community. */
               kms_uri,
               issuer,
               valid_from,
               valid_to,
               revoked,
               user_id_format, /* Optional. */

               pub_enc_key,    pub_enc_key_len,  /* AKA 'Z'. */
               pub_auth_key,   pub_auth_key_len, /* AKA 'KPAK'. */

               kms_domain_list);

} /* community_store */

/***************************************************************************//**
 * Removes a community (identified by parameter 'community').
 *
 * @return ES_SUCCESS ro ES_FAILURE 
 ******************************************************************************/
short community_remove(
    const uint8_t *community) {
    return msdb_communityDelete(community);
} /* community_remove */

/***************************************************************************//**
 * Indicates whether the specified community is stored. For use externally as
 * no reference to community is returned.
 *
 * @param[in] community The community name to check
 *
 * @return ES_TRUE or ES_FALSE.
 ******************************************************************************/
short community_exists(
    const uint8_t *community)
{
    return msdb_communityExists(community);
} /* community_exists */

/******************************************************************************/
/* GLOBAL PARAMETERS (HARD CODED)                                             */ 
/******************************************************************************/

/***************************************************************************//**
 * Get the commnunity 'n' value. 'n' is a security parameter; the size of 
 * symetric key in bits to be exchanged by SAKKE.
 *
 * Defined RFC 6507 Section 4.1
 *
 * @return The value for 'n' for success, '0' on failure.
 ******************************************************************************/
uint16_t community_get_n()
{
    return COMMUNITY_n;
} /* community_get_n */

/***************************************************************************//**
 * Get the commnunity 'N' value. 'N' is the number of octets used to represent
 * 'r' and 's' in signatures. Also the number of octets output by the hash 
 * function.
 *
 * Defined RFC 6507 Section 4.1
 *
 * @return The value for 'N' for success, '0' on failure.
 ******************************************************************************/
uint16_t community_get_N() 
{
    return COMMUNITY_N;
} /* community_get_N */

/***************************************************************************//**
 * Get the commnunity 'p' value. 'p' is a prime number of size 'n' bits. the 
 * finite field with 'p' elements is denoted F_p.
 *
 * Defined RFC 6507 Section 4.1
 *
 * @return The value for 'p' for success, NULL on failure.
 ******************************************************************************/
BIGNUM *community_get_p() 
{
    return p_bn;
} /* community_get_p */

/***************************************************************************//**
 * Get the NIST P256 Curve. 
 *
 * @return A pointer to the curvei on success, NULL on failure.
 ******************************************************************************/
EC_GROUP *community_get_NIST_P256_Curve() 
{
    return NIST_P256_Curve;
} /* community_get_NIST_P256_Curve */

/******************************************************************************/
/* COMMUNITY PARAMETERS (SUPPLIED BY KMS)                                     */ 
/******************************************************************************/

/***************************************************************************//**
 * Get the Mikey-Sakke parameter set. Initially only 1.
 *
 * Note! Potential problem future i.e. one community supporting multiple 
 * parameter sets? Would peers even know which to use/ is it even passedi P2P?
 *
 * @param[in] community     Octet string of the 'community'.
 *
 * @return The Mikey-Sakke paramneter set on success or 0 on failure.
 ******************************************************************************/
uint8_t community_get_paramSet(
    const uint8_t *community)
{
    if (NULL == community) {
        ES_ERROR("%s", "Community Storage Get Param Set, community reference is NULL!");
    } else {
        return 1;
    }

    return 0;
} /* community_get_paramSet */

/***************************************************************************//**
 * Get the commnunity 'KPAK' value. KMS Public Authentication Key - the root of 
 * trust for authentication.
 *
 * Defined RFC 6507 Section 4.2
 *
 * @param[in]  community    Octet string of the 'community'.
 * @param[out] KPAK         Result 'KPAK' Octet string. 
 * @param[out] KPAK_len     Length of 'KPAK' octet string.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short community_getKPAK_string(
    const uint8_t  *community,
    uint8_t       **KPAK,
    size_t         *KPAK_len)
{
    short           ret_val  = ES_FAILURE;
    uint8_t         kpak[COMMUNITY_MAX_KPAK_STR_LEN];
    size_t          kpak_len = 0;

    if (NULL == community) {
        ES_ERROR("%s", "Community Storage Get KPAK String, community reference is NULL!");
    } else {
        if (!msdb_communityGetPubAuthKey(community, (uint8_t *)&kpak)) {
            kpak_len =  strlen((char *)kpak);
            utils_convertHexStringToOctetString(
                (char *)kpak,
                kpak_len/2, /* Padded */
                KPAK, KPAK_len);
            ret_val = ES_SUCCESS;
        }
    }
    memset(kpak, 0, sizeof(kpak));

    return ret_val;
} /* community_getKPAK_string */

/***************************************************************************//**
 * Get the commnunity 'q' value. The prime 'q' is defined to be the order of G 
 * in E over F_p.
 *
 * Defined RFC 6507 Section 4.1
 *
 * @return The value for 'q' for success, NULL on failure.
 ******************************************************************************/
BIGNUM *community_getq_bn()
{
    return q_bn;
} /* community_getq_bn */

/***************************************************************************//**
 * Get the commnunity 'G' value. 'G' is a point on the elliptic curve 'E' that 
 * generates the subgroup of order 'q'.
 *
 * Defined RFC 6507 Section 4.1
 *
 * @param[out] G            Result 'G' Octet string. 
 * @param[out] G_len        Length of 'G' octet string.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short community_getG_string(
    uint8_t **G,
    size_t   *G_len) 
{ 
    short     ret_val = ES_FAILURE;

    if ((G_string != NULL) && (G_string_len != 0)) {
        *G      = G_string;
        *G_len  = G_string_len;
        ret_val = ES_SUCCESS;
    }
       
    return ret_val;
} /* community_getG_string */

/***************************************************************************//**
 * Get the community 'G' as a point.
 *
 * @return A pointer to the 'G' point.
 ******************************************************************************/
EC_POINT *community_getG_point(void)
{
     return G_point;
} /* community_getG_point */

/***************************************************************************//**
 * Returns an unsorted CSV (Comma Separated Value) list of currently stored
 * community names.
 *
 * It is expected this function may be useful at the application level to
 * list supported communities.
 *
 * Callers of this function are responsible for freeing the storage.
 *
 * @return The CSV list of stored communities which may be NULL.
 ******************************************************************************/
uint8_t *community_list() 
{
    return msdb_communityList();
} /* community_list*/

/***************************************************************************//**
 * Get the number of currently stored communities.
 *
 * @return The number of currently stored communitities.
 ******************************************************************************/
uint8_t community_count() 
{
    return msdb_communityCount();
} /* community_count*/

/***************************************************************************//**
 * Deletes all the community data stored in memory.
 *
 * @return A success failure indicator.
 ******************************************************************************/
short community_deleteAllCommunities()
{
    return msdb_communityPurge();
} /* community_deleteAllCommunities */

/***************************************************************************//**
 * Get the community 'KPAK' as a point.
 *
 * @return A pointer to the 'KPAK' point.
 ******************************************************************************/
EC_POINT *community_getKPAK_point(
    const uint8_t *community)
{
    uint8_t        error_encountered = 0;
    uint8_t        KPAK[COMMUNITY_MAX_KPAK_STR_LEN];
    size_t         KPAK_len = 0;
    BIGNUM        *KPAK_x = NULL;
    BIGNUM        *KPAK_y = NULL;

    uint8_t       *KPAKx  = NULL;
    uint8_t       *KPAKy  = NULL;

    EC_GROUP *nist_curve  = NULL; /* Temporary reference. */
    EC_POINT *KPAK_point  = NULL;

    /*************************************************************************/
    /* Check passed parameters                                               */
    /*************************************************************************/
    if (NULL == community) {
        ES_ERROR("%s", "Community Storage Get KPAK Point, community is NULL!");
        error_encountered = ES_TRUE;
    }

    /*************************************************************************/
    /* Init.                                                                 */
    /*************************************************************************/
    if (!error_encountered) {
        memset(KPAK, 0, sizeof(KPAK));
        if (msdb_communityGetPubAuthKey(community, (uint8_t *)&KPAK)) {
            ES_ERROR("Community Storage Get KPAK Point, could not retrieve KPAP data for <%s>!",
                community);
        }
        else {
            if (!(KPAK_len = strlen((char *)KPAK))) {
                ES_ERROR("%s", "Community Storage Get KPAK Point, length is 0!");
            } else if (!(KPAKx = calloc(1, KPAK_len/2))) {
                ES_ERROR("%s", "Community Storage Get KPAK Point, could not allocate space for KPAKx!");
            } else if (!(KPAKy = calloc(1, KPAK_len/2))) {
                ES_ERROR("%s", "Community Storage Get KPAK Point, could not allocate space for KPAKy!");
            }
            else {
                snprintf((char *)KPAKx, ((KPAK_len-2)/2)+1, "%s", KPAK+2);
                snprintf((char *)KPAKy, ((KPAK_len-2)/2)+1, "%s", KPAK+2+((KPAK_len-2)/2));

                if (!BN_hex2bn(&KPAK_x,  (char *)KPAKx)) {
                    ES_ERROR("%s", "Community Storage Get KPAK Point, could create KPAKx BN!");
                } else if (!BN_hex2bn(&KPAK_y,  (char *)KPAKy)) {
                    ES_ERROR("%s", "Community Storage Get KPAK Point, could create KPAKy BN!");
                } else if (!(nist_curve = NIST_P256_Curve)) {
                    ES_ERROR("%s", "Community Storage Get KPAK Point, error retrieving NIST_P256_Curve!");
                } else if (!(KPAK_point = EC_POINT_new(nist_curve))) {
                    ES_ERROR("%s", "Community Storage Get KPAK Point, failed to create KPAK point!");
                } else if (!EC_POINT_set_affine_coordinates(nist_curve,
                            KPAK_point, KPAK_x, KPAK_y, NULL)) { 
                    ES_ERROR("%s", "Community Storage Get KPAK Point, failed to set KPAK coordinates!");
                }
                /*   ES_DEBUG_DISPLAY_AFFINE_COORDS(ES_COMMUNITY_SECTION_NAME,
                 *       "   KPAK:", 8, nist_curve, KPAK_point);
                 */
            }
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    memset(KPAK, 0, sizeof(KPAK));
    BN_clear_free(KPAK_x);
    BN_clear_free(KPAK_y);

    if (NULL != KPAKx) {
        memset(KPAKx, 0, strlen((char *)KPAKx));
        free(KPAKx);
    }
    if (NULL != KPAKy) {
        memset(KPAKy, 0, strlen((char *)KPAKy));
        free(KPAKy);
    }

    return KPAK_point;
} /* community_getKPAK_point*/

/***************************************************************************//**
 * Get the community 'Z' as a point.
 *
 * @return A pointer to the 'Z' point.
 ******************************************************************************/
EC_POINT *community_getZ_point(
    const uint8_t *community)
{
    uint8_t  error_encountered = 0;
    uint8_t  Z[COMMUNITY_MAX_Z_STR_LEN];
    size_t    Z_len            = 0;
    BIGNUM   *Z_x              = NULL;
    BIGNUM   *Z_y              = NULL;
    uint8_t  *Zx               = NULL;
    uint8_t  *Zy               = NULL;
    EC_GROUP *ms_curve         = NULL; /* Temporary reference. */
    EC_POINT *Z_point          = NULL;

    /*************************************************************************/
    /* Check passed parameters                                               */
    /*************************************************************************/
    if (NULL == community) {
        ES_ERROR("%s", "Community Storage Get Z Point, community is NULL!");
        error_encountered = ES_TRUE;
    }

    /*************************************************************************/
    /* Init.                                                                 */
    /*************************************************************************/
    if (!error_encountered) {
        memset(Z, 0, sizeof(Z));
        if (msdb_communityGetPubEncKey(community, (uint8_t *)&Z)) {
            ES_ERROR("Community Storage Get Z Point, could not retrieve 'Z' data for <%s>!",
                community);
        }
        else {
            if (!(Z_len = strlen((char *)Z))) {
                ES_ERROR("%s", "Community Storage Get Z Point, length is 0!");
            } else if (!(Zx = calloc(1, Z_len/2))) {
                ES_ERROR("%s", "Community Storage Get Z Point, could not allocate space for Zx!");
            } else if (!(Zy = calloc(1, Z_len/2))) {
                ES_ERROR("%s", "Community Storage Get Z Point, could not allocate space for Zy!");
            }
            else {
                snprintf((char *)Zx, ((Z_len-2)/2)+1, "%s", Z+2);
                snprintf((char *)Zy, ((Z_len-2)/2)+1, "%s", Z+2+((Z_len-2)/2));

               if (!BN_hex2bn(&Z_x,  (char *)Zx)) {
                    ES_ERROR("%s", "Community Storage Get Z Point, could create Zx BN!");
                } else if (!BN_hex2bn(&Z_y,  (char *)Zy)) {
                    ES_ERROR("%s", "Community Storage Get Z Point, could create Zy BN!");
                } else if (!(ms_curve = ms_getParameter_E(community_get_paramSet(community)))) {
                    ES_ERROR("%s", "Community Storage Get Z Point, error retrieving Curve 'E'!");
                } else if (!(Z_point = EC_POINT_new(ms_curve))) {
                    ES_ERROR("%s", "Community Storage Get Z Point, failed to create Z point!");
                } else if (!EC_POINT_set_affine_coordinates(ms_curve,
                            Z_point, Z_x, Z_y, NULL)) {
                    ES_ERROR("%s", "Community Storage Get Z Point, failed to set Z coordinates!");
                }
                /*   ES_DEBUG_DISPLAY_AFFINE_COORDS(ES_COMMUNITY_SECTION_NAME,
                 *       "   Z:", 8, ms_curve, Z_point);
                 */
            }
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    memset(Z, 0, sizeof(Z));
    BN_clear_free(Z_x);
    BN_clear_free(Z_y);

    if (NULL != Zx) {
        memset(Zx, 0, strlen((char *)Zx));
        free(Zx);
    }
    if (NULL != Zy) {
        memset(Zy, 0, strlen((char *)Zy));
        free(Zy);
    }

    return Z_point;
} /* community_getZ_point*/

/***************************************************************************//**
 * Output the KMS certificate (AKA community parameter set) for the specified 
 * community.
 * 
 * A debug function.
 ******************************************************************************/
void community_outputKMSCertificate(
    uint8_t *community) 
{
#ifdef ES_OUTPUT_DEBUG
    uint8_t value[ES_MAX_ATTR_LEN];
    short   revoked = 0; /* revoked is Boolean */

    ES_DEBUG("%s    Mikey Sakke Certificate (Community Set, from RFC 6509)",
             ES_COMMUNITY_SECTION_NAME);
    ES_DEBUG("%s    ======================================================",
             ES_COMMUNITY_SECTION_NAME);

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetVersion(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        Version:       <%s>", 
                 ES_COMMUNITY_SECTION_NAME, value);
    } else {
        ES_DEBUG("%s        Version:       could not be retrieved",
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetCertUri(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        CertUri:       <%s>",
                 ES_COMMUNITY_SECTION_NAME, value);
    } else {
        ES_DEBUG("%s        CertUri:       could not be retrieved",
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetKmsUri(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        KmsUri:        <%s>", ES_COMMUNITY_SECTION_NAME,
                 value);
    } else {
        ES_DEBUG("%s        KmsUri:        could not be retrieved",
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetIssuer(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        Isuuer:        <%s>",
                 ES_COMMUNITY_SECTION_NAME, value);
    } else {
        ES_DEBUG("%s        Issuer:        could not be retrieved", 
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetValidFrom(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        ValidFrom:     <%s>",ES_COMMUNITY_SECTION_NAME,
                 value);
    } else {
        ES_DEBUG("%s        ValidFrom:     could not be retrieved", 
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetValidTo(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        ValidTo:       <%s>", ES_COMMUNITY_SECTION_NAME, 
                 value);
    } else {
        ES_DEBUG("%s        ValidTo:       could not be retrieved", 
                 ES_COMMUNITY_SECTION_NAME);
    }

    if (!msdb_communityGetRevoked(community, (short *)&revoked)) {
        ES_DEBUG("%s        Revoked:       <%d>", ES_COMMUNITY_SECTION_NAME,
                 revoked);
    } else {
        ES_DEBUG("%s        Revoked:       could not be retrieved", 
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetUserIDFormat(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        UserIDFormat:  <%s>", ES_COMMUNITY_SECTION_NAME,
                 value);
    } else {
        ES_DEBUG("%s        UserIDFormat:  could not be retrieved",
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetPubEncKey(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        PubEncKey:     <%s>", ES_COMMUNITY_SECTION_NAME,
                 value);
    } else {
        ES_DEBUG("%s        PubEncKey:     could not be retrieved",
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetPubAuthKey(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        PubAuthKey:    <%s>", ES_COMMUNITY_SECTION_NAME,
                 value);
    } else {
        ES_DEBUG("%s        PubAuthKey:    could not be retrieved",
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
    if (!msdb_communityGetKmsDomainList(community, (uint8_t *)&value)) {
        ES_DEBUG("%s        KmsDomainList: <%s>", ES_COMMUNITY_SECTION_NAME,
                 value);
    } else {
        ES_DEBUG("%s        KmsDomainList: could not be retrieved", 
                 ES_COMMUNITY_SECTION_NAME);
    }

    memset(value, 0, sizeof(value));
#endif /* ES_OUTPUT_DEBUG */
} /* community_outputKMSCertificate  */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
