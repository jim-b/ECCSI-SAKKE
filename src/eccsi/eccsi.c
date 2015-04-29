/******************************************************************************/
/* ECCSI (Eliptic Curve based Certificateless Signatures for Identity-Based   */
/* Encryption). Described in RFC6507.                                         */
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
 * @file eccsi.c
 * @brief ECCSI (RFC 6507).
 *
 * Provides the functionality in support of RFC 6507, ECCSI (Elliptic 
 * Curve-Based Certificateless Signatures for Identity Based Encryption).
 ******************************************************************************/

/* OpenSSL */
#include <openssl/bn.h> 
#include <openssl/sha.h> 

#include "eccsi.h"
#include "global.h"
#include "log.h"

/* Debug strings. */
#define ECCSI_SECTION_NAME "(ECCSI)            " /*!< Section name output */

/* Error strings. */
#define ECCSI_ERR_SIGN     "ECCSI Sign, "                  /*!< Error str */
#define ECCSI_ERR_VERIFY   "ECCSI Verify Signature, "      /*!< Error str */
#define ECCSI_ERR_VAL_SSK  "ECCSI Validate SSK, "          /*!< Error str */
#define ECCSI_ERR_HS       "ECCSI Compute HS, "            /*!< Error str */
#define ECCSI_ERR_HE       "ECCSI Compute HE, "            /*!< Error str */

/******************************************************************************/
/* Forward declarations.                                                      */
/******************************************************************************/
static uint8_t computeHE(
    const uint8_t  *HS,      const size_t HS_len,
    const uint8_t  *r,       const size_t r_len,
    const uint8_t  *message, const size_t message_len,
    uint8_t       **hash_result);

/******************************************************************************/
/* Accessible functions.                                                      */
/*     eccsi_sign (sign a message)                                            */
/*     eccsi_verify (verify a signature)                                      */
/*                                                                            */
/*     eccsi_validateSSK Note! only called internally when user data is added */
/*                             see userParameters.c                           */
/******************************************************************************/

/***************************************************************************//**
 * Create an ECCSI signature for the specified message.
 *
 * @param[in]  message       Octet string of the 'message' that was signed.
 * @param[in]  message_len   Length of 'message' octet string.
 * @param[in]  user_id       Octet string pointer of the 'user_id'.
 * @param[in]  user_id_len   Length of 'user_id' octet string.
 * @param[in]  community     Octet string pointer of the 'community'.
 * @param[in]  j_random      Octet string pointer to an random ephemeral 
 *                           value of 'j''.
 * @param[in]  j_random_len  Length of ephemeral random 'j' octet string.
 * @param[out] signature     Resultant octet string 'signature'. 
 *                           Caller is responsible to clearing allocated 
 *                           memory.
 * @param[out] signature_len Resultant octet string 'signature' length.
 *
 * @return ES_SUCCESS, ES_FAILURE. Additionally, two other values may be 
 *         returned that indicate there was an issue withn the 'j' value 
 *         provided and that the user may try again with another value of 'j':
 *             ES_ECCSI_ERROR_SIGN_J_VALUE_NOT_IN_RANGE, 
 *             ES_ECCSI_ERROR_SIGN_J_VALUE_TESTS_FAILED.
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
    size_t         *signature_len)
{
    uint8_t         ret_val      = ES_FAILURE;
    short           error_encountered = ES_FALSE;
    uint8_t         tmp_res      = 0;

    /* Octet Strings */
    uint8_t        *kpak         = NULL;
    size_t          kpak_len     = 0;
    uint8_t        *HS           = NULL;
    size_t          HS_len       = 0;
    uint8_t        *r            = NULL;
    size_t          r_len        = 0;

    uint16_t       community_N   = 0;

    /* BIGNUMs */
    BIGNUM         *hash_bn      = NULL;
    BIGNUM         *HE_bn        = NULL;
    BIGNUM         *j_bn         = NULL;
    BIGNUM         *r_bn         = NULL;
    BIGNUM         *s_bn         = NULL;
    BIGNUM         *ssk_bn       = NULL;
    BIGNUM         *tmp_x_bn     = NULL;
    BIGNUM         *tmp_y_bn     = NULL;
    BIGNUM         *pvt_x_bn     = NULL;
    BIGNUM         *pvt_y_bn     = NULL;
    BIGNUM         *q_bn         = NULL;

    /* Curves */
    EC_GROUP       *nist_curve   = NULL;

    /* Curve Points */
    EC_POINT       *G_point      = NULL;
    EC_POINT       *PVT_point    = NULL;
    EC_POINT       *res_point    = NULL;

    int             r_bn_len     = 0;
    int             s_bn_len     = 0;
    int             pvt_x_bn_len = 0;
    int             pvt_y_bn_len = 0;

    size_t          offset       = 0;
    uint8_t        *hash_result  = NULL;
    BN_CTX         *bn_ctx       = NULL;

    /*************************************************************************/
    /* Check passed parameters                                               */
    /*************************************************************************/
    if (message == NULL) {
        ES_ERROR("%sMessage reference is NULL!", ECCSI_ERR_SIGN);
        error_encountered = ES_TRUE;
    } else if (user_id_len == 0) {
        ES_ERROR("%sMessage length is 0!", ECCSI_ERR_SIGN);
        error_encountered = ES_TRUE;
    } else if (user_id == NULL) {
        ES_ERROR("%sUser ID reference is NULL!", ECCSI_ERR_SIGN);
        error_encountered = ES_TRUE;
    } else if (user_id_len == 0) {
        ES_ERROR("%sUser ID length is 0!", ECCSI_ERR_SIGN);
        error_encountered = ES_TRUE;
    } else if (community == NULL) {
        ES_ERROR("%sCommunity reference is NULL!", ECCSI_ERR_SIGN);
    } else if (!community_exists(community)) {
        ES_ERROR("%sCommunity <%s> is not stored!", ECCSI_ERR_SIGN, community);
        error_encountered = ES_TRUE;
    } else if (j_random  == NULL) {
        ES_ERROR("%s'j' reference is NULL!", ECCSI_ERR_SIGN);
        error_encountered = ES_TRUE;
    } else if (j_random_len == 0) {
        ES_ERROR("%s'j' length is 0!", ECCSI_ERR_SIGN);
        error_encountered = ES_TRUE;
    } else if (*signature != NULL) {
        ES_ERROR("%spassed Signature reference is NOT NULL!", ECCSI_ERR_SIGN);
        error_encountered = ES_TRUE;
    } else if (*signature_len != 0) {
        ES_ERROR("%spassed Signature reference length is NOT 0!", ECCSI_ERR_SIGN);
        error_encountered = ES_TRUE;
    }

    /*************************************************************************/
    /* Init                                                                  */
    /*************************************************************************/
    if (!error_encountered) {
        if ((community_getKPAK_string(community, &kpak, &kpak_len))) {
            ES_ERROR("%scould not get KPAK!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(pvt_x_bn = user_getPVTx(user_id, user_id_len, community))) {
            ES_ERROR("%sunable to get pvt_x_bn!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(pvt_y_bn = user_getPVTy(user_id, user_id_len, community))) {
            ES_ERROR("%sunable to get pvt_y_bn!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(ssk_bn = user_getSSK(user_id, user_id_len, community))) {
            ES_ERROR("%sunable to get SSK!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(q_bn = community_getq_bn())) {
            ES_ERROR("%sunable to get q!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if ((community_N = community_get_N())==0) {
            /* Local copy of community N value i.e. size of 'r' and 
             * 's' signature.
             */
            ES_ERROR("%sunable to get community N value!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(hash_result = calloc(1, community_N))) {
            ES_ERROR("%scould not allocate space for hash!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
	} else if (!(nist_curve = community_get_NIST_P256_Curve())) {
            ES_ERROR("%scould not retrieve NIST curve!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(bn_ctx = BN_CTX_new())) {
            ES_ERROR("%scould not create BN context!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        }
    }

    /*************************************************************************/
    /*! Perform actions described in RFC6507 Section 5.2.1                   */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  RFC 6507 5.2.1", ECCSI_SECTION_NAME);
        ES_DEBUG("%s    - Signing requires KPAK, userID, SSK and PVT", 
                 ECCSI_SECTION_NAME);
        ES_DEBUG("%s      where PVT=(PVTx, PVTy)", ECCSI_SECTION_NAME);

        /* Create PVT point on the curve. */

        /* KPAK - obtained in Init (above). */
        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME, 
            "    KPAK (RFC 6507 Appendix A, page 13):", 6, kpak, kpak_len);

        /* Uer-Id */
        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME,
            "    ID (RFC 6507 Appendix A, page 13):", 6, user_id, user_id_len);

        /* SSK - also obtained in Init (above). */
        ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
            "    SSK (RFC 6507 Appendix A, page 14):", 6, ssk_bn);

        /* PVT */
        if (!(PVT_point = EC_POINT_new(nist_curve))) {
            ES_ERROR("%sunable to create Point 'PVT' on Curve 'NIST'!", 
                     ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(EC_POINT_set_affine_coordinates_GFp(nist_curve,
                      PVT_point, pvt_x_bn, pvt_y_bn, bn_ctx))) {
            ES_ERROR("%sunable to set coordinates for 'PVT'!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else {  
            ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME,
                "    PVT (RFC 6507 Appendix A, page 14):", 6, 
                nist_curve, PVT_point);

            if (!(j_bn = BN_new())) {
                ES_ERROR("%scould not create BN for 'j'!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (!(tmp_x_bn = BN_new())) {
                ES_ERROR("%scould not create BN for 'tmp x'!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (!(tmp_y_bn = BN_new())) {
                ES_ERROR("%scould not create BN for 'tmp y'!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (!(s_bn     = BN_new())) {
                ES_ERROR("%scould not create BN for 's'!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (!(HE_bn    = BN_new())) {
                ES_ERROR("%scould not create BN for 'HE'!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (!(G_point  = community_getG_point())) {
                ES_ERROR("%scould not get 'G point'!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } 
        }
    }
 
    /* If calculation fails with the specified value of 'j', we inform the 
     * caller so they can try another 'j' and they know what's going on.
     */

    /**************************************************************************/
    /*! STEP 1) Choose a random (ephemeral) non-zero value j in F_q           */
    /*                                                                        */
    /*          Instead, in this code this is passed in to this function.     */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  1) Choose a random (ephemeral) non-zero value j in F_q", 
                 ECCSI_SECTION_NAME);
        ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
            "    q (RFC 6507 Appendix A, page 13):", 6, q_bn);

        if (!(j_bn = BN_bin2bn((unsigned char *)j_random, j_random_len, j_bn))) {
            ES_ERROR("%s'j' BN creation failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        }
        else if ((NULL == j_bn) || (BN_is_zero(j_bn))) {
            /* Check 'j' within allowed range. */
            /* If not - give the user a chance to use another 'j'. */
            ES_ERROR("%s'j' for range check failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
            ret_val = ES_ECCSI_ERROR_SIGN_J_VALUE_NOT_IN_RANGE;
        } else if (!BN_mod(j_bn, j_bn, q_bn, bn_ctx)) {
            ES_ERROR("%sBN mod of 'j' for range check failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
            ret_val = ES_ECCSI_ERROR_SIGN_J_VALUE_NOT_IN_RANGE;
        } else if ((NULL == j_bn) || BN_is_zero(j_bn)) {
            /* j in F_q. */
            ES_ERROR("%s'j' not in range F_q!", ECCSI_ERR_SIGN);
            /* Give the user a chance use another 'j'. */
            error_encountered = ES_TRUE;
            ret_val = ES_ECCSI_ERROR_SIGN_J_VALUE_NOT_IN_RANGE;
        }
    }

    /**************************************************************************/
    /*! STEP 2) Compute J = (Jx,Jy) = [j]G and assign Jx to r                 */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME, 
            "  2) Compute J = (Jx,Jy) = [j]G and assign Jx to r. G is:", 
            6, nist_curve, G_point);

        if (!(res_point = EC_POINT_new(nist_curve))) {
            ES_ERROR("%sunable to create Point 'J' on 'NIST' Curve!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!EC_POINT_mul(nist_curve, res_point, 0, G_point, j_bn, bn_ctx)) {
            ES_ERROR("%sPoint mul '[j]G' failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME, "    J:", 6, 
                nist_curve, res_point);
        
            if (!(EC_POINT_get_affine_coordinates_GFp(
                         nist_curve, res_point, tmp_x_bn, tmp_y_bn, bn_ctx))) {
                ES_ERROR("%sunable to get coordinates for 'J'!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (!(r_bn = BN_dup(tmp_x_bn))) {
                ES_ERROR("%scould not create BN for 'r'!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (!(r_len = BN_num_bytes(r_bn))) {
                ES_ERROR("%slength of 'r' is 0!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (!(r = calloc(1, community_N))) {
                ES_ERROR("%smemory allocation for 'r' failed!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            } else if (community_N < BN_bn2bin(r_bn, r+(community_N-r_len))) {
                /* 'r' offset for padding */
                ES_ERROR("%slength of 'r' is too long, expected <%d>!", 
                    ECCSI_ERR_SIGN,  community_N);
                error_encountered = ES_TRUE;
            }
        }
    }

    /**************************************************************************/
    /*! STEP 3) Compute HE = hash( HS || r || M )                             */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  3) Compute HE = hash( HS || r || M )", 
                 ECCSI_SECTION_NAME);

        if (!(hash_bn = user_getHash(user_id, user_id_len, community))) {
            ES_ERROR("%sunable to retrieve 'hash'!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
                "    HS hash (RFC 6507 Appendix A, page 14):", 6, hash_bn);
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME, 
                "    r (RFC 6507 Appendix A, page 15):", 6, r, community_N);
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME, 
                "    M (RFC 6507 Appendix A, page 14):", 6, message, message_len);

            HS_len = community_N;

            if (!(HS = calloc(1, community_N))) { 
                ES_ERROR("%smemory allocation for HS hash failed!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            }
            else {
                offset = community_N-BN_num_bytes(hash_bn);
                if (!BN_bn2bin(hash_bn, HS+offset)) {
                    ES_ERROR("%slength of 'hash' incorrect!", ECCSI_ERR_SIGN);
                    error_encountered = ES_TRUE;
                } else if (computeHE(HS,      community_N,
                                     r,       community_N,
                                     message, message_len,
                                     &hash_result)) {
                    ES_ERROR("%sHE hash failed!", ECCSI_ERR_SIGN);
                    error_encountered = ES_TRUE;
                } 
                else { /* Success, so far */
                    ES_DEBUG_DISPLAY_HASH(ECCSI_SECTION_NAME, 
                        "    HE (RFC 6507 Appendix A, page 15):", 6, 
                        (char *)hash_result, community_N);
                }
            }
            tmp_res = 0;
        }
    }

    /**************************************************************************/
    /*! STEP 4) Verify that HE + r * SSK is non-zero (mod q)
     *
     *    If this fails we must abort and tell the user, so they can try with
     *    another 'j' value.
     **************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  4) Verify that HE + r * SSK is non-zero (mod q)", 
                 ECCSI_SECTION_NAME);

        if (!(BN_bin2bn(hash_result, community_N, HE_bn))) {
            ES_ERROR("%screating 'HE' hash BN failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(BN_mod_mul(s_bn, r_bn, ssk_bn, q_bn, bn_ctx))) {
            ES_ERROR("%sMUL 'r * SSK' failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(BN_mod_add(s_bn, s_bn, HE_bn, q_bn, bn_ctx))) {
            ES_ERROR("%sADD 'HE + r * SSK' failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if ((!s_bn) || (BN_is_zero(s_bn))) {
            ES_ERROR("%s'HE+r*SSK!=zero' check failed. Try another 'j' value!", 
                     ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG("%s    HE + r * SSK non-zero (mod q) - verified", 
                     ECCSI_SECTION_NAME);
        }
    }

    /*************************************************************************/
    /*! STEP 5) Compute s' = ( (( HE + r * SSK )^-1) * j ) (mod q) 
     *          and erase ephemeral 'j'.
     *************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  5) Compute s' = ( (( HE + r * SSK )^-1) * j ) (mod q)",
                 ECCSI_SECTION_NAME);
        ES_DEBUG("%s     MUST then erase the value 'j'", ECCSI_SECTION_NAME);

        if (!(BN_mod_inverse(s_bn, s_bn, q_bn, bn_ctx))) {
            ES_ERROR("%s'(HE + r * SSK)^-1' failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        } else if (!(BN_mod_mul(s_bn, s_bn, j_bn, q_bn, bn_ctx))) {
            ES_ERROR("%s(((HE + r * SSK)^-1) * j) (mod q) failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        }
        ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME,
            "    s' (RFC 6507 Appendix A, page 15):", 6, s_bn);

        if (!BN_zero(j_bn)) {
            ES_ERROR("%serase 'j' failed!", ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG("%s    (local) 'j' erased!", ECCSI_SECTION_NAME);
            ES_DEBUG("%s   - NB callers reponsible for removing their copy of 'j'", 
                ECCSI_SECTION_NAME);
        }
    }

    /*************************************************************************/
    /*! STEP 6) Set s = q - s' if octet_count(s) > N                         */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  6) Set s = q - s' if octet_count(s) > N", 
                 ECCSI_SECTION_NAME);

        /* Note from RFC step 6 Section 5.2.1 is necessary because it is 
         * possible for q (and hence element of F_q) to be too big to fit 
         * within N octets. The Signer MAY instead elect to set s to be the 
         * least integer of s' and q-s', represented in N octets
         */

        if (BN_num_bytes(s_bn) > community_N) { 
            ES_DEBUG("%s    octet_count(s) > N? - YES, setting s = q -s'",
                     ECCSI_SECTION_NAME);
            if (!BN_sub(s_bn, q_bn, s_bn)) {
                ES_ERROR("%serase 'j' failed!", ECCSI_ERR_SIGN);
                error_encountered = ES_TRUE;
            }
            else {
                ES_DEBUG("%s    s set to q - s'",
                    ECCSI_SECTION_NAME);
            }
        }
        else {
            ES_DEBUG("%s    octet_count(s) > N? - NO, so OK", 
                     ECCSI_SECTION_NAME);
        }
   
        ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
            "    s (RFC 6507 Appendix A, page 15):", 11, s_bn);
    }

    /*************************************************************************/
    /*! STEP 7) Output the signature SIG = ( r || s || PVT )                 */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  7) Output the signature SIG = ( r || s || PVT )", 
                 ECCSI_SECTION_NAME);

        if ((*signature = calloc(1, (community_N*4)+1))) {
            /* Check r, s, pvt_x and pvt_y are > 0 and <= community_N. */
            r_bn_len     = BN_num_bytes(r_bn);             
            s_bn_len     = BN_num_bytes(s_bn);             
            pvt_x_bn_len = BN_num_bytes(pvt_x_bn);
            pvt_y_bn_len = BN_num_bytes(pvt_y_bn);

            if ((r_bn_len == 0) || (r_bn_len > community_N)) {
                ES_ERROR("%s'r' length incorrect <%d>!", 
                         ECCSI_ERR_SIGN, r_bn_len);
                error_encountered = ES_TRUE;
            }
            else if ((s_bn_len == 0) || (s_bn_len > community_N)) {
                ES_ERROR("%s's' length incorrect <%d>!", 
                         ECCSI_ERR_SIGN, s_bn_len);
                error_encountered = ES_TRUE;
            }
            else if ((pvt_x_bn_len == 0) || (pvt_x_bn_len > community_N)) {
                ES_ERROR("%s'PVTx' length incorrect <%d>!", 
                         ECCSI_ERR_SIGN, pvt_x_bn_len);
                error_encountered = ES_TRUE;
            }
            else if ((pvt_y_bn_len == 0) || (pvt_y_bn_len > community_N)) {
                ES_ERROR("%s'PVTy' length incorrect <%d>!", 
                         ECCSI_ERR_SIGN, pvt_y_bn_len);
                error_encountered = ES_TRUE;
            } 
            else {
                /* r */
                offset  += (community_N - r_bn_len);
                offset  += BN_bn2bin(r_bn, (*signature)+offset);
    
                /* s */
                offset  += (community_N - s_bn_len);
                offset  += BN_bn2bin(s_bn, (*signature)+offset);

                /* 0x04 */
                memset(*signature+offset, 0x04, 1); 
                offset++;

                /* PVT */
                offset  += (community_N - pvt_x_bn_len);
                offset  += BN_bn2bin(pvt_x_bn, *signature+offset);

                offset  += (community_N - pvt_y_bn_len);
                offset  += BN_bn2bin(pvt_y_bn, *signature+offset);

                *signature_len = offset;
                ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME, 
                    "    Signature (RFC 6507, Page 15, 'Sig'):", 6, 
                    *signature, *signature_len);

                if (*signature_len != ((community_N * 4) + 1)) {
                    ES_ERROR("%ssignature length check failed <%lu> expected <%d>!", 
                        ECCSI_ERR_SIGN, *signature_len, (community_N * 4) + 1);
                    ret_val = ES_ECCSI_ERROR_SIGN_J_VALUE_TESTS_FAILED;
                }
                else { /* All is well. */
                    ret_val = ES_SUCCESS;
                }
            }
        }
        else {
            ES_ERROR("%smemory allocation for 'Signature' failed!", 
                     ECCSI_ERR_SIGN);
            error_encountered = ES_TRUE;
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    /* BIGNUMs */
    BN_clear_free(hash_bn);
    BN_clear_free(HE_bn);
    BN_clear_free(j_bn);
    BN_clear_free(pvt_x_bn);
    BN_clear_free(pvt_y_bn);
    BN_clear_free(r_bn);
    BN_clear_free(s_bn);
    BN_clear_free(ssk_bn);
    BN_clear_free(tmp_x_bn);
    BN_clear_free(tmp_y_bn);
    q_bn       = NULL; /* Temporary reference */

    /* Curve */
    nist_curve = NULL;

    /* Octet Strings */
    if (NULL != kpak) {
        memset(kpak, 0, kpak_len);
        free(kpak);
        kpak     = NULL;
        kpak_len = 0;
    }
    if (NULL != HS) { 
        memset(HS, 0, HS_len); 
        free(HS); 
        HS     = NULL; 
        HS_len = 0; 
    }
    if (NULL != hash_result) {
        memset(hash_result , 0, community_N);
        free(hash_result);
    }
    if (NULL != r) { 
        memset(r, 0, r_len); 
        free(r); 
        r     = NULL; 
        r_len = 0; 
    }

    /* Points */
    G_point = NULL; /* Temporary reference. */
    EC_POINT_clear_free(PVT_point);
    EC_POINT_clear_free(res_point);

    /* BN Context */
    if (NULL != bn_ctx) {
       BN_CTX_free(bn_ctx);
    }

    return ret_val;

} /* eccsi_Sign */

/***************************************************************************//**
 * Verifies an ECCSI signature following the Actions described in section 5.2.2
 * of RFC 6507.
 *
 * @param[in] message        Octet string of the 'message' that was signed.
 * @param[in] message_len    Length of 'message' octet string.
 * @param[in] signature      Octet string of the message 'signature'.
 * @param[in] signature_len  Length of 'signature' octet string.
 * @param[in] user_id        Octet string pointer of the 'user_id'.
 * @param[in] user_id_len    Length of 'user_id' octet string.
 * @param[in] community      Octet string pointer of the 'community'.
 *
 * @return ES_SUCCESS, ES_FAILURE (general failure). Additionally, if the 
 *         verify actually failed then ES_ECCSI_ERROR_VERIFY_FAILED is 
 *         returned.
 *****************************************************************************/
uint8_t eccsi_verify(
    const uint8_t *message,
    const size_t   message_len,
    const uint8_t *signature,
    const size_t   signature_len,
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    uint8_t        ret_val                = ES_FAILURE;
    BN_CTX        *bn_ctx                 = BN_CTX_new();

    BIGNUM        *HE_bn                  = NULL;
    BIGNUM        *HS_bn                  = NULL;
    BIGNUM        *Jx_bn                  = NULL;
    BIGNUM        *Jy_bn                  = NULL;
    BIGNUM        *p_bn                   = NULL; /* Temporary reference */
    BIGNUM        *pvt_x_bn               = NULL;
    BIGNUM        *pvt_y_bn               = NULL; 
    BIGNUM        *r_bn                   = NULL;
    BIGNUM        *s_bn                   = NULL;

    uint8_t       *G                      = NULL;
    size_t         G_len                  = 0;
    uint8_t       *KPAK                   = NULL;
    size_t         KPAK_len               = 0; 

    EC_GROUP      *ms_curve               = NULL;
    EC_GROUP      *nist_curve             = NULL;

    EC_POINT      *kpak_nist_point        = NULL;
    EC_POINT      *pvt_ms_point           = NULL;
    EC_POINT      *pvt_nist_point         = NULL;
    EC_POINT      *J_point                = NULL;
    EC_POINT      *Y_point                = NULL;
    EC_POINT      *G_point                = NULL;

    size_t         expected_signature_len = 0;
    uint8_t        ms_param_set           = 0;
    short          error_encountered      = ES_FALSE;

    uint16_t       community_N            = 0;

    uint8_t       *HS_hash_result         = NULL;
    uint8_t       *HE_hash_result         = NULL;

    /* ES_DEBUG("                     ***%s:%s:%d", 
     * __FUNCTION__, __FILE__, __LINE__);
     */

    /*************************************************************************/
    /* Check passed parameters                                               */
    /*************************************************************************/
    if (user_id == NULL) {
        ES_ERROR("%sUser ID reference is NULL!", ECCSI_ERR_VERIFY);
        error_encountered = ES_TRUE;
    } else if (user_id_len == 0) {
        ES_ERROR("%sUser ID length is 0!", ECCSI_ERR_VERIFY);
        error_encountered = ES_TRUE;
    } else if (community == NULL) {
        ES_ERROR("%scommunity reference is NULL!", ECCSI_ERR_VERIFY);
        error_encountered = ES_TRUE;
    } else if (!community_exists(community)) {
        ES_ERROR("%scommunity <%s> is not stored!", 
                 ECCSI_ERR_VERIFY, community);
        error_encountered = ES_TRUE;
    }

    /*************************************************************************/
    /* Init.                                                                 */
    /*************************************************************************/
    if (!error_encountered) {
        /* We only support MS parameter set. */
        if (1 != (ms_param_set = community_get_paramSet(community))) {
            ES_ERROR("%sMS Parameter != 1 <%d> not supported",
                     ECCSI_ERR_VERIFY, ms_param_set);
            error_encountered = ES_TRUE;
        } else if (!(community_N = community_get_N())) {
            /* Local copy of community N value (i.e.size of 'r' and 
             * 's' n signature.
             */
            ES_ERROR("%sunable to get community N value!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if (!(HS_hash_result = calloc(1, community_N))) {
            ES_ERROR("%scould not allocate space for HS hash!", 
                     ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if (!(HE_hash_result = calloc(1, community_N))) {
            ES_ERROR("%scould not allocate space for HE hash!", 
                     ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else {
            /* No value in continuing if signature is not the correct size; 
             * two  N-octet integers r and s, plus an elliptical curve point
             * PVT over E expressed in uncompressed form with length 2N -- 
             * See RFC6507 3.3)
             */
            ES_DEBUG("%s  RFC 6507 3.3 Check Signature Length", 
                     ECCSI_SECTION_NAME); 

            expected_signature_len = (community_N * 4)+1;
            if (signature_len != expected_signature_len) {
                ES_ERROR("%swrong sig len <%lu> expected <%lu>!",
                         ECCSI_ERR_VERIFY, signature_len, 
                         expected_signature_len);
                error_encountered = ES_TRUE;
            } 
            /* Get reference to curves we're going to use */
            else if (!(ms_curve = ms_getParameter_E(ms_param_set))) {
                ES_ERROR("%scould not retrieve 'E' Curve!", ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            }
            else if (!(nist_curve = community_get_NIST_P256_Curve())) {
                ES_ERROR("%scould not retrieve 'NIST' curve!", 
                         ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            } 
            /* Parse the signature for r(32), s(32), pvt(65) */
            else if (!(r_bn = BN_bin2bn(signature, community_N, NULL))) {
                ES_ERROR("%screating 'r' BN failed!", ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            } else if (!(s_bn = BN_bin2bn(signature+community_N, 
                                          community_N, NULL))) {
                ES_ERROR("%screating 's' BN failed!", ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            } else if (!(pvt_x_bn = BN_bin2bn(signature+65, 32, NULL))) {
                ES_ERROR("%screating PVT_x BN failed!", ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            } else if (!(pvt_y_bn = BN_bin2bn(signature+97, 32, NULL))) {
                ES_ERROR("%screating PVT_y BN failed!", ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            }
        }
    }

    /*************************************************************************/
    /*! Perform actions described in RFC6507 Section 5.2.2                   */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  RFC 6507 5.2.2", ECCSI_SECTION_NAME);
    }

    /*************************************************************************/
    /*! STEP 1.    Check that PVT lies on the elliptical curve E             */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  1) The verifier MUST check that the PVT",
                 ECCSI_SECTION_NAME);
        ES_DEBUG("%s     lies on the elliptical curve E", ECCSI_SECTION_NAME);

        if (!(pvt_ms_point = EC_POINT_new(ms_curve))) {
            ES_ERROR("%sunable to create Point 'PVT' on Curve 'E'!", 
                     ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if (!(EC_POINT_set_affine_coordinates_GFp(
                     ms_curve, pvt_ms_point, 
                     pvt_x_bn, pvt_y_bn, bn_ctx))) {
            ES_ERROR("%sunable to set coordinates for 'PVT'!", 
                     ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else {
            ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME, 
                "    PVT (RFC 6507 Appendix A, page 14):", 6, 
                ms_curve, pvt_ms_point);
            /* Check the point is on the curve. */
            if (!EC_POINT_is_on_curve(ms_curve, pvt_ms_point, bn_ctx)) {
                ES_DEBUG("%s    Is PVT point on the curve? - YES", 
                         ECCSI_SECTION_NAME);
            } else {
                ES_DEBUG("%s    Is PVT point on the curve? - NO", 
                         ECCSI_SECTION_NAME);
                error_encountered = ES_TRUE;
            }
        }
    }

    /*************************************************************************/
    /*! STEP  2.    Compute HS = hash(G || KPAK || ID || PVT)                */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  2) Compute HS = hash(G || KPAK || ID || PVT)", 
                 ECCSI_SECTION_NAME);

        /* Prepare terms - (see step 2 description above) */
 
        /* G */   
        if (community_getG_string(&G, &G_len)) {
            ES_ERROR("%scould not get 'G'!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else {
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME, 
                "    G:", 6, G, G_len);

            /* KPAK */
            if (community_getKPAK_string(community, &KPAK, &KPAK_len)) {
                ES_ERROR("%scould not get 'KPAK'!", ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            }
            else {
                ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME, 
                    "    KPAK:", 6, KPAK, KPAK_len);

                /* ID */
                ES_DEBUG_PRINT_ID(ECCSI_SECTION_NAME, 
                    "    Alice-ID:", 6, user_id, user_id_len-1);

                ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME, 
                    "    PVT:", 6, signature+64, 65);

                /* Calculations */
                if (computeHS(G,         G_len, 
                              KPAK,      KPAK_len,
                              user_id,   user_id_len,
                              signature+64, 65, /* pvt retrieved from message. 
                                                 * JRB MAGIC NUMBERS
                                                 */
                              &HS_hash_result)) {
                    ES_ERROR("%scompute HS Hash failed!", ECCSI_ERR_VERIFY);
                    error_encountered = ES_TRUE;
                }
                else if (!(HS_bn = BN_bin2bn(HS_hash_result, community_N, NULL))) {
                   ES_ERROR("%screating HS Hash BN failed!", ECCSI_ERR_VERIFY);
                   error_encountered = ES_TRUE;
                } 
                else {
                    ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
                        "    HS (RFC 6507 Appendix A, page 14):", 6, HS_bn);
                }
            }
        }
    }

    /*************************************************************************/
    /*! STEP  3.    Compute HE = hash( HS || r || M )                        */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  3) Compute HE = hash( HS || r || M )", 
                 ECCSI_SECTION_NAME);

        /* Prepare terms - HS, r and M[essage], all obtained above. */

        /* Calculations */
        if (computeHE(HS_hash_result, SHA256_DIGEST_LENGTH,
                      signature, 32,/* r retrieved from  start of signature */
                      message, message_len,
                      &HE_hash_result)) {
            ES_ERROR("%scompute HE Hash failed!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if (!(HE_bn = BN_bin2bn(HE_hash_result, 32, NULL))) {
            ES_ERROR("%screating HE Hash BN failed!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else {
            ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
                "    HE Hash (RFC 6507 Appendix A, page 15):", 6, HE_bn);
        }
    }

    /*************************************************************************/
    /*! STEP 4.    Y = [HS]PVT + KPAK                                        */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  4) Y = [HS]PVT + KPAK", ECCSI_SECTION_NAME);

        /* Prepare terms */
        if (!(Y_point = EC_POINT_new(nist_curve))) { /* Result point. */
            ES_ERROR("%sunable to create Point 'Y' on Curve 'NIST'!", 
                     ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        }
        else {
            /* HS hash (calculated above). */
            ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
                "    HS Hash (RFC 6507 Appendix A, page 14):", 6, HS_bn);

            /* Create a point for PVT on NIST curve. */
            if (!(pvt_nist_point = EC_POINT_new(nist_curve))) { 
                ES_ERROR("%sunable to create Point 'PVT' on Curve 'NIST'!", 
                         ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            }
            /* Below - use same co-ordinates as previously obtained above 
             * for PVTx_bn and PVTy_bn. 
             */
            else if (!(EC_POINT_set_affine_coordinates_GFp(nist_curve, 
                         pvt_nist_point, pvt_x_bn, pvt_y_bn, bn_ctx))) {
                ES_ERROR("%sunable to set coordinates for 'PVT'!", 
                         ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            }
            else {
                ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME,
                    "    PVT (RFC 6507 Appendix A, page 14):", 6, 
                    nist_curve, pvt_nist_point);

                /* Create a point for KPAK on NIST curve. */
                if (!(kpak_nist_point = community_getKPAK_point(community))) {
                    ES_ERROR("%sunable to retrieve KPAK point!", 
                             ECCSI_ERR_VERIFY);
                    error_encountered = ES_TRUE;
                }
                else {
                    ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME,
                        "    KPAK (RFC 6507 Appendix A, page 13)", 6, 
                        nist_curve, kpak_nist_point);

                    /* Calculations */
                    if (!EC_POINT_mul(nist_curve, Y_point, 0, 
                                      pvt_nist_point, HS_bn, bn_ctx)) {
                        ES_ERROR("%sPoint mul '[HS]PVT' failed!", 
                                 ECCSI_ERR_VERIFY);
                        error_encountered = ES_TRUE;
                    } else if (!EC_POINT_add(nist_curve, Y_point, Y_point, 
                                             kpak_nist_point, bn_ctx)) {
                        ES_ERROR("%sPoint add '[HS]PVT + KPAK' failed!", 
                                 ECCSI_ERR_VERIFY);
                        error_encountered = ES_TRUE;
                    } else {
                        ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME,
                            "    Y (RFC 6507 Appendix A, page 15):", 6, 
                            nist_curve, Y_point);
                    }
                }
            }
        }
    }

    /*************************************************************************/
    /*! STEP 5.    Compute J = [s]([HE]G + [r]Y)                             */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  5) Compute J = [s]([HE]G + [r]Y)", ECCSI_SECTION_NAME);
        ES_DEBUG("%s    Bignums s, HE and r. Points on NIST curve J, G and Y.", 
                 ECCSI_SECTION_NAME);
        ES_DEBUG("%s    HE and Y shown above.", ECCSI_SECTION_NAME);

        /* Prepare terms */
        if (!(J_point = EC_POINT_new(nist_curve))) { /* For result */
            ES_ERROR("%sunable to create Point 'J' on Curve 'NIST'!", 
                     ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } 
        else {
            ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
                "    r (RFC 6507 Appendix A, page 15):", 6, r_bn);
            ES_DEBUG_DISPLAY_BN(ECCSI_SECTION_NAME, 
                "    s (RFC 6507 Appendix A, page 15):", 6, s_bn);

            /* HE hash calculated above. */
            /* G_point used in calculation so duplicate. */
            if (!(G_point = EC_POINT_dup(community_getG_point(), nist_curve))) {
                ES_ERROR("%sunable to create Point 'J' on Curve 'NIST'!", 
                         ECCSI_ERR_VERIFY);
                error_encountered = ES_TRUE;
            }
            else {
                /* Calculations */
                /*! [HE]G             */
                if (!EC_POINT_mul(nist_curve, G_point, 0, G_point, HE_bn, bn_ctx)) {
                    ES_ERROR("%sPoint mul '[HE]G' failed!", ECCSI_ERR_VERIFY);
                    error_encountered = ES_TRUE;
                } else /*! [r]Y              */
                if (!EC_POINT_mul(nist_curve, Y_point, 0, Y_point, r_bn, bn_ctx)) {
                    ES_ERROR("%sPoint mul '[r]Y' failed!", ECCSI_ERR_VERIFY);
                    error_encountered = ES_TRUE;
                } else /*! [HE]G + [r]Y      */
                if (!EC_POINT_add(nist_curve, J_point, G_point, Y_point, bn_ctx)) {
                    ES_ERROR("%sPoint add '[HE]G + [r]Y' failed!", 
                             ECCSI_ERR_VERIFY);
                    error_encountered = ES_TRUE;
                } else /*! [s]([HE]G + [r]Y) */
                if (!EC_POINT_mul(nist_curve, J_point, 0, J_point, s_bn, bn_ctx)) {
                    ES_ERROR("%sPoint add '[s]([HE]G + [r]Y)' failed!", 
                             ECCSI_ERR_VERIFY);
                    error_encountered = ES_TRUE;
                } else {
                    ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME,
                        "    J (RFC 6507 Appendix A, page 15):", 6, 
                        nist_curve, J_point);
                }
            }
        }
    }

    /*************************************************************************/
    /*! STEP 6.     Jx = r mod p, and Jx mod p != 0                          */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  6) Viewing J in affine coordinates (Jx,Jy), check", 
                 ECCSI_SECTION_NAME);
        ES_DEBUG("%s     that Jx = r mod p, and that Jx mod p != 0", 
                 ECCSI_SECTION_NAME);

        /* Prepare terms */
        if (!(Jx_bn = BN_new())) {
            ES_ERROR("%scould not create BN for 'Jx'!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if (!(Jy_bn = BN_new())) {
            ES_ERROR("%scould not create BN for 'Jy'!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if (!(EC_POINT_get_affine_coordinates_GFp(
                     nist_curve, J_point, Jx_bn, Jy_bn, bn_ctx))) {
            ES_ERROR("%sunable to get coordinates for 'J'!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if (!(p_bn = community_get_p())) {
            ES_ERROR("%scould not retrieve BN for 'p'!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if (!BN_mod(r_bn, r_bn, p_bn, bn_ctx)) { /* Calculations */
            ES_ERROR("%s'r' mod 'p' failed!", ECCSI_ERR_VERIFY);
            error_encountered = ES_TRUE;
        } else if ((BN_cmp(Jx_bn, r_bn) == 0) && (!BN_is_zero(Jx_bn))) {
            ES_DEBUG("%s    Does Jx = r mod p, and Jx mod p != 0? - YES", 
                     ECCSI_SECTION_NAME);
            ret_val = ES_SUCCESS;
        } else {
            ES_DEBUG("%s    Does Jx = r mod p, and Jx mod p != 0? - NO", 
                     ECCSI_SECTION_NAME);
            ret_val = ES_ECCSI_ERROR_VERIFY_FAILED;
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    BN_clear_free(Jx_bn);
    BN_clear_free(Jy_bn);
    p_bn         = NULL; /* Temporary reference */
    BN_clear_free(pvt_x_bn);
    BN_clear_free(pvt_y_bn);
    BN_clear_free(r_bn);
    BN_clear_free(s_bn);
    BN_clear_free(HE_bn);
    BN_clear_free(HS_bn);

    ms_curve     = NULL; /* Temporary reference */
    nist_curve   = NULL; /* Temporary reference */

    EC_POINT_clear_free(kpak_nist_point);
    EC_POINT_clear_free(pvt_ms_point);
    EC_POINT_clear_free(pvt_nist_point);
    EC_POINT_clear_free(J_point);
    EC_POINT_clear_free(Y_point);
    EC_POINT_clear_free(G_point);

    ms_param_set = 0;

    if (NULL != HE_hash_result) {
        memset(HE_hash_result, 0, community_N);
        free(HE_hash_result);
    }
    if (NULL != HS_hash_result) {
        memset(HS_hash_result, 0, community_N);
        free(HS_hash_result);
    }
    if (KPAK != NULL) {
        memset(KPAK, 0, KPAK_len);
        free(KPAK);
    }

    BN_CTX_free(bn_ctx);

    return ret_val;

} /* eccsi_verify */

/***************************************************************************//**
 * Validate a received (from KMS) SSK (RFC 6507 Section 5.1.2)
 *
 * Every SSK MUST be validated before being installed as a signing key.
 * The Signer uses its ID and the KPAK to validate a received (SSK,PVT)
 * pair.  
 *
 * @param[in]  user_id       Octet string pointer for 'user_id'.
 * @param[in]  user_id_len   Length of 'user_id' octet string.
 * @param[in]  community     Octet string pointer for 'community'.
 * @param[in]  SSK           Octet string pointer for 'SSK'.
 * @param[in]  SSK_len       Length of 'SSK' octet string.
 * @param[in]  KPAK          Octet string pointer for 'KPAK'.
 * @param[in]  KPAK_len      Length of 'KPAK' octet string.
 * @param[in]  PVT           Octet string pointer for 'PVT'.
 * @param[in]  PVT_len       Length of 'PVT' octet string.
 * @param[out] hash          Octet string pointer for resultant 'hash'.
 * @param[out] hash_len      Length of resultant 'hash' octet string.
 *
 * @return ES_SUCCESS or ES_FAILURE or ES_ECCSI_ERROR_SSK_VALIDATION_FAILED
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
    size_t         *hash_len) 
{
    uint8_t         ret_val           = ES_FAILURE;
    short           error_encountered = ES_FALSE;

    /* BNs */
    BIGNUM *SSK_bn            = NULL;
    BIGNUM *hash_bn           = NULL;
    BIGNUM *PVTx_bn           = NULL;
    BIGNUM *PVTy_bn           = NULL;

    uint8_t  *G               = NULL;
    size_t    G_len           = 0;

    /* Curves */
    EC_GROUP *nist_curve      = NULL;

    /* Temporary Points */
    EC_POINT *P_point         = NULL;
    EC_POINT *PVT_point       = NULL;
    EC_POINT *KPAK_point      = NULL;
    EC_POINT *LHS_point       = NULL;
    EC_POINT *RHS_point       = NULL;
    BN_CTX   *bn_ctx          = NULL;

    uint8_t   ms_param_set    = 0;
    uint16_t  community_N     = 0;

    /* ES_DEBUG("                      ***%s:%s:%d", 
     * __FUNCTION__, __FILE__, __LINE__);
     */

    /*************************************************************************/
    /* Check passed parameters                                               */
    /*************************************************************************/
    if (user_id == NULL) {
        ES_ERROR("%sUser ID reference is NULL!", ECCSI_ERR_VAL_SSK);
        error_encountered = ES_TRUE;
    } else if (user_id_len == 0) {
        ES_ERROR("%sUser ID length is 0!", ECCSI_ERR_VAL_SSK);
        error_encountered = ES_TRUE;
    } else if (community == NULL) {
        ES_ERROR("%sCommunity reference is NULL!", ECCSI_ERR_VAL_SSK);
        error_encountered = ES_TRUE;
    } else if (!community_exists(community)) {
        ES_ERROR("%sCommunity <%s> is not stored!", ECCSI_ERR_VAL_SSK, 
                 community);
        error_encountered = ES_TRUE;
    } else if (SSK == NULL) {
        ES_ERROR("%sSSK reference is NULL!", ECCSI_ERR_VAL_SSK);
        error_encountered = ES_TRUE;
    } else if (SSK_len < 32) { 
        ES_ERROR("%sSSK length is too short <%lu> expected <%d>!", 
                 ECCSI_ERR_VAL_SSK, SSK_len, 32);
        error_encountered = ES_TRUE;
    } else if (KPAK == NULL) {
        ES_ERROR("%sKPAK reference is NULL!", ECCSI_ERR_VAL_SSK);
        error_encountered = ES_TRUE;
    } else if (KPAK_len < 32) {
        ES_ERROR("%sKPAK length is too short <%lu> expected <%d>!", 
                 ECCSI_ERR_VAL_SSK, KPAK_len, 32);
        error_encountered = ES_TRUE;
    } else if (PVT == NULL) {
        ES_ERROR("%sPVT reference is NULL!", ECCSI_ERR_VAL_SSK);
        error_encountered = ES_TRUE;
    } else if (PVT_len < 32) { 
        ES_ERROR("%sPVT length is too short <%lu> expected <%d>!", 
                 ECCSI_ERR_VAL_SSK, PVT_len, 32);
        error_encountered = ES_TRUE;
    }

    /**************************************************************************/
    /* Init                                                                   */
    /**************************************************************************/
    if (!error_encountered) {
        /* N gives us 's' and 'r' and 'hash' size. */
        if (!(community_N = community_get_N())) {
            ES_ERROR("%sUnable to get community 'N' value from <%s>!\n", 
                     ECCSI_ERR_VAL_SSK, community);
            error_encountered = ES_TRUE;
        }
        else {
            *hash_len  = community_N;
            if (!(*hash = (uint8_t *)calloc(1, *hash_len))) {
                ES_ERROR("%scould not allocate space for hash!", 
                         ECCSI_ERR_VAL_SSK);
                error_encountered = ES_TRUE;
            } else if (!(nist_curve = community_get_NIST_P256_Curve())) {
                ES_ERROR("%scould not retrieve NIST curve!", ECCSI_ERR_VAL_SSK);
                error_encountered = ES_TRUE;
            } else if (!(bn_ctx = BN_CTX_new())) { 
                ES_ERROR("%scould not create BN context!", ECCSI_ERR_VAL_SSK);
                error_encountered = ES_TRUE;
            }
        }
    }

    /**************************************************************************/
    /*! Perform actions described in RFC6507 Section 5.1.2                    */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  RFC 6507 5.1.2 - Validate received SSK", 
            ECCSI_SECTION_NAME);
    }

    /**************************************************************************/
    /*! 1) Validate that the PVT lies on the curve E                          */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  1) Create point PVT on curve E and validate it",
                 ECCSI_SECTION_NAME);
        ES_DEBUG("%s     - will fail if not on curve", ECCSI_SECTION_NAME);

        /* Create a point on the curve 'E'. */
        if (1 != (ms_param_set = community_get_paramSet(community))) {
            ES_ERROR("%sMS Parameter != 1 <%d> not supported", 
                     ECCSI_ERR_VAL_SSK, ms_param_set);
            error_encountered = ES_TRUE;
        } else if (!(PVTx_bn = BN_bin2bn(PVT+1, PVT_len/2, NULL))) {
            ES_ERROR("%sunable to create PVTx BN!", ECCSI_ERR_VAL_SSK);
            error_encountered = ES_TRUE;
        } else if (!(PVTy_bn = BN_bin2bn(PVT+1+(PVT_len/2), PVT_len/2, NULL))) {
            ES_ERROR("%sunable to create PVTy BN!", ECCSI_ERR_VAL_SSK);
            error_encountered = ES_TRUE;
        } else if (!(P_point = EC_POINT_new(
                      ms_getParameter_E(ms_param_set)))) {
            ES_ERROR("%sunable to create Point 'P' on Curve 'E'!", 
                     ECCSI_ERR_VAL_SSK);
            error_encountered = ES_TRUE;
        } else if (!(EC_POINT_set_affine_coordinates_GFp(
                      ms_getParameter_E(ms_param_set), 
                          P_point, PVTx_bn, PVTy_bn, bn_ctx))) {
            ES_ERROR("%sunable to set coordinates for 'P'!", ECCSI_ERR_VAL_SSK);
            error_encountered = ES_TRUE;
        } else {
            ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME,
                "    PVT (RFC 6507 Appendix A, page 14):", 6, 
                ms_getParameter_E(ms_param_set), P_point);

            if (!EC_POINT_is_on_curve(ms_getParameter_E(ms_param_set), 
                                      P_point, bn_ctx)) {
                ES_DEBUG("%s    Is POINT on Curve? - YES!", ECCSI_SECTION_NAME);
                ES_DEBUG("%s    Point creation successful!",
                         ECCSI_SECTION_NAME);
            }
            else {
                ES_DEBUG("%s    Is POINT on Curve? - NO!", ECCSI_SECTION_NAME);
                ES_DEBUG("%s    Point creation unsuccessful!", 
                         ECCSI_SECTION_NAME);
                error_encountered = ES_TRUE;
            }
        }
    }

    /**************************************************************************/
    /*! 2) Compute HS = hash( G || KPAK || ID || PVT )                        */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  2) Compute HS = hash( G || KPAK || ID || PVT )", 
            ECCSI_SECTION_NAME);
        ES_DEBUG("%s      - G & KPAK from community, ID & PVT from user", 
            ECCSI_SECTION_NAME);

        /* G */
        if ((community_getG_string(&G, &G_len))) {
            ES_ERROR("%scould not get 'G'!", ECCSI_ERR_VAL_SSK);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME, 
                "    G (RFC 6507 Appendix A, page 13):", 6, G, G_len);

            /* KPAK */
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME,
                "    KPAK (RFC 6507 Appendix A, page 13):", 6, KPAK, KPAK_len);

            /* ID */
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME,
                "    ID:", 6, user_id, user_id_len);

            /* PVT */
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ECCSI_SECTION_NAME,
                "    PVT (RFC 6507 Appendix A, page 13):", 6, PVT, PVT_len);

            if (!computeHS(G,        G_len,
                           KPAK,     KPAK_len,
                           user_id,  user_id_len,
                           PVT,      PVT_len,
                           hash)) {

                /**************************************************************/
                /* Save HS for later use when Signing.                        */
                /**************************************************************/
                ES_DEBUG("%s  2.1) Cache HS for later use by Sign()", 
                    ECCSI_SECTION_NAME);

                /* We have calculated the hash HS (above). We return it so it 
                 * may be stored.
                 */
                ES_DEBUG_DISPLAY_HASH(ECCSI_SECTION_NAME, "    HASH:", 6, 
                                      (char *)*hash, *hash_len);
            }
            else {
                ES_ERROR("%scomputeHS failed!", ECCSI_ERR_VAL_SSK);
                error_encountered = ES_TRUE;
            }
        }
    }

    /**************************************************************************/
    /*! 3) Validate that KPAK = [SSK]G - [HS]PVT                              */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  3) Validate that KPAK = [SSK]G - [HS]PVT, which is", 
            ECCSI_SECTION_NAME);
        ES_DEBUG("%s     mathematically the same as [HS]PVT + KPAK = [SSK]G", 
            ECCSI_SECTION_NAME);
        ES_DEBUG("%s    LHS...", ECCSI_SECTION_NAME);
        ES_DEBUG("%s    Create a Point 'LHS' - Point PVT on curve 'E'", 
            ECCSI_SECTION_NAME);

        /* PVT on Affine NIST curve */
        if (!(PVT_point = EC_POINT_new(nist_curve))) {
            ES_ERROR("%sunable to create Point 'PVT' on Curve 'NIST'!", 
                     ECCSI_ERR_VAL_SSK);
            error_encountered = ES_TRUE;
        } else if (!(EC_POINT_set_affine_coordinates_GFp(nist_curve,
                      PVT_point, PVTx_bn, PVTy_bn, bn_ctx))) {
            ES_ERROR("%sunable to set coordinates for 'P'!", ECCSI_ERR_VAL_SSK);
            error_encountered = ES_TRUE;
        }

        /* Note! LHS == [HS]PVT + KPAK and RHS == [SSK]G */

        /**********************************************************************/
        /* LHS                                                                */
        /**********************************************************************/
        /* [HS]PVT */
        if (!(LHS_point = EC_POINT_new(nist_curve))) {
            ES_ERROR("%sunable to create Point '[HS]PVT' on Curve 'NIST'!", 
                     ECCSI_ERR_VAL_SSK);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG("%s    [HS]PVT - Multiply by PVT by HS", 
                     ECCSI_SECTION_NAME);

            if (!(hash_bn = BN_bin2bn(*hash, *hash_len, NULL))) {
                ES_ERROR("%screating 'HS' hash BN failed!", ECCSI_ERR_VAL_SSK);
                error_encountered = ES_TRUE;
            } else if (!EC_POINT_mul(nist_curve, LHS_point, 0, PVT_point, 
                                     hash_bn, bn_ctx)) {
                ES_ERROR("%sPoint mul '[HS]PVT' failed!", ECCSI_ERR_VAL_SSK);
                error_encountered = ES_TRUE;
            }
            else { /* [HS]PVT + KPAK */
                ES_DEBUG("%s    KPAK + HS[PVT] - Add KPAK", ECCSI_SECTION_NAME);
                if (!(KPAK_point = community_getKPAK_point(community))) {
                    ES_ERROR("%sunable to retrieve KPAK point!",
                             ECCSI_ERR_VAL_SSK);
                    error_encountered = ES_TRUE;
                } 
                /* Use LHS and store in same location. */
                else if (!EC_POINT_add(nist_curve, LHS_point, LHS_point, 
                                       KPAK_point, bn_ctx)) {
                    ES_ERROR("%sPoint add '[HS]PVT + KPAK' failed!",
                             ECCSI_ERR_VAL_SSK);
                }
                else {
                    ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME, 
                        "    LHS result is:", 8, nist_curve, LHS_point);
                }
            }
        }
    
        /**********************************************************************/
        /* RHS                                                                */
        /**********************************************************************/
        if (!error_encountered) {
            /* RHS SSK[G] Commumity params G from 6507 */
            ES_DEBUG("%s    RHS...", ECCSI_SECTION_NAME);

            /* [G], create G point on curve E */
            /* RHS used in calculation so duplicate G. */
            if (!(RHS_point = EC_POINT_dup(community_getG_point(), 
                                           nist_curve))) {
                ES_ERROR("%sunable to create Point 'G' on Curve 'NIST'!",
                         ECCSI_ERR_VAL_SSK);
                error_encountered = ES_TRUE;
            }
            else { /* SSK[G] */
                ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME,
                    "    Point G on Curve E:", 8, nist_curve, RHS_point);
                ES_DEBUG("%s    SSK[G] - SSK multipled by G", 
                         ECCSI_SECTION_NAME);
    
                if (!(SSK_bn = BN_bin2bn(SSK, SSK_len, NULL))) {
                    ES_ERROR("%screating 'SSK' BN failed!", ECCSI_ERR_VAL_SSK);
                    error_encountered = ES_TRUE;
                }
                /* SSK[G] */
                else if (!(EC_POINT_mul(nist_curve, RHS_point, 0, RHS_point, 
                                        SSK_bn, bn_ctx))) {
                    ES_ERROR("%sPoint mul 'SSK[G]' failed!", ECCSI_ERR_VAL_SSK);
                    error_encountered = ES_TRUE;
                }
                else {
                    ES_DEBUG_DISPLAY_AFFINE_COORDS(ECCSI_SECTION_NAME,
                        "    RHS Result is:", 8, nist_curve, RHS_point);

                    ES_DEBUG("%s    RHS calculation complete", 
                             ECCSI_SECTION_NAME);
    
                    /* Does KPAK == [SSK]G - [HS]PVT? Or, to put it another way,
                     * does: LHS (KPAK + [HS]PVT) == RHS ([SSK]G) 
                     */
                    if (EC_POINT_cmp(nist_curve, RHS_point, LHS_point, bn_ctx)) { 
                        ES_ERROR("%svalidation failed, LHS != RHS!", ECCSI_ERR_VAL_SSK);
                        error_encountered = ES_TRUE;
                        ret_val = ES_ECCSI_ERROR_SSK_VALIDATION_FAILED;
                    }
                    else {
                        ES_DEBUG("%s    SSK Validation, does LHS == RHS - YES!", 
                                 ECCSI_SECTION_NAME);
                        ret_val = ES_SUCCESS;
                    }
                }
            }
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    
    /* BIGNUMs */
    BN_clear_free(SSK_bn);
    BN_clear_free(hash_bn);
    BN_clear_free(PVTx_bn);
    BN_clear_free(PVTy_bn);

    nist_curve = NULL; /* Temporary reference. */

    /* Points */
    EC_POINT_clear_free(KPAK_point);
    EC_POINT_clear_free(LHS_point);
    EC_POINT_clear_free(P_point);
    EC_POINT_clear_free(PVT_point);
    EC_POINT_clear_free(RHS_point);

    /* BN context */
    if (bn_ctx != NULL) { 
        BN_CTX_free(bn_ctx);
        bn_ctx    = NULL;
    }
    ms_param_set  = 0;

    return ret_val;

} /* eccsi_validateSSK */

/******************************************************************************/
/* Internal functions not to be called externally.                            */
/******************************************************************************/

/***************************************************************************//**
 * RFC 6507, Section 5.1.2. bullet 2.
 *
 *     2) Compute HS = hash( G || KPAK || ID || PVT ), an N-octet
 *        integer.  The integer HS SHOULD be stored with the SSK for
 *        later use.
 *
 * @param[in]  community_G        Octet string pointer for 'G'.
 * @param[in]  community_G_len    Length of 'community_G' octet string.
 * @param[in]  community_KPAK     Octet string pointer for 'KPAK'.
 * @param[in]  community_KPAK_len Length of 'community_KPAK' octet string.
 * @param[in]  user_id            Octet string pointer for 'user_id'.
 * @param[in]  user_id_len        Length of 'user_id' octet string.
 * @param[in]  user_PVT           Octet string pointer for 'user_PVT'.
 * @param[in]  user_PVT_len       Length of 'user_PVT' octet string.
 * @param[out] hash_result        The resultant Hash.
 *
 * @return ES_SUCCESS or ES_FAILURE 
 ******************************************************************************/
uint8_t computeHS(
    const uint8_t  *community_G,
    const size_t    community_G_len,
    const uint8_t  *community_KPAK,
    const size_t    community_KPAK_len,
    const uint8_t  *user_id,
    const size_t    user_id_len,
    const uint8_t  *user_PVT,
    const size_t    user_PVT_len,
    uint8_t       **hash_result) {

    uint8_t         ret_val           = ES_FAILURE; /*!< The return status.   */
    short           error_encountered = ES_FALSE;   /*!< Local failure status.*/
    SHA256_CTX      sha_ctx;                        /*!< SHA256 context.      */
    memset(&sha_ctx, 0, sizeof(sha_ctx));

    /**************************************************************************/
    /* Check passed parameters                                                */
    /**************************************************************************/
    if (community_G == NULL) {
        ES_ERROR("%s'G' is NULL!", ECCSI_ERR_HS);
        error_encountered = ES_TRUE;
    } else if (community_G_len == 0) {
        ES_ERROR("%s'G length' is 0!", ECCSI_ERR_HS);
        error_encountered = ES_TRUE;
    } else if (community_KPAK == NULL) {
        ES_ERROR("%s'KPAK' is NULL!", ECCSI_ERR_HS);
        error_encountered = ES_TRUE;
    } else if (community_KPAK_len == 0) {
        ES_ERROR("%s'KPAK length' is 0!", ECCSI_ERR_HS);
        error_encountered = ES_TRUE;
    } else if (user_id == NULL) {
        ES_ERROR("%s'User ID' is NULL!", ECCSI_ERR_HS);
        error_encountered = ES_TRUE;
    } else if (user_id_len == 0) {
        ES_ERROR("%s'User ID length' is 0!", ECCSI_ERR_HS);
        error_encountered = ES_TRUE;
    } else if (user_PVT == NULL) {
        ES_ERROR("%s'PVT' is NULL!", ECCSI_ERR_HS);
        error_encountered = ES_TRUE;
    } else if (user_PVT_len == 0) {
        ES_ERROR("%s'PVT length' is 0!", ECCSI_ERR_HS);
        error_encountered = ES_TRUE;
    }

    /**************************************************************************/
    /* Construct the HS Hash                                                  */
    /**************************************************************************/
    if (!error_encountered) {
        memset(&sha_ctx, 0, sizeof(sha_ctx));

        /* Initialise ctx. */
        if (!SHA256_Init(&sha_ctx)) {
            ES_ERROR("%s SHA256_Init failed!", ECCSI_ERR_HS);
        } else if (!SHA256_Update(&sha_ctx, community_G, community_G_len)) {
            ES_ERROR("%s SHA256_Update (community 'G') failed!", ECCSI_ERR_HS);
        } else if (!SHA256_Update(&sha_ctx, 
                                  community_KPAK, community_KPAK_len)) {
            ES_ERROR("%s SHA256_Update (community 'KPAK') failed!", 
                     ECCSI_ERR_HS);
        } else if (!SHA256_Update(&sha_ctx, user_id, user_id_len)) {
            ES_ERROR("%s SHA256_Update (user 'ID') failed!", ECCSI_ERR_HS);
        } else if (!SHA256_Update(&sha_ctx, user_PVT, user_PVT_len)) {
            ES_ERROR("%s SHA256_Update (user 'PVT') failed!", ECCSI_ERR_HS);
        } else if (!SHA256_Final(*hash_result, &sha_ctx)) { /* Finalise hash */
            ES_ERROR("%s SHA256_Final failed!", ECCSI_ERR_HS);
        } else {
           ret_val = ES_SUCCESS;
        }

        /**********************************************************************/
        /* Cleanup.                 .                                         */
        /**********************************************************************/
        memset(&sha_ctx, 0, sizeof(sha_ctx));
    }

    return ret_val;

} /* computeHS */

/***************************************************************************//**
 * RFC 6507, Section 5.2.1. item 3).
 *
 *      2) Compute HE = hash( HS || r || M ), an N-octet integer.
 *
 * @param[in]  HS          Octet string pointer for 'HS'.
 * @param[in]  HS_len      Length of 'HS_len' octet string.
 * @param[in]  r           Octet string pointer for 'r_len'.
 * @param[in]  r_len       Length of 'r' octet string.
 * @param[in]  message     Octet string pointer for 'message'.
 * @param[in]  message_len Length of 'message' octet string.
 * @param[out] hash_result The resultant Hash.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
static uint8_t computeHE(
    const uint8_t  *HS,
    const size_t    HS_len,
    const uint8_t  *r,
    const size_t    r_len,
    const uint8_t  *message,
    const size_t    message_len,
    uint8_t       **hash_result) {

    uint8_t         ret_val           = ES_FAILURE;
    short           error_encountered = ES_FALSE;

    SHA256_CTX sha_ctx; 
    memset(&sha_ctx, 0, sizeof(sha_ctx));

    /*************************************************************************/
    /* Check passed parameters                                               */
    /*************************************************************************/
    if (HS == NULL) {
        ES_ERROR("%s'HS' is NULL, HE hash failed!", ECCSI_ERR_HE);
        error_encountered = ES_TRUE;
    } else if (HS_len == 0) {
        ES_ERROR("%s'HS length' is 0, HE hash failed!", ECCSI_ERR_HE);
        error_encountered = ES_TRUE;
    } else if (r == NULL) {
        ES_ERROR("%s'r' is NULL, HE hash failed!", ECCSI_ERR_HE);
        error_encountered = ES_TRUE;
    } else if (r_len == 0) {
        ES_ERROR("%s'r length' is NULL, HE hash failed!", ECCSI_ERR_HE);
        error_encountered = ES_TRUE;
    } else if (message == NULL) {
        ES_ERROR("%s'message' is NULL, HE hash failed!", ECCSI_ERR_HE);
        error_encountered = ES_TRUE;
    } else if (message_len == 0) {
        ES_ERROR("%s'message length' is NULL, HE hash failed!", ECCSI_ERR_HE);
        error_encountered = ES_TRUE;
    }

    /**************************************************************************/
    /* Construct the HS Hash                                                  */
    /**************************************************************************/
    if (!error_encountered) {
        /* Initialise ctx. */
        if (!SHA256_Init(&sha_ctx)) {
            ES_ERROR("%sHE SHA256_Init failed!", ECCSI_ERR_HE);
        } else if (!SHA256_Update(&sha_ctx, HS, HS_len)) { /* Construct hash. */
            ES_ERROR("%sHE SHA256_Update (HS) failed!", ECCSI_ERR_HE);
        } else if (!SHA256_Update(&sha_ctx, r, r_len)) {
            ES_ERROR("%sHE SHA256_Update (r) failed!", ECCSI_ERR_HE);
        } else if (!SHA256_Update(&sha_ctx, message, message_len)) {
            ES_ERROR("%sHE SHA256_Update (message) failed!", ECCSI_ERR_HE);
        } else if (!SHA256_Final(*hash_result, &sha_ctx)) { /* Finalise hash. */
            ES_ERROR("%sHE SHA256_Final failed!", ECCSI_ERR_HE);
        } else {
            ret_val = ES_SUCCESS;
        }

        /**********************************************************************/
        /* Cleanup.                 .                                         */
        /**********************************************************************/
        memset(&sha_ctx, 0, sizeof(sha_ctx));
    }

    return ret_val;

} /* computeHE */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
