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
 * @file sakke.c
 * @brief SAKKE (RFC 6508).
 *
 * Provides the functionality in support of RFC 6508, SAKKE.
 ******************************************************************************/
#include "global.h"
#include "mikeySakkeParameters.h" 
#include "communityParameters.h"
#include "userParameters.h"
#include "utils.h"
#include "sakke.h" 

/* Debug strings. */
#define SAKKE_SECTION_NAME   "(SAKKE)            "   /*!< Section name output */
/* Error strings. */
#define SAKKE_ERR_GEN_SED    "SAKKE Generate Encapsulated Data, "/*!< Err str */
#define SAKKE_ERR_EXT_SED    "SAKKE Extract Shared Secret, "     /*!< Err str */
#define SAKKE_ERR_VAL_RSK    "SAKKE Validate RSK, "              /*!< Err str */
#define SAKKE_ERR_H2INTRANGE "SAKKE Hash to integer range, "     /*!< Err str */

#define SAKKE_SUPPORTED_MS_PARAM_SET 1 /*!< The supported Mikey Sakke Parameter
                                        *   Set.
                                        */

BIGNUM *BN_two   = {0}; /*!< A BN of value 2. */
BIGNUM *BN_three = {0}; /*!< A BN of value 3. */

/******************************************************************************/
/* Forward declarations.                                                      */
/******************************************************************************/
/***************************************************************************//**
 * Defines a BN with value of 2.
 *
 * @return A BIGNUM of value 2.
 ******************************************************************************/
static inline BIGNUM *BN_value_two();

/***************************************************************************//**
 * Defines a BN with value of 3.
 *
 * @return A BIGNUM of value 3.
 ******************************************************************************/
static inline BIGNUM *BN_value_three();

static inline void sakke_pointSquare(
    BIGNUM *p,
    BIGNUM *result_x,  BIGNUM *result_y,
    BIGNUM *point_x,   BIGNUM *point_y);
static inline void sakke_pointsMultiply(
    BIGNUM *p,
    BIGNUM *result_x,  BIGNUM *result_y,
    BIGNUM *point_1_x, BIGNUM *point_1_y,
    BIGNUM *point_2_x, BIGNUM *point_2_y);
static inline void sakke_pointMultiply(
    BIGNUM *p,
    BIGNUM *result_x,  BIGNUM *result_y,
    BIGNUM *point_x,   BIGNUM *point_y,
    BIGNUM *multiplier);
static inline void sakke_pointsAdd(
    BIGNUM *p,
    BIGNUM *result_x,  BIGNUM *result_y,
    BIGNUM *point_1_x, BIGNUM *point_1_y,
    BIGNUM *point_2_x, BIGNUM *point_2_y);
static inline uint8_t sakke_pointExponent(
    BIGNUM *p,
    BIGNUM *result_x, BIGNUM *result_y,
    BIGNUM *point_x,  BIGNUM *point_y,
    BIGNUM *n);

static uint8_t sakke_computeTLPairing(
    BIGNUM   *w_bn,
    EC_POINT *R_point,
    EC_POINT *rsk_point,
    uint8_t   msParamSet);
static uint8_t sakke_hashToIntegerRangeSHA256(
    BIGNUM   *v,
    uint8_t  *s,
    size_t    s_len,
    BIGNUM   *n);

/******************************************************************************/
/* Accessible functions.                                                      */
/*     sakke_generateSakkeEncapsulatedData (prepare encrypted SSV)            */
/*     sakke_extractSharedSecret (decrypt SSV)                                */
/*                                                                            */
/*     sakke_validateRSK Note! only called internally when user data is added */
/*                             see userParameters.c                           */
/******************************************************************************/

/***************************************************************************//**
 * Create SAKKE encapsulated data. This includes SSV (Shared Secret Value).
 *
 * Described in RFC6508 Section 6.2.1.
 *
 * @param[out] encapsulated_data     Result 'encapsulated_data' octet string.
 * @param[in]  encapsulated_data_len Length of 'encapsulated_data' octet string.
 * @param[in]  user_id               String pointer of the 'user_id'.
 * @param[in]  user_id_len           Length of 'user_id' octet string.
 * @param[in]  community             String pointer of the 'community'.
 * @param[in]  ssv                   Octet string pointer of the 'community'.
 * @param[in]  ssv_len               Length of 'community' octet string.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
uint8_t sakke_generateSakkeEncapsulatedData(
    uint8_t       **encapsulated_data,
    size_t         *encapsulated_data_len,
    const uint8_t *user_id,       
    const size_t   user_id_len,
    const uint8_t *community,     /* Community null terminated octet string. */
    const uint8_t *ssv,
    const size_t   ssv_len) {

    short          error_encountered = ES_FALSE;
    uint8_t        ret_val           = ES_FAILURE;

    BIGNUM        *b_bn              = NULL;
    BIGNUM        *g_to_power_r_bn   = NULL;
    BIGNUM        *H_bn              = NULL;
    BIGNUM        *mask_bn           = NULL;
    BIGNUM        *p_tmp_bn          = NULL; /* Temporary reference. */
    BIGNUM        *r_bn              = NULL;
    BIGNUM        *Rbx_bn            = NULL;
    BIGNUM        *Rby_bn            = NULL;
    BIGNUM        *result_x_bn       = NULL;
    BIGNUM        *result_y_bn       = NULL;
    BIGNUM        *two_to_power_n_bn = NULL;

    EC_GROUP      *ms_curve          = NULL; /* Temporary reference. */

    EC_POINT      *R                 = NULL;
    EC_POINT      *Z_S               = NULL;

    uint8_t        ms_param_set      = 0;
    uint8_t       *g_pow_r           = NULL;
    size_t         g_pow_r_len       = 0;
    uint8_t       *ssv_concat_b      = NULL;
    size_t         ssv_concat_b_len  = 0;
    uint16_t       offset            = 1; /* Whether point 'R' is preceeded 
                                           * by 0x04 
                                           */
    int            count             = 0;

    BN_CTX        *bn_ctx            = BN_CTX_new();

    /**************************************************************************/
    /* Check passed parameters                                                */
    /**************************************************************************/
    if (*encapsulated_data != NULL) {
        ES_ERROR("%sEnc-Data reference is not NULL!", SAKKE_ERR_GEN_SED);
        error_encountered = ES_TRUE;
    }
    if (*encapsulated_data_len != 0) {
        ES_ERROR("%sEnc-Data length is not 0!", SAKKE_ERR_GEN_SED);
        error_encountered = ES_TRUE;
    }
    if (user_id == NULL) {
        ES_ERROR("%sUser ID reference is NULL!", SAKKE_ERR_GEN_SED);
        error_encountered = ES_TRUE;
    }
    if (user_id_len == 0) {
        ES_ERROR("%sUser ID length is 0!", SAKKE_ERR_GEN_SED);
        error_encountered = ES_TRUE;
    }
    if (community == NULL) {
        ES_ERROR("%sCommunity reference is NULL!", SAKKE_ERR_GEN_SED);
        error_encountered = ES_TRUE;
    }
    if (!community_exists(community)) {
        ES_ERROR("%sCommunity <%s> is not stored!", SAKKE_ERR_GEN_SED, 
                 community);
        error_encountered = ES_TRUE;
    }
    if (ssv == NULL) {
        ES_ERROR("%sSSV reference is NULL!", SAKKE_ERR_GEN_SED);
        error_encountered = ES_TRUE;
    }
    if (ssv_len == 0) {
        ES_ERROR("%sSSV length is 0!", SAKKE_ERR_GEN_SED);
        error_encountered = ES_TRUE;
    }

    /**************************************************************************/
    /* Init.                                                                  */
    /**************************************************************************/
    if (!error_encountered) {
        /* MS parameter set for community. */
        if (1 != (ms_param_set = community_get_paramSet(community))) {
            ES_ERROR("%sMS Parameter != 1 <%d> not supported",
                     SAKKE_ERR_GEN_SED, ms_param_set);
            error_encountered = ES_TRUE;
        }

        /* Get reference to curve` we're going to use */
        else if (!(ms_curve = ms_getParameter_E(ms_param_set))) {
            ES_ERROR("%sget MS param set curve for set <%d> returned NULL!",
                SAKKE_ERR_GEN_SED, ms_param_set);
            error_encountered = ES_TRUE;
        }
        /* check the supplied SSV is not too long. RFC 6508 Section 2.1 
         * states 'n' A security parameter; the size of symetric key in
         * bits to be exchanged by SAKKE. ssv_len is number of octets.
         */
        else if (ssv_len != (ms_getParameter_n(ms_param_set) / 8)) {
            ES_ERROR("%sSSV length is not equal to allowed, "
                     "got <%lu> expected <%d>!", SAKKE_ERR_GEN_SED,
                     ssv_len, (ms_getParameter_n(ms_param_set) / 8));
            error_encountered = ES_TRUE;
        }
    }

    /**************************************************************************/
    /*! Perform actions described in RFC6508 Section 6.2.1                    */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  RFC6508 6.2.1", SAKKE_SECTION_NAME);
    }

    /**************************************************************************/
    /*! 1) Select random ephemeral integer for SSV in [0,2^n)                 */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  1) Select random ephemeral integer for SSV in [0,2^n)", 
                 SAKKE_SECTION_NAME);
    }
 
    /*--------------------------- !!! NOTE !!! -------------------------------*/

    /* Instead of generating a random ephemeral SSV here, we'll take what
     * was passed in the parameters. In short, the reasons for this are 
     * that it is for the user (YOU) to decide what random number generation 
     * characteristics you are happy with. I do not presume to impose anything 
     * on you or others who may have 'specific' requirements or policies. 
     *
     * If you have such requirements or policies, it's best you do that code 
     * outside of this functionality and pass in what you want, assuming it 
     * complies with what is expected here in terms of length/ type etc. That 
     * way, this code remains untouched and can be easily updated, as/ when 
     * required. 
     *
     * Also as an aside, this way, you get to plug-in 'known' values and check 
     * the results more easily.
     */

    /**************************************************************************/
    /*! 2) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )          */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  2) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )",
                 SAKKE_SECTION_NAME);

        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(SAKKE_SECTION_NAME,
            "    b (aka userId) (RFC 6508 Appendix A, page 16):", 6, 
            user_id, user_id_len);

        /* ssv_len was checked above to be 'n' from the MS parameters. */
        ssv_concat_b_len = ssv_len + user_id_len;
        if (!(ssv_concat_b = calloc(1, ssv_concat_b_len+1))) {
            ES_ERROR("%smemory allocation  for 'ssv concat b' failed!", 
                     SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        }
        else {
            memcpy(ssv_concat_b, ssv, ssv_len);
            memcpy(ssv_concat_b+ssv_len, user_id, user_id_len);

            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(SAKKE_SECTION_NAME,
                "    SSV||b (RFC 6508 Appendix A, page 17):", 6, 
                ssv_concat_b, ssv_concat_b_len);
            if (!(r_bn = BN_new())) {
                ES_ERROR("%screate of BN for 'r' failed!", SAKKE_ERR_GEN_SED);
                error_encountered = ES_TRUE;
            }
            else if (sakke_hashToIntegerRangeSHA256(r_bn, 
                        ssv_concat_b, ssv_concat_b_len, 
                        ms_getParameter_q(ms_param_set))) {
                ES_ERROR("%shash to integer range failed!", SAKKE_ERR_GEN_SED);
                error_encountered = ES_TRUE;
            } else {
                ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                    "    r(hash) (RFC 6508 Appendix A, page 17):", 6, r_bn);
            }
        }
    }

    /**************************************************************************/
    /*! 3) Compute R_(b,S) = [r]([b]P + Z_S) in E(F_p)                        */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  3) Compute R_(b,S) = [r]([b]P + Z_S) in E(F_p)",
                 SAKKE_SECTION_NAME);

        /* Create R */
        if (!(R = EC_POINT_new(ms_curve))) {
            ES_ERROR("%s'R' EC_POINT creation failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!(b_bn = BN_bin2bn(user_id, user_id_len, NULL))) { /* b - id */
            ES_ERROR("%s'b' (id) BN creation failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!(Z_S = community_getZ_point(community))) { /* Z_S */
            ES_ERROR("%s'Z_S' EC_POINT creation failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!EC_POINT_mul(ms_curve, R, 0, ms_getParameter_P(ms_param_set), 
                                 b_bn, bn_ctx)) {
            /* [b]P - place running result in R */
            ES_ERROR("%sEC_POINT_mul 'b[P]' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!EC_POINT_add(ms_curve, R, R, Z_S, bn_ctx)) {
            /* [b]P + Z_S - place running result in R */
            ES_ERROR("%sEC_POINT_add '[b]P + Z_S' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!EC_POINT_mul(ms_curve, R, 0, R, r_bn, bn_ctx)) {
            /* [r]([b]P + Z_S) - place running result in R */
            ES_ERROR("%sEC_POINT_mul '[r]([b]P + Z_S)' failed!", 
                     SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!(Rbx_bn = BN_new())) {
            ES_ERROR("%sCreate of BN for 'Rbx' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!(Rby_bn = BN_new())) {
            ES_ERROR("%sCreate of BN for 'Rby' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!EC_POINT_get_affine_coordinates_GFp(
                      ms_curve, R, Rbx_bn, Rby_bn, bn_ctx)) {
            ES_ERROR("%sget coordinates for 'R' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else {
            /* We have R, we can proceed. */
            ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                "    Rbx (RFC 6508 Appendix A, page 17):", 6, Rbx_bn);
                ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                "    Rby (RFC 6508 Appendix A, page 17):", 6, Rby_bn);
        }
    }

    /**************************************************************************/
    /*! 4) Compute the HINT, H;                                               */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  4) Compute the HINT, H;", SAKKE_SECTION_NAME);
    } 

    /**************************************************************************/
    /*! 4.a) Compute g^r.                                                     */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s    4.a) Compute g^r", SAKKE_SECTION_NAME);

        /* Prepare terms */
        if (BN_is_zero(r_bn)) {
            ES_ERROR("%sCalculating 'g^r' but 'r' is zero, failed!", 
                     SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!(g_to_power_r_bn = BN_new())) {
            ES_ERROR("%s'g_to_power_r_bn' BN creation failed!", 
                     SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!(p_tmp_bn = ms_getParameter_p(ms_param_set))) { 
            ES_ERROR("%sretrieval of 'p' BN from set <%d> failed!", 
                     SAKKE_ERR_GEN_SED, ms_param_set);
            error_encountered = ES_TRUE;
        } else if (!(result_x_bn = BN_new())) {
            ES_ERROR("%s'result_x' BN creation failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!(result_y_bn = BN_new())) {
            ES_ERROR("%s'result_y' BN creation failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        }
        else if (sakke_pointExponent(p_tmp_bn, 
                    result_x_bn, result_y_bn,
                    (BIGNUM *)BN_value_one(),       /* gx */
                    ms_getParameter_g(ms_param_set),/* gy */
                    r_bn)) {
            ES_ERROR("%scall to point exponent failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!BN_mod(g_to_power_r_bn, result_x_bn, p_tmp_bn, bn_ctx)) {
            ES_ERROR("%s'result_x mod p' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!BN_mod_inverse(g_to_power_r_bn, g_to_power_r_bn, 
                                   p_tmp_bn, bn_ctx)) {
            ES_ERROR("%s'g^r mod inverse p' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!BN_mul(g_to_power_r_bn, g_to_power_r_bn, result_y_bn, 
                           bn_ctx)) {
            ES_ERROR("%s'g^r mul result_y' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        } else if (!BN_mod(g_to_power_r_bn, g_to_power_r_bn, p_tmp_bn, 
                           bn_ctx)) {
            ES_ERROR("%s'g^r mod p' failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                "      g^r (RFC 6508 Appendix A, page 17):", 8, 
                g_to_power_r_bn);
        }
    }

    /**************************************************************************/
    /*! 4.b) Compute H := SSV XOR HashToIntegerRange(g^r, 2^n, Hash);         */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s", SAKKE_SECTION_NAME
            "    4.b) Compute H := SSV XOR HashToIntegerRange( g^r, 2^n, Hash );");

        if (!(two_to_power_n_bn = BN_new())) {
            ES_ERROR("%s'2^n' BN creation failed!", SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        }
        else {
            BN_set_bit(two_to_power_n_bn, ms_getParameter_n(ms_param_set));

            if (!(mask_bn = BN_new())) {
                ES_ERROR("%s'mask' BN creation failed!", SAKKE_ERR_GEN_SED);
                error_encountered = ES_TRUE;
            }
            else {
                if (!(g_pow_r_len = BN_num_bytes(g_to_power_r_bn))) {
                    ES_ERROR("%s'g_pow_r_len' is 0!", SAKKE_ERR_GEN_SED);
                    error_encountered = ES_TRUE;
                } 
                else if (!(g_pow_r = calloc(1, g_pow_r_len))) {
                    ES_ERROR("%smemory allocation  for 'g_pow_r' failed!", 
                             SAKKE_ERR_GEN_SED);
                    error_encountered = ES_TRUE;
                }
                else if (!BN_bn2bin(g_to_power_r_bn, g_pow_r)) {
                    ES_ERROR("%s'g_pow_r' incorrect length!", SAKKE_ERR_GEN_SED);
                    error_encountered = ES_TRUE;
                }
                else if (sakke_hashToIntegerRangeSHA256(
                            mask_bn, g_pow_r, g_pow_r_len, two_to_power_n_bn)) {
                    ES_ERROR("%scall to hashToIntegerRange failed!", SAKKE_ERR_GEN_SED);
                    error_encountered = ES_TRUE;
                } else {
                    ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                        "      mask (RFC 6508 Appendix A, page 18):", 8, mask_bn);

                    if (!(H_bn = BN_bin2bn(ssv, ssv_len, NULL))) {
                        ES_ERROR("%s'ssv' BN creation failed!", SAKKE_ERR_GEN_SED);
                        error_encountered = ES_TRUE;
                    }
                    else {
                        /* For loop, use whichever is larger of H or mask. */
                        count = (BN_num_bits(H_bn) >  BN_num_bits(mask_bn) ? 
                                 BN_num_bits(H_bn) : BN_num_bits(mask_bn)); 
                        for (; count >= 0; count--) {
                            if ((BN_is_bit_set(H_bn, count))^
                                    (BN_is_bit_set(mask_bn, count))) {
                                BN_set_bit(H_bn, count);
                            } else {
                                BN_clear_bit(H_bn, count);
                            }
                        }
         
                        /* H (RFC 6508 Appendix A, page 18): */
                        ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                           "      H (RFC 6508 Appendix A, page 18):", 8, H_bn);
                    }
                }
            }
        }
    }

    /**************************************************************************/
    /*! 5) Form the Encapsulated Data (R_(b,S), H), and transmit it to B;     */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  5) Form the Encapsulated Data ( R_(b,S), H ), and transmit it to B;",
                 SAKKE_SECTION_NAME);

        /* Create Encapsulated data - pad appropriately. */

        /* Produce SED */
        *encapsulated_data_len  = (ES_MAX_COORD_SIZE*2)+ES_MAX_HINT_SIZE+1;
        if (!(*encapsulated_data = calloc(1, *encapsulated_data_len))) {
            ES_ERROR("%scalloc for encapsulated date failed!", 
                     SAKKE_ERR_GEN_SED);
            error_encountered = ES_TRUE;
        }
        else {
            if (offset == 1) { /* Add 04 start */
                memset(*encapsulated_data, 0x04, 1); /* Initial '04'. */
            }

            /* Add Rbx - In case it's shorter, pad. BN_bn2bin returns length 
             * copied so use that to check something was copied.
             */
            offset = (ES_MAX_COORD_SIZE-BN_num_bytes(Rbx_bn))+1;
            if (!BN_bn2bin(Rbx_bn, (unsigned char *)*encapsulated_data+offset)) {
                ES_ERROR("%scopy of Rb_x to encapsulated date failed!", 
                         SAKKE_ERR_GEN_SED);
                error_encountered = ES_TRUE;
            }
            /* Add Rby - In case it's shorter, pad. BN_bn2bin returns length 
             * copied so use that to check something was copied.
             */
            else {
                offset = ES_MAX_COORD_SIZE+(ES_MAX_COORD_SIZE-BN_num_bytes(Rby_bn))+1;
                if (!BN_bn2bin(Rby_bn, (unsigned char *)*encapsulated_data+offset)) {
                    ES_ERROR("%scopy of Rb_y to encapsulated data failed!", 
                             SAKKE_ERR_GEN_SED);
                    error_encountered = ES_TRUE;
                }
                else {
                    /* Add H - In case it's shorter, pad. BN_bn2bin returns 
                     * length copied so use that to check something was copied.
                     */
                    offset = (ES_MAX_COORD_SIZE*2)+
                             (ES_MAX_HINT_SIZE-BN_num_bytes(H_bn))+1;
                    if (!BN_bn2bin(H_bn, 
                                   (unsigned char *)*encapsulated_data+offset)){
                        ES_ERROR("%scopy of Hint to encapsulated data failed!", 
                                 SAKKE_ERR_GEN_SED);
                        error_encountered = ES_TRUE;
                    }
                    else {
                        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(
                            SAKKE_SECTION_NAME,
                            "    Encapsulated data:", 6, 
                            *encapsulated_data, *encapsulated_data_len);

                        /* Success */
                        ret_val = ES_SUCCESS;
                    }
                }
            }
        }
    }

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_clear_free(b_bn);
    BN_clear_free(g_to_power_r_bn);
    BN_clear_free(H_bn);
    BN_clear_free(mask_bn);
    BN_clear_free(r_bn);
    BN_clear_free(Rbx_bn);
    BN_clear_free(Rby_bn);
    BN_clear_free(result_x_bn);
    BN_clear_free(result_y_bn);
    BN_clear_free(two_to_power_n_bn);

    ms_curve = NULL; /* Temporary reference. */

    EC_POINT_clear_free(R);
    EC_POINT_clear_free(Z_S);

    if (g_pow_r != NULL) { 
        memset(g_pow_r, 0, g_pow_r_len); 
        free(g_pow_r);
    }
    if (ssv_concat_b != NULL) { 
        memset(ssv_concat_b, 0, ssv_concat_b_len); 
        free(ssv_concat_b); 
    }

    BN_CTX_free(bn_ctx);
    bn_ctx = NULL;

    return ret_val;
} /* sakke_generateSakkeEncapsulatedData */

/***************************************************************************//**
 * Extract SSV (Shared Secret Value) from SED( Sakke Encapsulated Data).
 * Described in Section 6.2.2 of RFC 6508.
 *
 * @param[in]  encapsulated_data     Octet string pointer of the 
 *                                   'encapsulated_data'.
 * @param[in]  encapsulated_data_len Length of 'encapsulated_data' octet string.
 * @param[in]  user_id               Octet string pointer of the 'user_id'.
 * @param[in]  user_id_len           Length of 'user_id' octet string.
 * @param[in]  community             Octet string pointer of the 'community'.
 * @param[out] ssv                   Result octet string pointer of the 'ssv'.
 * @param[out] ssv_len               Result length of 'ssv_len' octet string.
 *
 * @return ES_SUCCESS or ES_FAILURE.
 ******************************************************************************/
uint8_t sakke_extractSharedSecret(
    const uint8_t  *encapsulated_data, /* In:  Signed Encrypted Data.     */
    const size_t    encapsulated_data_len,
    const uint8_t  *user_id,           /* In:  User Identifier date + id. */
    const size_t    user_id_len,
    const uint8_t  *community,         /* In:  User community.            */
    uint8_t       **ssv,               /* Out: The Shared Secret Value.   */
    size_t         *ssv_len) {

    int            ret_val           = ES_FAILURE;
    short          error_encountered = ES_FALSE;

    int            coord_len         = 0;
    int            count             = 0;
    int            expected_len      = 0;
    int            H_len             = 0;

    BIGNUM        *b_bn              = NULL;
    BIGNUM        *H_bn              = NULL;
    BIGNUM        *mask_bn           = NULL;
    BIGNUM        *r_bn              = NULL;
    BIGNUM        *Rx_bn             = NULL;
    BIGNUM        *Ry_bn             = NULL;
    BIGNUM        *two_power_n_bn    = NULL;
    BIGNUM        *w_bn              = NULL;

    EC_POINT      *Z_S_point         = NULL;
    EC_POINT      *P_point           = NULL;
    EC_POINT      *R_point           = NULL;
    EC_POINT      *K_point           = NULL;
    EC_POINT      *TEST_point        = NULL;

    EC_GROUP      *ms_curve          = NULL; /* Temporary reference. */

    uint8_t       *H_ostr            = NULL;
    uint8_t       *Rx_ostr           = NULL;
    uint8_t       *Ry_ostr           = NULL;
    uint8_t       *ssv_concat_id     = NULL;
    uint8_t       *w_ostr            = NULL;

    uint8_t        ms_param_set      = 0;
    int            offset            = 0; /* Handle if the encapsulated data 
                                           * starts with '04' or not.
                                           */
    size_t         ssv_concat_id_len = 0;
    size_t         w_ostr_length     = 0;

    BN_CTX        *bn_ctx            = NULL;

    /*************************************************************************/
    /* Check passed parameters                                               */
    /*************************************************************************/
    if (encapsulated_data == NULL) {
        ES_ERROR("%sEncapsulated Data reference is NULL!", SAKKE_ERR_EXT_SED);
        error_encountered = ES_TRUE;
    } else if (encapsulated_data_len == 0) {
        ES_ERROR("%sEncapsulated Data length is 0!", SAKKE_ERR_EXT_SED);
        error_encountered = ES_TRUE;
    } else if (user_id == NULL) {
        ES_ERROR("%sUser ID is NULL!", SAKKE_ERR_EXT_SED);
        error_encountered = ES_TRUE;
    } else if (user_id_len == 0) {
        ES_ERROR("%sUser ID length is 0!", SAKKE_ERR_EXT_SED);
        error_encountered = ES_TRUE;
    } else if (community == NULL) {
        ES_ERROR("%sCommunity is NULL!", SAKKE_ERR_EXT_SED);
        error_encountered = ES_TRUE;
    } else if (!community_exists(community)) {
        ES_ERROR("%sCommunity <%s> is not stored!",
            community, SAKKE_ERR_EXT_SED);
        error_encountered = ES_TRUE;
    } else if (!user_exists(user_id, user_id_len, community)) {
        ES_ERROR("%sUser <%s.%s> in community <%s> is not stored!",
            SAKKE_ERR_EXT_SED, user_id, user_id+strlen((char *)user_id)+1, 
            community);
        error_encountered = ES_TRUE;
    } else if (*ssv != NULL) {
        ES_ERROR("%sSSV is not NULL!", SAKKE_ERR_EXT_SED);
        error_encountered = ES_TRUE;
    } else if (*ssv_len != 0) {
        ES_ERROR("%sSSV length is not 0!", SAKKE_ERR_EXT_SED);
        error_encountered = ES_TRUE;
    }
    /*************************************************************************/
    /* Init.                                                                 */
    /*************************************************************************/
    if (!error_encountered) {
        /* MS parameter set for community. */
        if (1 != (ms_param_set = community_get_paramSet(community))) {
            ES_ERROR("%sMS Parameter != 1 <%d> not supported",
                     SAKKE_ERR_EXT_SED, ms_param_set);
            error_encountered = ES_TRUE;
        } 
        /* Get reference to curves we're going to use */
        else if (!(ms_curve = ms_getParameter_E(ms_param_set))) {
            ES_ERROR("%scould not retrieve curve 'E' for set <%d>!",
                SAKKE_ERR_EXT_SED, ms_param_set);
            error_encountered = ES_TRUE;
        } 
        else {
            /* Set ssv_len to MS set configured value. */
            *ssv_len = ms_getParameter_n(ms_param_set) / 8;
            if (!(bn_ctx = BN_CTX_new())) {
                ES_ERROR("%scould not create BN context!", SAKKE_ERR_EXT_SED);
                error_encountered = ES_TRUE;
            }
        }
    }
   
    /*************************************************************************/
    /*! Perform actions described in RFC6508 Section 6.2.2                   */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s", SAKKE_SECTION_NAME"  RFC6508 6.2.2");
    }

    /*************************************************************************/
    /*! 1) Parse the Encapsulated Data ( R_(b,S), H ),
     *     and extract R_(b,S) and H.
     *************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  1) Parse the Encapsulated Data (R_(b,S), H),",
                 SAKKE_SECTION_NAME);
        ES_DEBUG("%s     and extract R_(b,S) and H", SAKKE_SECTION_NAME);

        /* Calculate size of Rb coords in Encapsulated Data. */
        coord_len    = BN_num_bytes(ms_getParameter_p(SAKKE_SUPPORTED_MS_PARAM_SET)); 
                      /* Not sure about this as a length indicator? */
        H_len        = 16; /* TBD get size from file... Size is given by 256 hash - 32  */
        expected_len = 1 /* 04 */ + (coord_len * 2) + H_len;

        /** Postel's Law
          * It's not absolutely clear from the RFC if an initial '04' is 
          * required at the start of the 'R' coords, so try and play nice and 
          * handle both cases.
          */
        if ((encapsulated_data_len != expected_len) && (encapsulated_data_len != (expected_len-1))) { 
            ES_ERROR("%sError parsing R_ and H from SED, length <%lu> incorrect!",
                     SAKKE_ERR_EXT_SED, encapsulated_data_len);
            error_encountered = ES_TRUE;
        }
        else {
            if (encapsulated_data_len == expected_len) { /* With '04' start. */
                if (!(*encapsulated_data ^ 0x04)) { /* Must start with '04' */
                    offset=1;
                }
                else {
                    ES_ERROR("%sSED of length <%lu> MUST begin with 0x04!",
                        SAKKE_ERR_EXT_SED, encapsulated_data_len);
                    error_encountered = ES_TRUE;
                }
            }
            if (!error_encountered) {
                /* Parse the encapsulated data */
                if (!(Rx_ostr = calloc(1, 128+1))) {
                    ES_ERROR("%scalloc for Rx failed!", SAKKE_ERR_EXT_SED);
                    error_encountered = ES_TRUE;
                } else if (!(Ry_ostr = calloc(1, 128+1))) {
                    ES_ERROR("%scalloc for Ry failed!", SAKKE_ERR_EXT_SED);
                    error_encountered = ES_TRUE;
                } else if (!(H_ostr = calloc(1, 16+1))) {
                    ES_ERROR("%scalloc for H failed!", SAKKE_ERR_EXT_SED);
                    error_encountered = ES_TRUE;
                }
                else {
                    memcpy(Rx_ostr, encapsulated_data+offset,        128);
                    memcpy(Ry_ostr, encapsulated_data+offset+128,    128);
                    memcpy(H_ostr,  encapsulated_data+offset+128+128, 16);

                    /* Convert to BIGNUMs so we can do calculations. */ 
                    if (!(Rx_bn = BN_bin2bn(Rx_ostr, 128, NULL))) {
                        ES_ERROR("%screation of 'Rx' BN failed!", SAKKE_ERR_EXT_SED);
                        error_encountered = ES_TRUE;
                    } else if (!(Ry_bn = BN_bin2bn(Ry_ostr, 128, NULL))) {
                        ES_ERROR("%screation of 'Ry' BN failed!", SAKKE_ERR_EXT_SED);
                        error_encountered = ES_TRUE;
                    } else if (!(H_bn = BN_bin2bn(H_ostr, 16, NULL))) {
                        ES_ERROR("%screation of 'H' BN failed!", SAKKE_ERR_EXT_SED);
                        error_encountered = ES_TRUE;
                    } 
                    else {
                        ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                            "    Rx (RFC 6508 Appendix A, page 17):", 6, Rx_bn);
                        ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                            "    Ry (RFC 6508 Appendix A, page 17):", 6, Ry_bn);
                        ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                            "    H  (RFC 6508 Appendix A, page 18):", 6, H_bn);
                    }
                }
            }
        }
    }

    /**************************************************************************/
    /*! 2) Compute w := < R_(b,S), K_(b,S) >
     *
     * R, we've just been passed and K (aka RSK, and Kbx/Kby in RFC 6508)
     **************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  2) Compute w := < R_(b,S), K_(b,S) >", 
                 SAKKE_SECTION_NAME);

        /* ms_curve retrieved during Init (above) */

        /* Create point 'R'. */
        if (!(R_point = EC_POINT_new(ms_curve))) {
            ES_ERROR("%screate of new 'EC_POINT' for 'R' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (EC_POINT_set_affine_coordinates(
                       ms_curve, R_point, Rx_bn, Ry_bn, bn_ctx)==0) {
            ES_ERROR("%ssetting of coordinates for 'R' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (!(K_point = user_getRSKpoint(
                       user_id, user_id_len, community))) {
            /* Retrieve point 'K'. */
            ES_ERROR("%scould not retrieve POINT 'K'!", SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (!(w_bn = BN_new())) {
            ES_ERROR("%scould not create new BN 'w' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (sakke_computeTLPairing(
                       w_bn, R_point, K_point, ms_param_set)) {
            ES_ERROR("%scompute TL pairing failed!", SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else { /* Success - computed 'w'. */
            ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                "    w (RFC 6508 Appendix A, page 18): ", 6, w_bn); 
        }
    }

    /**************************************************************************/
    /*! 3) Compute SSV := H XOR HashToIntegerRange( w, 2^n, Hash );           */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  3) Compute SSV := H XOR HashToIntegerRange( w, 2^n, Hash );",
                 SAKKE_SECTION_NAME);

        /* w */ 
        if (!(w_ostr = calloc(1, 128))) {
            ES_ERROR("%scalloc for 'w' failed!", SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (!(w_ostr_length = BN_bn2bin(w_bn, w_ostr))) {
            ES_ERROR("%s'w' length incorrect!", SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (!(two_power_n_bn = BN_new())) { /* 2^n */
            ES_ERROR("%scall to create BN '2^n' failed!", SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        }
        else {
            BN_set_bit(two_power_n_bn, ms_getParameter_n(ms_param_set));
  
            /* XOR mask =  HashToIntegerRange( w, 2^n, Hash ) */
            if (!(mask_bn = BN_new())) {
                ES_ERROR("%scall to create BN 'mask' failed!", 
                         SAKKE_ERR_EXT_SED);
                error_encountered = ES_TRUE;
            } 
            else if (sakke_hashToIntegerRangeSHA256(mask_bn, w_ostr, 
                         w_ostr_length, two_power_n_bn)) {
                ES_ERROR("%scall to 'HashToIntegerRangeSHA256' failed!", 
                         SAKKE_ERR_EXT_SED);
                error_encountered = ES_TRUE;
            } 
            else {
                ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                    "    mask (RFC 6508 Appendix A): ", 6, mask_bn);

                /* SSV = H XOR HashtoIntegerRange( w, 2^n, Hash) */
                count = (BN_num_bits(H_bn) >  BN_num_bits(mask_bn) ? 
                         BN_num_bits(H_bn) : BN_num_bits(mask_bn)); 
                /* Use whichever is larger. */
                for (; count >= 0; count--) {
                    if ((BN_is_bit_set(H_bn, count))^(BN_is_bit_set(mask_bn, count))) {
                        BN_set_bit(H_bn, count);
                    } else {
                        BN_clear_bit(H_bn, count);
                    }
                }
                if (BN_num_bytes(H_bn) > *ssv_len) { /* Too big? */
                    ES_ERROR("%scalculated SSV is too long <%d> expected <%d>, failed!",
                             SAKKE_ERR_EXT_SED, BN_num_bytes(H_bn), (int)*ssv_len);
                    error_encountered = ES_TRUE;
                } else if (!(*ssv = calloc(1, *ssv_len))) {
                    ES_ERROR("%scalloc for 'w' failed!", SAKKE_ERR_EXT_SED);
                    error_encountered = ES_TRUE;
                }
                else if (!(BN_bn2bin(H_bn, *ssv+(*ssv_len-BN_num_bytes(H_bn))))) {
                    /* pad if required */
                    ES_ERROR("%s'H' length incorrect!", SAKKE_ERR_EXT_SED);
                    error_encountered = ES_TRUE;
                }
                else {
                    ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(SAKKE_SECTION_NAME,
                        "    ssv (RFC 6508 Appendix A, page 19):", 6, 
                        *ssv, *ssv_len);
                }
            }
        }
    }

    /**************************************************************************/
    /*! 4) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )          */
    /**************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  4) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )", 
                 SAKKE_SECTION_NAME);

        /* Prepare SSV */
        ssv_concat_id_len = *ssv_len+user_id_len;
        if (!(ssv_concat_id = calloc(1, ssv_concat_id_len+1))) {
            ES_ERROR("%scalloc for 'ssv||id' failed!", SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        }
        /* SSV must be in hex format and MUST be (MSB) padded. */
        else if (!(BN_bn2bin(H_bn,  ssv_concat_id+(16-BN_num_bytes(H_bn))))) {
            ES_ERROR("%s'H' length incorrect!", SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        }
        else {
            /* SSV || b */
            memcpy(ssv_concat_id+*ssv_len, user_id, user_id_len);

            /* r = HashToIntegerRangeSHA256( SSV || b, q, Hash ) */
            if (!(r_bn = BN_new())) { /* 2^n */
                ES_ERROR("%scall to create BN 'r' failed!", SAKKE_ERR_EXT_SED);
                error_encountered = ES_TRUE;
            }
            else if (sakke_hashToIntegerRangeSHA256(
                     r_bn, ssv_concat_id, ssv_concat_id_len, 
                     ms_getParameter_q(ms_param_set))) {
                ES_ERROR("%scall to 'HashToIntegerRangeSHA256' failed!",
                         SAKKE_ERR_EXT_SED);
                error_encountered = ES_TRUE;
            } else { /* r computed */
                ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                    "    r (RFC 6508 Appendix A, page 19):", 6, r_bn);
            }
        }
    }

    /*************************************************************************/
    /*! 5) Compute TEST = [r]([b]P + Z_S)                                    */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  5) Compute TEST = [r]([b]P + Z_S)", SAKKE_SECTION_NAME);

        /* Get b, P and Z_S and prep TEST(result)  */
        if (!(Z_S_point = community_getZ_point(community))) {
            ES_ERROR("%scall to retrieve EC_POINT 'Z' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (!(P_point = ms_getParameter_P(ms_param_set))) {
            ES_ERROR("%scall to retrieve EC_POINT 'P' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (!(b_bn = BN_bin2bn(user_id, user_id_len, NULL))) {
            ES_ERROR("%scall to create BN 'b' failed!", SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        } else if (!(TEST_point = EC_POINT_new(ms_getParameter_E(ms_param_set)))) {
            ES_ERROR("%scall to create result POINT 'TEST' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        }

        /* Calculate [r]([b]P + Z_S */ 
        /* [b]P */
        else if (!(EC_POINT_mul(ms_curve, TEST_point, 0, P_point, b_bn, bn_ctx))) {
            ES_ERROR("%scall to EC_POINT_mul '[b]P' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        }
        /* [b]P + Z_S */
        else if (!(EC_POINT_add(ms_curve, TEST_point, TEST_point, Z_S_point, bn_ctx))) {
            ES_ERROR("%scall to EC_POINT_add '[b]P + Z_S' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        }
        /* [r]([b]P + Z_S), r is from step 4 (above) */ 
        else if (!(EC_POINT_mul(ms_curve, TEST_point, 0, TEST_point, r_bn, bn_ctx))) {
            ES_ERROR("%scall to EC_POINT_mul '[r]([b]P + Z_S)' failed!", 
                     SAKKE_ERR_EXT_SED);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME,
                "    TEST (RFC 6508 Appendix A, page 19):", 8, ms_curve, TEST_point);

            /* TEST == Rb */ 
            if (EC_POINT_cmp(ms_curve, TEST_point, R_point, bn_ctx) == 0) {
                ES_DEBUG("%s    TEST == Rb? - YES!", SAKKE_SECTION_NAME);
                ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(SAKKE_SECTION_NAME,
                    "    ssv (RFC 6508 Appendix A, page 19):", 8, 
                    *ssv, *ssv_len);

                ret_val = ES_SUCCESS;
    
                /* Actually done on return to main */
                ES_DEBUG("%s  6) Output SSV for use to derive key material",
                         SAKKE_SECTION_NAME);
                ES_DEBUG("%s     for the application to be keyed.",
                         SAKKE_SECTION_NAME);
            }
            else {
                ES_DEBUG("%s    TEST == Rb? - NO! DO NOT use SSV!",
                         SAKKE_SECTION_NAME);
                /* If TEST does not equal R_(b,S), then B MUST NOT */
                /* use the SSV to derive key material              */
                memset(*ssv, 0x0, *ssv_len);
                *ssv = NULL;
            }
        }
    }

    /**************************************************************************/
    /* Cleanup.                     .                                         */
    /**************************************************************************/
    BN_clear_free(b_bn);
    BN_clear_free(H_bn);
    BN_clear_free(mask_bn);
    BN_clear_free(r_bn);
    BN_clear_free(Rx_bn);
    BN_clear_free(Ry_bn);
    BN_clear_free(two_power_n_bn);
    BN_clear_free(w_bn);

    ms_curve = NULL; /* Temporary reference. */

    if (w_ostr != NULL) { 
        memset(w_ostr, 0, w_ostr_length); 
        free(w_ostr);
    }
    if (Rx_ostr != NULL) {
        memset(Rx_ostr, 0, 128);
        free(Rx_ostr);
    }
    if (Ry_ostr != NULL) {
        memset(Ry_ostr, 0, 128 + 1);
        free(Ry_ostr);
    }
    if (H_ostr != NULL) {
        memset(H_ostr,  0,  16 + 1);
        free(H_ostr);
    }
    if (ssv_concat_id != NULL) { 
        memset(ssv_concat_id, 0, ssv_concat_id_len); 
        free(ssv_concat_id); 
    }

    P_point = NULL; /* Temporary reference. */
    EC_POINT_clear_free(K_point);
    EC_POINT_clear_free(R_point);
    EC_POINT_clear_free(TEST_point);
    EC_POINT_clear_free(Z_S_point);

    BN_CTX_free(bn_ctx);

    return ret_val;

} /* sakke_extractSharedSecret */

/***************************************************************************//**
 * Validates the RSK provided by the KMS for use by this user.
 *
 *     RFC6508 6.1.2 (para 2)
 *     ----------------------
 *
 *     Upon receipt of key material, each user MUST verify its RSK. For
 *     Identifier 'a', RSKs from KES_T are verified by checking that the
 *     following equation holds: < [a]P + Z, K_(a,T) > = g, where 'a' is
 *     interpreted as an integer.
 *
 * @param[in] user_id        String of the 'user_id'.
 * @param[in] user_id_len    Length of 'user_id' string.
 * @param[in] community      String of the 'community'.
 * @param[in] RSK            RSK (Receiver Secret Key) octet string.
 * @param[in] RSK_len        Length of RSK (Receiver Secret Key).
 *
 * @return ES_SUCCESS, ES_FAILURE or ES_SAKKE_ERROR_RSK_VALIDATION_FAILED. The 
 *         latter meaning the caller MUST revoke the keyset for the id.
 ******************************************************************************/
uint8_t sakke_validateRSK(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    const uint8_t *RSK,
    const size_t   RSK_len)
{
    uint8_t  ret_val           = ES_FAILURE;
    uint8_t  error_encountered = ES_FALSE;
    BN_CTX   *bn_ctx           = NULL;

    EC_GROUP *ec_group         = NULL;
    EC_GROUP *ms_curve         = NULL;

    EC_POINT *a_P_plus_Z_point = NULL;
    EC_POINT *Z_point          = NULL;
    EC_POINT *RSK_point        = NULL;

    BIGNUM   *RSKx_bn          = NULL;
    BIGNUM   *RSKy_bn          = NULL;
    BIGNUM   *a                = NULL;
    BIGNUM   *result           = NULL; /* i.e. the result < [a]P + Z, K_(a,T) >
                                        * that will be compared with 'g'.
                                        */
    uint8_t   ms_param_set     = 1;  /* Initially there is only one Set. */

    /* ES_DEBUG("                   ***%s:%s:%d", 
     * __FUNCTION__, __FILE__, __LINE__);
     */

    /*************************************************************************/
    /* Check passed parameters                                               */
    /*************************************************************************/
    if (NULL == user_id) {
        ES_ERROR("%sUser ID is NULL!", SAKKE_ERR_VAL_RSK);
        error_encountered = ES_TRUE;
    } else if (user_id_len == 0) {
        ES_ERROR("%sUser ID length is 0!", SAKKE_ERR_VAL_RSK);
        error_encountered = ES_TRUE;
    } else if (NULL == community) {
        ES_ERROR("%sCommunity reference is NULL!", SAKKE_ERR_VAL_RSK);
        error_encountered = ES_TRUE;
    } else if (!community_exists(community)) {
        ES_ERROR("%sCommunity <%s> not stored!", SAKKE_ERR_VAL_RSK, community);
        error_encountered = ES_TRUE;
    } else if (NULL == RSK) {
        ES_ERROR("%sRSK  is NULL!", SAKKE_ERR_VAL_RSK);
        error_encountered = ES_TRUE;
    } else if (RSK_len == 0) {
        ES_ERROR("%sRSK length is 0!", SAKKE_ERR_VAL_RSK);
        error_encountered = ES_TRUE;
    }

    /*************************************************************************/
    /* Init                                                                  */
    /*************************************************************************/
    if (!error_encountered) {
        if (!(bn_ctx = BN_CTX_new())) {
            ES_ERROR("%scould not create BN context!", SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        } 
        else if (1 != (ms_param_set = community_get_paramSet(community))) {
            ES_ERROR("%sMS Parameter != 1 <%d> not supported", 
                     SAKKE_ERR_VAL_RSK, ms_param_set);
            error_encountered = ES_TRUE;
        }
        else if (!(RSKx_bn = BN_bin2bn(RSK+1, RSK_len/2, NULL))) {
            ES_ERROR("%sunable to create BN 'RSkx'!", SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        }
        else if (!(RSKy_bn = BN_bin2bn(RSK+1+(RSK_len/2), RSK_len/2, NULL))) {
            ES_ERROR("%sunable to create BN 'RSky'!", SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        }
        else if (!(ms_curve = ms_getParameter_E(SAKKE_SUPPORTED_MS_PARAM_SET))) {
            ES_ERROR("%scould not retrieve 'E' Curve!", SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        } 
        else if (!(RSK_point = EC_POINT_new(ms_curve))) {
            ES_ERROR("%sunable to create Point 'P' on Curve 'E'!", 
                     SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        }
        else if (EC_POINT_set_affine_coordinates(
                    ms_curve, RSK_point, RSKx_bn, RSKy_bn, NULL)==0) {
            ES_ERROR("%sunable to set coordinates for 'RSK'!", 
                     SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME,
                "   RSK:", 8, ms_curve, RSK_point);
        }
    }
    /*************************************************************************/
    /*              START PROCESS AS PER RFC 6508 SECTION 6.1.2              */
    /*************************************************************************/
    if (!error_encountered) {
        ES_DEBUG("%s  RFC 6508 6.1.2.", SAKKE_SECTION_NAME);
        ES_DEBUG("%s  1) The following MUST hold < [a]P + Z, K_(a,T) > = g,",
                 SAKKE_SECTION_NAME);
        ES_DEBUG("%s     where a is interpreted as an integer", 
                 SAKKE_SECTION_NAME);

        /* Group is used several times, so get a local copy. */ 
        if (!(ec_group = EC_GROUP_dup(
                ms_getParameter_E(ms_param_set)))) {
            ES_ERROR("%sunable to create group!", SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        }
        /* Result holder for [a]P + Z */
        else if (!(a_P_plus_Z_point = EC_POINT_new(ec_group))) {
            ES_ERROR("%sEC_POINT 'a_P_plus_Z' creation failed!", 
                     SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        }
        /* 'a'  ID as int. */
        else if (!(a = BN_bin2bn((unsigned char *)user_id, (int)user_id_len, NULL))) {
            ES_ERROR("i%sBN 'a' (ID) creation failed!", SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        }
        /* 'P' obtained from call to ms public parameters */

        /* 'Z' (point) */
        else if (!(Z_point = community_getZ_point(community))) {
            ES_ERROR("%sretrieval of EC_POINT 'Z' failed!", SAKKE_ERR_VAL_RSK);
            error_encountered = ES_TRUE;
        }
        else {
            ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME,
                "   Z:", 8, ec_group, Z_point);

            ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                "    a aka 'identifier':", 6, a);
            ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME,
                "    K_(a,T) aka Kb(RFC 6508 Appendix A, page 18):",
                8, ec_group, RSK_point);
            ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME, 
                "    P (RFC 6509 Appendix A, page 19) :",
                8, ec_group, ms_getParameter_P(ms_param_set));
            ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME, 
                "    Z (RFC 6508 Appendix A, page 16):", 8, ec_group, Z_point);

            /* Multiply [a]P */
            if (!(EC_POINT_mul(ec_group, a_P_plus_Z_point, 0, 
                               ms_getParameter_P(ms_param_set), a, bn_ctx))) {
                ES_ERROR("%sPoint mul '[a]P' failed!", SAKKE_ERR_VAL_RSK);
                error_encountered = ES_TRUE;
            }
            else {
                ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME, 
                    "    [a]P:", 8, ec_group, a_P_plus_Z_point);

                /* Add 'Z' */
                if (!(EC_POINT_add(ec_group, a_P_plus_Z_point, 
                        a_P_plus_Z_point, Z_point, bn_ctx))) {
                    ES_ERROR("%sPoint add '[a]P + Z' failed!", 
                             SAKKE_ERR_VAL_RSK);
                    error_encountered = ES_TRUE;
                }
                else {
                    ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME, 
                        "    [a]P+Z:", 8, ec_group, a_P_plus_Z_point);
    
                    if (!(result = BN_new())) {
                        ES_ERROR("%scould not create BN for 'result'!", 
                                 SAKKE_ERR_VAL_RSK);
                        error_encountered = ES_TRUE;
                    }
                    else {
                        ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME,
                            "    RSK:", 8, ec_group, RSK_point);
                                          
                        if (sakke_computeTLPairing(result, a_P_plus_Z_point, 
                                                    RSK_point, ms_param_set)) {
                            ES_ERROR("%scompute TL pairing failed!", 
                                     SAKKE_ERR_VAL_RSK);
                            error_encountered = ES_TRUE;
                        }
                        else {
                            ES_DEBUG_DISPLAY_AFFINE_COORDS(SAKKE_SECTION_NAME,
                                "    < [a]P + Z, K_(a,T) >:", 8, 
                                ec_group, a_P_plus_Z_point);
                            ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, "    (calculated):", 6, result);
                            ES_DEBUG_DISPLAY_BN(SAKKE_SECTION_NAME, 
                                "    g (RFC 6509 Appendix A, page 20):", 6, 
                                ms_getParameter_g(ms_param_set));
    
                            if (BN_cmp(result, ms_getParameter_g(ms_param_set))) {
                                ES_ERROR("%sValidation failed <[a]P + Z, K_(a,T)> != g!", SAKKE_ERR_VAL_RSK);
                                ES_ERROR("%sthe keyset for the id MUST be revoked!", SAKKE_ERR_VAL_RSK);
                                error_encountered = ES_TRUE;
                                ret_val = ES_SAKKE_ERROR_RSK_VALIDATION_FAILED;
                            }
                            else {
                                ES_DEBUG("%s    w == g? YES, Validation success!", 
                                         SAKKE_SECTION_NAME);
                                ret_val = ES_SUCCESS;
                            }
                        }
                    }
                }
            }
        }
    }

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_clear_free(a);
    BN_clear_free(result);
    BN_clear_free(RSKx_bn);
    BN_clear_free(RSKy_bn);
    EC_GROUP_free(ec_group);
    EC_POINT_clear_free(RSK_point);
    EC_POINT_clear_free(Z_point);
    EC_POINT_clear_free(a_P_plus_Z_point);
    BN_CTX_free(bn_ctx);

    return ret_val;
} /* sakke_validateRSK */

/******************************************************************************/
/* Internal functions not to be called externally.                            */
/******************************************************************************/

/***************************************************************************//**
 * Defines a BN with value of 2.
 *
 * @return A pointer to a BIGNUM of value 2.
 ******************************************************************************/
static inline BIGNUM *BN_value_two() {
    if (BN_two == NULL) {
       BN_dec2bn(&BN_two, "2+");
    }
    return BN_two;
} /* BN_value_two */

/***************************************************************************//**
 * Defines a BN with value of 3.
 *
 * @return A pointer to a BIGNUM of value 3.
 ******************************************************************************/
static inline BIGNUM *BN_value_three() {
    if (BN_three == NULL) {
       BN_dec2bn(&BN_three, "3");
    }
    return BN_three;
} /* BN_value_three */

/***************************************************************************//**
 * Square a point defined by point_x and point_y, placing the result in
 * result_x, result_y.
 *
 * Note! result_x, result_y can be the same as point_x, point_y.
 *
 * @param[in]  p
 * @param[out] result_x
 * @param[out] result_y
 * @param[in]  point_x
 * @param[in]  point_y
 ******************************************************************************/
static inline void sakke_pointSquare(
    BIGNUM *p,
    BIGNUM *result_x,
    BIGNUM *result_y,
    BIGNUM *point_x,
    BIGNUM *point_y) 
{
    BIGNUM *tmp_Ax1 = NULL;
    BIGNUM *tmp_Ax2 = NULL;
    BIGNUM *tmp_Bx1 = NULL;
    BIGNUM *tmp_Bx2 = NULL;
    BN_CTX *bn_ctx  = BN_CTX_new();

    tmp_Ax1 = BN_new(); 
    tmp_Ax2 = BN_new(); 
    tmp_Bx1 = BN_new(); 
    tmp_Bx2 = BN_new(); 

    BN_copy(tmp_Ax1, point_x);
    BN_copy(tmp_Ax2, point_y);
    BN_add(tmp_Bx1, point_x, point_y);
    BN_sub(tmp_Bx2, point_x, point_y);

    /* X1 */
    BN_mul(result_x, tmp_Bx1, tmp_Bx2, bn_ctx); 
    BN_nnmod(result_x, result_x, p, bn_ctx);    

    /* X2 */
    BN_mul(result_y, tmp_Ax1, tmp_Ax2, bn_ctx); 
    BN_mul(result_y, result_y, BN_value_two(), bn_ctx); 
    BN_nnmod(result_y, result_y, p, bn_ctx);    

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_clear_free(tmp_Ax1); 
    BN_clear_free(tmp_Ax2); 
    BN_clear_free(tmp_Bx1); 
    BN_clear_free(tmp_Bx2); 

    BN_CTX_free(bn_ctx);

} /* sakke_pointSquare */

/***************************************************************************//**
 * Multiply two points (point_1 and point_2), with coordinates of point_1_x,
 * point_1_y, and, point_2_x, point_2_y,  placing the result in result_x,
 * result_y.
 *
 * Note! result_x, result_y can be the same as point_1_x, point_1_y, or
 *       point_2_x, point_2_y.
 *
 * @param[in]  p
 * @param[out] result_x
 * @param[out] result_y
 * @param[in]  point_1_x
 * @param[in]  point_1_y
 * @param[in]  point_2_x
 * @param[in]  point_2_y
 ******************************************************************************/
static inline void sakke_pointsMultiply(
    BIGNUM *p, 
    BIGNUM *result_x,
    BIGNUM *result_y,
    BIGNUM *point_1_x,
    BIGNUM *point_1_y,
    BIGNUM *point_2_x,
    BIGNUM *point_2_y)
{
    BIGNUM *tmp    = NULL;
    BIGNUM *res_x  = NULL;
    BIGNUM *res_y  = NULL;
    BN_CTX *bn_ctx = BN_CTX_new();

    tmp   = BN_new();
    res_x = BN_new();
    res_y = BN_new();

    /* X1 */
    BN_mul(res_x, point_1_x, point_2_x, bn_ctx); 
    BN_mul(tmp, point_1_y, point_2_y, bn_ctx); 
    BN_sub(res_x, res_x, tmp);
    BN_nnmod(res_x, res_x, p, bn_ctx);

    /* X2 */
    BN_mul(res_y, point_1_x, point_2_y, bn_ctx);
    BN_mul(tmp, point_1_y, point_2_x, bn_ctx);
    BN_add(res_y, res_y, tmp);
    BN_nnmod(res_y, res_y, p, bn_ctx);

    BN_copy(result_x, res_x);
    BN_copy(result_y, res_y);

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_clear_free(tmp);
    BN_clear_free(res_x);
    BN_clear_free(res_y);

    BN_CTX_free(bn_ctx);
} /* sakke_pointsMultiply */

/***************************************************************************//**
 * Multiply a point the corrdinates of point_x, point_y by mulitplier,
 * placing the result in result_x, result_y.
 *
 * Note! result_x, result_y can be the same as point_x, point_y.
 *
 * Readers might be wondering why (as I did) we can't just do something like:
 *
 *     EC_POINT_set_affine_coordinates(a-group, a-point, x, y, bn_ctx);
 *     EC_POINT_mul(a-group, a-point, 0, a-point, BN_value_two(), bn_ctx);
 *     EC_POINT_get_affine_coordinates_GFp(-agroup, a-point, x, y, bn_ctx);
 *     EC_GROUP_free(a-group);
 *     EC_POINT_free(a-point);
 *
 * Turns out, having tried it, that is 50%-60% slower than this code.
 *
 * @param[in]  p
 * @param[out] result_x
 * @param[out] result_y
 * @param[in]  point_x
 * @param[in]  point_y
 * @param[in]  multiplier 
 ******************************************************************************/
static inline void sakke_pointMultiply(
    BIGNUM *p, 
    BIGNUM *result_x,
    BIGNUM *result_y,
    BIGNUM *point_x,
    BIGNUM *point_y,
    BIGNUM *multiplier)
{
    BIGNUM *lambda    = NULL;
    BIGNUM *lambda_sq = NULL;
    BIGNUM *EAT1      = NULL;
    BIGNUM *EARx      = NULL;
    BIGNUM *EARy      = NULL;
    BN_CTX *bn_ctx    = BN_CTX_new();

    lambda    = BN_new();
    lambda_sq = BN_new();
    EAT1      = BN_new();
    EARx      = BN_new();
    EARy      = BN_new();

    BN_exp(lambda, point_x, BN_value_two(), bn_ctx);
    BN_nnmod(lambda, lambda, p, bn_ctx);

    BN_sub(lambda, lambda, BN_value_one());
    BN_mul(lambda, lambda, BN_value_three(), bn_ctx);

    BN_mul(EAT1, point_y, BN_value_two(), bn_ctx);

    /* Should check NULL here if inverse cannot be found! */
    BN_mod_inverse(EAT1, EAT1, p, bn_ctx);

    BN_mul(lambda, lambda, EAT1, bn_ctx);
    BN_nnmod(lambda, lambda, p, bn_ctx);

    BN_exp(lambda_sq, lambda, BN_value_two(), bn_ctx);
    BN_nnmod(lambda_sq, lambda_sq, p, bn_ctx);

    BN_mul(EAT1, point_x, BN_value_two(), bn_ctx);
    BN_sub(EARx, lambda_sq, EAT1);
    BN_nnmod(EARx, EARx, p, bn_ctx);

    BN_sub(EARy, EAT1, lambda_sq);
    BN_add(EARy, EARy, point_x);
    BN_mul(EARy, EARy, lambda, bn_ctx);
    BN_nnmod(EARy, EARy, p,      bn_ctx);

    BN_sub(EARy, EARy, point_y);
    BN_nnmod(EARy, EARy, p, bn_ctx);

    result_x = BN_copy(result_x, EARx);
    result_y = BN_copy(result_y, EARy);

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_clear_free(lambda);
    BN_clear_free(lambda_sq);
    BN_clear_free(EAT1);
    BN_clear_free(EARx);
    BN_clear_free(EARy);
    BN_CTX_free(bn_ctx);

} /* sakke_pointMultiply */

/***************************************************************************//**
 * Add two points the corrdinates of which are of point_1_x, point_1_y and
 * point_2_x, point_2_y,  placing the result in result_x, result_y.
 *
 * Note! result_x, result_y can be the same as point_1_x, point_1_y, or,
 *       point_2_x, point_2_y.
 *
 * @param[in]  p
 * @param[out] result_x
 * @param[out] result_y
 * @param[in]  point_1_x
 * @param[in]  point_1_y
 * @param[in]  point_2_x
 * @param[in]  point_2_y
 ******************************************************************************/
static inline void sakke_pointsAdd(
    BIGNUM *p, 
    BIGNUM       *result_x,
    BIGNUM       *result_y,
    BIGNUM *point_1_x,
    BIGNUM *point_1_y,
    BIGNUM *point_2_x,
    BIGNUM *point_2_y)
{
    BIGNUM *lambda    = NULL;
    BIGNUM *lambda_sq = NULL;
    BIGNUM *EAT1      = NULL;
    BIGNUM *EARx      = NULL;
    BIGNUM *EARy      = NULL;
    BN_CTX *bn_ctx    = BN_CTX_new();

    lambda    = BN_new();
    lambda_sq = BN_new();
    EAT1      = BN_new();
    EARx      = BN_new();
    EARy      = BN_new();

    BN_sub(lambda, point_1_y, point_2_y);
    BN_sub(EAT1, point_1_x, point_2_x);

    /* TBD - Should check NULL here if inverse cannot be found!!! */
    BN_mod_inverse(EAT1, EAT1, p, bn_ctx);

    BN_mul(lambda, lambda, EAT1, bn_ctx);
    BN_nnmod(lambda, lambda, p, bn_ctx);

    BN_exp(lambda_sq, lambda, BN_value_two(), bn_ctx);
    BN_nnmod(lambda_sq, lambda_sq, p, bn_ctx);

    BN_sub(EARx, lambda_sq, point_2_x);
    BN_sub(EARx, EARx, point_1_x);
    BN_nnmod(EARx, EARx, p, bn_ctx);

    BN_sub(EARy, point_1_x, lambda_sq);

    BN_mul(point_2_x, point_2_x, BN_value_two(), bn_ctx);
    BN_add(EARy, EARy, point_2_x);

    BN_mul(EARy, EARy, lambda, bn_ctx);
    BN_nnmod(EARy, EARy, p, bn_ctx);

    BN_sub(EARy, EARy, point_2_y);
    BN_nnmod(EARy, EARy, p, bn_ctx);

    result_x = BN_copy(result_x, EARx);
    result_y = BN_copy(result_y, EARy);

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_clear_free(lambda);
    BN_clear_free(lambda_sq);
    BN_clear_free(EAT1);
    BN_clear_free(EARx);
    BN_clear_free(EARy);

    BN_CTX_free(bn_ctx);

} /* sakke_pointsAdd */

/***************************************************************************//**
 * Raise point (defined by point_x, point_y) to power 'n', placing the result
 * in result_x, result_y.
 *
 * Note! result_x, result_y can be the same as point_x, point_y.
 *
 * @param[in]  p
 * @param[out] result_x
 * @param[out] result_y
 * @param[in]  point_x
 * @param[in]  point_y
 * @param[in]  n
 *
 * @return ES_SUCESS or ES_FAILURE
 ******************************************************************************/
static inline uint8_t sakke_pointExponent(
    BIGNUM *p,
    BIGNUM *result_x,
    BIGNUM *result_y,
    BIGNUM *point_x,
    BIGNUM *point_y,
    BIGNUM *n)
{
    uint8_t ret_val = ES_FAILURE;
    BN_CTX *bn_ctx  = BN_CTX_new();
    size_t N        = 0;

   if (!BN_is_zero(n)) {
        BN_copy(result_x, point_x);
        BN_copy(result_y, point_y);

        N = BN_num_bits(n)-1;
        for (; N != 0; --N) {
            sakke_pointSquare(p, result_x, result_y, result_x, result_y);
            if (BN_is_bit_set(n, (int)N-1)) {
                sakke_pointsMultiply(p, result_x, result_y, result_x, result_y, 
                                     point_x, point_y);
            }
        }
        ret_val = ES_SUCCESS;
    }

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_CTX_free(bn_ctx);

    return ret_val;
} /* sakke_pointExponent */

/***************************************************************************//**
 * Note! result_x, result_y can be the same as point_x, point_y.
 *
 * @param[out] w_bn the result.
 * @param[in]  R_point 
 * @param[in]  rsk_point 
 * @param[in]  msParamSet 
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
static uint8_t sakke_computeTLPairing(
    BIGNUM   *w_bn,
    EC_POINT *R_point,    /* C */
    EC_POINT *rsk_point,  /* Q */
    uint8_t   msParamSet) {

    uint8_t ret_val        = ES_FAILURE;
    BIGNUM *p_bn           = NULL;
    BIGNUM *q_bn           = NULL;
    BIGNUM *q_minus_one_bn = NULL;
    BIGNUM *Vx_bn          = NULL;
    BIGNUM *Vy_bn          = NULL;
    BIGNUM *Rx_bn          = NULL;
    BIGNUM *Ry_bn          = NULL;
    BIGNUM *RSKx_bn        = NULL;
    BIGNUM *RSKy_bn        = NULL;
    BIGNUM *Cx_bn          = NULL;
    BIGNUM *Cy_bn          = NULL;
    BIGNUM *Qx_bn          = NULL;
    BIGNUM *Qy_bn          = NULL;
    BIGNUM *tmp_t_bn       = NULL;
    BIGNUM *T_x1_bn        = NULL;
    BIGNUM *T_x2_bn        = NULL;
    BIGNUM *t_bn           = NULL;
    size_t  N              = 0;

    BN_CTX *bn_ctx = BN_CTX_new();

    p_bn           = BN_dup(ms_getParameter_p(msParamSet));
    q_bn           = BN_dup(ms_getParameter_q(msParamSet));
    q_minus_one_bn = BN_new();
    BN_sub(q_minus_one_bn, q_bn, BN_value_one());

    Vx_bn     = BN_new(); 
    Vy_bn     = BN_new();
    Rx_bn     = BN_new(); /* R X, Y coords   */
    Ry_bn     = BN_new();
    RSKx_bn   = BN_new(); /* RSK X, Y coords */
    RSKy_bn   = BN_new();
    tmp_t_bn  = BN_new(); /* Temporary BN    */
    T_x1_bn   = BN_new();
    T_x2_bn   = BN_new();
    t_bn      = BN_new();

    /* ES_DEBUG("                  ***%s:%s:%d RFC 6508 3.2.1. Tate-Lichtenbaum pairing", 
     *          __FUNCTION__, __FILE__, __LINE__);
     */

    EC_POINT_get_affine_coordinates_GFp(
        ms_getParameter_E(msParamSet), R_point, Rx_bn, Ry_bn, bn_ctx);
    Cx_bn = BN_dup(Rx_bn);
    Cy_bn = BN_dup(Ry_bn);

    EC_POINT_get_affine_coordinates_GFp(
        ms_getParameter_E(msParamSet), rsk_point, RSKx_bn, RSKy_bn, bn_ctx);
    Qx_bn = BN_dup(RSKx_bn);
    Qy_bn = BN_dup(RSKy_bn);

    N = BN_num_bits(q_minus_one_bn)-1;
    /* printf("Number of bits: %d\n", N); */
 
    BN_dec2bn(&Vx_bn, "1");
    BN_dec2bn(&Vy_bn, "0");

    /* for bits of q-1, starting with second most significant
     * bit, ending with the least significant bit, do
     */
    for (; N != 0; --N) {
        sakke_pointSquare(p_bn, Vx_bn, Vy_bn, Vx_bn, Vy_bn);

        BN_exp(T_x1_bn, Cx_bn, BN_value_two(), bn_ctx);
        BN_nnmod(T_x1_bn, T_x1_bn, p_bn, bn_ctx);
        BN_sub(T_x1_bn, T_x1_bn, BN_value_one());
        BN_mul(T_x1_bn, T_x1_bn, BN_value_three(), bn_ctx);

        BN_add(t_bn, Qx_bn, Cx_bn);

        BN_mul(T_x1_bn, T_x1_bn, t_bn, bn_ctx);
        BN_nnmod(T_x1_bn, T_x1_bn, p_bn, bn_ctx);

        BN_exp(t_bn, Cy_bn, BN_value_two(), bn_ctx);
        BN_nnmod(t_bn, t_bn, p_bn, bn_ctx);

        BN_mul(t_bn, t_bn, BN_value_two(), bn_ctx);
        BN_sub(T_x1_bn, T_x1_bn, t_bn);
        BN_nnmod(T_x1_bn, T_x1_bn, p_bn, bn_ctx);

        BN_mul(T_x2_bn, Cy_bn, BN_value_two(), bn_ctx);
        BN_mul(T_x2_bn, T_x2_bn, Qy_bn, bn_ctx);
        BN_nnmod(T_x2_bn, T_x2_bn, p_bn, bn_ctx);

        sakke_pointsMultiply(p_bn, Vx_bn, Vy_bn,
                             Vx_bn, Vy_bn, T_x1_bn, T_x2_bn); 

        /* Doubling EC point
         * (it is known the C is not at infinity)
         */
        sakke_pointMultiply(p_bn, Cx_bn, Cy_bn, Cx_bn, Cy_bn, BN_value_two());

        if (BN_is_bit_set(q_minus_one_bn, (int)N-1)) {
            BN_add(T_x1_bn, Qx_bn, Rx_bn);
            BN_mul(T_x1_bn, T_x1_bn, Cy_bn, bn_ctx);
            BN_nnmod(T_x1_bn, T_x1_bn, p_bn, bn_ctx);
            BN_add(tmp_t_bn, Qx_bn, Cx_bn);
            BN_mul(tmp_t_bn, tmp_t_bn, Ry_bn, bn_ctx);
            BN_sub(T_x1_bn, T_x1_bn, tmp_t_bn);
            BN_nnmod(T_x1_bn, T_x1_bn, p_bn, bn_ctx);
            BN_sub(T_x2_bn, Cx_bn, Rx_bn);
            BN_mul(T_x2_bn, T_x2_bn, Qy_bn, bn_ctx);
            BN_nnmod(T_x2_bn, T_x2_bn, p_bn, bn_ctx);

            sakke_pointsMultiply(p_bn, Vx_bn, Vy_bn,
                           Vx_bn, Vy_bn, T_x1_bn, T_x2_bn); 

            /* Addition of EC points R and C                      */
            /* (it is known that neither R nor C are at infinity) */
            sakke_pointsAdd(p_bn, Cx_bn, Cy_bn, Rx_bn, Ry_bn, Cx_bn, Cy_bn);
        }
    }

    sakke_pointSquare(p_bn, Vx_bn, Vy_bn, Vx_bn, Vy_bn);
    sakke_pointSquare(p_bn, Vx_bn, Vy_bn, Vx_bn, Vy_bn);
    BN_mod_inverse(w_bn, Vx_bn, p_bn, bn_ctx);
    BN_mul(w_bn, w_bn, Vy_bn, bn_ctx);
    BN_nnmod(w_bn, w_bn, p_bn, bn_ctx);

    ret_val = ES_SUCCESS;

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_clear_free(p_bn);
    BN_clear_free(q_bn);
    BN_clear_free(q_minus_one_bn);
    BN_clear_free(Vx_bn);
    BN_clear_free(Vy_bn);
    BN_clear_free(Rx_bn);
    BN_clear_free(Ry_bn);
    BN_clear_free(RSKx_bn);
    BN_clear_free(RSKy_bn);
    BN_clear_free(Cx_bn);
    BN_clear_free(Cy_bn);
    BN_clear_free(Qx_bn);
    BN_clear_free(Qy_bn);
    BN_clear_free(tmp_t_bn);
    BN_clear_free(T_x1_bn);
    BN_clear_free(T_x2_bn);
    BN_clear_free(t_bn);

    BN_CTX_free(bn_ctx);

    return ret_val;
} /* sakke_computeTLPairing */

/***************************************************************************//**
 * Described in RFC6508 Section 5.1.
 *
 * @param[out] v     Result integer.
 * @param[in]  s     's' string.
 * @param[in]  s_len Length of 's' string.
 * @param[in]  n     'n' value.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
static uint8_t sakke_hashToIntegerRangeSHA256(
    BIGNUM  *v,
    uint8_t *s,
    size_t   s_len,
    BIGNUM  *n) 
{
    uint8_t        ret_val           = ES_FAILURE;
    uint8_t        error_encountered = ES_FALSE;
    BIGNUM        *vprime_bn         = NULL;
    unsigned int   l                 = 0;
    unsigned char  hash_A[SHA256_DIGEST_LENGTH];
    unsigned char  hash_h[SHA256_DIGEST_LENGTH];
    uint8_t        hi_concat_A[2*SHA256_DIGEST_LENGTH];
    char           hash_vi[SHA256_DIGEST_LENGTH];
    unsigned int   count_i           = 0;
    uint8_t       *vprime            = NULL;
    SHA256_CTX     h;
    SHA256_CTX     A;
    SHA256_CTX     vi;
    BN_CTX        *bn_ctx            = NULL;

    /*ES_DEBUG("                       ***%s:%s:%d HashToIntegerRangeSHA256", 
     *         __FUNCTION__, __FILE__, __LINE__);
     */

    /**************************************************************************/
    /* Check passed parameters                                                */
    /**************************************************************************/

    /**************************************************************************/
    /* Init.                                                                  */
    /**************************************************************************/
    bn_ctx = BN_CTX_new();
    memset(&hash_A[0],      0, sizeof(hash_A));
    memset(&hash_h[0],      0, sizeof(hash_h));
    memset(&hi_concat_A[0], 0, sizeof(hi_concat_A));
    memset(&hash_vi[0],     0, sizeof(hash_vi));

    /**************************************************************************/
    /*! Perform actions described in RFC6508 Section 5.1                      */
    /**************************************************************************/

    /**************************************************************************/
    /*! 1) A = hashfn(s) - hash the string                                    */
    /**************************************************************************/
    if (!SHA256_Init(&A)) {
        ES_ERROR("%s'A' SHA256_Init failed!", SAKKE_ERR_H2INTRANGE);
        error_encountered = ES_TRUE;
    } else if (!SHA256_Update(&A, (char *)s, s_len)) {
        ES_ERROR("%s'A' SHA256_Update failed!", SAKKE_ERR_H2INTRANGE);
        error_encountered = ES_TRUE;
    } else if (!SHA256_Final((unsigned char *)&hash_A, &A)) {
        ES_ERROR("%s'A' SHA256_Final failed!", SAKKE_ERR_H2INTRANGE);
        error_encountered = ES_TRUE;
    }

    /**************************************************************************/
    /*! 2) Let h_0 = 00...00 is a string of null bits of length hash_len bits.*/
    /**************************************************************************/
    if (!error_encountered) {
        memset(&h, 0, sizeof(h));
    }

    /**************************************************************************/
    /*! 3) l = ceiling(lg(n)/hashlen)                                         */
    /**************************************************************************/
    if (!error_encountered) {
        l = (BN_num_bits(n)+255) >> 8;
        /* Now we have l, allocate enough space for v'... */
        if (!(vprime = calloc(1, l * 32))) {
            ES_ERROR("%scould not allocate space for 'vprime'!", 
                     SAKKE_ERR_H2INTRANGE);
            error_encountered = ES_TRUE;
        }
    }

    /**************************************************************************/
    /*! 4) For i in [1, l] do                                                 */
    /**************************************************************************/
    if (!error_encountered) {
        for (count_i=0; count_i < l; count_i++) {
            /******************************************************************/
            /* 4.a.   Let h_i = hashfn(h_(i - 1)) i                           */
            /******************************************************************/
            if (!SHA256_Init(&h)) {
                ES_ERROR("%s'h' SHA256_Init failed!", SAKKE_ERR_H2INTRANGE);
                error_encountered = ES_TRUE;
            } else if (!SHA256_Update(&h, &hash_h, sizeof(hash_h))) {
                ES_ERROR("%s'h' SHA256_Update failed!", SAKKE_ERR_H2INTRANGE);
                error_encountered = ES_TRUE;
            } else if (!SHA256_Final((unsigned char *)&hash_h, &h)) {
                ES_ERROR("%s'h' SHA256_Final failed!", SAKKE_ERR_H2INTRANGE);
                error_encountered = ES_TRUE;
            } else {
                /**************************************************************/
                /* 4.b.   Let v_i = hashfn(h_i || A)                          */
                /*        where || denotes concatenation.                     */
                /**************************************************************/
                /* First concat h_i and A. */
                memset(&hi_concat_A, 0,       sizeof(hi_concat_A));
                memcpy(&hi_concat_A, &hash_h, sizeof(hash_h));
                memcpy(&hi_concat_A[sizeof(hash_h)], &hash_A, sizeof(hash_A));
        
                /* Hash it to obtain v_i. */
                if (!SHA256_Init(&vi)) {
                    ES_ERROR("%s'v_i' SHA256_Init failed!", SAKKE_ERR_H2INTRANGE);
                    error_encountered = ES_TRUE;
                } else if (!SHA256_Update(&vi, &hi_concat_A, sizeof(hi_concat_A))) {
                    ES_ERROR("%s'v_i' SHA256_Update failed!", SAKKE_ERR_H2INTRANGE);
                    error_encountered = ES_TRUE;
                } else if (!SHA256_Final((unsigned char *)&hash_vi, &vi)) {
                    ES_ERROR("%s'v_i' SHA256_Final failed!", SAKKE_ERR_H2INTRANGE);
                    error_encountered = ES_TRUE;
                } else {
                    /**********************************************************/
                    /*! 5.   Let v' = v_1 || ...  || v_l\n");                 */
                    /**********************************************************/
                    memcpy(vprime+(count_i * 32), &hash_vi, 32);
                }
            }
        }
    }

    /**************************************************************************/
    /*! 6) v = v' mod n                                                       */
    /**************************************************************************/
    if (!error_encountered) {
        if (!(vprime_bn = BN_bin2bn((unsigned char *)vprime, (count_i)*32, NULL))) {
            ES_ERROR("%sunable to create BN 'vprime'!", SAKKE_ERR_H2INTRANGE);
            error_encountered = ES_TRUE;
        } else if (!(BN_nnmod(v, vprime_bn, n, bn_ctx))) {
            ES_ERROR("%sv = v' mod n failed!", SAKKE_ERR_H2INTRANGE);
            error_encountered = ES_TRUE;
        }
        else {
            ret_val = ES_SUCCESS;
        }
    }

    /**************************************************************************/
    /* Cleanup.                                                               */
    /**************************************************************************/
    BN_clear_free(vprime_bn);
    BN_CTX_free(bn_ctx);

    if (vprime != NULL) {
        memset(vprime, 0, l*32);
        free(vprime);
        vprime = NULL;
    }
   
    return ret_val;
} /* sakke_hashToIntegerRangeSHA256 */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
