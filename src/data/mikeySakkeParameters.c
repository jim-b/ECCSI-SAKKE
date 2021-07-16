/******************************************************************************/
/* Mikey Sakke Parameters                                                     */
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
 * @file mikeySakkeParameters.c
 * @brief Storage of Mikey Sakke Parameters sets.
 *
 * At time of writing there is only one defined parameter set (1). See RFC 6509
 * Section 7 "Initial values for SAKKE parms registry".
 * <BR>
 * Additional parameter sets can easily be added in ms_initParameterSets as 
 * they become available by following the same same mechanism as descibed in 
 * this function. Look for "Add new Mikey Sakke parameter sets here" to see 
 * where to perform this insert, and the preceeding code, for how to insert 
 * them.
 ******************************************************************************/
#include "global.h"
#include "mikeySakkeParameters.h"

#define MS_PUB_PARAMS_SECTION_NAME "(MS-PUBLIC-PARAMS) " /*!< DEBUG strng. */

#define MAX_ES_PARAMETER_SETS 1 /*!< Number of stored MS parameter sets. */

#define MIKEY_SAKKE_p  "997ABB1F" "0A563FDA" "65C61198" "DAD0657A"\
                       "416C0CE1" "9CB48261" "BE9AE358" "B3E01A2E"\
                       "F40AAB27" "E2FC0F1B" "228730D5" "31A59CB0"\
                       "E791B39F" "F7C88A19" "356D27F4" "A666A6D0"\
                       "E26C6487" "326B4CD4" "512AC5CD" "65681CE1"\
                       "B6AFF4A8" "31852A82" "A7CF3C52" "1C3C09AA"\
                       "9F94D6AF" "56971F1F" "FCE3E823" "89857DB0"\
                       "80C5DF10" "AC7ACE87" "666D807A" "FEA85FEB"
                        /*!< RFC 6509 Appendix A page 19.  */


#define MIKEY_SAKKE_q  "265EAEC7" "C2958FF6" "99718466" "36B4195E"\
                       "905B0338" "672D2098" "6FA6B8D6" "2CF8068B"\
                       "BD02AAC9" "F8BF03C6" "C8A1CC35" "4C69672C"\
                       "39E46CE7" "FDF22286" "4D5B49FD" "2999A9B4"\
                       "389B1921" "CC9AD335" "144AB173" "595A0738"\
                       "6DABFD2A" "0C614AA0" "A9F3CF14" "870F026A"\
                       "A7E535AB" "D5A5C7C7" "FF38FA08" "E2615F6C"\
                       "203177C4" "2B1EB3A1" "D99B601E" "BFAA17FB"
                        /*!< RFC 6509 Appendix A page 19.  */

#define MIKEY_SAKKE_Px "53FC09EE" "332C29AD" "0A799005" "3ED9B52A"\
                       "2B1A2FD6" "0AEC69C6" "98B2F204" "B6FF7CBF"\
                       "B5EDB6C0" "F6CE2308" "AB10DB90" "30B09E10"\
                       "43D5F22C" "DB9DFA55" "718BD9E7" "406CE890"\
                       "9760AF76" "5DD5BCCB" "337C8654" "8B72F2E1"\
                       "A702C339" "7A60DE74" "A7C1514D" "BA66910D"\
                       "D5CFB4CC" "80728D87" "EE9163A5" "B63F73EC"\
                       "80EC46C4" "967E0979" "880DC8AB" "EAE63895"
                        /*!< RFC 6509 Appendix A page 19.  */

#define MIKEY_SAKKE_Py "0A824906" "3F6009F1" "F9F1F053" "3634A135"\
                       "D3E82016" "02990696" "3D778D82" "1E141178"\
                       "F5EA69F4" "654EC2B9" "E7F7F5E5" "F0DE55F6"\
                       "6B598CCF" "9A140B2E" "416CFF0C" "A9E032B9"\
                       "70DAE117" "AD547C6C" "CAD696B5" "B7652FE0"\
                       "AC6F1E80" "164AA989" "492D979F" "C5A4D5F2"\
                       "13515AD7" "E9CB99A9" "80BDAD5A" "D5BB4636"\
                       "ADB9B570" "6A67DCDE" "75573FD7" "1BEF16D7"
                        /*!< RFC 6509 Appendix A page 19.  */

#define MIKEY_SAKKE_g  "66FC2A43" "2B6EA392" "148F1586" "7D623068"\
                       "C6A87BD1" "FB94C41E" "27FABE65" "8E015A87"\
                       "371E9474" "4C96FEDA" "449AE956" "3F8BC446"\
                       "CBFDA85D" "5D00EF57" "7072DA8F" "541721BE"\
                       "EE0FAED1" "828EAB90" "B99DFB01" "38C78433"\
                       "55DF0460" "B4A9FD74" "B4F1A32B" "CAFA1FFA"\
                       "D682C033" "A7942BCC" "E3720F20" "B9B7B040"\
                       "3C8CAE87" "B7A0042A" "CDE0FAB3" "6461EA46"
                        /*!< RFC 6509 Appendix A page 20.  */

/***************************************************************************//**
 * Mikey Sakke Parameter Set storage structure.
 ******************************************************************************/
typedef struct msParameterSet_t {
    short    data_set; /*!< Indicates whether this data set has been set. */

    uint8_t  iana_sakke_params; /*!< The MS Parameter Set number.
                                 * presently on one set defined. 
                                 */

    uint8_t  n; /*!< RFC 6508 Section 6.2.1 states 'n' is security parameter; 
                 *   The size of symmetric keys in bits to be exchanged by 
                 *   SAKKE.
                 */ 

    BIGNUM  *p; /*!< RFC 6508 Section 6.2.1 states 'p' is a prime, which is 
                 *    the order of the finite field F_p. Also 'p' is always 
                 *    congruent to 3 modulo 4.
                 */
                 
    BIGNUM  *q; /*!< RFC 6508 Section 6.2.1 states 'q' is an odd prime that 
                 *   divides p + 1. To provide the desired level of security,
                 *   lg(q) MUST be greater than 2*n.
                 */

    EC_POINT *P; /*!< RFC 6508 Section 6.2.1 states 'P' is a point of E(F_p) 
                  *   that generates the cyclic subgroup of order 'q'.  The 
                  *   coordinates of P are given by P = (P_x,P_y).  These
                  *   coordinates are in F_p, and they satisfy the curve 
                  *   equation.
                  */
    BIGNUM   *Px; /*!< The X coordinate of Point P. */
    BIGNUM   *Py; /*!< The Y coordinate of Point P. */

    BIGNUM   *g; /*!< RFC 6508 Section 6.2.1 states 'g' is an element of PF_p[q]
                  *   represented by an element of F_p.
                  */

    /* E */
    EC_GROUP *E;  /*!< 'E' is defined in Section 2.1 of RFC 6508 as, 'An 
                   *    elliptic curve defined over F_p, having a subgroup of 
                   *    order q. In this document, we use supersingular curves 
                   *    with equation y^2 = x^3 -3 * x modulo p.'
                   */

} msParameterSet_t; /*!< A storage structure for MS set data. */

msParameterSet_t ms_parameter_sets[ES_MAX_MS_PARAMETER_SETS]; 
/*!< Array of parameter sets. */

short ms_parameter_sets_initialised; /*!< Indicator as to whether Mikey Sakke 
                                      *   Param sets have been initialised. 
                                      */

/***************************************************************************//**
 * Initialise the Mikey Sakke Parameter set storage. Presently there is only
 * one set (1), defined in RFC 6509, Appendix A.
 *
 * @return A boolean indicating success or failure.
 ******************************************************************************/
short ms_initParameterSets() {
    short   ret_val = 1;
    uint8_t c       = 0;
    BIGNUM *a       = NULL;
    BIGNUM *b       = NULL;
    BN_CTX *bn_ctx  = NULL;

    if (!ms_parameter_sets_initialised) {
        /* Clear out the storage structure */
        memset(ms_parameter_sets, 0, sizeof(ms_parameter_sets));

        /**********************************************************************/
        /* Add Parameter Set 1 (the default)                                  */
        /*   - these values are immutable and defined in RFC 6509, Appendix A.*/
        /**********************************************************************/
        ms_parameter_sets[c].iana_sakke_params = 1;

        ms_parameter_sets[c].n                 = 128;

        ms_parameter_sets[c].p = BN_new();
        BN_hex2bn(&ms_parameter_sets[c].p, MIKEY_SAKKE_p);

        ms_parameter_sets[c].q = BN_new();
        BN_hex2bn(&ms_parameter_sets[c].q, MIKEY_SAKKE_q);

        ms_parameter_sets[c].Px = BN_new();
        BN_hex2bn(&ms_parameter_sets[c].Px, MIKEY_SAKKE_Px);

        ms_parameter_sets[c].Py = BN_new();
        BN_hex2bn(&ms_parameter_sets[c].Py, MIKEY_SAKKE_Py);

        ms_parameter_sets[c].g = BN_new();
        BN_hex2bn(&ms_parameter_sets[c].g, MIKEY_SAKKE_g);

        ms_parameter_sets[c].data_set = ES_TRUE;

        if ((NULL != ms_parameter_sets[c].Px) &&
            (NULL != ms_parameter_sets[c].Py) &&
            (NULL != ms_parameter_sets[c].p)) {
            bn_ctx = BN_CTX_new();
            a      = BN_new();
            b      = BN_new();

            /* Create a curve E */
            BN_dec2bn(&a, "-3l"); /* Coefficient of 'x', see RFC 6508 Section 
                                   * 2.1 description of 'E'. 
                                   */
            BN_dec2bn(&b, "0");
            ms_parameter_sets[c].E =
                EC_GROUP_new_curve_GFp(ms_parameter_sets[c].p, a, b, bn_ctx);
            if (NULL != ms_parameter_sets[c].E) {

                ms_parameter_sets[c].P = EC_POINT_new(ms_parameter_sets[c].E);
                if (EC_POINT_set_affine_coordinates(
                    ms_parameter_sets[c].E,
                    ms_parameter_sets[c].P,
                    ms_parameter_sets[c].Px,
                    ms_parameter_sets[c].Py, bn_ctx)) {
         
                    /* Indicate the MS parameter set(s) storage is initialised. */
                    ret_val = 0;
                    ms_parameter_sets_initialised = ES_TRUE;
                    ret_val = 0;
                }
                else {
                    ES_ERROR("%s:%s:%d - MS parameter initialisation, unable to create Point 'P'!",
                        __FILE__, __FUNCTION__, __LINE__);
                }
            }
            else { 
                ES_ERROR("%s:%s:%d - MS parameter initialisation, unable to create curve 'E'!",
                    __FILE__, __FUNCTION__, __LINE__);
            }
            BN_CTX_free(bn_ctx);
            BN_clear_free(a);
            BN_clear_free(b);
            bn_ctx = NULL;
            a      = NULL;
            b      = NULL;
        }
        /* Else just fall through and fail. */

        /**********************************************************************/
        /* !!!!!        Add new Mikey Sakke parameter sets here.        !!!!! */
        /**********************************************************************/
        /* increment c to add new set. */

    }
    else {
        ES_ERROR("%s:%s:%d - MS parameter set already initialiased. Delete and reinitialise.",
            __FILE__, __FUNCTION__, __LINE__);

        /* Already initialised so return success. */
        ret_val = 0;
    }
    return ret_val;

} /* ms_initParameterSets */

/***************************************************************************//**
 * Has the Parameter Set storage been initialised.
 *
 * @return If MS parameter setis initialised return ES_TRUE otherwise ES_FALSE.
 ******************************************************************************/
short ms_isParameterSetsInitialised() {
    return ms_parameter_sets_initialised;
} /* ms_isParameterSetsInitialised */

/***************************************************************************//**
 * Delete all Mikey Sakke parameter set data.
 ******************************************************************************/
void ms_deleteParameterSets() {

    int c = 0;
    for (c = 0; c <  MAX_ES_PARAMETER_SETS; c++) {
        if (NULL != ms_parameter_sets[c].p) {
            BN_clear_free(ms_parameter_sets[c].p);
        }
        if (NULL != ms_parameter_sets[c].q) {
            BN_clear_free(ms_parameter_sets[c].q);
        }
        if (NULL != ms_parameter_sets[c].Px) {
            BN_clear_free(ms_parameter_sets[c].Px);
        }
        if (NULL != ms_parameter_sets[c].Py) {
            BN_clear_free(ms_parameter_sets[c].Py);
        }
        if (NULL != ms_parameter_sets[c].g) {
            BN_clear_free(ms_parameter_sets[c].g);
        }
        if (NULL != ms_parameter_sets[c].E) {
            EC_GROUP_clear_free(ms_parameter_sets[c].E);
        }
        if (NULL != ms_parameter_sets[c].P) {
            EC_POINT_clear_free(ms_parameter_sets[c].P);
        }
        memset(&ms_parameter_sets[c], 0, sizeof(struct msParameterSet_t));
    }
    ms_parameter_sets_initialised = ES_FALSE;

} /* ms_deleteParameterSets */

/***************************************************************************//**
 * Indicates if MS Parameter Set exists.
 *
 * @param[in] ms_param_set The MS parameter Set to check for.
 *
 * @return If MS parameter setis initialised return ES_TRUE otherwise ES_FALSE.
 *******************************************************************************/
short ms_parameterSetExists(
    uint8_t ms_param_set) 
{
    int c = 0;

    for (c = 0; c <  MAX_ES_PARAMETER_SETS; c++) {
        if (ms_parameter_sets[c].iana_sakke_params == ms_param_set) {
            return ES_TRUE;
        }
    }
    return ES_FALSE;
} /* ms_parameterSetExists */

/***************************************************************************//**
 * Return a reference to a MS parameters data structure for a specified 
 * parameter set.
 *
 * @param[in] ms_set_number The parameter set number.
 * @return A reference the MS structure, or, NULL if not found.
 ******************************************************************************/
static msParameterSet_t *ms_getParameterSet(
    const uint8_t ms_set_number)
{
    int c = 0;
    for (c = 0; c <  MAX_ES_PARAMETER_SETS; c++) {
        if (ms_parameter_sets[c].iana_sakke_params == ms_set_number) {
            return &ms_parameter_sets[c];
        }
    }
    return NULL;
} /* ms_getParameterSet */

/***************************************************************************//**
 * Return 'n' for the specified Mikey-Sakke parameter set. 
 *
 * 'n' is defined in Section 2.1 of RFC 6508 as, 'A security parameter; the 
 * size of symetric keys in bits to be exchanged by SAKKE'.
 *
 * @param[in] ms_set_number The Mikey-Sakke parameter set.
 * @return The stored integer for 'n', or, '0' on failure.
 ******************************************************************************/
uint16_t  ms_getParameter_n(
    const uint8_t ms_set_number) 
{
    msParameterSet_t *tmp_set_p = ms_getParameterSet(ms_set_number);

    if (NULL != tmp_set_p) {
        return tmp_set_p->n;
    }
    else {
        return 0;
    }
} /* ms_getParameter_n */

/***************************************************************************//**
 * Return 'p' for the specified Mikey-Sakke parameter set.
 *
 * 'p' is defined in Section 2.1 of RFC 6508 as, 'A prime, which is the 
 * order of the finite field F_p. In this document, p is always conguent 
 * to 3 modulo 4.'
 *
 * @param[in] ms_set_number The Mikey-Sakke parameter set.
 * @return A pointer to a BIGNUM for 'p' if it exists, or, NULL on failure.
 ******************************************************************************/
BIGNUM *ms_getParameter_p(
    const uint8_t ms_set_number) 
{
    msParameterSet_t *tmp_set_p = ms_getParameterSet(ms_set_number);

    if (NULL != tmp_set_p) {
        return tmp_set_p->p;
    }
    else {
        return NULL;
    }
} /* ms_getParameter_p */

/***************************************************************************//**
 * Return 'q' for the specified Mikey-Sakke parameter set.
 *
 * 'q' is defined in Section 2.1 of RFC 6508 as, 'An odd prime that divides 
 * p + 1. To provide the desired level of security, lg(q) MUST be greater than 
 * 2*n'.
 *  
 * @param[in] ms_set_number The Mikey-Sakke parameter set.
 * @return A pointer to a BIGNUM 'q' if it exists, or, NULL on failure.
 ******************************************************************************/
BIGNUM *ms_getParameter_q(
    uint8_t ms_set_number) 
{
    msParameterSet_t *tmp_set_p = ms_getParameterSet(ms_set_number);

    if (NULL != tmp_set_p) {
        return tmp_set_p->q;
    }
    else {
        return NULL;
    }
} /* ms_getParameter_q */

/***************************************************************************//**
 * Return 'P' for the specified Mikey-Sakke parameter set.
 *
 * 'P' is defined in Section 2.1 of RFC 6508 as, 'A point of E(F_p) that 
 * generates the cyclic subgroup of order q.  The coordinates of P are given 
 * by P = (P_x,P_y).  These coordinates are in F_p, and they satisfy the 
 * curve equation.
 *  
 * @param[in] ms_set_number The Mikey-Sakke parameter set.
 * @return A pointer to a EC_POINT 'P' if it exists, or, NULL on failure.
 ******************************************************************************/
EC_POINT *ms_getParameter_P(
    const uint8_t ms_set_number)
{
    msParameterSet_t *tmp_set_p = ms_getParameterSet(ms_set_number);

    if (NULL != tmp_set_p) {
        return tmp_set_p->P;
    }
    else {
        return NULL;
    }
} /* ms_getParameter_P */

/***************************************************************************//**
 * Return 'g' for the specified Mikey-Sakke parameter set.
 *
 * 'g' is NOT defined in Section 2.1 of RFC 6508. It is instead described in 
 * RFC 6508 Section 6.2.1, step 4, part a), as 'g is an element of PF_p[q] 
 * represented by an element of F_p'.
 *
 * @param[in] ms_set_number The Mikey-Sakke parameter set.
 * @return A pointer to a BIGNUM 'g' if it exists, or, NULL on failure.
 ******************************************************************************/
BIGNUM *ms_getParameter_g(
    const uint8_t ms_set_number) 
{
    msParameterSet_t *tmp_set_p = ms_getParameterSet(ms_set_number);

    if (NULL != tmp_set_p) {
        return tmp_set_p->g;
    }
    else {
        return NULL;
    }
} /* ms_getParameter_g */

/***************************************************************************//**
 * Return curve 'E' for the specified Mikey-Sakke parameter set.
 *
 * 'E' is defined in Section 2.1 of RFC 6508 as, 'An elliptic curve defined
 * over F_p, having a subgroup of order q. In this document, we use 
 * supersingular curves with equation y^2 = x^3 -3 * x modulo p.'
 *
 * @param[in] ms_set_number The Mikey-Sakke parameter set.
 *
 * @return A pointer to a EC_GROUP 'E' if it exists, or, NULL on failure.
 ******************************************************************************/
EC_GROUP *ms_getParameter_E(
    const uint8_t ms_set_number) 
{
    msParameterSet_t *tmp_set_p = ms_getParameterSet(ms_set_number);

    if (NULL != tmp_set_p) {
        return tmp_set_p->E;
    }
    else {
        return NULL;
    }
} /* ms_getParameter_E */

/***************************************************************************//**
 * Output all Mikey Sakke parameter set data for all stored sets.
 ******************************************************************************/
void ms_outputParameterSets() {
#ifdef ES_OUTPUT_DEBUG
    unsigned int count = 0;

    ES_DEBUG( "%s    Mikey-Sakke Public Parameters", 
        MS_PUB_PARAMS_SECTION_NAME);

    ES_DEBUG( "%s    -----------------------------", 
        MS_PUB_PARAMS_SECTION_NAME);

    for (count = 0; count < MAX_ES_PARAMETER_SETS; count++) {
        if (ms_parameter_sets[count].data_set) {

            /* Global Parameters */
            ES_DEBUG("%s      Parameter-Set: <%03d>", 
                MS_PUB_PARAMS_SECTION_NAME, 
                ms_parameter_sets[count].iana_sakke_params);
            ES_DEBUG("%s        'n' (RFC 6509, Page 19):", 
                     MS_PUB_PARAMS_SECTION_NAME); 
            ES_DEBUG("%s          %d", MS_PUB_PARAMS_SECTION_NAME, 
                ms_parameter_sets[count].n);

            if (NULL == ms_parameter_sets[count].p) { 
                ES_DEBUG("%s        'p' [mandatory] could not be retrieved", 
                         MS_PUB_PARAMS_SECTION_NAME);
            } 
            else { 
                utils_BNdump(ES_LOGGING_DEBUG, MS_PUB_PARAMS_SECTION_NAME, 
                    "        'p' (RFC 6509, Page 19):", 10, 
                    ms_parameter_sets[count].p);
            }

            if (NULL == ms_parameter_sets[count].q) { 
                ES_DEBUG("%s        'q' [mandatory] could not be retrieved", 
                         MS_PUB_PARAMS_SECTION_NAME);
            } 
            else { 
                utils_BNdump(ES_LOGGING_DEBUG, MS_PUB_PARAMS_SECTION_NAME, 
                    "        'q' (RFC 6509, Page 19):", 10, 
                    ms_parameter_sets[count].q);
            }

            /*
             * P - A point of E(F_p) that generates the cyclic subgroup of order
             *     q.  The coordinates of P are given by P = (P_x,P_y).  These
             *     coordinates are in F_p, and they satisfy the curve equation.
             */
            if (NULL == ms_parameter_sets[count].E) {
                ES_DEBUG("%s        'E' EC_group [mandatory] could not be retrieved",
                         MS_PUB_PARAMS_SECTION_NAME);
            } else {
                if (NULL == ms_parameter_sets[count].P) { 
                    ES_DEBUG("%s        'P' [mandatory] could not be retrieved",
                             MS_PUB_PARAMS_SECTION_NAME);
                } else { 
                    utils_displayAffineCoordinates(ES_LOGGING_DEBUG, 
                        MS_PUB_PARAMS_SECTION_NAME,
                        "        P (as Point) (RFC 6509, Page 19):", 12,
                        ms_parameter_sets[count].E, 
                        ms_parameter_sets[count].P);
                }
            }

            if (NULL == ms_parameter_sets[count].Px) { 
                ES_DEBUG("%s        'Px' [mandatory] could not be retrieved",
                         MS_PUB_PARAMS_SECTION_NAME);
            } 
            else {
                utils_BNdump(ES_LOGGING_DEBUG, MS_PUB_PARAMS_SECTION_NAME,
                    "        Px (RFC 6509, Page 19):", 10, 
                    ms_parameter_sets[count].Px);
            }

            if (NULL == ms_parameter_sets[count].Py) { 
                ES_DEBUG("%s        'Py' [mandatory] could not be retrieved",
                         MS_PUB_PARAMS_SECTION_NAME);
            }
            else {
                utils_BNdump(ES_LOGGING_DEBUG, MS_PUB_PARAMS_SECTION_NAME, 
                    "        Py (RFC 6509, Page 19):", 10, 
                    ms_parameter_sets[count].Py);
            }

            if (NULL == ms_parameter_sets[count].g) { 
                ES_DEBUG("%s        'g' [mandatory] could not be retrieved",
                         MS_PUB_PARAMS_SECTION_NAME);
            }
            else { 
                utils_BNdump(ES_LOGGING_DEBUG, MS_PUB_PARAMS_SECTION_NAME, 
                    "        g (RFC 6509, Page 20):", 10, 
                    ms_parameter_sets[count].g);
            }
        }
    }
#endif /* ES_OUTPUT_DEBUG */
} /* ms_outputParameterSets */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
