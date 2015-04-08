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
 * @file mikeySakkeParameters.h
 * @brief Storage of Mikey Sakke Parameters sets.
 ******************************************************************************/
#ifndef __ES_MIKEY_SAKKE_PARAMETERS_STORAGE_H__
#define __ES_MIKEY_SAKKE_PARAMETERS_STORAGE_H__

#ifdef __cplusplus
extern "C" {
#endif
    
#include <openssl/bn.h> 
#include <openssl/ec.h> 

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "utils.h"

/*******************************************************************************
 * Initialise the Mikey Sakke Parameter set storage. 
 *
 * Presently there is only one set (1), defined in RFC 6509, Appendix A.
 ******************************************************************************/
short ms_initParameterSets(void);

/*******************************************************************************
 * Has the Parameter Set storage been initialised.
 ******************************************************************************/
short ms_isParameterSetsInitialised();

/*******************************************************************************
 * Delete all Mikey Sakke parameter set data.
 ******************************************************************************/
void  ms_deleteParameterSets(void);

/*******************************************************************************
 * Indicates if MS Parameter Set exists.
 *******************************************************************************/
short ms_parameterSetExists(
    uint8_t ms_param_set);

/*******************************************************************************
 * Return 'n' for the specified Mikey-Sakke parameter set. 
 *
 * 'n' is defined in Section 2.1 of RFC 6508 as, 'A security parameter; the 
 * size of symetric keys in bits to be exchanged by SAKKE'.
 ******************************************************************************/
uint16_t  ms_getParameter_n(
    const uint8_t ms_set_number);

/*******************************************************************************
 * Return 'p' for the specified Mikey-Sakke parameter set.
 *
 * 'p' is defined in Section 2.1 of RFC 6508 as, 'A prime, which is the 
 * order of the finite field F_p. In this document, p is always conguent 
 * to 3 modulo 4.'
 ******************************************************************************/
BIGNUM   *ms_getParameter_p(
    const uint8_t ms_set_number);

/*******************************************************************************
 * Return 'q' for the specified Mikey-Sakke parameter set.
 *
 * 'q' is defined in Section 2.1 of RFC 6508 as, 'An odd prime that divides 
 * p + 1. To provide the desired level of security, lg(q) MUST be greater than 
 * 2*n'.
 ******************************************************************************/
BIGNUM   *ms_getParameter_q(
    const uint8_t ms_set_number);

/*******************************************************************************
 * Return 'P' for the specified Mikey-Sakke parameter set.
 *  
 * 'P' is defined in Section 2.1 of RFC 6508 as, 'A point of E(F_p) that 
 * generates the cyclic subgroup of order q.  The coordinates of P are given 
 * by P = (P_x,P_y).  These coordinates are in F_p, and they satisfy the 
 * curve equation.
 ******************************************************************************/
EC_POINT *ms_getParameter_P(
    const uint8_t ms_set_number);

/*******************************************************************************
 * Return 'g' for the specified Mikey-Sakke parameter set.
 *
 * 'g' is NOT defined in Section 2.1 of RFC 6508. It is instead described in 
 * RFC 6508 Section 6.2.1, step 4, part a), as 'g is an element of PF_p[q] 
 * represented by an element of F_p'.
 ******************************************************************************/
BIGNUM   *ms_getParameter_g(
    const uint8_t ms_set_number);

/*******************************************************************************
 * Return curve 'E' for the specified Mikey-Sakke parameter set.
 *
 * 'E' is defined in Section 2.1 of RFC 6508 as, 'An elliptic curve defined
 * over F_p, having a subgroup of order q. In this document, we use 
 * supersingular curves with equation y^2 = x^3 -3 * x modulo p.'
 ******************************************************************************/
EC_GROUP *ms_getParameter_E(
    const uint8_t ms_set_number);

/*******************************************************************************
 * Output all Mikey Sakke parameter set data for all stored sets.
 ******************************************************************************/
void  ms_outputParameterSets(void);

#ifdef __cplusplus
}
#endif
#endif /* __ES_MIKEY_SAKKE_PARAMETERS_STORAGE_H__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
