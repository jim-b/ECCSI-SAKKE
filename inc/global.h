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
 * @file global.h
 * @brief Global definitions.
 ******************************************************************************/
#ifndef __ES_GLOBAL__
#define __ES_GLOBAL__

#ifdef __cplusplus
extern "C" {
#endif
    
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SOFTWARE_VERSION "0.0.1" /*!< Current Code Version  */

#ifndef ES_TRUE
#define ES_TRUE 1                /*!< Global TRUE value.    */
#endif
#ifndef ES_FALSE
#define ES_FALSE (!ES_TRUE)      /*!< Global FALSE value.   */
#endif

#ifndef ES_FAILURE_
#define ES_FAILURE 1             /*!< Global FAILURE value. */
#endif
#ifndef ES_SUCCESS
#define ES_SUCCESS (!ES_FAILURE) /*!< Global SUCCESS value. */
#endif

#define ES_MAX_MS_PARAMETER_SETS                 1 /*!< Max Number of stored MS
                                                    *   parameter sets. 
                                                    */

#define ES_MAX_COORD_SIZE                        128 /*!< Mac coordinate len. */
#define ES_MAX_HINT_SIZE                         16  /*!< Max len of Hint.    */

/***************************************************************************//**
 * ECCSI base error value 
 ******************************************************************************/
#define ES_ECCSI_ERROR_BASE                      10  
/** 'j' value not in range whilst creating ECCSI signature. */
#define ES_ECCSI_ERROR_SIGN_J_VALUE_NOT_IN_RANGE ES_ECCSI_ERROR_BASE+1 
/** 'j' value failed calculations whilst creating ECCSI signature use another.*/
#define ES_ECCSI_ERROR_SIGN_J_VALUE_TESTS_FAILED ES_ECCSI_ERROR_BASE+2
/** ECCSI SSK validation failed. */
#define ES_ECCSI_ERROR_SSK_VALIDATION_FAILED     ES_ECCSI_ERROR_BASE+3
/** ECCSI Signature Verify failed. */
#define ES_ECCSI_ERROR_VERIFY_FAILED             ES_ECCSI_ERROR_BASE+4

/***************************************************************************//**
 * SAKKE base error value 
 ******************************************************************************/
#define ES_SAKKE_ERROR_BASE                      20 
/** SAKKE RSK validation failed. */
#define ES_SAKKE_ERROR_RSK_VALIDATION_FAILED     ES_SAKKE_ERROR_BASE+1

#ifdef ES_OUTPUT_DEBUG
#define ES_MAX_ATTR_LEN 1024 /*!< Maximum attribute length for output functions
                              *   only accessible if debug output enabled.
                              */
#endif

#ifdef __cplusplus
}
#endif
#endif /* __ES_GLOBAL__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
