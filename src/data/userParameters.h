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
 * @file userParameters.h
 * @brief Storage of Mikey Sakke User data.
 ******************************************************************************/
#ifndef __ES_USER_PARAMETERS_STORAGE__
#define __ES_USER_PARAMETERS_STORAGE__

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Checks the user ID/ Community data and the key material supplied by the KMS
 * (SSK, RSK and PVT). Note there are specific checks for SSK (RFC 6507 Section 
 * 5.1.2)and RSK (RFC6508 6.1.2 para 2). A call is then made to the msdb API 
 * in order to store the user data. 
 *
 * Validation of the SSK results in a hash that is also stored for subsequent 
 * use in calculations.
 ******************************************************************************/
short user_store(
    const uint8_t *id_date,
    const uint8_t *id_uri,
    const uint8_t *community,
    const uint8_t *ssk,
    const size_t   ssk_len,
    const uint8_t *rsk,
    const size_t   rsk_len,
    const uint8_t *pvt,
    const size_t   pvt_len);

/*******************************************************************************
 * Remove user account identified by community and user_id from storage 
 * structure.
 ******************************************************************************/
short user_remove(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community);

/*******************************************************************************
 * Get user SSK (Secret Signing Key) value if stored.
 ******************************************************************************/
BIGNUM *user_getSSK(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community);

/*******************************************************************************
 * Get user PVT (Public Validation Token) x-coordinate value if stored.
 ******************************************************************************/
BIGNUM *user_getPVTx(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community);

/*******************************************************************************
 * Get user PVT (Public Validation Token) y-coordinate value if stored.
 ******************************************************************************/
BIGNUM *user_getPVTy(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community);

/*******************************************************************************
 * Get user Hash value if stored.
 ******************************************************************************/
BIGNUM *user_getHash(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community);

/*******************************************************************************
 * Get user PVT (Public Validation Token) octet string if stored.
 ******************************************************************************/
short user_getPVT(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t  *community,
    uint8_t       **pvt,
    size_t         *pvt_len);

/*******************************************************************************
 * Indicates whether the specified community+user_id combination is stored. 
 ******************************************************************************/
short user_exists(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community);

/******************************************************************************/
/* SAKKE                                                                      */
/******************************************************************************/

/*******************************************************************************
 * Get user RSK as point.
 ******************************************************************************/
EC_POINT *user_getRSKpoint(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community);

/*******************************************************************************
 * Delete all user parameter sets. 
 ******************************************************************************/
short user_deleteAllUserAccounts();

/*******************************************************************************
 * Returns an unsorted CSV (comma separated value) list of currently stored
 * user account names.
 *
 * Note! Callers of this function are responsible for freeing the space
 * allocated to the list returned.
 ******************************************************************************/
uint8_t *user_list();

/*******************************************************************************
 * Outputs parameter set data for the identified user. Only used when running 
 * in debug mode.
 ******************************************************************************/
void user_outputParameterSet(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community);


#ifdef __cplusplus
}
#endif
#endif /* __ES_USER_PARAMETERS_STORAGE__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
