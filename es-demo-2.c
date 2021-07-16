/******************************************************************************/
/* Main/ test program 2.                                                      */
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
/******************************************************************************/
/**
 * @brief
 * Main program 2 - Non RFC values, alice and bob different and different 
 * community. More of a real world example; Charlie creates a SSV (Shared 
 * Secret Value) and then produces an encrypted (for Dylan) version of this,
 * the encapsulated data. Charlie then Signs the encapsulated data. Dylan can 
 * now check (verify) that Charlie really send it the message, then decrypt
 * the encapsulated data to retrieve the SSV. Now, Charlie and Dylan both know
 * the SSV and can set about encrypting their communications.
 *
 * @file
 * Main program 2.
 */
/******************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <eccsi.h>
#include <sakke.h>
#include <mikeySakkeParameters.h>
#include <communityParameters.h>
#include <esprng.h>

#include <global.h>

#define ES_MAIN_SECTION_NAME "(ES-MAIN)        " /*!< Section name output */

#define ES_USE_RFC_VALUES    /*!< Comment this out to NOT use RFC values. */
#define SSV_LEN              16 /*!< The length of an SSV in bytes.       */
#define RND_J_LEN            32 /*!< The length of random 'j' in bytes.   */

/***************************************************************************//**
 * Example of how to add a community (community.mikey-sakke.org).
 *
 * Data created with sister project (also on GitHub) KMS.
 *
 * @return ES_SUCCESS or ES_FAILURE
 *****************************************************************************/
short main_addExampleCommunity() {
    short    ret_val  = ES_FAILURE;

    char    *pub_enc_key  = NULL; /* Z_T  */
    char    *pub_auth_key = NULL; /* KPAK */

    uint8_t *KPAK         = NULL;
    size_t   KPAK_len     = 0;
    uint8_t *Z            = NULL;
    size_t   Z_len        = 0;

    /**************************************************************************/
    /* Init.                                                                  */
    /**************************************************************************/
    pub_auth_key = 
           strdup("04253587" "2D7931C6" "891210FF" "2CDFFD06"
                  "FD464107" "AC5F819E" "5EACC8AC" "D4BBA806"
                  "72C813BA" "18955F4E" "A37D9BE3" "DD9FAFED"
                  "38BD1BF9" "A9DF42B8" "FD3D52E1" "C64FB62B"
                  "E8");

    pub_enc_key = 
           strdup("0478475A" "19DB9038" "50E4402D" "01629185"
                  "B58971DB" "CCB08CA2" "7AECEE50" "DFA2C981"
                  "DFEF96CA" "AB8F449C" "CADC0966" "7FC5AC0C"
                  "28B335CC" "7D18A013" "5482E97C" "8E38FA40"
                  "0C517734" "7CC4E7B1" "128A7015" "EFF23788"
                  "77CF4BD2" "BBAF911A" "DD63D9FC" "56018134"
                  "B3D83330" "D12C981A" "A1955951" "CCF4F55A"
                  "231D69C8" "3EE82D92" "8EC0DFE7" "80237C90"
                  "D93414D5" "0EEC3F11" "99CD9B06" "1C477CDA"
                  "717AD07F" "152EF956" "ADD52C2F" "2FE3B66D"
                  "862040D6" "9D10E6E6" "4F095A57" "E5AB1261"
                  "541DF307" "B965243C" "0F053420" "A92007D5"
                  "21B83F3C" "91F290E8" "BDB0BE03" "BF6B404A"
                  "3539D030" "A4438B82" "244099DF" "90F74332"
                  "B8058462" "A37FF4DD" "5FC73253" "A2892FC6"
                  "7B08205B" "D87EE768" "6ED7C67F" "B801F3A8"
                  "C0");

    utils_convertHexStringToOctetString((char *)pub_auth_key, 
        strlen((char *)pub_auth_key)/2, &KPAK, &KPAK_len);
    utils_convertHexStringToOctetString((char *)pub_enc_key,    
        strlen((char *)pub_enc_key)/2,  &Z,    &Z_len);

    if (!community_store(
        NULL,     /* Optional version */
        (uint8_t *)"community.mikey-sakke.org",
                  /* Mandatory cert_uri - community */
        (uint8_t *)"kms.mikey-sakke.org",
                  /* Mandatory kms_uri  - kms. */
        NULL,     /* Optional issuer */
        NULL,     /* Optional valid_from */
        NULL,     /* Optional valid_to */
        0,        /* Optional revoked */
        NULL,     /* Optional user_id_format */
        Z,        /* Mandatory pub_enc_key - AKA 'Z'. */
        Z_len,    /* Mandatory pub_enc_key len. */
        KPAK,     /* Mandatory pub_auth_key - 'KPAK'. */
        KPAK_len, /* Mandatory pub_auth_key len. */
        NULL      /* Optional kms_domain_list */
        )) {
        ret_val = ES_SUCCESS;
    }
    else {
        ES_ERROR("%s:%s:%d - Failed to store community (KMS Certificate) data!",
              __FILE__, __FUNCTION__, __LINE__);
    }

    /**************************************************************************/
    /* Clear down                                                             */
    /**************************************************************************/
    if (NULL != pub_auth_key) {
        memset(pub_auth_key, 0, strlen(pub_auth_key));
        free(pub_auth_key);
    }
    if (NULL != pub_enc_key) {
        memset(pub_enc_key,  0, strlen(pub_enc_key));
        free(pub_enc_key);
    }
    if (NULL != KPAK) {
        memset(KPAK, 0, KPAK_len);
        free(KPAK);
    }
    if (NULL != Z) {
        memset(Z,    0, Z_len);
        free(Z);
    }

    return ret_val;
} /* main_addExampleCommunity */

/***************************************************************************//**
 * Add User Charlie
 *
 * Data created with sister project (also on GitHub) KMS.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short main_addExampleUserCharlie() {
    uint8_t  ret_val       = ES_FAILURE;

    uint8_t *community     = NULL;
    uint8_t *date          = NULL;
    uint8_t *uri           = NULL;
    uint8_t *id            = NULL;
    size_t   id_len        = 0;

    char    *ssk           = NULL;
    char    *rsk           = NULL;
    char    *pvt           = NULL;

    uint8_t *SSK           = NULL;
    size_t   SSK_len       = 0;
    uint8_t *RSK           = NULL;
    size_t   RSK_len       = 0;
    uint8_t *PVT           = NULL;
    size_t   PVT_len       = 0;

    /**************************************************************************/
    /* Init.                                                                  */
    /**************************************************************************/
    community     = (uint8_t *)strdup("community.mikey-sakke.org");
    date          = (uint8_t *)strdup("2015-04");
    uri           = (uint8_t *)strdup("tel:+441111111111");
    id_len        = strlen((char *)date) + strlen((char *)uri) + 2;
                        /* 2 is for NULL separator plus NULL termninal as 
                         * per RFC 6507 Appendix A, Page 13, 'ID'.
                         */
    id            = (uint8_t *)calloc(1, id_len);
    strcpy((char *)id, (char *)date);
    strcat((char *)id+strlen((char *)id)+1, (char *)uri);

    /**************************************************************************/
    /* Values from KMS for SSK(private), RSK(private) and PVT (public).       */
    /**************************************************************************/
    ssk = strdup("EF78C601" "CE73934C" "BFA1D578" "E34E4E3E"
                 "3FCBAA8F" "DC8EE0B4" "36DD34E9" "71DD72D7");

    rsk = strdup("041BB681" "A2008151" "EE7A788A" "ADBFA170"
                 "8745FE05" "94987AA2" "D4111410" "A98DDA8A"
                 "78DA6767" "4AD22533" "ADC20490" "1D72DBF2"
                 "0A01384F" "FB7799A3" "18E4160A" "34352A1B"
                 "66575EB7" "53F14C2D" "2292608A" "38344650"
                 "AA252745" "2CC29A1A" "C66027D7" "19714C38"
                 "AE5601E3" "035B4B93" "7C3B8B8E" "1C1FDEAB"
                 "6D466FE1" "5E3A65E0" "572F0912" "D0E9CD44"
                 "B60D812D" "1EAA9B30" "370394ED" "0791EDEE"
                 "34B151C8" "92802B6E" "65750F28" "DEFE0028"
                 "46B2DA19" "D052B6CC" "F4F3C6ED" "C24722A4"
                 "FF4F1F36" "59ECED52" "BE3592E8" "18A04A99"
                 "598CCE1A" "EA56694B" "75B4665D" "58D3F91E"
                 "3A2F613A" "B6D3D80E" "5FB5D090" "0988E072"
                 "04CA5D33" "CE29829D" "7F1A72A8" "BD0D8F2F"
                 "DF2C26BB" "34DD25E3" "B3015490" "34A23F4F"
                 "5B");

    pvt = strdup("041D2EFB" "DDBB4E00" "C31F7CD8" "6FFA6CA3"
                 "BDD1F0C9" "93C113FB" "2A10622C" "FA8328BB"
                 "DAF14480" "2672D0CC" "EF9747E6" "0EEAE222"
                 "F68A92ED" "815E523C" "5CC045B8" "06C1883E"
                 "D0");

    utils_convertHexStringToOctetString((char *)ssk, strlen((char *)ssk)/2, 
                                        &SSK, &SSK_len);
    utils_convertHexStringToOctetString((char *)rsk, strlen((char *)rsk)/2, 
                                        &RSK, &RSK_len);
    utils_convertHexStringToOctetString((char *)pvt, strlen((char *)pvt)/2, 
                                        &PVT, &PVT_len);

    /***************************************************************************
     *! Store User Details.
     *
     * RSK will be validated during save.
     * SSK will be validated during save (and Hash created).
     * Hash created during validate-SSK will also be saved to storage.
     **************************************************************************/
    if (user_store((uint8_t *)date, (uint8_t *)uri, (uint8_t *)community, 
                    SSK, SSK_len, RSK, RSK_len, PVT, PVT_len)) {
        /* This call can return ES_SAKKE_ERROR_RSK_VALIDATION_FAILED or
         * ES_ECCSI_ERROR_SSK_VALIDATION_FAILED as well as ES_SUCCESS, or, 
         * ES_FAILURE.
         */
        ES_ERROR("%s:%s:%d - New user Key Mat was NOT stored!",
            __FILE__, __FUNCTION__, __LINE__);
    }
    else {
        ret_val = ES_SUCCESS;
    }

    /* community_outputKMSCertificate(community); */
    /* user_outputParameterSets(id, id_len, community); */

    /**************************************************************************/
    /* Clear down                                                             */
    /**************************************************************************/
    if (NULL != community) { 
        memset(community, 0, strlen((char *)community)); 
        free(community);
    }
    if (NULL != date) { 
        memset(date, 0, strlen((char *)date)); 
        free(date);
    }
    if (NULL != uri) { 
        memset(uri, 0, strlen((char *)uri)); 
        free(uri);
    }
    if (NULL != id) { 
        memset(id, 0, strlen((char *)id)); 
        free(id);
    }
    if (NULL != ssk) { 
        memset(ssk, 0, strlen((char *)ssk)); 
        free(ssk);
    }
    if (NULL != rsk) {
        memset(rsk, 0, strlen((char *)rsk)); 
        free(rsk);
    }
    if (NULL != pvt) {
        memset(pvt, 0, strlen((char *)pvt)); 
        free(pvt);
    }
    if (NULL != SSK) { 
        memset(SSK, 0, SSK_len);
        free(SSK);
    }
    if (NULL != RSK) { 
        memset(RSK, 0, RSK_len);
        free(RSK);
    }
    if (NULL != PVT) { 
        memset(PVT, 0, PVT_len);
        free(PVT);
    }

    return ret_val;

} /* main_addExampleUserCharlie */

/***************************************************************************//**
 * Add User Dylan
 *
 * Data created with sister project (also on GitHub) KMS.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short main_addExampleUserDylan() {
    uint8_t  ret_val       = ES_FAILURE;

    uint8_t *community     = NULL;
    uint8_t *date          = NULL;
    uint8_t *uri           = NULL;
    uint8_t *id            = NULL;
    size_t   id_len        = 0;

    char    *ssk           = NULL;
    char    *rsk           = NULL;
    char    *pvt           = NULL;

    uint8_t *SSK           = NULL;
    size_t   SSK_len       = 0;
    uint8_t *RSK           = NULL;
    size_t   RSK_len       = 0;
    uint8_t *PVT           = NULL;
    size_t   PVT_len       = 0;

    /**************************************************************************/
    /* Init.                                                                  */
    /**************************************************************************/
    community     = (uint8_t *)strdup("community.mikey-sakke.org");
    date          = (uint8_t *)strdup("2015-04");
    uri           = (uint8_t *)strdup("tel:+442222222222");
    id_len        = strlen((char *)date) + strlen((char *)uri) + 2;
                        /* 2 is for NULL separator plus NULL termninal as 
                         * per RFC 6507 Appendix A, Page 13, 'ID'.
                         */
    id            = (uint8_t *)calloc(1, id_len);
    strcpy((char *)id, (char *)date);
    strcat((char *)id+strlen((char *)id)+1, (char *)uri);

    /**************************************************************************/
    /* Values from KMS for SSK(private), RSK(private) and PVT (public).       */
    /**************************************************************************/
    ssk = strdup("133AB0D7" "920D0D16" "FF11870E" "9B8ED29C"
                 "D759C547" "FEA1BAA3" "189AABFD" "91D1EFE8");

    rsk = strdup("045096DC" "BDB29B2D" "A3580EC9" "6CF1F50E"
                 "0D348EA5" "F69F6B53" "7626B469" "79662B0E"
                 "D645CD9B" "AD35D547" "8574D882" "D55B604B"
                 "1B0CFE60" "28C8C618" "6EDD9079" "8A77F3C7"
                 "A9FD09F8" "37211069" "C01A640A" "20B81F31"
                 "BDAF641C" "B2C9EAFB" "9838FB38" "5C78463E"
                 "4780BD4D" "135CED1F" "FB6D8D7F" "088015A1"
                 "57576550" "7669A6DC" "A9585D63" "00709F75"
                 "75149282" "CBD698BC" "44B8FC19" "D057ADFE"
                 "B5E7A379" "5013598D" "C5EDEF55" "39F2C98A"
                 "C2E2027B" "D6C564B3" "92A728FB" "EE59359A"
                 "2E1B5AD0" "4AA80936" "13A307D6" "E3D75CC2"
                 "599C0D02" "FD2C737D" "ED82946D" "7CFB9791"
                 "452C90B6" "62DA5007" "25FB433B" "6F54D16C"
                 "6AAD3D29" "ABABB689" "675FE898" "00A0FF33"
                 "B8F58633" "7A931A9F" "3BA5E91A" "A55E183C"
                 "AE");

    pvt = strdup("04FD3CDA" "286E41DF" "C2AACFE7" "9911727E"
                 "2314FA7A" "66FDA655" "BBA5C5FE" "9AFF4777"
                 "20479E8D" "999CFBED" "32028AFE" "B6C19DF0"
                 "BCBA44AD" "F2FE95D4" "985749F9" "54CB4634"
                 "27");

    utils_convertHexStringToOctetString((char *)ssk, strlen((char *)ssk)/2, 
                                        &SSK, &SSK_len);
    utils_convertHexStringToOctetString((char *)rsk, strlen((char *)rsk)/2, 
                                        &RSK, &RSK_len);
    utils_convertHexStringToOctetString((char *)pvt, strlen((char *)pvt)/2, 
                                        &PVT, &PVT_len);

    /***************************************************************************
     * Store User Details.
     *
     * RSK will be validated during save.
     * SSK will be validated during save (and Hash created).
     * Hash created during validate-SSK will also be saved to storage.
     **************************************************************************/
    if (user_store((uint8_t *)date, (uint8_t *)uri, (uint8_t *)community, 
                    SSK, SSK_len, RSK, RSK_len, PVT, PVT_len)) {
        /* This call can return ES_SAKKE_ERROR_RSK_VALIDATION_FAILED or
         * ES_ECCSI_ERROR_SSK_VALIDATION_FAILED as well as ES_SUCCESS, or, 
         * ES_FAILURE.
         */
        ES_ERROR("%s:%s:%d - New user Key Mat was NOT stored!",
            __FILE__, __FUNCTION__, __LINE__);
    }
    else {
        ret_val = ES_SUCCESS;
    }

    /* community_outputKMSCertificate(community); */
    /* user_outputParameterSets(id, id_len, community); */

    /**************************************************************************/
    /* Clear down                                                             */
    /**************************************************************************/
    if (NULL != community) { 
        memset(community, 0, strlen((char *)community)); 
        free(community);
    }
    if (NULL != date) { 
        memset(date, 0, strlen((char *)date)); 
        free(date);
    }
    if (NULL != uri) { 
        memset(uri, 0, strlen((char *)uri)); 
        free(uri);
    }
    if (NULL != id) { 
        memset(id, 0, strlen((char *)id)); 
        free(id);
    }
    if (NULL != ssk) { 
        memset(ssk, 0, strlen((char *)ssk)); 
        free(ssk);
    }
    if (NULL != rsk) {
        memset(rsk, 0, strlen((char *)rsk)); 
        free(rsk);
    }
    if (NULL != pvt) {
        memset(pvt, 0, strlen((char *)pvt)); 
        free(pvt);
    }
    if (NULL != SSK) { 
        memset(SSK, 0, SSK_len);
        free(SSK);
    }
    if (NULL != RSK) { 
        memset(RSK, 0, RSK_len);
        free(RSK);
    }
    if (NULL != PVT) { 
        memset(PVT, 0, PVT_len);
        free(PVT);
    }

    return ret_val;

} /* main_addExampleUserDylan */

/***************************************************************************//**
 * Initialise all the Mikey-Sakke data structures in the correct order.
 *
 * MUST be called before ANY Mikey-Sakke processing.
 *
 * @return ES_SUCCESS or ES_FAILURE
 *****************************************************************************/
static short main_initialiseMSInCorrectOrder() {
    short ret_val = ES_FAILURE;

    /*************************************************************************/
    /* Mikey-Sakke Parameters                                                */
    /*************************************************************************/
    ES_DEBUG("%s    ****************************************", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s    * Create Mikey-Sakke Parameter List(s) *", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s    * Obtained and stored by Alice and Bob *", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s    ****************************************", ES_MAIN_SECTION_NAME);
    if (ms_initParameterSets()) {
        ES_ERROR("%s:%s:%d - Mikey Sakke Parameter Set initialisation failed. Check logs for errors!",
              __FILE__, __FUNCTION__, __LINE__);
    }
    else {
        /* If you want to see the parameter sets - ms_outputParameterSets(); */

        /*********************************************************************/
        /* Community Parameters                                              */
        /*********************************************************************/
        ES_DEBUG("%s    ****************************************", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s    * Create Community Parameter List      *", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s    * Obtained and stored by Alice and Bob *", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s    ****************************************", ES_MAIN_SECTION_NAME);
        if (community_initStorage()) {
            ES_ERROR("%s:%s:%d - Community initialisation failed. Check logs for errors!",
                  __FILE__, __FUNCTION__, __LINE__);
        }
        else {
            /* If you want to see the community data 
             * community_outputParameterSets. Note however, all we have done
             * is initialise. If there are no communities stored you will have
             * to add one to see it, see main_addCommunity() (above).
             */

            /******************************************************************/
            /* User Accounts - no init required.                              */
            /******************************************************************/
            ret_val = ES_SUCCESS;
        }
    }

    return ret_val;
} /* main_initialiseMSInCorrectOrder */

/***************************************************************************//**
 * Main example code - Charlie establishes a SSV for dialogs with Dylan.
 *
 * @param[in] argc           Number of arguments.
 * @param[in] argv[]         Array of arguments.
 *
 * @return Status code.
 *****************************************************************************/

int main(int argc, char *argv[]) {
    /* User Id's have a NULL between date and ID so we need len indication. */
    uint8_t       *charlie_id               = NULL;
    size_t         charlie_id_len           = 0;
    uint8_t       *dylan_id                 = NULL;
    size_t         dylan_id_len             = 0;  
    uint8_t       *community                = NULL;

    uint8_t       *ssv_for_dylan            = NULL;
    size_t         ssv_for_dylan_length     = 0;
    uint8_t       *encapsulated_data        = NULL;
    size_t         encapsulated_data_length = 0;

    uint8_t       *charlie_ssv              = NULL;

    uint8_t       *signature                = NULL;
    size_t         signature_len            = 0;

    unsigned int   loop                     = 0;
    uint8_t       *j_rnd                    = NULL;
    BIGNUM        *j_rnd_bn                 = NULL;

    ES_INFO("The ECCSI/ SAKKE Software Version is <%s>", softwareVersion());

    /**************************************************************************/
    /* Set up user id's - Note the RFC use the same ID for Alice and Bob..    */
    /**************************************************************************/
    charlie_id = (uint8_t *)calloc(1, 255); /* Some space */
    strcpy((char *)charlie_id, "2015-04");
    strcat((char *)charlie_id+strlen((char *)charlie_id)+1, "tel:+441111111111");
    charlie_id_len = strlen((char *)charlie_id) +
                     strlen((char *)charlie_id+(strlen((char *)charlie_id)+1))
                     +2; /* Null separator for date+id and NULL terminator. */

    dylan_id = (uint8_t *)calloc(1, 255); /* Some space */
    strcpy((char *)dylan_id, "2015-04");
    strcat((char *)dylan_id+strlen((char*)dylan_id)+1, "tel:+442222222222");
    dylan_id_len = strlen((char *)dylan_id) +
                   strlen((char *)dylan_id+(strlen((char *)dylan_id)+1))
                   +2; /* Null separator for date+id and NULL terminator. */

    /**************************************************************************/
    /* Community name                                                         */
    /**************************************************************************/
    community = (uint8_t *)strdup("community.mikey-sakke.org");

    /**************************************************************************/
    /* Initialise internal storage structures !MUST! be called before any     */  
    /* ECCSI/ SAKKE code is performed.                                        */
    /**************************************************************************/
    main_initialiseMSInCorrectOrder();

    /* If the community exists, it is overwritten/ updated.  */
    if (ES_SUCCESS != main_addExampleCommunity()) {
        exit(1);
    }
    /* If the user exists, it is overwritten/ updated. For specific user 
     * deletion use user_remove.
     */
    if (ES_SUCCESS != main_addExampleUserCharlie()) { 
        exit(1);
    }
    if (ES_SUCCESS != main_addExampleUserDylan()) { 
        exit(1);
    }

    /* If you want to repeat/ test this code, for instance with non RFC values
     * you can modify the characteristics of this loop and comment out
     * ES_USE_RFC_VALUES at the start of this file.
     */
    for (loop=0; loop < 1; loop++) {
        ES_INFO("%s  Counter <%d>", ES_MAIN_SECTION_NAME, loop);

        /**********************************************************************/
        /* ACTING AS CHARLIE                                                  */
        /**********************************************************************/

        ES_INFO("%s  *****************************************", ES_MAIN_SECTION_NAME);
        ES_INFO("%s  * CHARLIE                               *", ES_MAIN_SECTION_NAME);
        ES_INFO("%s  *****************************************", ES_MAIN_SECTION_NAME);
        /* Charlie creates an SSV (Shared Secret Value) and constructs
         * the Encapsulated Data (message).
         */
        ES_PRNG(&charlie_ssv, SSV_LEN);
        ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
            "    Charlie creates a random SSV :", 8, 
            charlie_ssv, SSV_LEN);

        ES_INFO("%s   Charlie makes encapsulated data message", ES_MAIN_SECTION_NAME);
        if (sakke_generateSakkeEncapsulatedData(
                &encapsulated_data, &encapsulated_data_length,
                dylan_id,            dylan_id_len, /* Use the receiver's ID */
                community,
                charlie_ssv,         SSV_LEN)) {
            ES_ERROR("%s:%s:%d - SAKKE Encapsulated Data creation failed. Exiting!",
                  __FILE__, __FUNCTION__, __LINE__);
            exit(1);
        }
        else {
            /* Now we have the message (encapsulated data) let's sign it. */
            /* First we need a random 'j' 1..q-1. As we do the checks here,
             * we don't need to check the response from the sign request
             */
            do {
               ES_PRNG(&j_rnd, RND_J_LEN);
               j_rnd_bn = BN_bin2bn((unsigned char *)j_rnd, RND_J_LEN, NULL);

               if ((BN_cmp(j_rnd_bn, BN_value_one()) >= 0) &&
                   (BN_cmp(j_rnd_bn, community_getq_bn()) == -1)) {
                   BN_clear_free(j_rnd_bn);
                   j_rnd_bn = NULL;
                   break;
               }
               BN_clear_free(j_rnd_bn);
               j_rnd_bn = NULL;
            } while(1);

            /* If you want to see that 'j' is definately random, uncomment 
             * the following line and recompile.
             */
            /*ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
             *   "    Create a (random) 'j' value:", 8, j_rnd, j_rnd_len);
             */

            /* Now we sign the (encapsulated data) message. */
            if (NULL != signature) {
                free(signature); 
                signature = NULL; 
                signature_len = 0;
            }
            ES_INFO("%s   Charlie signs the message", ES_MAIN_SECTION_NAME);
            if (eccsi_sign(
                    encapsulated_data, encapsulated_data_length,
                    charlie_id, charlie_id_len, /* Use the signer's ID */
                    community, j_rnd, RND_J_LEN, &signature, &signature_len)) {
                ES_ERROR("%s:%s:%d - Sign failed. Exiting!", 
                         __FILE__, __FUNCTION__, __LINE__);
                exit(1);
            } 
            ES_INFO("%s  *****************************************", ES_MAIN_SECTION_NAME);
            ES_INFO("%s  * What CHARLIE sends to DYLAN >>>>>>>>> *", ES_MAIN_SECTION_NAME);
            ES_INFO("%s  *****************************************", ES_MAIN_SECTION_NAME);
            ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
                "    ECCSI Signature   :", 8, 
                signature, signature_len);
            ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
                "    Encapsulated Data :", 8,
                encapsulated_data, encapsulated_data_length);
        }

        /**********************************************************************/
        /* ACTING AS DYLAN                                                    */
        /**********************************************************************/
        ES_INFO("%s  *****************************************", ES_MAIN_SECTION_NAME);
        ES_INFO("%s  * DYLAN                                 *", ES_MAIN_SECTION_NAME);
        ES_INFO("%s  *****************************************", ES_MAIN_SECTION_NAME);
        ES_INFO("%s    DYLAN verifies message from CHARLIE", ES_MAIN_SECTION_NAME);
        if (eccsi_verify(encapsulated_data, encapsulated_data_length,
                         signature,  signature_len, 
                         charlie_id, charlie_id_len, /* Use the sender's ID */
                         community)) {
            ES_ERROR("%s:%s:%d - Verification of received signed message failed. Exiting!",
                  __FILE__, __FUNCTION__, __LINE__);
            ES_DEBUG("%s     Signature NOT VERIFIED!", ES_MAIN_SECTION_NAME);
            exit(1);
        }
        ES_INFO("%s    Signature VERIFIED", ES_MAIN_SECTION_NAME);
        ES_INFO("%s      - the message is from Charlie!", ES_MAIN_SECTION_NAME);

        ES_INFO("%s    DYLAN parses the Encapsulated Data", ES_MAIN_SECTION_NAME);
        ES_INFO("%s      to get the SSV (Shared Secret Value).", ES_MAIN_SECTION_NAME);
        ssv_for_dylan = NULL;
        if (sakke_extractSharedSecret(
                encapsulated_data, encapsulated_data_length, 
                /* Use the receiver's ID */
                dylan_id,            dylan_id_len, 
                community,
                &ssv_for_dylan,      &ssv_for_dylan_length) == ES_SUCCESS) {
            ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
                  "    SSV obtained/ used by Dylan:", 
                  8, ssv_for_dylan, ssv_for_dylan_length); 
        }
        else {
            ES_DEBUG("%s Failed to parse encapsulated data", ES_MAIN_SECTION_NAME);
            exit(1);
        }

        if (NULL != j_rnd) { 
            free(j_rnd); 
            j_rnd = NULL;
        }
        if (NULL != charlie_ssv) { 
            free(charlie_ssv); 
            charlie_ssv = NULL; 
            /* Do not reset length, used if regenerating ssv in loop. */
        }
        if (NULL != ssv_for_dylan) { 
            free(ssv_for_dylan); 
            ssv_for_dylan = NULL; 
            ssv_for_dylan_length = 0;
        }
        if (NULL != encapsulated_data) { 
            free(encapsulated_data); 
            encapsulated_data = NULL; 
            encapsulated_data_length = 0;
        }
    } 

    /* Cleanup */
    community_deleteStorage();
    ms_deleteParameterSets();

    free(charlie_id);
    free(dylan_id);
    free(ssv_for_dylan);  
    free(encapsulated_data);
    free(signature);

    free(community);
    free(charlie_ssv);

    return 0;
    
} /* main */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/ 
