/******************************************************************************/
/* Main/ test program.                                                        */
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
 *  * @brief
 * Main program.
 *
 * @file
 * Main program.
 */
/******************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h> /* For random */

#include <eccsi.h>
#include <sakke.h>
#include <mikeySakkeParameters.h>
#include <communityParameters.h>
#include <esprng.h>

#include <global.h>

#define ES_MAIN_SECTION_NAME "(ES-MAIN)        " /*!< Section name output */

#define ES_USE_RFC_VALUES    /*!< Comment this out to NOT use RFC values. */

/***************************************************************************//**
 * Example of how to add a community.
 *
 * There's some work to be done here as it's highly likely the Mikey-Sakke data
 * supplied will be in octet string format, rather than hex string shown in
 * this example.
 *
 * Also note! When the call is made to community_store, to add the community, 
 * if B, q and G are not specified (as in the example, then default RFC value 
 * will be added for these terms.
 *
 * @return ES_SUCCESS or ES_FAILURE
 *****************************************************************************/
short main_addExampleCommunity() {
    short    ret_val  = ES_FAILURE;

    char    *kpak     = NULL;
    char    *z        = NULL;

    uint8_t *KPAK     = NULL;
    size_t   KPAK_len = 0;
    uint8_t *Z        = NULL;
    size_t   Z_len    = 0;

    /**************************************************************************/
    /* Init.                                                                  */
    /**************************************************************************/
    kpak = strdup("04"
                  "50D4670B" "DE75244F" "28D2838A" "0D25558A"
                  "7A72686D" "4522D4C8" "273FB644" "2AEBFA93"
                  "DBDD3755" "1AFD263B" "5DFD617F" "3960C65A"
                  "8C298850" "FF99F203" "66DCE7D4" "367217F4");

    z    = strdup("04"
                  /* X */
                  "5958EF1B" "1679BF09" "9B3A030D" "F255AA6A"
                  "23C1D8F1" "43D4D23F" "753E69BD" "27A832F3"
                  "8CB4AD53" "DDEF4260" "B0FE8BB4" "5C4C1FF5"
                  "10EFFE30" "0367A37B" "61F701D9" "14AEF097"
                  "24825FA0" "707D61A6" "DFF4FBD7" "273566CD"
                  "DE352A0B" "04B7C16A" "78309BE6" "40697DE7"
                  "47613A5F" "C195E8B9" "F328852A" "579DB8F9"
                  "9B1D0034" "479EA9C5" "595F47C4" "B2F54FF2"
                  /* Y */
                  "1508D375" "14DCF7A8" "E143A605" "8C09A6BF"
                  "2C9858CA" "37C25806" "5AE6BF75" "32BC8B5B"
                  "63383866" "E0753C5A" "C0E72709" "F8445F2E"
                  "6178E065" "857E0EDA" "10F68206" "B63505ED"
                  "87E534FB" "2831FF95" "7FB7DC61" "9DAE6130"
                  "1EEACC2F" "DA3680EA" "4999258A" "833CEA8F"
                  "C67C6D19" "487FB449" "059F26CC" "8AAB655A"
                  "B58B7CC7" "96E24E9A" "39409575" "4F5F8BAE");

    utils_convertHexStringToOctetString((char *)kpak, strlen((char *)kpak)/2, 
                                        &KPAK, &KPAK_len);
    utils_convertHexStringToOctetString((char *)z,    strlen((char *)z)/2,    
                                        &Z,    &Z_len);

    if (!community_store(
        (uint8_t *)"1.0.0",                   /* Optional version */
        (uint8_t *)"aliceandbob.co.uk",       /* Mandatory cert_uri - community*/
        (uint8_t *)"aliceandbob.co.uk",       /* Mandatory kms_uri  - kms. */
        (uint8_t *)"issuer.aliceandbob.co.uk",/* Optional issuer */
        (uint8_t *)"2011-02-14T00:00:00",     /* Optional valid_from */
        (uint8_t *)"2011-03-13T23:59:59",     /* Optional valid_to */
        1,                                    /* Optional revoked */
        (uint8_t *)"#uri?P-Year=#year&amp;P-Month=#month", /* Optional user_id_format */
        Z,                                    /* Mandatory pub_enc_key - AKA 'Z'. */
        Z_len,                                /* Mandatory pub_enc_key len. */
        KPAK,                                 /* Mandatory pub_auth_key - 'KPAK'. */
        KPAK_len,                             /* Mandatory pub_auth_key len. */
        (uint8_t *)"sec1.aliceandbob.co.uk"   /* Optional kms_domain_list */
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
    if (NULL != kpak) {
        memset(kpak, 0, strlen(kpak));
        free(kpak);
    }
    if (NULL != z) {
        memset(z,    0, strlen(z));
        free(z);
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
 * Example of how to add a user.
 *
 * In practice the RSK (Receiver Secret Key), SSK (Secret Signing Key) and 
 * PVT (Public Validation Token) are obtained from the KMS (Key Management 
 * Server). So, there's some work to be done here as it's likely these data
 * will be supplied in octet string format, rather than hex string shown in
 * this example.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short main_addExampleUser() {
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
    community     = (uint8_t *)strdup("aliceandbob.co.uk");
    date          = (uint8_t *)strdup("2011-02");
    uri           = (uint8_t *)strdup("tel:+447700900123");
    id_len        = strlen((char *)date) + strlen((char *)uri) + 2;
                        /* 2 is for NULL separator plus NULL termninal as 
                         * per RFC 6507 Appendix A, Page 13, 'ID'.
                         */
    id            = calloc(1, id_len);
    strcpy((char *)id, (char *)date);
    strcat((char *)id+strlen((char *)id)+1, (char *)uri);

    /**************************************************************************/
    /* Values from KMS for SSK(private), RSK(private) and PVT (public).       */
    /**************************************************************************/
    ssk = strdup("23F374AE" "1F4033F3" "E9DBDDAA" "EF20F4CF"
                 "0B86BBD5" "A138A5AE" "9E7E006B" "34489A0D");

    rsk = strdup("04"
                 /* RSK-X */
                 "93AF67E5" "007BA6E6" "A80DA793" "DA300FA4"
                 "B52D0A74" "E25E6E7B" "2B3D6EE9" "D18A9B5C"
                 "5023597B" "D82D8062" "D3401956" "3BA1D25C"
                 "0DC56B7B" "979D74AA" "50F29FBF" "11CC2C93"
                 "F5DFCA61" "5E609279" "F6175CEA" "DB00B58C"
                 "6BEE1E7A" "2A47C4F0" "C456F052" "59A6FA94"
                 "A634A40D" "AE1DF593" "D4FECF68" "8D5FC678"
                 "BE7EFC6D" "F3D68353" "25B83B2C" "6E69036B"
                 /* RSK-Y */
                 "155F0A27" "241094B0" "4BFB0BDF" "AC6C670A"
                 "65C325D3" "9A069F03" "659D44CA" "27D3BE8D"
                 "F311172B" "55416018" "1CBE94A2" "A783320C"
                 "ED590BC4" "2644702C" "F371271E" "496BF20F"
                 "588B78A1" "BC01ECBB" "6559934B" "DD2FB65D"
                 "2884318A" "33D1A42A" "DF5E33CC" "5800280B"
                 "28356497" "F87135BA" "B9612A17" "26042440"
                 "9AC15FEE" "996B744C" "33215123" "5DECB0F5");

    pvt = strdup("04"
                 "758A1427" "79BE89E8" "29E71984" "CB40EF75"
                 "8CC4AD77" "5FC5B9A3" "E1C8ED52" "F6FA36D9"
                 "A79D2476" "92F4EDA3" "A6BDAB77" "D6AA6474"
                 "A464AE49" "34663C52" "65BA7018" "BA091F79");

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

} /* main_addExampleUser */

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
 * Main example code.
 *
 * @param[in] argc           Number of arguments.
 * @param[in] argv[]         Array of arguments.
 *
 * @return Status code.
 *****************************************************************************/

int main(int argc, char *argv[]) {
    /* User Id's have a NULL between date and ID so we need len indication. */
    uint8_t       *alice_id                 = NULL;
    size_t         alice_id_len             = 0;
    uint8_t       *bob_id                   = NULL;
    size_t         bob_id_len               = 0;  
    uint8_t       *community                = NULL;

    uint8_t       *ssv_for_bob              = NULL;
    size_t         ssv_for_bob_length       = 0;
    uint8_t       *encapsulated_data        = NULL;
    size_t         encapsulated_data_length = 0;

    uint8_t       *alice_ssv                = NULL;
    size_t         alice_ssv_len            = 16;

    uint8_t        res_verify               = 0;
    uint8_t       *message                  = NULL;
    size_t         message_len              = 0;
    uint8_t       *signature                = NULL;
    size_t         signature_len            = 0;

    unsigned int   loop                     = 0;
    uint8_t       *j_rnd                    = NULL;
    size_t         j_rnd_len                = 32;
    uint8_t        tmp_res                  = 0; /* A temp result value. */

    ES_INFO("The ECCSI/ SAKKE Software Version is <%s>", softwareVersion());

    ES_DEBUG("%s", ES_MAIN_SECTION_NAME "    Initialize and configure");
    ES_DEBUG("%s", ES_MAIN_SECTION_NAME "    ========================");

    /**************************************************************************/
    /* Set up user id's - Note the RFC use the same ID for Alice and Bob..    */
    /**************************************************************************/
    alice_id = calloc(1, 255); /* Some space */
    strcpy((char *)alice_id, "2011-02");
    strcat((char *)alice_id+strlen((char *)alice_id)+1, /* +1 NULL separator */
           "tel:+447700900123");
    alice_id_len = strlen((char *)alice_id) +
                   strlen((char *)alice_id+(strlen((char *)alice_id)+1))
                   +2; /* Null separator for date+id and NULL terminator. */

    bob_id = calloc(1, 255); /* Some space */
    strcpy((char *)bob_id, "2011-02");
    strcat((char *)bob_id+strlen((char*)bob_id)+1, /* +1 NULL separator */
           "tel:+447700900123");
    bob_id_len = strlen((char *)bob_id) +
                 strlen((char *)bob_id+(strlen((char *)bob_id)+1))
                 +2; /* Null separator for date+id and NULL terminator. */

    /**************************************************************************/
    /* Community name                                                         */
    /**************************************************************************/
    community = (uint8_t *)strdup("aliceandbob.co.uk");

    /**************************************************************************/
    /* Initialise internal storage structures !MUST! be called before any     */  
    /* ECCSI/ SAKKE code is performed.                                        */
    /**************************************************************************/
    main_initialiseMSInCorrectOrder();

    /* For examples of how to add users and communities, see: */

    /* If the community exists, it is overwritten/ updated.  */
    if (ES_SUCCESS != main_addExampleCommunity()) {
        exit(1);
    }
    /* If the user exists, it is overwritten/ updated. For specific user 
     * deletion use user_remove.
     */
    if (ES_SUCCESS != main_addExampleUser()) { 
        exit(1);
    }

    /* Note! Key data will usually be required to be obtained from a 
     * Mikey-Sakke KMS.
     *
     * Adding new MS parameter sets require code changes, see:
     *     data/mikeySakkeParameters.c
     */

    /* For DEBUG output of Mikey-Sakke, community or user data before run: 
     *    ms_outputParameterSets();
     *    community_outputParameterSets();
     *    user_outputParameterSet();
     */

    ES_DEBUG("%s", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s      NOTE! (BELOW) RFC USER DETAILS FOR ALICE AND", 
             ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s             BOB ARE THE SAME", ES_MAIN_SECTION_NAME);

    ES_DEBUG("%s", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s  * Validation of Alice/ Bob's RSK/ SSK  *", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s  * and Hash generation occurs during    *", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s  * user data storage (above).           *", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s", ES_MAIN_SECTION_NAME);

    ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s  * Alice Signs the  message             *", ES_MAIN_SECTION_NAME);
    ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);

#ifdef ES_USE_RFC_VALUES
    message     = (uint8_t *)strdup("message");
#else
    message     = (uint8_t *)strdup((char *)"some-other-message");
#endif

    /* For the signing calculations listed in RFC 6507 to match, we need the 
     * terminating NULL to included in the length of the message.
     */
    message_len = strlen((char *)message)+1; 
    signature   = NULL;
    res_verify  = 0;

    /* If you want to repeat/ test this code, for instance with non RFC values
     * you can modify the characteristics of this loop and comment out
     * ES_USE_RFC_VALUES at the start of this file.
     */
    for (loop=0; loop < 1; loop++) {
        ES_INFO("%s  Counter <%d>", ES_MAIN_SECTION_NAME, loop);

        /* The message to send to Bob (RFC 6507 Appendix A, page 14) */
        utils_printFormattedOctetString(ES_LOGGING_DEBUG, ES_MAIN_SECTION_NAME, 
            "    The message to send to Bob (RFC 6507 Appendix A, page 14):", 8, 
            message, message_len);

#ifdef ES_USE_RFC_VALUES
        utils_convertHexStringToOctetString("34567", j_rnd_len, &j_rnd, &j_rnd_len);
        ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
            "     Create a (RFC value) 'j' value:", 7, j_rnd, j_rnd_len);
#else
        ES_PRNG(&j_rnd, j_rnd_len);
        ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
            "     Create a (random) 'j' value:", 7, j_rnd, j_rnd_len);
#endif /* ES_USE_RFC_VALUES */

        /* We could check 'j' is in the range 1 to 
         * FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63255 here
         * but let's pass it to ECCSI sign and let it tell us.
         */
        while ((tmp_res = eccsi_sign(
                message,  message_len, 
                /* Use the signer's/ sender's  ID */
                alice_id, alice_id_len, 
                community,
                j_rnd, j_rnd_len,
                /* 'j' is a random number, should be in the range 1 to 
                 * FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550
                 */
                &signature, &signature_len))) {

            /* The two cases we can supply a new 'j' value and try again. */
            if ((tmp_res != ES_ECCSI_ERROR_SIGN_J_VALUE_NOT_IN_RANGE) && 
                (tmp_res != ES_ECCSI_ERROR_SIGN_J_VALUE_TESTS_FAILED)) {
                /* Other internal failure */
                ES_ERROR("%s:%s:%d - Sign failed. Exiting!", 
                         __FILE__, __FUNCTION__, __LINE__);
                exit(1);
            }
            ES_DEBUG("%s  Create a new 'j' value", ES_MAIN_SECTION_NAME);
            free(j_rnd);
            j_rnd = NULL;
            ES_PRNG(&j_rnd, j_rnd_len);
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
                "     Created a new (random) 'j' value:", 8, j_rnd, j_rnd_len);
        }
        if (j_rnd != NULL) {
            memset(j_rnd, 0, j_rnd_len);
            free(j_rnd);
            j_rnd = NULL;
        } 

        ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  * ALICE sends signed message to BOB    *", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
        ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
            "    ECCSI Signature sent to Bob is:", 6, 
            signature, signature_len);

        ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  * BOB verifies message from ALICE      *", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
        if (eccsi_verify(message,       message_len, 
                         signature,     signature_len, 
                         /* Use the signer's/ sender's ID */
                         alice_id,      alice_id_len, 
                         community)) {
            ES_ERROR("%s:%s:%d - Verification of received signed message failed. Exiting!",
                  __FILE__, __FUNCTION__, __LINE__);
            ES_DEBUG("%s     Signature NOT VERIFIED!", ES_MAIN_SECTION_NAME);
            exit(1);
        }
        ES_INFO("%s     Signature VERIFIED!", ES_MAIN_SECTION_NAME);

        ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  * ALICE creates SSV and also           *", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  * Encapsulated Data to send to BOB     *", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);

        if (NULL != signature) {
            free(signature); signature = NULL; signature_len = 0;
        }

        /* Create Shared Secret and construct Encapsulated Data */
#ifdef ES_USE_RFC_VALUES
        utils_convertHexStringToOctetString("123456789ABCDEF0123456789ABCDEF0", 
            16, &alice_ssv, &alice_ssv_len);
        ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
            "     SSV (RFC value) created/ used by Alice:", 7, alice_ssv, alice_ssv_len);
#else 
        ES_PRNG(&alice_ssv, alice_ssv_len);
        ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
            "     SSV created/ used by Alice:", 7, alice_ssv, alice_ssv_len);
#endif /* ES_USE_RFC_VALUES */

        if (sakke_generateSakkeEncapsulatedData(
                &encapsulated_data, &encapsulated_data_length, 
                /* Use the receiver's ID */
                bob_id,              bob_id_len, 
                community, 
                alice_ssv,           alice_ssv_len)) {
            ES_ERROR("%s:%s:%d - SAKKE Encapsulated Data creation failed. Exiting!",
                  __FILE__, __FUNCTION__, __LINE__);
            exit(1);
        }
        else {
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
                "    SSV to use locally for encryption:", 6, alice_ssv, alice_ssv_len);
            ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
            ES_DEBUG("%s  * ALICE sends Encapsulated Data to BOB *", ES_MAIN_SECTION_NAME);
            ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
            ES_DEBUG_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
                "  Encapsulated Data sent to Bob:", 6, 
                encapsulated_data, encapsulated_data_length);
        }

        /* Sign and SED sent to Bob (could be Mikey). Now we act as if Bob. */

        ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  * Bob parses Encapsulated Data sent    *", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  * from Alice                           *", ES_MAIN_SECTION_NAME);
        ES_DEBUG("%s  ****************************************", ES_MAIN_SECTION_NAME);

        ssv_for_bob = NULL;
        if (sakke_extractSharedSecret(
                encapsulated_data, encapsulated_data_length, 
                /* Use the receiver's ID */
                bob_id,            bob_id_len, 
                community,
                &ssv_for_bob,      &ssv_for_bob_length) == ES_SUCCESS) {
            ES_INFO_PRINT_FORMATTED_OCTET_STRING(ES_MAIN_SECTION_NAME,
                  "     SSV obtained/ used by Bob:", 
                  7, ssv_for_bob, ssv_for_bob_length); 
        }
        else {
            ES_DEBUG("%s Failed to parse encapsulated data", ES_MAIN_SECTION_NAME);
            exit(1);
        }

        if (NULL != alice_ssv) { 
            free(alice_ssv); 
            alice_ssv = NULL; 
            /* Do not reset length, used if regenerating ssv in loop. */
        }
        if (NULL != ssv_for_bob) { 
            free(ssv_for_bob); 
            ssv_for_bob = NULL; 
            ssv_for_bob_length = 0;
        }
        if (NULL != encapsulated_data) { 
            free(encapsulated_data); 
            encapsulated_data = NULL; 
            encapsulated_data_length= 0;
        }
    } 

    /* Cleanup */
    community_deleteStorage();
    ms_deleteParameterSets();

    free(alice_id);
    free(bob_id);
    free(ssv_for_bob);  
    free(encapsulated_data);
    free(signature);

    free(message);
    free(community);
    free(alice_ssv);

    return 0;
    
} /* main */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/ 
