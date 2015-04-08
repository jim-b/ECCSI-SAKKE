/******************************************************************************/
/* Generic Data Handling                                                      */
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
 * @file msdb.c
 * @brief Example MSDB API implemntation to store Mikey Sakke Community and 
 * User Key Mat data.
 ******************************************************************************/
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>

#include "msdb.h"

#define ES_MAX_LINE_LEN               1024 /*!< Maximum line len for reading 
                                            *   data from file. 
                                            */
#define ES_MAX_DIR_FILE_NAME_LEN      1024 /*!< The maximum file name length. */

#define STORAGE_DIRECTORY             STORAGE_ROOT"/storage" 
/*!< The storage directory where user and community data is stored. */

#define STORAGE_COMMUNITIES_DIRECTORY STORAGE_DIRECTORY"/communities"
/*!< The storage directory where community data is stored. */

#define STORAGE_USERS_DIRECTORY       STORAGE_DIRECTORY"/users"
/*!< The storage directory where user data is stored. */

/***************************************************************************//**
 * Strip the white space from the  provided string 'in'.
 *
 * @param[in]  in The input string to strip white space from.
 *
 * @return A pointer to the modified 'in' string.
 ******************************************************************************/
static uint8_t *utils_stripWS(
    uint8_t *in)
{
    int count   = 0;
    int cur_pos = 0;

    if (in != NULL) {
        for (count = 0; count < strlen((char *)in); count++) {
            if ((in[count] != ' ')  && (in[count] != '\t') &&
                (in[count] != '\n') && (in[count] != '\r')) {
                in[cur_pos] = in[count];
                cur_pos++;
            }
        }
        in[cur_pos] = 0;
    }
    return in;
} /* utils_stripWS */

/***************************************************************************//**
 * Cleanup the parsed data (stripping trailing spaces) or indicating the line
 * should be ignored if it empty or a comment (indicated by';').
 *
 * @param[in] opt The line that was parsed.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
static short cleanConfigLine(
    char* opt) 
{
    short ret_val = MSDB_FAILURE;
    int   i       = 0;

    /* Remove initial white spaces */
    while (isspace(*opt)) {
        opt++;
    }
    /* Remove trailing white spaces */
    for (i=strlen(opt)-1; i>=0 && isspace(opt[i]); --i) {
        opt[i]='\0';
    }
    /* Empty or comment */
    if(opt[0]!='\0' && opt[0]!=';') {
        ret_val = MSDB_SUCCESS;
    }

    return ret_val;
} /* cleanConfigLine */

/***************************************************************************//**
 * Parse the specified file looking for the 'key' and return the 'value'.
 *
 * Note! THIS IS INTERNAL AND NOT PART OF THE REQUIRED API.
 *
 * @param[in]  fp    A pointer to the file to be parsed.
 * @param[in]  key   The 'key' identifier we are looking for.
 * @param[out] value The return 'value' for the specified 'key'.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
static short parseDataAttribute(
    FILE    *fp, 
    char    *key,
    uint8_t *value) 
{
    short ret_val = MSDB_FAILURE; 
    char conf_line[ES_MAX_LINE_LEN];
    char conf_total[ES_MAX_LINE_LEN];

    if (NULL != fp) {
        /* Read the configuration line by line looking for key */
        short first_line=1;
        memset(conf_line, 0, sizeof(conf_line));
        while (NULL != fgets(conf_line, ES_MAX_LINE_LEN, fp)) {
            if (first_line==1) {
                if ((conf_line[0] != ';') && (conf_line[0] != '\n')) {
                    strcpy(conf_total, conf_line);
                    first_line=0;
                }
                /* else ignore comment or blank line. */
            }
            else {
                utils_stripWS((uint8_t *)&conf_line);
                /* Not comment or CRLF */
                if ((conf_line[0] != ';') && (conf_line[0] != '\n')) {
                    /* Used to allow key:([WS|CRLF])*value, but Secure Chorus 
                     * date spec has ':' * so now format MUST comply with 
                     * key:CRLF[ws]value
                     */
                    if (conf_line[0] != 0) { /* Blank line - skip it. */
                        if (conf_line[strlen(conf_line)-1] != ':') {
                            conf_total[strlen(conf_total)] = 0x0;
                            strcat(conf_total, conf_line);
                        }
                        else {
                            /* Cleanup the config line */
                            if (cleanConfigLine(conf_total)) { 
                                continue;
                            }
        
                            utils_stripWS((uint8_t *)&conf_total);
                            if ((strlen(conf_total) > 0) && 
                                       (!strncmp(conf_total, key, strlen(key)))) {
                                /* Found what we were looking fori. */
                                break;
                            }
     
                            memset(conf_total, 0, sizeof(conf_total));
                            if (conf_line[0] != ';') {
                                strcpy(conf_total, conf_line);
                            }
                        }
                    }
                }
                /* else skip comment or blank line */
            }
            memset(conf_line, 0, sizeof(conf_line));
        }

        utils_stripWS((uint8_t*)&conf_total);
        if (strlen(conf_total) > 0) {
            if (!strncmp(conf_total, key, strlen(key))) {
                strcpy((char *)value, conf_total+(strlen(key)));
                ret_val = MSDB_SUCCESS;
            }       
        } 
    }

    return ret_val;
} /* parseDataAttribute */

/***************************************************************************//**
 * Opens the specified community file.
 *
 * Note! THIS IS INTERNAL AND NOT PART OF THE REQUIRED API.
 *
 * @param[in]  community The community, the file for which will be opened.
 *
 * @return Success (a FILE pointer) or Failure (NULL).
 ******************************************************************************/
static FILE *openCommunityFile(
    const uint8_t *community)
{
    char  filename[ES_MAX_DIR_FILE_NAME_LEN];
    FILE *fp = NULL;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Open Community File, no community specified!");
    }
    else {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s", 
                 STORAGE_COMMUNITIES_DIRECTORY, community);

        if (NULL == (fp = fopen(filename, "r"))) {
            MSDB_ERROR("MSDB Open Community File, unable to access community data <%s>!",
                community);
        }
   }
   return fp;
} /* openCommunityFile */

/***************************************************************************//**
 * Opens the specified community file.
 *
 * Note! THIS IS INTERNAL AND NOT PART OF THE REQUIRED API.
 *  
 * @param[in]  user_id     The user identity, to be combined with community to
 *                         identify the file to be opened.
 * @param[in]  user_id_len The iuser_id length, user id's are Date|NULL|URI.
 * @param[in]  community   The community, the file for which will be opened.
 *      
 * @return Success (a FILE pointer) or Failure (NULL).
 ******************************************************************************/
static FILE *openUserFile(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    char  filename[ES_MAX_DIR_FILE_NAME_LEN];
    FILE *fp = NULL;

    if (NULL == user_id) {
        MSDB_ERROR("%s", "MSDB Open User File, no user specified!");
    } else if (user_id_len != (strlen((char *)user_id) +
                               strlen((char *)user_id  +
                               strlen((char *)user_id)+1)+2)) {
        MSDB_ERROR("%s", "MSDB Open User File, User ID is of wrong length!");
    } else if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Open User File, no community specified!");
    } else {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s %s %s",
                 STORAGE_USERS_DIRECTORY,
                 user_id, user_id+(strlen((char *)user_id)+1), community);

        if (NULL == (fp = fopen(filename, "r"))) {
            MSDB_ERROR("MSDB Open User File, unable to access user data <%s>!",
                filename);
        }
   }
   return fp;
} /* openUserFile */

/***************************************************************************//**
 * Produces 'pretty' (for humans) 4 byte space and 16 byte line separated 
 * output. The output is used to store hex strings to file.
 *
 * @param[out] out_line The output string of the prettyfication.
 * @param[in]  str      The input octet string.
 * @param[in]  str_len  The length of the input octet string.
 * @param[in]  pad      Pad for the output line of the hash.
 ******************************************************************************/
static void utils_prettyPrintOctetString(
    uint8_t       *out_line,
    const uint8_t *str,
    const size_t   str_len,
    const uint8_t  pad)
{
    uint16_t loop = 0;
    strcpy((char *)out_line, "");
    for (loop=0; loop < str_len; loop++) {
        if ((loop%16)==0) {
            sprintf((char *)&out_line[strlen((char *)out_line)], "\n%*s", pad, " ");
        }
        else {
            if ((loop%4)==0) {
                sprintf((char *)&out_line[strlen((char *)out_line)], " ");
            }
        }
        sprintf((char *)&out_line[strlen((char *)out_line)], "%X%X",
                (((str[loop])&0xf0)>>4), (str[loop])&0x0f);
    }
    sprintf((char *)&out_line[strlen((char *)out_line)], "\n\n");
} /* utils_prettyPrintOctetString */

/*****************************************************************************/
/* Community Data Accessor Functions.                                        */
/*****************************************************************************/
/* Management */

/**************************************************************************//**
 * Add KMS certificate data for a new KMS (community). If the kms_uri 
 * (community) name exists the storage is deleted first.
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
 * @return MSDB_SUCCESS or MSDB_FAILURE.
 ******************************************************************************/
short msdb_communityAdd(
    const uint8_t *version,
    const uint8_t *cert_uri,
    const uint8_t *kms_uri,        /* AKA community. */
    const uint8_t *issuer,
    const uint8_t *valid_from,
    const uint8_t *valid_to,
    const short    revoked,
    const uint8_t *user_id_format, /* Optional. */
    const uint8_t *pub_enc_key,    /* AKA 'Z'. */
    const size_t   pub_enc_key_len, 
    const uint8_t *pub_auth_key,   /* AKA 'KPAK'. */
    const size_t   pub_auth_key_len,
    const uint8_t *kms_domain_list) {

    short  ret_val = MSDB_FAILURE;
    FILE  *file_p  = NULL;

    char out_line[ES_MAX_LINE_LEN];
    char filename[ES_MAX_DIR_FILE_NAME_LEN];

    /* For some reason Secure Chorus doesn't mandate the KMS provide MS
     * parameter set.
     */
    if (NULL == kms_uri) {
        MSDB_ERROR("%s", "MSDB Community Add, missing mandatory parameter 'KmsUri' (community)!");
    }
    /* Mandatory - Absolute minimum */
    else if (NULL == pub_enc_key) {
        MSDB_ERROR("MSDB Community Add, <%s>, missing mandatory parameter 'PubEncKey' (Z)!",
            kms_uri);
    } else if (NULL == pub_auth_key) {
        MSDB_ERROR("MSDB Community Add, <%s>, missing mandatory parameter 'PubAuthKey' (KPAK)!",
            kms_uri);
    }
    else {
        /* Remove existing storage */
        msdb_communityDelete(kms_uri);

        /* Create the temporary file. */
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s", 
                 STORAGE_COMMUNITIES_DIRECTORY, kms_uri);

        if (NULL == (file_p = fopen(filename, "w"))) {
            MSDB_ERROR("MSDB Community Add, unable to access KmsUri (community) storage <%s>!",
                     kms_uri);
        }
        else {
            if (NULL != version) {
                snprintf(out_line, sizeof(out_line), 
                         "Version:\n    %s\n\n", version);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }
            if (NULL != cert_uri) {
                snprintf(out_line, sizeof(out_line),
                         "CertUri:\n    %s\n\n", cert_uri);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }
            if (NULL != kms_uri) {
                snprintf(out_line, sizeof(out_line), 
                         "KmsUri:\n    %s\n\n", kms_uri);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }
            if (NULL != issuer) {
                snprintf(out_line, sizeof(out_line), 
                         "Issuer:\n    %s\n\n", issuer);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }
            if (NULL != valid_from) {
                snprintf(out_line, sizeof(out_line), 
                         "ValidFrom:\n    %s\n\n", valid_from);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }
            if (NULL != valid_to) {
                snprintf(out_line, sizeof(out_line), 
                         "ValidTo:\n    %s\n\n", valid_to);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }
            if (revoked) {
                snprintf(out_line, sizeof(out_line), 
                         "Revoked:\n    %s\n\n", "TRUE");
            } else {
                snprintf(out_line, sizeof(out_line), 
                         "Revoked:\n    %s\n\n", "FALSE");
            }
            fwrite(out_line, strlen(out_line), 1, file_p);
            /* Optional */
            if (NULL != user_id_format) {
                snprintf(out_line, sizeof(out_line), 
                         "UserIdFormat:\n    %s\n\n", user_id_format);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }

            /* Z */
            if (NULL != pub_enc_key) {
                snprintf(out_line, sizeof(out_line), "PubEncKey:");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                utils_prettyPrintOctetString((uint8_t *)&out_line, 
                    (uint8_t *)pub_enc_key, pub_enc_key_len, 4); 
                fwrite(out_line, strlen(out_line), 1, file_p);
            }

            /* KPAK */
            if (NULL != pub_auth_key) {
                snprintf(out_line, sizeof(out_line), "PubAuthKey:");
                fwrite(out_line, strlen(out_line), 1, file_p);
                memset(out_line, 0, sizeof(out_line));
                utils_prettyPrintOctetString((uint8_t *)&out_line, 
                    (uint8_t *)pub_auth_key, pub_auth_key_len, 4); 
                fwrite(out_line, strlen(out_line), 1, file_p);
            }

            /* KMS domain list */
            if (NULL != kms_domain_list) {
                snprintf(out_line, sizeof(out_line), "KmsDomainList:\n    %s\n\n", kms_domain_list);
                fwrite(out_line, strlen(out_line), 1, file_p);
            }

            /* Close the file. */
            fclose(file_p);

            ret_val = MSDB_SUCCESS;
        }
    }

    memset(out_line,  0, sizeof(out_line));
    memset(filename, 0, sizeof(filename));

    return ret_val;

} /* msdb_communityAdd */

/***************************************************************************//**
 * Check whether the specified community exists.
 *
 * @param[in]  community The community name to check if it exists.
 *
 * @return ES_TRUE or ES_FALSE
 ******************************************************************************/
short msdb_communityExists(
    const uint8_t *community)
{
    short       ret_val = MSDB_FALSE;
    char        filename[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;

    if (NULL != community) {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s", 
                 STORAGE_COMMUNITIES_DIRECTORY, community);

        if ((!stat(filename, &file_info)) && /* Regular file? */
            (S_ISREG(file_info.st_mode))) {
                ret_val = MSDB_TRUE;
        }
    }

    return ret_val;

} /* msdb_communityExists */

/***************************************************************************//**
 * Delete specified community.
 *
 * @param[in]  community The name of the community to delete.
 *
 * @return ES_SUCCESS or ES_FAILURE
 ******************************************************************************/
short msdb_communityDelete(
    const uint8_t *community)
{
    short       ret_val = MSDB_FAILURE;
    char        filename[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Delete, no community specified!");
    }
    else {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s", 
                 STORAGE_COMMUNITIES_DIRECTORY, community);

        /* Regular file? */
        if ((!stat(filename, &file_info)) && 
            (S_ISREG(file_info.st_mode))) {

            if (!remove(filename)) {
                ret_val = MSDB_SUCCESS;
            }
            else {
                 MSDB_ERROR("MSDB Community Delete, unable to delete community <%s>!",
                          community);
             }
        }
        else { /* Does not exist, success */
            ret_val = MSDB_SUCCESS;
        }
 
    }

    return ret_val;

} /* msdb_communityDelete */

/***************************************************************************//**
 * Delete all (purge) stored communities.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityPurge() 
{
    short          ret_val         = MSDB_FAILURE;
    DIR           *dir_p           = NULL;
    struct dirent *dirEntry_p      = NULL;
    char           tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat    file_info;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));
    snprintf(tmpPath, sizeof(tmpPath), STORAGE_COMMUNITIES_DIRECTORY);

    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {

                memset(tmpPath, 0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath), 
                         "%s/%s", STORAGE_COMMUNITIES_DIRECTORY, dirEntry_p->d_name);

                /* Regular file? */
                if ((!stat(tmpPath, &file_info)) &&
                    (S_ISREG(file_info.st_mode))) {

                    if (remove(tmpPath)) {
                        MSDB_ERROR("MSDB Community Purge, unable to delete community file <%s>!",
                            dirEntry_p->d_name);
                    }
                }
            }
        }
        ret_val = MSDB_SUCCESS;
    }

    return ret_val;

} /* msdb_communityPurge */

/***************************************************************************//**
 * Get a comma separated list of stored communities.
 *
 * @return A pointer to the list of communities, NULL if none.
 ******************************************************************************/
uint8_t *msdb_communityList() {
    DIR            *dir_p           = NULL;
    struct  dirent *dirEntry_p      = NULL;
    char            tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat     file_info;
    uint8_t        *communityList   = NULL;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));

    snprintf(tmpPath, sizeof(tmpPath), STORAGE_COMMUNITIES_DIRECTORY);
    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmpPath,  0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath), "%s/%s", 
                         STORAGE_COMMUNITIES_DIRECTORY, dirEntry_p->d_name);

                if ((!stat(tmpPath, &file_info)) && 
                    (S_ISREG(file_info.st_mode))) {

                    if (NULL == communityList) {
                        communityList = calloc(1, strlen(dirEntry_p->d_name)+1);
                        strcpy((char *)communityList, dirEntry_p->d_name);
                    }
                    else {
                        /* comma and NULL terminator. */
                        communityList = realloc(communityList,
                            strlen((char *)communityList)+strlen(dirEntry_p->d_name)+ 2); 
                        strcat((char *)communityList, ",");
                        strcat((char *)communityList, dirEntry_p->d_name);
                    }
                }
            }
        }
    }

    return communityList;
} /* msdb_communityList */

/***************************************************************************//**
 * The number of stored communities.
 *
 * @return A count indicating the number of stored communities.
 ******************************************************************************/
uint16_t msdb_communityCount() 
{
    DIR                 *dir_p           = NULL;
    struct  dirent      *dirEntry_p      = NULL;
    char    tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;
    uint8_t              count           = 0;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));

    snprintf(tmpPath, sizeof(tmpPath), STORAGE_COMMUNITIES_DIRECTORY);
    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmpPath,  0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath), "%s/%s", 
                         STORAGE_COMMUNITIES_DIRECTORY, dirEntry_p->d_name);

                if ((!stat(tmpPath, &file_info)) && 
                    (S_ISREG(file_info.st_mode))) {
                    count++;
                }
            }
        }
    }

    return count;
} /* msdb_communityCount */

/* Get Attributes */

/***************************************************************************//**
 * Get the stored version for the specified community.
 *
 * @param[in]  community The name of the community from which to get the 
 *                       version.
 * @param[out] version   The version, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetVersion(
    const uint8_t *community,
    uint8_t       *version) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get Version, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "Version:", version)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get Version, unable to get Version from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get Version, failed to retrieve Version!")
    }

    return ret_val;
} /* msdb_communityGetVersion */

/***************************************************************************//**
 * Get the stored CertUri for the specified community.
 *
 * @param[in]  community The name of the community from which to get the 
 *                       CertUri.
 * @param[out] cert_uri  The CertUri, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetCertUri(
    const uint8_t *community,
    uint8_t       *cert_uri) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get CertUri, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "CertUri:", cert_uri)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get CertUri, unable to get CertUri from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get CertUri, failed to retrieve CertUri!");
    }

    return ret_val;
} /* msdb_communityGetCertUri */

/***************************************************************************//**
 * Get the stored KmUri for the specified community.
 *
 * @param[in]  community The name of the community from which to get the KmsUri.
 * @param[out] kms_uri   The KmsUri, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetKmsUri(
    const uint8_t *community,
    uint8_t       *kms_uri) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get KmsUri, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "KmsUri:", kms_uri)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get KmsUri, unable to get KmsUri from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get KmsUri, failed to retrieve KmsUri!");
    }

    return ret_val;
} /* msdb_communityGetKmsUri */

/***************************************************************************//**
 * Get the stored Issuer for the specified community.
 *
 * @param[in]  community The name of the community from which to get the 
 *                       issuer.
 * @param[out] issuer    The issuer, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetIssuer(
    const uint8_t *community,
    uint8_t       *issuer) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get Issuer, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "Issuer:", issuer)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get Issuer, unable to get Issuer from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get Issuer, failed to retrieve Issuer!");
    }

    return ret_val;
} /* msdb_communityGetIssuer */

/***************************************************************************//**
 * Get the stored ValidFrom for the specified community.
 *
 * @param[in]  community  The name of the community from which to get the 
 *                        ValidFrom date.
 * @param[out] valid_from The ValidFrom date, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetValidFrom(
    const uint8_t *community,
    uint8_t       *valid_from) {
    FILE          *fp      = NULL; 
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get ValidFrom, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "ValidFrom:", valid_from)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get ValidFrom, unable to get ValidFrom from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get ValidFrom, failed to retrieve ValidFrom!");
    }

    return ret_val;
} /* msdb_communityGetValidFrom */

/***************************************************************************//**
 * Get the stored ValidTo for the specified community.
 *
 * @param[in]  community The name of the community from which to get the 
 *                       ValidTo date.
 * @param[out] valid_to  The ValidTo date, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetValidTo(
    const uint8_t *community,
    uint8_t       *valid_to) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get ValidTo, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "ValidTo:", valid_to)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get ValidTo, unable to get validTo from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get ValidTo, failed to retrieve ValidTo!");
    }

    return ret_val;
} /* msdb_communityGetValidTo */

/***************************************************************************//**
 * Get the stored Revoked indicator for the specified community.
 *
 * @param[in]  community The name of the community from which to get the 
 *                       revoked indicator.
 * @param[out] revoked   The Revoked indicator, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetRevoked(
    const uint8_t *community,
    short         *revoked) {
    FILE          *fp     = NULL;
    uint8_t       rev[16];
    short         ret_val = MSDB_FAILURE;

    memset(rev, 0, sizeof(revoked));

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get Revoked, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "Revoked:", (uint8_t *)&rev)) {
            if (strcasecmp((char *)rev, "true") == 0) {
                *revoked = 1; 
            }
            else {
                *revoked = 0;
            }
            ret_val  = MSDB_SUCCESS;
            memset(rev, 0, sizeof(rev));
        }
        else {
            MSDB_ERROR("MSDB Community Get Revoked, unable to get Revoke status from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Get Revoked, failed to retrieve Revoke status!");
    }

    return ret_val;
} /* msdb_communityGetRevoked */

/* Optional */

/***************************************************************************//**
 * Get the stored UserIdFormat for the specified community.
 *
 * @param[in]  community      The name of the community from which to get the 
 *                            UserIdFormat.
 * @param[out] user_id_format The UserIdFormat date, on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetUserIDFormat(
    const uint8_t  *community,
    uint8_t       *user_id_format) {
    FILE           *fp      = NULL;
    short           ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get UserIdFormat, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "UserIdFormat:", user_id_format)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get UserIdFormat, unable to get UserIDFormat from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get UserIdFormat, failed to retrieve UserIDFormat!");
    }

    return ret_val;
} /* msdb_communityGetUserIDFormat */

/***************************************************************************//**
 * Get the stored PubEncKey (Z) for the specified community.
 *
 * @param[in]  community  The name of the community from which to get the 
 *                        PubEncKey (Z).
 * @param[out] Z          The PubEncKey (Z), on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetPubEncKey(
    const uint8_t *community,
    uint8_t       *Z)
{
    short          ret_val = MSDB_FAILURE;
    FILE          *fp      = NULL;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get PubEncKey, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "PubEncKey:", Z)) { 
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get PubEncKey, unable to get PubEncKey from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get PubEncKey, failed to retrieve PubEncKey!");
    }

    return ret_val;
} /* msdb_communityGetPubEncKey */

/***************************************************************************//**
 * Get the stored PubAuthKey (KPAK) for the specified community.
 *
 * @param[in]  community  The name of the community from which to get the 
 *                        PubAuthKey (KPAK).
 * @param[out] KPAK       The PubAuthKey (KPAK), on success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetPubAuthKey(
    const uint8_t *community,
    uint8_t       *KPAK)
{
    short          ret_val = MSDB_FAILURE;
    FILE          *fp      = NULL;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get PubAuthKey, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "PubAuthKey:", KPAK)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get PubAuthKey, unable to get PubAuthKey from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get PubAuthKey, failed to retrieve PubAuthAkey!");
    }

    return ret_val;
} /* msdb_communityGetPubAuthKey */

/***************************************************************************//**
 * Get the stored KmsDomainList for the specified community.
 *
 * @param[in]  community       The name of the community from which to get the 
 *                             KmsDomainList.
 * @param[out] kms_domain_list The KmsDomainList (as stored - maybe CSV), on 
                               success.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_communityGetKmsDomainList(
    const uint8_t *community,
    uint8_t       *kms_domain_list)
{
    short          ret_val = MSDB_FAILURE;
    FILE          *fp      = NULL;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB Community Get KmsDomainList, no community specified!");
    } else if (NULL != (fp = openCommunityFile(community))) {
        if (!parseDataAttribute(fp, "KmsDomainList:", kms_domain_list)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Community Get KmsDomainList, unable to get KmsDomainList from community <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Community Get KmsDomainList, failed to retrieve KmsDomainList!");
    }

    return ret_val;
} /* msdb_communityGetKmsDomainList */

/* User Data Accessor Functions. */

/***************************************************************************//**
 * Add a user to the user store.
 *
 * If the user exists already that data entry is deleted first.
 *
 * @param[in]  user_id     A pointer to user id string (date|NULL|uri).
 * @param[in]  user_id_len The length of user id string.
 * @param[in]  community   The community name string. 
 * @param[in]  ssk         A pointer to the SSK (Secret Signing Key) octet 
 *                         string.
 * @param[in]  ssk_len     The length of SSK octet String.
 * @param[in]  rsk         A pointer to the RSK (Receiver Secret Key) octet 
 *                         string.
 * @param[in]  rsk_len     The length of the RSK octet string.
 * @param[in]  hash        A pointer to the calculated hash value as an octet 
 *                         string. Calculate when the SSK was validated (an 
 *                         ECCSI action).
 * @param[in]  hash_len    The length of hash octet string.
 * @param[in]  pvt         A pointer to the PVT (public Validation Token) octet 
 *                         string.
 * @param[in]  pvt_len     The length of PVT octet string.
 *
 * @return MSDB_SUCCESS, MSDB_FAILURE
 ******************************************************************************/
uint8_t msdb_userAdd(
    /* Identifier */
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    /* Data */
    const uint8_t *ssk,
    const size_t   ssk_len,
    const uint8_t *rsk,
    const size_t   rsk_len,
    const uint8_t *hash,
    const size_t   hash_len,
    const uint8_t *pvt,
    const size_t   pvt_len) {

    short  ret_val = MSDB_FAILURE;
    FILE  *file_p  = NULL;

    char outLine[ES_MAX_LINE_LEN];
    char filename[ES_MAX_DIR_FILE_NAME_LEN];

    if (NULL == user_id) {
        MSDB_ERROR("%s", "MSDB User Add, missing mandatory parameter 'user_id'!");
    } else if (user_id_len != (strlen((char *)user_id) +
                               strlen((char *)user_id  +
                               strlen((char *)user_id)+1)+2)) {
        MSDB_ERROR("%s", "MSDB User Add, User ID is of wrong length!");
    } else if (NULL == community) {
        MSDB_ERROR("MSDB User Add, <%s %s>, missing mandatory parameter 'community'!",
            user_id, user_id+strlen((char *)user_id)+1);
    } else if (NULL == ssk) {
        MSDB_ERROR("MSDB User Add, <%s %s %s>, missing mandatory parameter 'ssk'!",
            user_id, user_id+strlen((char *)user_id)+1, community);
    } else if (NULL == rsk) {
        MSDB_ERROR("MSDB User Add, <%s %s %s>, missing mandatory parameter 'rsk'!",
            user_id, user_id+strlen((char *)user_id)+1, community);
    } else if (NULL == hash) {
        MSDB_ERROR("MSDB User Add, <%s %s %s>, missing mandatory parameter 'hash'!",
            user_id, user_id+strlen((char *)user_id)+1, community);
    } else if (NULL == pvt) {
        MSDB_ERROR("MSDB User Add, <%s %s %s>, missing mandatory parameter 'pvt'!",
            user_id, user_id+strlen((char *)user_id)+1, community);
    } else {
        /* Remove exsiting storage */
        msdb_userDelete(user_id, user_id_len, community);

        /* Create the temporary file. */
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s %s %s",
                 STORAGE_USERS_DIRECTORY,
                 user_id, user_id+(strlen((char *)user_id)+1), community);
        if (NULL != (file_p = fopen(filename, "w"))) {
            snprintf(outLine, sizeof(outLine), "SSK:");
            fwrite(outLine, strlen(outLine), 1, file_p);
            memset(outLine, 0, sizeof(outLine));
            utils_prettyPrintOctetString((uint8_t *)&outLine, 
                (uint8_t *)ssk, ssk_len, 4);
            fwrite(outLine, strlen(outLine), 1, file_p);

            snprintf(outLine, sizeof(outLine), "RSK:");
            fwrite(outLine, strlen(outLine), 1, file_p);
            memset(outLine, 0, sizeof(outLine));
            utils_prettyPrintOctetString((uint8_t *)&outLine, 
                (uint8_t *)rsk, rsk_len, 4);
            fwrite(outLine, strlen(outLine), 1, file_p);

            snprintf(outLine, sizeof(outLine), "HASH:");
            fwrite(outLine, strlen(outLine), 1, file_p);
            memset(outLine, 0, sizeof(outLine));
            utils_prettyPrintOctetString((uint8_t *)&outLine, 
                (uint8_t *)hash, hash_len, 4);
            fwrite(outLine, strlen(outLine), 1, file_p);

            snprintf(outLine, sizeof(outLine), "PVT:");
            fwrite(outLine, strlen(outLine), 1, file_p);
            memset(outLine, 0, sizeof(outLine));
            utils_prettyPrintOctetString((uint8_t *)&outLine, 
                (uint8_t *)pvt, pvt_len, 4);
            fwrite(outLine, strlen(outLine), 1, file_p);

            /* Close the file. */
            fclose(file_p);

            ret_val = MSDB_SUCCESS;
        }
    }

    memset(outLine,  0, sizeof(outLine));
    memset(filename, 0, sizeof(filename));

    return ret_val;
} /* msdb_userAdd */

/***************************************************************************//**
 * Check whether the specified user exists.
 *
 * @param[in]  user_id     A pointer to user id string (date|NULL|uri).
 * @param[in]  user_id_len The length of user id string.
 * @param[in]  community   The community name string. 
 *
 * @return MSDB_TRUE or MSDB_FALSE
 ******************************************************************************/
short msdb_userExists(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    short       ret_val = MSDB_FALSE;
    char        filename[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB User Exists, No community specified!");
    } else if (NULL == user_id) {
        MSDB_ERROR("%s", "MSDB User Exists, No user specified!");
    } else if (user_id_len != (strlen((char *)user_id) +
                               strlen((char *)user_id  +
                               strlen((char *)user_id)+1)+2)) {
        MSDB_ERROR("%s", "MSDB User Exists, User ID is of wrong length!");
    } else {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s %s %s", 
                 STORAGE_USERS_DIRECTORY, 
                 user_id, user_id+(strlen((char *)user_id)+1), community);
        if ((!stat(filename, &file_info)) && /* Regular file? */
            (S_ISREG(file_info.st_mode))) {
            ret_val = MSDB_TRUE;
        }
    }

    return ret_val;

} /* msdb_userExists */

/***************************************************************************//**
 * Delete a specified user within a community.
 *
 * @param[in]  user_id     A pointer to user id string (date|NULL|uri).
 * @param[in]  user_id_len The length of user id string.
 * @param[in]  community   The community name string. 
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_userDelete(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community)
{
    short       ret_val = MSDB_FAILURE;
    char        filename[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB User Delete, no community specified!");
    } else if (NULL == user_id) {
        MSDB_ERROR("%s", "MSDB User Delete, no user specified!");
    } else if (user_id_len != (strlen((char *)user_id) +
                               strlen((char *)user_id  +
                               strlen((char *)user_id)+1)+2)) {
        MSDB_ERROR("%s", "MSDB User Delete, User ID is of wrong length!");
    } else {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "%s/%s %s %s", 
                 STORAGE_USERS_DIRECTORY, 
                 user_id, user_id+(strlen((char *)user_id)+1), community);

        /* Regular file? */
        if ((!stat(filename, &file_info)) &&
            (S_ISREG(file_info.st_mode))) {

            if (!remove(filename)) {
                ret_val = MSDB_SUCCESS;
            }
            else {
                MSDB_ERROR("MSDB User Delete, unable to delete user <%s.%s> in <%s>!",
                    user_id, user_id+(strlen((char *)user_id)+1), community);
            }
        }
        else { /* Does not exist, success */
            ret_val = MSDB_SUCCESS;
        }

    }

    return ret_val;

} /* msdb_userDelete */

/***************************************************************************//**
 * Delete all (purge) stored users.
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_userPurge()
{
    short          ret_val    = MSDB_FAILURE;
    DIR           *dir_p      = NULL;
    struct dirent *dirEntry_p = NULL;
    char           tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat    file_info;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));
    snprintf(tmpPath, sizeof(tmpPath), STORAGE_USERS_DIRECTORY);

    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {

                memset(tmpPath, 0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath),
                         "%s/%s", STORAGE_USERS_DIRECTORY, dirEntry_p->d_name);

                /* Regular file? */
                if ((!stat(tmpPath, &file_info)) &&
                    (S_ISREG(file_info.st_mode))) {

                    if (remove(tmpPath)) {
                        MSDB_ERROR("MSDB User Purge, unable to delete user file <%s>!",
                            dirEntry_p->d_name);
                    }
                }
            }
        }
        ret_val = MSDB_SUCCESS;
    }
    return ret_val;
} /* msdb_userPurge */

/***************************************************************************//**
 * Get a comma separated list of stored users.
 *
 * @return A pointer to the list of users, NULL if none.
 ******************************************************************************/
uint8_t *msdb_userList() {
    DIR            *dir_p      = NULL;
    struct  dirent *dirEntry_p = NULL;
    char            tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat     file_info;
    uint8_t        *userList   = NULL;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));

    snprintf(tmpPath, sizeof(tmpPath), STORAGE_USERS_DIRECTORY);
    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmpPath,  0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath), "%s/%s",
                         STORAGE_USERS_DIRECTORY, dirEntry_p->d_name);

                if ((!stat(tmpPath, &file_info)) &&
                    (S_ISREG(file_info.st_mode))) {

                    if (NULL == userList) {
                        userList = calloc(1, strlen(dirEntry_p->d_name)+1);
                        strcpy((char *)userList, dirEntry_p->d_name);
                    }
                    else {
                        /* comma and NULL terminator. */
                        userList = realloc(userList,
                            strlen((char *)userList)+strlen(dirEntry_p->d_name)+ 2);
                        strcat((char *)userList, ",");
                        strcat((char *)userList, dirEntry_p->d_name);
                    }
                }
            }
        }
    }

    return userList;

} /* msdb_userList */

/***************************************************************************//**
 * Get the number of stored users.
 *
 * @return A count indicating the number of stored users.
 ******************************************************************************/
uint16_t msdb_userCount() {
    DIR                 *dir_p      = NULL;
    struct  dirent      *dirEntry_p = NULL;
    char    tmpPath[ES_MAX_DIR_FILE_NAME_LEN];
    struct stat file_info;
    uint8_t              count      = 0;

    /* Initialise storage structure. */
    memset(tmpPath,  0, sizeof(tmpPath));

    snprintf(tmpPath, sizeof(tmpPath), STORAGE_USERS_DIRECTORY);
    dir_p = opendir(tmpPath);
    if (NULL != dir_p) {

        while (NULL != (dirEntry_p = readdir(dir_p))) {
            if ((strcmp(dirEntry_p->d_name,  ".") != 0) &&
                (strcmp(dirEntry_p->d_name, "..") != 0)) {
                memset(tmpPath,  0, sizeof(tmpPath));
                snprintf(tmpPath, sizeof(tmpPath), "%s/%s",
                         STORAGE_USERS_DIRECTORY, dirEntry_p->d_name);

                if ((!stat(tmpPath, &file_info)) &&
                    (S_ISREG(file_info.st_mode))) {
                    count++;
                }
            }
        }
    }

    return count;
} /* msdb_userCount */

/***************************************************************************//**
 * Get a specified user's SSK (Secret Signing Key).
 *
 * @param[in]  user_id     A pointer to user id string (date|NULL|uri).
 * @param[in]  user_id_len The length of user id string.
 * @param[in]  community   The community name string. 
 * @param[out] ssk         The user SSK. 
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_userGetSSK(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    uint8_t       *ssk) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB User Get SSK, no community specified!");
    } else if (NULL == user_id) {
        MSDB_ERROR("%s", "MSDB User Get SSK, no user specified!");
    } else if (user_id_len != (strlen((char *)user_id) +
                               strlen((char *)user_id  +
                               strlen((char *)user_id)+1)+2)) {
        MSDB_ERROR("%s", "MSDB User Get SSK, User ID is of wrong length!");
    } else if (NULL != (fp = openUserFile(user_id, user_id_len, community))) {
        if (!parseDataAttribute(fp, "SSK:", ssk)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB User Get SSK, unable to get user data <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB User Get SSK, failed to retrieve SSK!");
    }

    return ret_val;
} /* msdb_userGetSSK */

/***************************************************************************//**
 * Get a specified user's RSK (Receiver Secret Key).
 *
 * @param[in]  user_id     A pointer to user id string (date|NULL|uri).
 * @param[in]  user_id_len The length of user id string.
 * @param[in]  community   The community name string. 
 * @param[out] rsk         The user RSK. 
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_userGetRSK(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    uint8_t       *rsk) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB User Get RSK, no community specified!");
    } else if (NULL == user_id) {
        MSDB_ERROR("%s", "MSDB User Get RSK, no user specified!");
    } else if (user_id_len != (strlen((char *)user_id) +
                               strlen((char *)user_id  +
                               strlen((char *)user_id)+1)+2)) {
        MSDB_ERROR("%s", "MSDB User Get RSK, User ID is of wrong length!");
    } else if (NULL != (fp = openUserFile(user_id, user_id_len, community))) {
        if (!parseDataAttribute(fp, "RSK:", rsk)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB User Get RSK, unable to get user data <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB User Get RSK, failed to retrieve RSK!");
    }

    return ret_val;
} /* msdb_userGetRSK */

/***************************************************************************//**
 * Get a specified user's Hash.
 *
 * @param[in]  user_id     A pointer to user id string (date|NULL|uri).
 * @param[in]  user_id_len The length of user id string.
 * @param[in]  community   The community name string. 
 * @param[out] hash        The user hash. 
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_userGetHash(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    uint8_t       *hash) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB User Get Hash, no community specified!");
    } else if (NULL == user_id) {
        MSDB_ERROR("%s", "MSDB User Get Hash, no user specified!");
    } else if (user_id_len != (strlen((char *)user_id) +
                               strlen((char *)user_id  +
                               strlen((char *)user_id)+1)+2)) {
        MSDB_ERROR("%s", "MSDB User Get Hash, User ID is of wrong length!");
    } else if (NULL != (fp = openUserFile(user_id, user_id_len, community))) {
        if (!parseDataAttribute(fp, "HASH:", hash)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB Uer Get Hash, unable to get user data <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Uer Get Hash, failed to retrieve Hash!");
    }

    return ret_val;
} /* msdb_userGetHash */

/***************************************************************************//**
 * Get a specified user's PVT (Public Validation Token).
 *
 * @param[in]  user_id     A pointer to user id string (date|NULL|uri).
 * @param[in]  user_id_len The length of user id string.
 * @param[in]  community   The community name string. 
 * @param[out] pvt         The user PVT. 
 *
 * @return MSDB_SUCCESS or MSDB_FAILURE
 ******************************************************************************/
short msdb_userGetPVT(
    const uint8_t *user_id,
    const size_t   user_id_len,
    const uint8_t *community,
    uint8_t       *pvt) {
    FILE          *fp      = NULL;
    short          ret_val = MSDB_FAILURE;

    if (NULL == community) {
        MSDB_ERROR("%s", "MSDB User Get PVT, no community specified!");
    } else if (NULL == user_id) {
        MSDB_ERROR("%s", "MSDB User Get PVT, no user specified!");
    } else if (user_id_len != (strlen((char *)user_id) +
                               strlen((char *)user_id  +
                               strlen((char *)user_id)+1)+2)) {
        MSDB_ERROR("%s", "MSDB User Get PVT, User ID is of wrong length!");
    } else if (NULL != (fp = openUserFile(user_id, user_id_len, community))) {
        if (!parseDataAttribute(fp, "PVT:", pvt)) {
            ret_val = MSDB_SUCCESS;
        }
        else {
            MSDB_ERROR("MSDB User Get PVT, unable to get user data <%s>!",
                community);
        }
        fclose(fp);
    }
    else {
        MSDB_ERROR("%s", "MSDB Get PVT, failed to retrieve PVT!");
    }

    return ret_val;
} /* msdb_userGetPVT */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
