/******************************************************************************/
/* A simple PRNG (Pseudo Random Number Generator)                             */
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
 * @file esprng.c
 * @brief A simple PRNG (Pseudo Random Number Generator).
 ******************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <sys/time.h> /* For random */

#include "esprng.h"

/***************************************************************************//**
 * Generate a pseudo random number of specified length.
 *
 * Callers are responsible for clearing/ freeing the allocated space.
 *
 * @param[out] rnd     A pointer to to the PRNG output.
 * @param[in]  rnd_len The length of the required random data. 
 *
 * @return A success(1) indication.
 ******************************************************************************/
short ES_PRNG(
    uint8_t **rnd,
    uint8_t   rnd_len)
{
    unsigned int    size_count = 0;
    unsigned int    seed       = 0;
    unsigned int    prng       = 0;
    struct timeval  tv;
    struct timezone tz;

    gettimeofday(&tv, &tz);
    seed = (tv.tv_sec * tv.tv_usec);

    srand(seed);
    *rnd = calloc(1, rnd_len);

    for (; size_count < (rnd_len/sizeof(int)); size_count++) {
        prng = rand();

        /* This is (pseudo) random so doesn't matter if unordered. */
        memcpy(*rnd+(size_count*(sizeof(int))), &prng, sizeof(int));
    }
    return 1;
} /* ES_PRNG */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
