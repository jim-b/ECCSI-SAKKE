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
 * @file esprng.h
 * @brief A simple PRNG (Pseudo Random Number Generator).
 ******************************************************************************/
#ifndef __ES_PRNG__
#define __ES_PRNG__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Generate a pseudo random number of specified length.
 ******************************************************************************/
short ES_PRNG(
    uint8_t **rnd,
    uint8_t   rnd_len);

#ifdef __cplusplus
}
#endif
#endif /* __ES_PRNG__ */

/******************************************************************************/
/*                                End of file                                 */
/******************************************************************************/
