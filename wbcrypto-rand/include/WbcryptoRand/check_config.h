/**
 * \file check_config.h
 *
 * \brief Consistency checks for configuration options
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * It is recommended to include this file from your config.h
 * in order to catch dependency issues early.
 */

#ifndef WBCRYPTO_CHECK_CONFIG_H
#define WBCRYPTO_CHECK_CONFIG_H

/*
 * We assume CHAR_BIT is 8 in many places. In practice, this is true on our
 * target platforms, so not an issue, but let's just be extra sure.
 */
#include <limits.h>
#if CHAR_BIT != 8
#error "mbed TLS requires a platform with 8-bit chars"
#endif

#if defined(_WIN32)
#if !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_C is required on Windows"
#endif

/* Fix the config here. Not convenient to put an #ifdef _WIN32 in config.h as
 * it would confuse config.pl. */
#if !defined(WBCRYPTO_PLATFORM_SNPRINTF_ALT) && \
    !defined(WBCRYPTO_PLATFORM_SNPRINTF_MACRO)
#define WBCRYPTO_PLATFORM_SNPRINTF_ALT
#endif
#endif /* _WIN32 */

#if defined(TARGET_LIKE_MBED) && \
    ( defined(WBCRYPTO_NET_C) || defined(WBCRYPTO_TIMING_C) )
#error "The NET and TIMING modules are not available for mbed OS - please use the network and timing functions provided by mbed OS"
#endif

#if defined(WBCRYPTO_DEPRECATED_WARNING) && \
    !defined(__GNUC__) && !defined(__clang__)
#error "WBCRYPTO_DEPRECATED_WARNING only works with GCC and Clang"
#endif

#if defined(WBCRYPTO_HAVE_TIME_DATE) && !defined(WBCRYPTO_HAVE_TIME)
#error "WBCRYPTO_HAVE_TIME_DATE without WBCRYPTO_HAVE_TIME does not make sense"
#endif

#if defined(WBCRYPTO_AESNI_C) && !defined(WBCRYPTO_HAVE_ASM)
#error "WBCRYPTO_AESNI_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_CTR_DRBG_C) && !defined(WBCRYPTO_AES_C)
#error "WBCRYPTO_CTR_DRBG_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_DHM_C) && !defined(WBCRYPTO_BIGNUM_C)
#error "WBCRYPTO_DHM_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_CMAC_C) && \
    !defined(WBCRYPTO_AES_C) && !defined(WBCRYPTO_DES_C)
#error "WBCRYPTO_CMAC_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECDH_C) && !defined(WBCRYPTO_ECP_C)
#error "WBCRYPTO_ECDH_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECDSA_C) &&            \
    ( !defined(WBCRYPTO_ECP_C) ||           \
      !defined(WBCRYPTO_ASN1_PARSE_C) ||    \
      !defined(WBCRYPTO_ASN1_WRITE_C) )
#error "WBCRYPTO_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECJPAKE_C) &&           \
    ( !defined(WBCRYPTO_ECP_C) || !defined(WBCRYPTO_MD_C) )
#error "WBCRYPTO_ECJPAKE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECDSA_DETERMINISTIC) && !defined(WBCRYPTO_HMAC_DRBG_C)
#error "WBCRYPTO_ECDSA_DETERMINISTIC defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_C) && ( !defined(WBCRYPTO_BIGNUM_C) || (   \
    !defined(WBCRYPTO_ECP_DP_SECP192R1_ENABLED) &&                  \
    !defined(WBCRYPTO_ECP_DP_SECP224R1_ENABLED) &&                  \
    !defined(WBCRYPTO_ECP_DP_SECP256R1_ENABLED) &&                  \
    !defined(WBCRYPTO_ECP_DP_SECP384R1_ENABLED) &&                  \
    !defined(WBCRYPTO_ECP_DP_SECP521R1_ENABLED) &&                  \
    !defined(WBCRYPTO_ECP_DP_BP256R1_ENABLED)   &&                  \
    !defined(WBCRYPTO_ECP_DP_BP384R1_ENABLED)   &&                  \
    !defined(WBCRYPTO_ECP_DP_BP512R1_ENABLED)   &&                  \
    !defined(WBCRYPTO_ECP_DP_SECP192K1_ENABLED) &&                  \
    !defined(WBCRYPTO_ECP_DP_SECP224K1_ENABLED) &&                  \
    !defined(WBCRYPTO_ECP_DP_SECP256K1_ENABLED) ) )
#error "WBCRYPTO_ECP_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ENTROPY_C) && (!defined(WBCRYPTO_SHA512_C) &&      \
                                    !defined(WBCRYPTO_SHA256_C))
#error "WBCRYPTO_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(WBCRYPTO_ENTROPY_C) && defined(WBCRYPTO_SHA512_C) &&         \
    defined(WBCRYPTO_CTR_DRBG_ENTROPY_LEN) && (WBCRYPTO_CTR_DRBG_ENTROPY_LEN > 64)
#error "WBCRYPTO_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(WBCRYPTO_ENTROPY_C) &&                                            \
    ( !defined(WBCRYPTO_SHA512_C) || defined(WBCRYPTO_ENTROPY_FORCE_SHA256) ) \
    && defined(WBCRYPTO_CTR_DRBG_ENTROPY_LEN) && (WBCRYPTO_CTR_DRBG_ENTROPY_LEN > 32)
#error "WBCRYPTO_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(WBCRYPTO_ENTROPY_C) && \
    defined(WBCRYPTO_ENTROPY_FORCE_SHA256) && !defined(WBCRYPTO_SHA256_C)
#error "WBCRYPTO_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_TEST_NULL_ENTROPY) && \
    ( !defined(WBCRYPTO_ENTROPY_C) || !defined(WBCRYPTO_NO_DEFAULT_ENTROPY_SOURCES) )
#error "WBCRYPTO_TEST_NULL_ENTROPY defined, but not all prerequisites"
#endif
#if defined(WBCRYPTO_TEST_NULL_ENTROPY) && \
     ( defined(WBCRYPTO_ENTROPY_NV_SEED) || defined(WBCRYPTO_ENTROPY_HARDWARE_ALT) || \
    defined(WBCRYPTO_HAVEGE_C) )
#error "WBCRYPTO_TEST_NULL_ENTROPY defined, but entropy sources too"
#endif

#if defined(WBCRYPTO_GCM_C) && (                                        \
        !defined(WBCRYPTO_AES_C) && !defined(WBCRYPTO_CAMELLIA_C) )
#error "WBCRYPTO_GCM_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_RANDOMIZE_JAC_ALT) && !defined(WBCRYPTO_ECP_INTERNAL_ALT)
#error "WBCRYPTO_ECP_RANDOMIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_ADD_MIXED_ALT) && !defined(WBCRYPTO_ECP_INTERNAL_ALT)
#error "WBCRYPTO_ECP_ADD_MIXED_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_DOUBLE_JAC_ALT) && !defined(WBCRYPTO_ECP_INTERNAL_ALT)
#error "WBCRYPTO_ECP_DOUBLE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_NORMALIZE_JAC_MANY_ALT) && !defined(WBCRYPTO_ECP_INTERNAL_ALT)
#error "WBCRYPTO_ECP_NORMALIZE_JAC_MANY_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_NORMALIZE_JAC_ALT) && !defined(WBCRYPTO_ECP_INTERNAL_ALT)
#error "WBCRYPTO_ECP_NORMALIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_DOUBLE_ADD_MXZ_ALT) && !defined(WBCRYPTO_ECP_INTERNAL_ALT)
#error "WBCRYPTO_ECP_DOUBLE_ADD_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_RANDOMIZE_MXZ_ALT) && !defined(WBCRYPTO_ECP_INTERNAL_ALT)
#error "WBCRYPTO_ECP_RANDOMIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ECP_NORMALIZE_MXZ_ALT) && !defined(WBCRYPTO_ECP_INTERNAL_ALT)
#error "WBCRYPTO_ECP_NORMALIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_HAVEGE_C) && !defined(WBCRYPTO_TIMING_C)
#error "WBCRYPTO_HAVEGE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_HMAC_DRBG_C) && !defined(WBCRYPTO_MD_C)
#error "WBCRYPTO_HMAC_DRBG_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) &&                 \
    ( !defined(WBCRYPTO_ECDH_C) || !defined(WBCRYPTO_X509_CRT_PARSE_C) )
#error "WBCRYPTO_KEY_EXCHANGE_ECDH_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_ECDH_RSA_ENABLED) &&                 \
    ( !defined(WBCRYPTO_ECDH_C) || !defined(WBCRYPTO_X509_CRT_PARSE_C) )
#error "WBCRYPTO_KEY_EXCHANGE_ECDH_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_DHE_PSK_ENABLED) && !defined(WBCRYPTO_DHM_C)
#error "WBCRYPTO_KEY_EXCHANGE_DHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_ECDHE_PSK_ENABLED) &&                     \
    !defined(WBCRYPTO_ECDH_C)
#error "WBCRYPTO_KEY_EXCHANGE_ECDHE_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_DHE_RSA_ENABLED) &&                   \
    ( !defined(WBCRYPTO_DHM_C) || !defined(WBCRYPTO_RSA_C) ||           \
      !defined(WBCRYPTO_X509_CRT_PARSE_C) || !defined(WBCRYPTO_PKCS1_V15) )
#error "WBCRYPTO_KEY_EXCHANGE_DHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_ECDHE_RSA_ENABLED) &&                 \
    ( !defined(WBCRYPTO_ECDH_C) || !defined(WBCRYPTO_RSA_C) ||          \
      !defined(WBCRYPTO_X509_CRT_PARSE_C) || !defined(WBCRYPTO_PKCS1_V15) )
#error "WBCRYPTO_KEY_EXCHANGE_ECDHE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) &&                 \
    ( !defined(WBCRYPTO_ECDH_C) || !defined(WBCRYPTO_ECDSA_C) ||          \
      !defined(WBCRYPTO_X509_CRT_PARSE_C) )
#error "WBCRYPTO_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_RSA_PSK_ENABLED) &&                   \
    ( !defined(WBCRYPTO_RSA_C) || !defined(WBCRYPTO_X509_CRT_PARSE_C) || \
      !defined(WBCRYPTO_PKCS1_V15) )
#error "WBCRYPTO_KEY_EXCHANGE_RSA_PSK_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_RSA_ENABLED) &&                       \
    ( !defined(WBCRYPTO_RSA_C) || !defined(WBCRYPTO_X509_CRT_PARSE_C) || \
      !defined(WBCRYPTO_PKCS1_V15) )
#error "WBCRYPTO_KEY_EXCHANGE_RSA_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_KEY_EXCHANGE_ECJPAKE_ENABLED) &&                    \
    ( !defined(WBCRYPTO_ECJPAKE_C) || !defined(WBCRYPTO_SHA256_C) ||      \
      !defined(WBCRYPTO_ECP_DP_SECP256R1_ENABLED) )
#error "WBCRYPTO_KEY_EXCHANGE_ECJPAKE_ENABLED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_MEMORY_BUFFER_ALLOC_C) &&                          \
    ( !defined(WBCRYPTO_PLATFORM_C) || !defined(WBCRYPTO_PLATFORM_MEMORY) )
#error "WBCRYPTO_MEMORY_BUFFER_ALLOC_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PADLOCK_C) && !defined(WBCRYPTO_HAVE_ASM)
#error "WBCRYPTO_PADLOCK_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PEM_PARSE_C) && !defined(WBCRYPTO_BASE64_C)
#error "WBCRYPTO_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PEM_WRITE_C) && !defined(WBCRYPTO_BASE64_C)
#error "WBCRYPTO_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PK_C) && \
    ( !defined(WBCRYPTO_RSA_C) && !defined(WBCRYPTO_ECP_C) )
#error "WBCRYPTO_PK_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PK_PARSE_C) && !defined(WBCRYPTO_PK_C)
#error "WBCRYPTO_PK_PARSE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PK_WRITE_C) && !defined(WBCRYPTO_PK_C)
#error "WBCRYPTO_PK_WRITE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PKCS11_C) && !defined(WBCRYPTO_PK_C)
#error "WBCRYPTO_PKCS11_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_EXIT_ALT) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_EXIT_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_EXIT_MACRO) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_EXIT_MACRO defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_EXIT_MACRO) &&\
    ( defined(WBCRYPTO_PLATFORM_STD_EXIT) ||\
        defined(WBCRYPTO_PLATFORM_EXIT_ALT) )
#error "WBCRYPTO_PLATFORM_EXIT_MACRO and WBCRYPTO_PLATFORM_STD_EXIT/WBCRYPTO_PLATFORM_EXIT_ALT cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_TIME_ALT) &&\
    ( !defined(WBCRYPTO_PLATFORM_C) ||\
        !defined(WBCRYPTO_HAVE_TIME) )
#error "WBCRYPTO_PLATFORM_TIME_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_TIME_MACRO) &&\
    ( !defined(WBCRYPTO_PLATFORM_C) ||\
        !defined(WBCRYPTO_HAVE_TIME) )
#error "WBCRYPTO_PLATFORM_TIME_MACRO defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_TIME_TYPE_MACRO) &&\
    ( !defined(WBCRYPTO_PLATFORM_C) ||\
        !defined(WBCRYPTO_HAVE_TIME) )
#error "WBCRYPTO_PLATFORM_TIME_TYPE_MACRO defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_TIME_MACRO) &&\
    ( defined(WBCRYPTO_PLATFORM_STD_TIME) ||\
        defined(WBCRYPTO_PLATFORM_TIME_ALT) )
#error "WBCRYPTO_PLATFORM_TIME_MACRO and WBCRYPTO_PLATFORM_STD_TIME/WBCRYPTO_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_TIME_TYPE_MACRO) &&\
    ( defined(WBCRYPTO_PLATFORM_STD_TIME) ||\
        defined(WBCRYPTO_PLATFORM_TIME_ALT) )
#error "WBCRYPTO_PLATFORM_TIME_TYPE_MACRO and WBCRYPTO_PLATFORM_STD_TIME/WBCRYPTO_PLATFORM_TIME_ALT cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_FPRINTF_ALT) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_FPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_FPRINTF_MACRO) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_FPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_FPRINTF_MACRO) &&\
    ( defined(WBCRYPTO_PLATFORM_STD_FPRINTF) ||\
        defined(WBCRYPTO_PLATFORM_FPRINTF_ALT) )
#error "WBCRYPTO_PLATFORM_FPRINTF_MACRO and WBCRYPTO_PLATFORM_STD_FPRINTF/WBCRYPTO_PLATFORM_FPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_FREE_MACRO) &&\
    ( !defined(WBCRYPTO_PLATFORM_C) || !defined(WBCRYPTO_PLATFORM_MEMORY) )
#error "WBCRYPTO_PLATFORM_FREE_MACRO defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_FREE_MACRO) &&\
    defined(WBCRYPTO_PLATFORM_STD_FREE)
#error "WBCRYPTO_PLATFORM_FREE_MACRO and WBCRYPTO_PLATFORM_STD_FREE cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_FREE_MACRO) && !defined(WBCRYPTO_PLATFORM_CALLOC_MACRO)
#error "WBCRYPTO_PLATFORM_CALLOC_MACRO must be defined if WBCRYPTO_PLATFORM_FREE_MACRO is"
#endif

#if defined(WBCRYPTO_PLATFORM_CALLOC_MACRO) &&\
    ( !defined(WBCRYPTO_PLATFORM_C) || !defined(WBCRYPTO_PLATFORM_MEMORY) )
#error "WBCRYPTO_PLATFORM_CALLOC_MACRO defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_CALLOC_MACRO) &&\
    defined(WBCRYPTO_PLATFORM_STD_CALLOC)
#error "WBCRYPTO_PLATFORM_CALLOC_MACRO and WBCRYPTO_PLATFORM_STD_CALLOC cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_CALLOC_MACRO) && !defined(WBCRYPTO_PLATFORM_FREE_MACRO)
#error "WBCRYPTO_PLATFORM_FREE_MACRO must be defined if WBCRYPTO_PLATFORM_CALLOC_MACRO is"
#endif

#if defined(WBCRYPTO_PLATFORM_MEMORY) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_MEMORY defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_PRINTF_ALT) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_PRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_PRINTF_MACRO) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_PRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_PRINTF_MACRO) &&\
    ( defined(WBCRYPTO_PLATFORM_STD_PRINTF) ||\
        defined(WBCRYPTO_PLATFORM_PRINTF_ALT) )
#error "WBCRYPTO_PLATFORM_PRINTF_MACRO and WBCRYPTO_PLATFORM_STD_PRINTF/WBCRYPTO_PLATFORM_PRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_SNPRINTF_ALT) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_SNPRINTF_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_SNPRINTF_MACRO) && !defined(WBCRYPTO_PLATFORM_C)
#error "WBCRYPTO_PLATFORM_SNPRINTF_MACRO defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_SNPRINTF_MACRO) &&\
    ( defined(WBCRYPTO_PLATFORM_STD_SNPRINTF) ||\
        defined(WBCRYPTO_PLATFORM_SNPRINTF_ALT) )
#error "WBCRYPTO_PLATFORM_SNPRINTF_MACRO and WBCRYPTO_PLATFORM_STD_SNPRINTF/WBCRYPTO_PLATFORM_SNPRINTF_ALT cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_MEM_HDR) &&\
    !defined(WBCRYPTO_PLATFORM_NO_STD_FUNCTIONS)
#error "WBCRYPTO_PLATFORM_STD_MEM_HDR defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_CALLOC) && !defined(WBCRYPTO_PLATFORM_MEMORY)
#error "WBCRYPTO_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_CALLOC) && !defined(WBCRYPTO_PLATFORM_MEMORY)
#error "WBCRYPTO_PLATFORM_STD_CALLOC defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_FREE) && !defined(WBCRYPTO_PLATFORM_MEMORY)
#error "WBCRYPTO_PLATFORM_STD_FREE defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_EXIT) &&\
    !defined(WBCRYPTO_PLATFORM_EXIT_ALT)
#error "WBCRYPTO_PLATFORM_STD_EXIT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_TIME) &&\
    ( !defined(WBCRYPTO_PLATFORM_TIME_ALT) ||\
        !defined(WBCRYPTO_HAVE_TIME) )
#error "WBCRYPTO_PLATFORM_STD_TIME defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_FPRINTF) &&\
    !defined(WBCRYPTO_PLATFORM_FPRINTF_ALT)
#error "WBCRYPTO_PLATFORM_STD_FPRINTF defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_PRINTF) &&\
    !defined(WBCRYPTO_PLATFORM_PRINTF_ALT)
#error "WBCRYPTO_PLATFORM_STD_PRINTF defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_SNPRINTF) &&\
    !defined(WBCRYPTO_PLATFORM_SNPRINTF_ALT)
#error "WBCRYPTO_PLATFORM_STD_SNPRINTF defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_ENTROPY_NV_SEED) &&\
    ( !defined(WBCRYPTO_PLATFORM_C) || !defined(WBCRYPTO_ENTROPY_C) )
#error "WBCRYPTO_ENTROPY_NV_SEED defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_NV_SEED_ALT) &&\
    !defined(WBCRYPTO_ENTROPY_NV_SEED)
#error "WBCRYPTO_PLATFORM_NV_SEED_ALT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_NV_SEED_READ) &&\
    !defined(WBCRYPTO_PLATFORM_NV_SEED_ALT)
#error "WBCRYPTO_PLATFORM_STD_NV_SEED_READ defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_STD_NV_SEED_WRITE) &&\
    !defined(WBCRYPTO_PLATFORM_NV_SEED_ALT)
#error "WBCRYPTO_PLATFORM_STD_NV_SEED_WRITE defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_PLATFORM_NV_SEED_READ_MACRO) &&\
    ( defined(WBCRYPTO_PLATFORM_STD_NV_SEED_READ) ||\
      defined(WBCRYPTO_PLATFORM_NV_SEED_ALT) )
#error "WBCRYPTO_PLATFORM_NV_SEED_READ_MACRO and WBCRYPTO_PLATFORM_STD_NV_SEED_READ cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_PLATFORM_NV_SEED_WRITE_MACRO) &&\
    ( defined(WBCRYPTO_PLATFORM_STD_NV_SEED_WRITE) ||\
      defined(WBCRYPTO_PLATFORM_NV_SEED_ALT) )
#error "WBCRYPTO_PLATFORM_NV_SEED_WRITE_MACRO and WBCRYPTO_PLATFORM_STD_NV_SEED_WRITE cannot be defined simultaneously"
#endif

#if defined(WBCRYPTO_RSA_C) && ( !defined(WBCRYPTO_BIGNUM_C) ||         \
    !defined(WBCRYPTO_OID_C) )
#error "WBCRYPTO_RSA_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_RSA_C) && ( !defined(WBCRYPTO_PKCS1_V21) &&         \
    !defined(WBCRYPTO_PKCS1_V15) )
#error "WBCRYPTO_RSA_C defined, but none of the PKCS1 versions enabled"
#endif

#if defined(WBCRYPTO_X509_RSASSA_PSS_SUPPORT) &&                        \
    ( !defined(WBCRYPTO_RSA_C) || !defined(WBCRYPTO_PKCS1_V21) )
#error "WBCRYPTO_X509_RSASSA_PSS_SUPPORT defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_PROTO_SSL3) && ( !defined(WBCRYPTO_MD5_C) ||     \
    !defined(WBCRYPTO_SHA1_C) )
#error "WBCRYPTO_SSL_PROTO_SSL3 defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_PROTO_TLS1) && ( !defined(WBCRYPTO_MD5_C) ||     \
    !defined(WBCRYPTO_SHA1_C) )
#error "WBCRYPTO_SSL_PROTO_TLS1 defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_PROTO_TLS1_1) && ( !defined(WBCRYPTO_MD5_C) ||     \
    !defined(WBCRYPTO_SHA1_C) )
#error "WBCRYPTO_SSL_PROTO_TLS1_1 defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_PROTO_TLS1_2) && ( !defined(WBCRYPTO_SHA1_C) &&     \
    !defined(WBCRYPTO_SHA256_C) && !defined(WBCRYPTO_SHA512_C) )
#error "WBCRYPTO_SSL_PROTO_TLS1_2 defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_PROTO_DTLS)     && \
    !defined(WBCRYPTO_SSL_PROTO_TLS1_1)  && \
    !defined(WBCRYPTO_SSL_PROTO_TLS1_2)
#error "WBCRYPTO_SSL_PROTO_DTLS defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_CLI_C) && !defined(WBCRYPTO_SSL_TLS_C)
#error "WBCRYPTO_SSL_CLI_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_TLS_C) && ( !defined(WBCRYPTO_CIPHER_C) ||     \
    !defined(WBCRYPTO_MD_C) )
#error "WBCRYPTO_SSL_TLS_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_SRV_C) && !defined(WBCRYPTO_SSL_TLS_C)
#error "WBCRYPTO_SSL_SRV_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_TLS_C) && (!defined(WBCRYPTO_SSL_PROTO_SSL3) && \
    !defined(WBCRYPTO_SSL_PROTO_TLS1) && !defined(WBCRYPTO_SSL_PROTO_TLS1_1) && \
    !defined(WBCRYPTO_SSL_PROTO_TLS1_2))
#error "WBCRYPTO_SSL_TLS_C defined, but no protocols are active"
#endif

#if defined(WBCRYPTO_SSL_TLS_C) && (defined(WBCRYPTO_SSL_PROTO_SSL3) && \
    defined(WBCRYPTO_SSL_PROTO_TLS1_1) && !defined(WBCRYPTO_SSL_PROTO_TLS1))
#error "Illegal protocol selection"
#endif

#if defined(WBCRYPTO_SSL_TLS_C) && (defined(WBCRYPTO_SSL_PROTO_TLS1) && \
    defined(WBCRYPTO_SSL_PROTO_TLS1_2) && !defined(WBCRYPTO_SSL_PROTO_TLS1_1))
#error "Illegal protocol selection"
#endif

#if defined(WBCRYPTO_SSL_TLS_C) && (defined(WBCRYPTO_SSL_PROTO_SSL3) && \
    defined(WBCRYPTO_SSL_PROTO_TLS1_2) && (!defined(WBCRYPTO_SSL_PROTO_TLS1) || \
    !defined(WBCRYPTO_SSL_PROTO_TLS1_1)))
#error "Illegal protocol selection"
#endif

#if defined(WBCRYPTO_SSL_DTLS_HELLO_VERIFY) && !defined(WBCRYPTO_SSL_PROTO_DTLS)
#error "WBCRYPTO_SSL_DTLS_HELLO_VERIFY  defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_DTLS_CLIENT_PORT_REUSE) && \
    !defined(WBCRYPTO_SSL_DTLS_HELLO_VERIFY)
#error "WBCRYPTO_SSL_DTLS_CLIENT_PORT_REUSE  defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_DTLS_ANTI_REPLAY) &&                              \
    ( !defined(WBCRYPTO_SSL_TLS_C) || !defined(WBCRYPTO_SSL_PROTO_DTLS) )
#error "WBCRYPTO_SSL_DTLS_ANTI_REPLAY  defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_DTLS_BADMAC_LIMIT) &&                              \
    ( !defined(WBCRYPTO_SSL_TLS_C) || !defined(WBCRYPTO_SSL_PROTO_DTLS) )
#error "WBCRYPTO_SSL_DTLS_BADMAC_LIMIT  defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_ENCRYPT_THEN_MAC) &&   \
    !defined(WBCRYPTO_SSL_PROTO_TLS1)   &&      \
    !defined(WBCRYPTO_SSL_PROTO_TLS1_1) &&      \
    !defined(WBCRYPTO_SSL_PROTO_TLS1_2)
#error "WBCRYPTO_SSL_ENCRYPT_THEN_MAC defined, but not all prerequsites"
#endif

#if defined(WBCRYPTO_SSL_EXTENDED_MASTER_SECRET) && \
    !defined(WBCRYPTO_SSL_PROTO_TLS1)   &&          \
    !defined(WBCRYPTO_SSL_PROTO_TLS1_1) &&          \
    !defined(WBCRYPTO_SSL_PROTO_TLS1_2)
#error "WBCRYPTO_SSL_EXTENDED_MASTER_SECRET defined, but not all prerequsites"
#endif

#if defined(WBCRYPTO_SSL_TICKET_C) && !defined(WBCRYPTO_CIPHER_C)
#error "WBCRYPTO_SSL_TICKET_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_CBC_RECORD_SPLITTING) && \
    !defined(WBCRYPTO_SSL_PROTO_SSL3) && !defined(WBCRYPTO_SSL_PROTO_TLS1)
#error "WBCRYPTO_SSL_CBC_RECORD_SPLITTING defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_SSL_SERVER_NAME_INDICATION) && \
        !defined(WBCRYPTO_X509_CRT_PARSE_C)
#error "WBCRYPTO_SSL_SERVER_NAME_INDICATION defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_THREADING_PTHREAD)
#if !defined(WBCRYPTO_THREADING_C) || defined(WBCRYPTO_THREADING_IMPL)
#error "WBCRYPTO_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define WBCRYPTO_THREADING_IMPL
#endif

#if defined(WBCRYPTO_THREADING_ALT)
#if !defined(WBCRYPTO_THREADING_C) || defined(WBCRYPTO_THREADING_IMPL)
#error "WBCRYPTO_THREADING_ALT defined, but not all prerequisites"
#endif
#define WBCRYPTO_THREADING_IMPL
#endif

#if defined(WBCRYPTO_THREADING_C) && !defined(WBCRYPTO_THREADING_IMPL)
#error "WBCRYPTO_THREADING_C defined, single threading implementation required"
#endif
#undef WBCRYPTO_THREADING_IMPL

#if defined(WBCRYPTO_VERSION_FEATURES) && !defined(WBCRYPTO_VERSION_C)
#error "WBCRYPTO_VERSION_FEATURES defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_X509_USE_C) && ( !defined(WBCRYPTO_BIGNUM_C) ||  \
    !defined(WBCRYPTO_OID_C) || !defined(WBCRYPTO_ASN1_PARSE_C) ||      \
    !defined(WBCRYPTO_PK_PARSE_C) )
#error "WBCRYPTO_X509_USE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_X509_CREATE_C) && ( !defined(WBCRYPTO_BIGNUM_C) ||  \
    !defined(WBCRYPTO_OID_C) || !defined(WBCRYPTO_ASN1_WRITE_C) ||       \
    !defined(WBCRYPTO_PK_WRITE_C) )
#error "WBCRYPTO_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_X509_CRT_PARSE_C) && ( !defined(WBCRYPTO_X509_USE_C) )
#error "WBCRYPTO_X509_CRT_PARSE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_X509_CRL_PARSE_C) && ( !defined(WBCRYPTO_X509_USE_C) )
#error "WBCRYPTO_X509_CRL_PARSE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_X509_CSR_PARSE_C) && ( !defined(WBCRYPTO_X509_USE_C) )
#error "WBCRYPTO_X509_CSR_PARSE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_X509_CRT_WRITE_C) && ( !defined(WBCRYPTO_X509_CREATE_C) )
#error "WBCRYPTO_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_X509_CSR_WRITE_C) && ( !defined(WBCRYPTO_X509_CREATE_C) )
#error "WBCRYPTO_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#if defined(WBCRYPTO_HAVE_INT32) && defined(WBCRYPTO_HAVE_INT64)
#error "WBCRYPTO_HAVE_INT32 and WBCRYPTO_HAVE_INT64 cannot be defined simultaneously"
#endif /* WBCRYPTO_HAVE_INT32 && WBCRYPTO_HAVE_INT64 */

#if ( defined(WBCRYPTO_HAVE_INT32) || defined(WBCRYPTO_HAVE_INT64) ) && \
    defined(WBCRYPTO_HAVE_ASM)
#error "WBCRYPTO_HAVE_INT32/WBCRYPTO_HAVE_INT64 and WBCRYPTO_HAVE_ASM cannot be defined simultaneously"
#endif /* (WBCRYPTO_HAVE_INT32 || WBCRYPTO_HAVE_INT64) && WBCRYPTO_HAVE_ASM */

/*
 * Avoid warning from -pedantic. This is a convenient place for this
 * workaround since this is included by every single file before the
 * #if defined(WBCRYPTO_xxx_C) that results in emtpy translation units.
 */
typedef int wbcrypto_iso_c_forbids_empty_translation_units;

#endif /* WBCRYPTO_CHECK_CONFIG_H */
