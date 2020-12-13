/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#ifndef WBCRYPTO_CONFIG_H
#define WBCRYPTO_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

// WBCRYPTO_PLATFORM_C is required on Windows
#define WBCRYPTO_PLATFORM_C

// ALLOW FS
#define WBCRYPTO_FS_IO

// ENABLE MD
#define WBCRYPTO_MD_C

// ENABLE SM3
#define WBCRYPTO_SM3_C

// ENABLE HMAC_DRBG
#define WBCRYPTO_HMAC_DRBG_C

#include <WbcryptoRand/check_config.h>

// Lib version
#define WBCRYPTO_RAND_VER_WBCRYPTO

// Hash Algorithm
#define WBCRYPTO_RAND_HASH_ALG_SM3

#define UNIT_TEST

#endif /* WBCRYPTO_CONFIG_H */
