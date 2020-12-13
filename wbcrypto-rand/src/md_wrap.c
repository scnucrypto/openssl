/**
 * \file md_wrap.c
 *
 * \brief Generic message digest wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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

#include <WbcryptoRand/config.h>

#if defined(WBCRYPTO_MD_C)

#include <WbcryptoRand/md_internal.h>


#if defined(WBCRYPTO_SM3_C)
#include <WbcryptoRand/sm3.h>
#endif

#if defined(WBCRYPTO_PLATFORM_C)
#include <WbcryptoRand/platform.h>
#else
#include <stdlib.h>
#define wbcrypto_calloc    calloc
#define wbcrypto_free       free
#endif

#if defined(WBCRYPTO_MD2_C)

static void md2_starts_wrap( void *ctx )
{
    wbcrypto_md2_starts( (wbcrypto_md2_context *) ctx );
}

static void md2_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    wbcrypto_md2_update( (wbcrypto_md2_context *) ctx, input, ilen );
}

static void md2_finish_wrap( void *ctx, unsigned char *output )
{
    wbcrypto_md2_finish( (wbcrypto_md2_context *) ctx, output );
}

static void *md2_ctx_alloc( void )
{
    void *ctx = wbcrypto_calloc( 1, sizeof( wbcrypto_md2_context ) );

    if( ctx != NULL )
        wbcrypto_md2_init( (wbcrypto_md2_context *) ctx );

    return( ctx );
}

static void md2_ctx_free( void *ctx )
{
    wbcrypto_md2_free( (wbcrypto_md2_context *) ctx );
    wbcrypto_free( ctx );
}

static void md2_clone_wrap( void *dst, const void *src )
{
    wbcrypto_md2_clone( (wbcrypto_md2_context *) dst,
                 (const wbcrypto_md2_context *) src );
}

static void md2_process_wrap( void *ctx, const unsigned char *data )
{
    ((void) data);

    wbcrypto_md2_process( (wbcrypto_md2_context *) ctx );
}

const wbcrypto_md_info_t wbcrypto_md2_info = {
    WBCRYPTO_MD_MD2,
    "MD2",
    16,
    16,
    md2_starts_wrap,
    md2_update_wrap,
    md2_finish_wrap,
    wbcrypto_md2,
    md2_ctx_alloc,
    md2_ctx_free,
    md2_clone_wrap,
    md2_process_wrap,
};

#endif /* WBCRYPTO_MD2_C */

#if defined(WBCRYPTO_MD4_C)

static void md4_starts_wrap( void *ctx )
{
    wbcrypto_md4_starts( (wbcrypto_md4_context *) ctx );
}

static void md4_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    wbcrypto_md4_update( (wbcrypto_md4_context *) ctx, input, ilen );
}

static void md4_finish_wrap( void *ctx, unsigned char *output )
{
    wbcrypto_md4_finish( (wbcrypto_md4_context *) ctx, output );
}

static void *md4_ctx_alloc( void )
{
    void *ctx = wbcrypto_calloc( 1, sizeof( wbcrypto_md4_context ) );

    if( ctx != NULL )
        wbcrypto_md4_init( (wbcrypto_md4_context *) ctx );

    return( ctx );
}

static void md4_ctx_free( void *ctx )
{
    wbcrypto_md4_free( (wbcrypto_md4_context *) ctx );
    wbcrypto_free( ctx );
}

static void md4_clone_wrap( void *dst, const void *src )
{
    wbcrypto_md4_clone( (wbcrypto_md4_context *) dst,
                 (const wbcrypto_md4_context *) src );
}

static void md4_process_wrap( void *ctx, const unsigned char *data )
{
    wbcrypto_md4_process( (wbcrypto_md4_context *) ctx, data );
}

const wbcrypto_md_info_t wbcrypto_md4_info = {
    WBCRYPTO_MD_MD4,
    "MD4",
    16,
    64,
    md4_starts_wrap,
    md4_update_wrap,
    md4_finish_wrap,
    wbcrypto_md4,
    md4_ctx_alloc,
    md4_ctx_free,
    md4_clone_wrap,
    md4_process_wrap,
};

#endif /* WBCRYPTO_MD4_C */

#if defined(WBCRYPTO_MD5_C)

static void md5_starts_wrap( void *ctx )
{
    wbcrypto_md5_starts( (wbcrypto_md5_context *) ctx );
}

static void md5_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    wbcrypto_md5_update( (wbcrypto_md5_context *) ctx, input, ilen );
}

static void md5_finish_wrap( void *ctx, unsigned char *output )
{
    wbcrypto_md5_finish( (wbcrypto_md5_context *) ctx, output );
}

static void *md5_ctx_alloc( void )
{
    void *ctx = wbcrypto_calloc( 1, sizeof( wbcrypto_md5_context ) );

    if( ctx != NULL )
        wbcrypto_md5_init( (wbcrypto_md5_context *) ctx );

    return( ctx );
}

static void md5_ctx_free( void *ctx )
{
    wbcrypto_md5_free( (wbcrypto_md5_context *) ctx );
    wbcrypto_free( ctx );
}

static void md5_clone_wrap( void *dst, const void *src )
{
    wbcrypto_md5_clone( (wbcrypto_md5_context *) dst,
                 (const wbcrypto_md5_context *) src );
}

static void md5_process_wrap( void *ctx, const unsigned char *data )
{
    wbcrypto_md5_process( (wbcrypto_md5_context *) ctx, data );
}

const wbcrypto_md_info_t wbcrypto_md5_info = {
    WBCRYPTO_MD_MD5,
    "MD5",
    16,
    64,
    md5_starts_wrap,
    md5_update_wrap,
    md5_finish_wrap,
    wbcrypto_md5,
    md5_ctx_alloc,
    md5_ctx_free,
    md5_clone_wrap,
    md5_process_wrap,
};

#endif /* WBCRYPTO_MD5_C */

#if defined(WBCRYPTO_RIPEMD160_C)

static void ripemd160_starts_wrap( void *ctx )
{
    wbcrypto_ripemd160_starts( (wbcrypto_ripemd160_context *) ctx );
}

static void ripemd160_update_wrap( void *ctx, const unsigned char *input,
                                   size_t ilen )
{
    wbcrypto_ripemd160_update( (wbcrypto_ripemd160_context *) ctx, input, ilen );
}

static void ripemd160_finish_wrap( void *ctx, unsigned char *output )
{
    wbcrypto_ripemd160_finish( (wbcrypto_ripemd160_context *) ctx, output );
}

static void *ripemd160_ctx_alloc( void )
{
    void *ctx = wbcrypto_calloc( 1, sizeof( wbcrypto_ripemd160_context ) );

    if( ctx != NULL )
        wbcrypto_ripemd160_init( (wbcrypto_ripemd160_context *) ctx );

    return( ctx );
}

static void ripemd160_ctx_free( void *ctx )
{
    wbcrypto_ripemd160_free( (wbcrypto_ripemd160_context *) ctx );
    wbcrypto_free( ctx );
}

static void ripemd160_clone_wrap( void *dst, const void *src )
{
    wbcrypto_ripemd160_clone( (wbcrypto_ripemd160_context *) dst,
                       (const wbcrypto_ripemd160_context *) src );
}

static void ripemd160_process_wrap( void *ctx, const unsigned char *data )
{
    wbcrypto_ripemd160_process( (wbcrypto_ripemd160_context *) ctx, data );
}

const wbcrypto_md_info_t wbcrypto_ripemd160_info = {
    WBCRYPTO_MD_RIPEMD160,
    "RIPEMD160",
    20,
    64,
    ripemd160_starts_wrap,
    ripemd160_update_wrap,
    ripemd160_finish_wrap,
    wbcrypto_ripemd160,
    ripemd160_ctx_alloc,
    ripemd160_ctx_free,
    ripemd160_clone_wrap,
    ripemd160_process_wrap,
};

#endif /* WBCRYPTO_RIPEMD160_C */

#if defined(WBCRYPTO_SHA1_C)

static void sha1_starts_wrap( void *ctx )
{
    wbcrypto_sha1_starts( (wbcrypto_sha1_context *) ctx );
}

static void sha1_update_wrap( void *ctx, const unsigned char *input,
                              size_t ilen )
{
    wbcrypto_sha1_update( (wbcrypto_sha1_context *) ctx, input, ilen );
}

static void sha1_finish_wrap( void *ctx, unsigned char *output )
{
    wbcrypto_sha1_finish( (wbcrypto_sha1_context *) ctx, output );
}

static void *sha1_ctx_alloc( void )
{
    void *ctx = wbcrypto_calloc( 1, sizeof( wbcrypto_sha1_context ) );

    if( ctx != NULL )
        wbcrypto_sha1_init( (wbcrypto_sha1_context *) ctx );

    return( ctx );
}

static void sha1_clone_wrap( void *dst, const void *src )
{
    wbcrypto_sha1_clone( (wbcrypto_sha1_context *) dst,
                  (const wbcrypto_sha1_context *) src );
}

static void sha1_ctx_free( void *ctx )
{
    wbcrypto_sha1_free( (wbcrypto_sha1_context *) ctx );
    wbcrypto_free( ctx );
}

static void sha1_process_wrap( void *ctx, const unsigned char *data )
{
    wbcrypto_sha1_process( (wbcrypto_sha1_context *) ctx, data );
}

const wbcrypto_md_info_t wbcrypto_sha1_info = {
    WBCRYPTO_MD_SHA1,
    "SHA1",
    20,
    64,
    sha1_starts_wrap,
    sha1_update_wrap,
    sha1_finish_wrap,
    wbcrypto_sha1,
    sha1_ctx_alloc,
    sha1_ctx_free,
    sha1_clone_wrap,
    sha1_process_wrap,
};

#endif /* WBCRYPTO_SHA1_C */

/*
 * Wrappers for generic message digests
 */
#if defined(WBCRYPTO_SHA256_C)

static void sha224_starts_wrap( void *ctx )
{
    wbcrypto_sha256_starts( (wbcrypto_sha256_context *) ctx, 1 );
}

static void sha224_update_wrap( void *ctx, const unsigned char *input,
                                size_t ilen )
{
    wbcrypto_sha256_update( (wbcrypto_sha256_context *) ctx, input, ilen );
}

static void sha224_finish_wrap( void *ctx, unsigned char *output )
{
    wbcrypto_sha256_finish( (wbcrypto_sha256_context *) ctx, output );
}

static void sha224_wrap( const unsigned char *input, size_t ilen,
                    unsigned char *output )
{
    wbcrypto_sha256( input, ilen, output, 1 );
}

static void *sha224_ctx_alloc( void )
{
    void *ctx = wbcrypto_calloc( 1, sizeof( wbcrypto_sha256_context ) );

    if( ctx != NULL )
        wbcrypto_sha256_init( (wbcrypto_sha256_context *) ctx );

    return( ctx );
}

static void sha224_ctx_free( void *ctx )
{
    wbcrypto_sha256_free( (wbcrypto_sha256_context *) ctx );
    wbcrypto_free( ctx );
}

static void sha224_clone_wrap( void *dst, const void *src )
{
    wbcrypto_sha256_clone( (wbcrypto_sha256_context *) dst,
                    (const wbcrypto_sha256_context *) src );
}

static void sha224_process_wrap( void *ctx, const unsigned char *data )
{
    wbcrypto_sha256_process( (wbcrypto_sha256_context *) ctx, data );
}

const wbcrypto_md_info_t wbcrypto_sha224_info = {
    WBCRYPTO_MD_SHA224,
    "SHA224",
    28,
    64,
    sha224_starts_wrap,
    sha224_update_wrap,
    sha224_finish_wrap,
    sha224_wrap,
    sha224_ctx_alloc,
    sha224_ctx_free,
    sha224_clone_wrap,
    sha224_process_wrap,
};

static void sha256_starts_wrap( void *ctx )
{
    wbcrypto_sha256_starts( (wbcrypto_sha256_context *) ctx, 0 );
}

static void sha256_wrap( const unsigned char *input, size_t ilen,
                    unsigned char *output )
{
    wbcrypto_sha256( input, ilen, output, 0 );
}

const wbcrypto_md_info_t wbcrypto_sha256_info = {
    WBCRYPTO_MD_SHA256,
    "SHA256",
    32,
    64,
    sha256_starts_wrap,
    sha224_update_wrap,
    sha224_finish_wrap,
    sha256_wrap,
    sha224_ctx_alloc,
    sha224_ctx_free,
    sha224_clone_wrap,
    sha224_process_wrap,
};

#endif /* WBCRYPTO_SHA256_C */

#if defined(WBCRYPTO_SHA512_C)

static void sha384_starts_wrap( void *ctx )
{
    wbcrypto_sha512_starts( (wbcrypto_sha512_context *) ctx, 1 );
}

static void sha384_update_wrap( void *ctx, const unsigned char *input,
                                size_t ilen )
{
    wbcrypto_sha512_update( (wbcrypto_sha512_context *) ctx, input, ilen );
}

static void sha384_finish_wrap( void *ctx, unsigned char *output )
{
    wbcrypto_sha512_finish( (wbcrypto_sha512_context *) ctx, output );
}

static void sha384_wrap( const unsigned char *input, size_t ilen,
                    unsigned char *output )
{
    wbcrypto_sha512( input, ilen, output, 1 );
}

static void *sha384_ctx_alloc( void )
{
    void *ctx = wbcrypto_calloc( 1, sizeof( wbcrypto_sha512_context ) );

    if( ctx != NULL )
        wbcrypto_sha512_init( (wbcrypto_sha512_context *) ctx );

    return( ctx );
}

static void sha384_ctx_free( void *ctx )
{
    wbcrypto_sha512_free( (wbcrypto_sha512_context *) ctx );
    wbcrypto_free( ctx );
}

static void sha384_clone_wrap( void *dst, const void *src )
{
    wbcrypto_sha512_clone( (wbcrypto_sha512_context *) dst,
                    (const wbcrypto_sha512_context *) src );
}

static void sha384_process_wrap( void *ctx, const unsigned char *data )
{
    wbcrypto_sha512_process( (wbcrypto_sha512_context *) ctx, data );
}

const wbcrypto_md_info_t wbcrypto_sha384_info = {
    WBCRYPTO_MD_SHA384,
    "SHA384",
    48,
    128,
    sha384_starts_wrap,
    sha384_update_wrap,
    sha384_finish_wrap,
    sha384_wrap,
    sha384_ctx_alloc,
    sha384_ctx_free,
    sha384_clone_wrap,
    sha384_process_wrap,
};

static void sha512_starts_wrap( void *ctx )
{
    wbcrypto_sha512_starts( (wbcrypto_sha512_context *) ctx, 0 );
}

static void sha512_wrap( const unsigned char *input, size_t ilen,
                    unsigned char *output )
{
    wbcrypto_sha512( input, ilen, output, 0 );
}

const wbcrypto_md_info_t wbcrypto_sha512_info = {
    WBCRYPTO_MD_SHA512,
    "SHA512",
    64,
    128,
    sha512_starts_wrap,
    sha384_update_wrap,
    sha384_finish_wrap,
    sha512_wrap,
    sha384_ctx_alloc,
    sha384_ctx_free,
    sha384_clone_wrap,
    sha384_process_wrap,
};

#endif /* WBCRYPTO_SHA512_C */

#if defined(WBCRYPTO_SM3_C)

static void sm3_starts_wrap(void *ctx) {
    sm3_starts((sm3_context *) ctx);
}

static void sm3_update_wrap(void *ctx, const unsigned char *input,
                            size_t ilen) {
    sm3_update((sm3_context *) ctx, input, ilen);
}

static void sm3_finish_wrap(void *ctx, unsigned char *output) {
    sm3_finish((sm3_context *) ctx, output);
}

static void sm3_wrap(const unsigned char *input, size_t ilen,
                     unsigned char *output) {
    sm3(input, ilen, output);
}

static void *sm3_ctx_alloc(void) {
    void *ctx = wbcrypto_calloc(1, sizeof(sm3_context));

    if (ctx != NULL)
        sm3_init((sm3_context *) ctx);

    return (ctx);
}

static void sm3_ctx_free(void *ctx) {
    sm3_free((sm3_context *) ctx);
    wbcrypto_free(ctx);
}

static void sm3_clone_wrap(void *dst, const void *src) {
    sm3_clone((sm3_context *) dst,
                         (const sm3_context *) src);
}

static void sm3_process_wrap(void *ctx, const unsigned char *data) {
    sm3_process((sm3_context *) ctx, data);
}


const wbcrypto_md_info_t sm3_info = {
        MD_SM3,
        "SM3",
        32,
        64,
        sm3_starts_wrap,
        sm3_update_wrap,
        sm3_finish_wrap,
        sm3_wrap,
        sm3_ctx_alloc,
        sm3_ctx_free,
        sm3_clone_wrap,
        sm3_process_wrap,
};

#endif /* WBCRYPTO_SM3_C */


#endif /* WBCRYPTO_MD_C */
