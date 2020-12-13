/**
 * \file wbcrypto_md.c
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

#if !defined(WBCRYPTO_CONFIG_FILE)
#include <WbcryptoRand/config.h>
#else
#include WBCRYPTO_CONFIG_FILE
#endif

#if defined(WBCRYPTO_MD_C)

#include <WbcryptoRand/md.h>
#include <WbcryptoRand/md_internal.h>

#if defined(WBCRYPTO_PLATFORM_C)
#include <WbcryptoRand/platform.h>
#else
#include <stdlib.h>
#define wbcrypto_calloc    calloc
#define wbcrypto_free       free
#endif

#include <string.h>

#if defined(WBCRYPTO_FS_IO)
#include <stdio.h>
#endif

/* Implementation that should never be optimized out by the compiler */
static void wbcrypto_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {

#if defined(WBCRYPTO_SHA512_C)
        WBCRYPTO_MD_SHA512,
        WBCRYPTO_MD_SHA384,
#endif

#if defined(WBCRYPTO_SHA256_C)
        WBCRYPTO_MD_SHA256,
        WBCRYPTO_MD_SHA224,
#endif

#if defined(WBCRYPTO_SHA1_C)
        WBCRYPTO_MD_SHA1,
#endif

#if defined(WBCRYPTO_RIPEMD160_C)
        WBCRYPTO_MD_RIPEMD160,
#endif

#if defined(WBCRYPTO_MD5_C)
        WBCRYPTO_MD_MD5,
#endif

		  MD_SM3,
#if defined(WBCRYPTO_MD4_C)
        WBCRYPTO_MD_MD4,
#endif

#if defined(WBCRYPTO_MD2_C)
        WBCRYPTO_MD_MD2,
#endif

        WBCRYPTO_MD_NONE
};

const int *wbcrypto_md_list( void )
{
    return( supported_digests );
}

const wbcrypto_md_info_t *wbcrypto_md_info_from_string( const char *md_name )
{
    if( NULL == md_name )
        return( NULL );

    /* Get the appropriate digest information */
#if defined(WBCRYPTO_MD2_C)
    if( !strcmp( "MD2", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_MD2 );
#endif
#if defined(WBCRYPTO_MD4_C)
    if( !strcmp( "MD4", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_MD4 );
#endif
#if defined(WBCRYPTO_MD5_C)
    if( !strcmp( "MD5", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_MD5 );
#endif
#if defined(WBCRYPTO_RIPEMD160_C)
    if( !strcmp( "RIPEMD160", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_RIPEMD160 );
#endif
#if defined(WBCRYPTO_SHA1_C)
    if( !strcmp( "SHA1", md_name ) || !strcmp( "SHA", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_SHA1 );
#endif
#if defined(WBCRYPTO_SHA256_C)
    if( !strcmp( "SHA224", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_SHA224 );
    if( !strcmp( "SHA256", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_SHA256 );
#endif
#if defined(WBCRYPTO_SHA512_C)
    if( !strcmp( "SHA384", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_SHA384 );
    if( !strcmp( "SHA512", md_name ) )
        return wbcrypto_md_info_from_type( WBCRYPTO_MD_SHA512 );
#endif
    if (!strcmp("SM3", md_name))
        return wbcrypto_md_info_from_type(MD_SM3);
    return( NULL );
}

const wbcrypto_md_info_t *wbcrypto_md_info_from_type( wbcrypto_md_type_t md_type )
{
    switch( md_type )
    {
#if defined(WBCRYPTO_MD2_C)
        case WBCRYPTO_MD_MD2:
            return( &wbcrypto_md2_info );
#endif
#if defined(WBCRYPTO_MD4_C)
        case WBCRYPTO_MD_MD4:
            return( &wbcrypto_md4_info );
#endif
#if defined(WBCRYPTO_MD5_C)
        case WBCRYPTO_MD_MD5:
            return( &wbcrypto_md5_info );
#endif
#if defined(WBCRYPTO_RIPEMD160_C)
        case WBCRYPTO_MD_RIPEMD160:
            return( &wbcrypto_ripemd160_info );
#endif
#if defined(WBCRYPTO_SHA1_C)
        case WBCRYPTO_MD_SHA1:
            return( &wbcrypto_sha1_info );
#endif
#if defined(WBCRYPTO_SHA256_C)
        case WBCRYPTO_MD_SHA224:
            return( &wbcrypto_sha224_info );
        case WBCRYPTO_MD_SHA256:
            return( &wbcrypto_sha256_info );
#endif
#if defined(WBCRYPTO_SHA512_C)
        case WBCRYPTO_MD_SHA384:
            return( &wbcrypto_sha384_info );
        case WBCRYPTO_MD_SHA512:
            return( &wbcrypto_sha512_info );
#endif
        case MD_SM3:
                return (&sm3_info);
        default:
            return( NULL );
    }
}

void wbcrypto_md_init( wbcrypto_md_context_t *ctx )
{
    memset( ctx, 0, sizeof( wbcrypto_md_context_t ) );
}

void wbcrypto_md_free( wbcrypto_md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return;

    if( ctx->md_ctx != NULL )
        ctx->md_info->ctx_free_func( ctx->md_ctx );

    if( ctx->hmac_ctx != NULL )
    {
        wbcrypto_zeroize( ctx->hmac_ctx, 2 * ctx->md_info->block_size );
        wbcrypto_free( ctx->hmac_ctx );
    }

    wbcrypto_zeroize( ctx, sizeof( wbcrypto_md_context_t ) );
}

int wbcrypto_md_clone( wbcrypto_md_context_t *dst,
                      const wbcrypto_md_context_t *src )
{
    if( dst == NULL || dst->md_info == NULL ||
        src == NULL || src->md_info == NULL ||
        dst->md_info != src->md_info )
    {
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );
    }

    dst->md_info->clone_func( dst->md_ctx, src->md_ctx );

    return( 0 );
}

#if ! defined(WBCRYPTO_DEPRECATED_REMOVED)
int wbcrypto_md_init_ctx( wbcrypto_md_context_t *ctx, const wbcrypto_md_info_t *md_info )
{
    return wbcrypto_md_setup( ctx, md_info, 1 );
}
#endif

int wbcrypto_md_setup( wbcrypto_md_context_t *ctx, const wbcrypto_md_info_t *md_info, int hmac )
{
    if( md_info == NULL || ctx == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    if( ( ctx->md_ctx = md_info->ctx_alloc_func() ) == NULL )
        return( WBCRYPTO_ERR_MD_ALLOC_FAILED );

    if( hmac != 0 )
    {
        ctx->hmac_ctx = wbcrypto_calloc( 2, md_info->block_size );
        if( ctx->hmac_ctx == NULL )
        {
            md_info->ctx_free_func( ctx->md_ctx );
            return( WBCRYPTO_ERR_MD_ALLOC_FAILED );
        }
    }

    ctx->md_info = md_info;

    return( 0 );
}

int wbcrypto_md_starts( wbcrypto_md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->starts_func( ctx->md_ctx );

    return( 0 );
}

int wbcrypto_md_update( wbcrypto_md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->update_func( ctx->md_ctx, input, ilen );

    return( 0 );
}

int wbcrypto_md_finish( wbcrypto_md_context_t *ctx, unsigned char *output )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->finish_func( ctx->md_ctx, output );

    return( 0 );
}

int wbcrypto_md( const wbcrypto_md_info_t *md_info, const unsigned char *input, size_t ilen,
            unsigned char *output )
{
    if( md_info == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    md_info->digest_func( input, ilen, output );

    return( 0 );
}

#if defined(WBCRYPTO_FS_IO)
int wbcrypto_md_file( const wbcrypto_md_info_t *md_info, const char *path, unsigned char *output )
{
    int ret;
    FILE *f;
    size_t n;
    wbcrypto_md_context_t ctx;
    unsigned char buf[1024];

    if( md_info == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( WBCRYPTO_ERR_MD_FILE_IO_ERROR );

    wbcrypto_md_init( &ctx );

    if( ( ret = wbcrypto_md_setup( &ctx, md_info, 0 ) ) != 0 )
        goto cleanup;

    md_info->starts_func( ctx.md_ctx );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        md_info->update_func( ctx.md_ctx, buf, n );

    if( ferror( f ) != 0 )
    {
        ret = WBCRYPTO_ERR_MD_FILE_IO_ERROR;
        goto cleanup;
    }

    md_info->finish_func( ctx.md_ctx, output );

cleanup:
    fclose( f );
    wbcrypto_md_free( &ctx );

    return( ret );
}
#endif /* WBCRYPTO_FS_IO */

int wbcrypto_md_hmac_starts( wbcrypto_md_context_t *ctx, const unsigned char *key, size_t keylen )
{
    unsigned char sum[WBCRYPTO_MD_MAX_SIZE];
    unsigned char *ipad, *opad;
    size_t i;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    if( keylen > (size_t) ctx->md_info->block_size )
    {
        ctx->md_info->starts_func( ctx->md_ctx );
        ctx->md_info->update_func( ctx->md_ctx, key, keylen );
        ctx->md_info->finish_func( ctx->md_ctx, sum );

        keylen = ctx->md_info->size;
        key = sum;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;
    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    memset( ipad, 0x36, ctx->md_info->block_size );
    memset( opad, 0x5C, ctx->md_info->block_size );

    for( i = 0; i < keylen; i++ )
    {
        ipad[i] = (unsigned char)( ipad[i] ^ key[i] );
        opad[i] = (unsigned char)( opad[i] ^ key[i] );
    }

    wbcrypto_zeroize( sum, sizeof( sum ) );

    ctx->md_info->starts_func( ctx->md_ctx );
    ctx->md_info->update_func( ctx->md_ctx, ipad, ctx->md_info->block_size );

    return( 0 );
}

int wbcrypto_md_hmac_update( wbcrypto_md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->update_func( ctx->md_ctx, input, ilen );

    return( 0 );
}

int wbcrypto_md_hmac_finish( wbcrypto_md_context_t *ctx, unsigned char *output )
{
    unsigned char tmp[WBCRYPTO_MD_MAX_SIZE];
    unsigned char *opad;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    ctx->md_info->finish_func( ctx->md_ctx, tmp );
    ctx->md_info->starts_func( ctx->md_ctx );
    ctx->md_info->update_func( ctx->md_ctx, opad, ctx->md_info->block_size );
    ctx->md_info->update_func( ctx->md_ctx, tmp, ctx->md_info->size );
    ctx->md_info->finish_func( ctx->md_ctx, output );

    return( 0 );
}

int wbcrypto_md_hmac_reset( wbcrypto_md_context_t *ctx )
{
    unsigned char *ipad;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    ipad = (unsigned char *) ctx->hmac_ctx;

    ctx->md_info->starts_func( ctx->md_ctx );
    ctx->md_info->update_func( ctx->md_ctx, ipad, ctx->md_info->block_size );

    return( 0 );
}

int wbcrypto_md_hmac( const wbcrypto_md_info_t *md_info, const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char *output )
{
    wbcrypto_md_context_t ctx;
    int ret;

    if( md_info == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    wbcrypto_md_init( &ctx );

    if( ( ret = wbcrypto_md_setup( &ctx, md_info, 1 ) ) != 0 )
        return( ret );

    wbcrypto_md_hmac_starts( &ctx, key, keylen );
    wbcrypto_md_hmac_update( &ctx, input, ilen );
    wbcrypto_md_hmac_finish( &ctx, output );

    wbcrypto_md_free( &ctx );

    return( 0 );
}

int wbcrypto_md_process( wbcrypto_md_context_t *ctx, const unsigned char *data )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( WBCRYPTO_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->process_func( ctx->md_ctx, data );

    return( 0 );
}

unsigned char wbcrypto_md_get_size( const wbcrypto_md_info_t *md_info )
{
    if( md_info == NULL )
        return( 0 );

    return md_info->size;
}

wbcrypto_md_type_t wbcrypto_md_get_type( const wbcrypto_md_info_t *md_info )
{
    if( md_info == NULL )
        return( WBCRYPTO_MD_NONE );

    return md_info->type;
}

const char *wbcrypto_md_get_name( const wbcrypto_md_info_t *md_info )
{
    if( md_info == NULL )
        return( NULL );

    return md_info->name;
}

#endif /* WBCRYPTO_MD_C */
