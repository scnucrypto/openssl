/**
 * \file md.h
 *
 * \brief Generic message digest wrapper
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
#ifndef WBCRYPTO_MD_H
#define WBCRYPTO_MD_H

#include <stddef.h>

#include <WbcryptoRand/config.h>

#define WBCRYPTO_ERR_MD_FEATURE_UNAVAILABLE                -0x5080  /**< The selected feature is not available. */
#define WBCRYPTO_ERR_MD_BAD_INPUT_DATA                     -0x5100  /**< Bad input parameters to function. */
#define WBCRYPTO_ERR_MD_ALLOC_FAILED                       -0x5180  /**< Failed to allocate memory. */
#define WBCRYPTO_ERR_MD_FILE_IO_ERROR                      -0x5200  /**< Opening or reading of file failed. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WBCRYPTO_MD_NONE=0,
    WBCRYPTO_MD_MD2,
    WBCRYPTO_MD_MD4,
    WBCRYPTO_MD_MD5,
    WBCRYPTO_MD_SHA1,
    WBCRYPTO_MD_SHA224,
    WBCRYPTO_MD_SHA256,
    WBCRYPTO_MD_SHA384,
    WBCRYPTO_MD_SHA512,
    WBCRYPTO_MD_RIPEMD160,
	MD_SM3,
} wbcrypto_md_type_t;

#if defined(WBCRYPTO_SHA512_C)
#define WBCRYPTO_MD_MAX_SIZE         64  /* longest known is SHA512 */
#else
#define WBCRYPTO_MD_MAX_SIZE         32  /* longest known is SHA256 or less */
#endif

/**
 * Opaque struct defined in md_internal.h
 */
typedef struct wbcrypto_md_info_t wbcrypto_md_info_t;

/**
 * Generic message digest context.
 */
typedef struct {
    /** Information about the associated message digest */
    const wbcrypto_md_info_t *md_info;

    /** Digest-specific context */
    void *md_ctx;

    /** HMAC part of the context */
    void *hmac_ctx;
} wbcrypto_md_context_t;

/**
 * \brief Returns the list of digests supported by the generic digest module.
 *
 * \return          a statically allocated array of digests, the last entry
 *                  is 0.
 */
const int *wbcrypto_md_list( void );

/**
 * \brief           Returns the message digest information associated with the
 *                  given digest name.
 *
 * \param md_name   Name of the digest to search for.
 *
 * \return          The message digest information associated with md_name or
 *                  NULL if not found.
 */
const wbcrypto_md_info_t *wbcrypto_md_info_from_string( const char *md_name );

/**
 * \brief           Returns the message digest information associated with the
 *                  given digest type.
 *
 * \param md_type   type of digest to search for.
 *
 * \return          The message digest information associated with md_type or
 *                  NULL if not found.
 */
const wbcrypto_md_info_t *wbcrypto_md_info_from_type( wbcrypto_md_type_t md_type );

/**
 * \brief           Initialize a md_context (as NONE)
 *                  This should always be called first.
 *                  Prepares the context for wbcrypto_md_setup() or wbcrypto_md_free().
 */
void wbcrypto_md_init( wbcrypto_md_context_t *ctx );

/**
 * \brief           Free and clear the internal structures of ctx.
 *                  Can be called at any time after wbcrypto_md_init().
 *                  Mandatory once wbcrypto_md_setup() has been called.
 */
void wbcrypto_md_free( wbcrypto_md_context_t *ctx );

#if ! defined(wbcrypto_DEPRECATED_REMOVED)
#if defined(wbcrypto_DEPRECATED_WARNING)
#define wbcrypto_DEPRECATED    __attribute__((deprecated))
#else
#define wbcrypto_DEPRECATED
#endif
/**
 * \brief           Select MD to use and allocate internal structures.
 *                  Should be called after wbcrypto_md_init() or wbcrypto_md_free().
 *                  Makes it necessary to call wbcrypto_md_free() later.
 *
 * \deprecated      Superseded by wbcrypto_md_setup() in 2.0.0
 *
 * \param ctx       Context to set up.
 * \param md_info   Message digest to use.
 *
 * \returns         \c 0 on success,
 *                  \c wbcrypto_ERR_MD_BAD_INPUT_DATA on parameter failure,
 *                  \c wbcrypto_ERR_MD_ALLOC_FAILED memory allocation failure.
 */
int wbcrypto_md_init_ctx( wbcrypto_md_context_t *ctx, const wbcrypto_md_info_t *md_info ) wbcrypto_DEPRECATED;
#undef wbcrypto_DEPRECATED
#endif /* wbcrypto_DEPRECATED_REMOVED */

/**
 * \brief           Select MD to use and allocate internal structures.
 *                  Should be called after wbcrypto_md_init() or wbcrypto_md_free().
 *                  Makes it necessary to call wbcrypto_md_free() later.
 *
 * \param ctx       Context to set up.
 * \param md_info   Message digest to use.
 * \param hmac      0 to save some memory if HMAC will not be used,
 *                  non-zero is HMAC is going to be used with this context.
 *
 * \returns         \c 0 on success,
 *                  \c wbcrypto_ERR_MD_BAD_INPUT_DATA on parameter failure,
 *                  \c wbcrypto_ERR_MD_ALLOC_FAILED memory allocation failure.
 */
int wbcrypto_md_setup( wbcrypto_md_context_t *ctx, const wbcrypto_md_info_t *md_info, int hmac );

/**
 * \brief           Clone the state of an MD context
 *
 * \note            The two contexts must have been setup to the same type
 *                  (cloning from SHA-256 to SHA-512 make no sense).
 *
 * \warning         Only clones the MD state, not the HMAC state! (for now)
 *
 * \param dst       The destination context
 * \param src       The context to be cloned
 *
 * \return          \c 0 on success,
 *                  \c wbcrypto_ERR_MD_BAD_INPUT_DATA on parameter failure.
 */
int wbcrypto_md_clone( wbcrypto_md_context_t *dst,
                      const wbcrypto_md_context_t *src );

/**
 * \brief           Returns the size of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          size of the message digest output in bytes.
 */
unsigned char wbcrypto_md_get_size( const wbcrypto_md_info_t *md_info );

/**
 * \brief           Returns the type of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          type of the message digest output.
 */
wbcrypto_md_type_t wbcrypto_md_get_type( const wbcrypto_md_info_t *md_info );

/**
 * \brief           Returns the name of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          name of the message digest output.
 */
const char *wbcrypto_md_get_name( const wbcrypto_md_info_t *md_info );

/**
 * \brief           Prepare the context to digest a new message.
 *                  Generally called after wbcrypto_md_setup() or wbcrypto_md_finish().
 *                  Followed by wbcrypto_md_update().
 *
 * \param ctx       generic message digest context.
 *
 * \returns         0 on success, wbcrypto_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int wbcrypto_md_starts( wbcrypto_md_context_t *ctx );

/**
 * \brief           Generic message digest process buffer
 *                  Called between wbcrypto_md_starts() and wbcrypto_md_finish().
 *                  May be called repeatedly.
 *
 * \param ctx       Generic message digest context
 * \param input     buffer holding the  datal
 * \param ilen      length of the input data
 *
 * \returns         0 on success, wbcrypto_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int wbcrypto_md_update( wbcrypto_md_context_t *ctx, const unsigned char *input, size_t ilen );

/**
 * \brief           Generic message digest final digest
 *                  Called after wbcrypto_md_update().
 *                  Usually followed by wbcrypto_md_free() or wbcrypto_md_starts().
 *
 * \param ctx       Generic message digest context
 * \param output    Generic message digest checksum result
 *
 * \returns         0 on success, wbcrypto_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int wbcrypto_md_finish( wbcrypto_md_context_t *ctx, unsigned char *output );

/**
 * \brief          Output = message_digest( input buffer )
 *
 * \param md_info  message digest info
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   Generic message digest checksum result
 *
 * \returns        0 on success, wbcrypto_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
int wbcrypto_md( const wbcrypto_md_info_t *md_info, const unsigned char *input, size_t ilen,
        unsigned char *output );

#if defined(wbcrypto_FS_IO)
/**
 * \brief          Output = message_digest( file contents )
 *
 * \param md_info  message digest info
 * \param path     input file name
 * \param output   generic message digest checksum result
 *
 * \return         0 if successful,
 *                 WBCRYPTO_ERR_MD_FILE_IO_ERROR if file input failed,
 *                 WBCRYPTO_ERR_MD_BAD_INPUT_DATA if md_info was NULL.
 */
int wbcrypto_md_file( const wbcrypto_md_info_t *md_info, const char *path,
                     unsigned char *output );
#endif /* WBCRYPTO_FS_IO */

/**
 * \brief           Set HMAC key and prepare to authenticate a new message.
 *                  Usually called after wbcrypto_md_setup() or wbcrypto_md_hmac_finish().
 *
 * \param ctx       HMAC context
 * \param key       HMAC secret key
 * \param keylen    length of the HMAC key in bytes
 *
 * \returns         0 on success, WBCRYPTO_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int wbcrypto_md_hmac_starts( wbcrypto_md_context_t *ctx, const unsigned char *key,
                    size_t keylen );

/**
 * \brief           Generic HMAC process buffer.
 *                  Called between wbcrypto_md_hmac_starts() or wbcrypto_md_hmac_reset()
 *                  and wbcrypto_md_hmac_finish().
 *                  May be called repeatedly.
 *
 * \param ctx       HMAC context
 * \param input     buffer holding the  data
 * \param ilen      length of the input data
 *
 * \returns         0 on success, WBCRYPTO_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int wbcrypto_md_hmac_update( wbcrypto_md_context_t *ctx, const unsigned char *input,
                    size_t ilen );

/**
 * \brief           Output HMAC.
 *                  Called after wbcrypto_md_hmac_update().
 *                  Usually followed by wbcrypto_md_hmac_reset(),
 *                  wbcrypto_md_hmac_starts(), or wbcrypto_md_free().
 *
 * \param ctx       HMAC context
 * \param output    Generic HMAC checksum result
 *
 * \returns         0 on success, WBCRYPTO_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int wbcrypto_md_hmac_finish( wbcrypto_md_context_t *ctx, unsigned char *output);

/**
 * \brief           Prepare to authenticate a new message with the same key.
 *                  Called after wbcrypto_md_hmac_finish() and before
 *                  wbcrypto_md_hmac_update().
 *
 * \param ctx       HMAC context to be reset
 *
 * \returns         0 on success, WBCRYPTO_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int wbcrypto_md_hmac_reset( wbcrypto_md_context_t *ctx );

/**
 * \brief          Output = Generic_HMAC( hmac key, input buffer )
 *
 * \param md_info  message digest info
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key in bytes
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   Generic HMAC-result
 *
 * \returns        0 on success, WBCRYPTO_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
int wbcrypto_md_hmac( const wbcrypto_md_info_t *md_info, const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char *output );

/* Internal use */
int wbcrypto_md_process( wbcrypto_md_context_t *ctx, const unsigned char *data );

#ifdef __cplusplus
}
#endif

#endif /* WBCRYPTO_MD_H */
