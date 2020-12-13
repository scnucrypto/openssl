/**
 * \file platform.h
 *
 * \brief mbed TLS Platform abstraction layer
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
#ifndef WBCRYPTO_PLATFORM_H
#define WBCRYPTO_PLATFORM_H

#if !defined(WBCRYPTO_CONFIG_FILE)
#include <WbcryptoRand/config.h>
#else
#include WBCRYPTO_CONFIG_FILE
#endif


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(WBCRYPTO_PLATFORM_NO_STD_FUNCTIONS)
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#if !defined(WBCRYPTO_PLATFORM_STD_SNPRINTF)
#if defined(_WIN32)
#define WBCRYPTO_PLATFORM_STD_SNPRINTF   wbcrypto_platform_win32_snprintf /**< Default snprintf to use  */
#else
#define WBCRYPTO_PLATFORM_STD_SNPRINTF   snprintf /**< Default snprintf to use  */
#endif
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_PRINTF)
#define WBCRYPTO_PLATFORM_STD_PRINTF   printf /**< Default printf to use  */
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_FPRINTF)
#define WBCRYPTO_PLATFORM_STD_FPRINTF fprintf /**< Default fprintf to use */
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_CALLOC)
#define WBCRYPTO_PLATFORM_STD_CALLOC   calloc /**< Default allocator to use */
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_FREE)
#define WBCRYPTO_PLATFORM_STD_FREE       free /**< Default free to use */
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_EXIT)
#define WBCRYPTO_PLATFORM_STD_EXIT      exit /**< Default exit to use */
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_TIME)
#define WBCRYPTO_PLATFORM_STD_TIME       time    /**< Default time to use */
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_EXIT_SUCCESS)
#define WBCRYPTO_PLATFORM_STD_EXIT_SUCCESS  EXIT_SUCCESS /**< Default exit value to use */
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_EXIT_FAILURE)
#define WBCRYPTO_PLATFORM_STD_EXIT_FAILURE  EXIT_FAILURE /**< Default exit value to use */
#endif
#if defined(WBCRYPTO_FS_IO)
#if !defined(WBCRYPTO_PLATFORM_STD_NV_SEED_READ)
#define WBCRYPTO_PLATFORM_STD_NV_SEED_READ   wbcrypto_platform_std_nv_seed_read
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_NV_SEED_WRITE)
#define WBCRYPTO_PLATFORM_STD_NV_SEED_WRITE  wbcrypto_platform_std_nv_seed_write
#endif
#if !defined(WBCRYPTO_PLATFORM_STD_NV_SEED_FILE)
#define WBCRYPTO_PLATFORM_STD_NV_SEED_FILE   "seedfile"
#endif
#endif /* WBCRYPTO_FS_IO */
#else /* WBCRYPTO_PLATFORM_NO_STD_FUNCTIONS */
#if defined(WBCRYPTO_PLATFORM_STD_MEM_HDR)
#include WBCRYPTO_PLATFORM_STD_MEM_HDR
#endif
#endif /* WBCRYPTO_PLATFORM_NO_STD_FUNCTIONS */


/* \} name SECTION: Module settings */

/*
 * The function pointers for calloc and free
 */
#if defined(WBCRYPTO_PLATFORM_MEMORY)
#if defined(WBCRYPTO_PLATFORM_FREE_MACRO) && \
    defined(WBCRYPTO_PLATFORM_CALLOC_MACRO)
#define wbcrypto_free       WBCRYPTO_PLATFORM_FREE_MACRO
#define wbcrypto_calloc     WBCRYPTO_PLATFORM_CALLOC_MACRO
#else
/* For size_t */
#include <stddef.h>
extern void * (*wbcrypto_calloc)( size_t n, size_t size );
extern void (*wbcrypto_free)( void *ptr );

/**
 * \brief   Set your own memory implementation function pointers
 *
 * \param calloc_func   the calloc function implementation
 * \param free_func     the free function implementation
 *
 * \return              0 if successful
 */
int wbcrypto_platform_set_calloc_free( void * (*calloc_func)( size_t, size_t ),
                              void (*free_func)( void * ) );
#endif /* WBCRYPTO_PLATFORM_FREE_MACRO && WBCRYPTO_PLATFORM_CALLOC_MACRO */
#else /* !WBCRYPTO_PLATFORM_MEMORY */
#define wbcrypto_free       free
#define wbcrypto_calloc     calloc
#endif /* WBCRYPTO_PLATFORM_MEMORY && !WBCRYPTO_PLATFORM_{FREE,CALLOC}_MACRO */

/*
 * The function pointers for fprintf
 */
#if defined(WBCRYPTO_PLATFORM_FPRINTF_ALT)
/* We need FILE * */
#include <stdio.h>
extern int (*wbcrypto_fprintf)( FILE *stream, const char *format, ... );

/**
 * \brief   Set your own fprintf function pointer
 *
 * \param fprintf_func   the fprintf function implementation
 *
 * \return              0
 */
int wbcrypto_platform_set_fprintf( int (*fprintf_func)( FILE *stream, const char *,
                                               ... ) );
#else
#if defined(WBCRYPTO_PLATFORM_FPRINTF_MACRO)
#define wbcrypto_fprintf    WBCRYPTO_PLATFORM_FPRINTF_MACRO
#else
#define wbcrypto_fprintf    fprintf
#endif /* WBCRYPTO_PLATFORM_FPRINTF_MACRO */
#endif /* WBCRYPTO_PLATFORM_FPRINTF_ALT */

/*
 * The function pointers for printf
 */
#if defined(WBCRYPTO_PLATFORM_PRINTF_ALT)
extern int (*wbcrypto_printf)( const char *format, ... );

/**
 * \brief   Set your own printf function pointer
 *
 * \param printf_func   the printf function implementation
 *
 * \return              0
 */
int wbcrypto_platform_set_printf( int (*printf_func)( const char *, ... ) );
#else /* !WBCRYPTO_PLATFORM_PRINTF_ALT */
#if defined(WBCRYPTO_PLATFORM_PRINTF_MACRO)
#define wbcrypto_printf     WBCRYPTO_PLATFORM_PRINTF_MACRO
#else
#define wbcrypto_printf     printf
#endif /* WBCRYPTO_PLATFORM_PRINTF_MACRO */
#endif /* WBCRYPTO_PLATFORM_PRINTF_ALT */

/*
 * The function pointers for snprintf
 *
 * The snprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */
#if defined(_WIN32)
/* For Windows (inc. MSYS2), we provide our own fixed implementation */
int wbcrypto_platform_win32_snprintf( char *s, size_t n, const char *fmt, ... );
#endif

#if defined(WBCRYPTO_PLATFORM_SNPRINTF_ALT)
extern int (*wbcrypto_snprintf)( char * s, size_t n, const char * format, ... );

/**
 * \brief   Set your own snprintf function pointer
 *
 * \param snprintf_func   the snprintf function implementation
 *
 * \return              0
 */
int wbcrypto_platform_set_snprintf( int (*snprintf_func)( char * s, size_t n,
                                                 const char * format, ... ) );
#else /* WBCRYPTO_PLATFORM_SNPRINTF_ALT */
#if defined(WBCRYPTO_PLATFORM_SNPRINTF_MACRO)
#define wbcrypto_snprintf   WBCRYPTO_PLATFORM_SNPRINTF_MACRO
#else
#define wbcrypto_snprintf   snprintf
#endif /* WBCRYPTO_PLATFORM_SNPRINTF_MACRO */
#endif /* WBCRYPTO_PLATFORM_SNPRINTF_ALT */

/*
 * The function pointers for exit
 */
#if defined(WBCRYPTO_PLATFORM_EXIT_ALT)
extern void (*wbcrypto_exit)( int status );

/**
 * \brief   Set your own exit function pointer
 *
 * \param exit_func   the exit function implementation
 *
 * \return              0
 */
int wbcrypto_platform_set_exit( void (*exit_func)( int status ) );
#else
#if defined(WBCRYPTO_PLATFORM_EXIT_MACRO)
#define wbcrypto_exit   WBCRYPTO_PLATFORM_EXIT_MACRO
#else
#define wbcrypto_exit   exit
#endif /* WBCRYPTO_PLATFORM_EXIT_MACRO */
#endif /* WBCRYPTO_PLATFORM_EXIT_ALT */

/*
 * The default exit values
 */
#if defined(WBCRYPTO_PLATFORM_STD_EXIT_SUCCESS)
#define WBCRYPTO_EXIT_SUCCESS WBCRYPTO_PLATFORM_STD_EXIT_SUCCESS
#else
#define WBCRYPTO_EXIT_SUCCESS 0
#endif
#if defined(WBCRYPTO_PLATFORM_STD_EXIT_FAILURE)
#define WBCRYPTO_EXIT_FAILURE WBCRYPTO_PLATFORM_STD_EXIT_FAILURE
#else
#define WBCRYPTO_EXIT_FAILURE 1
#endif

/*
 * The function pointers for reading from and writing a seed file to
 * Non-Volatile storage (NV) in a platform-independent way
 *
 * Only enabled when the NV seed entropy source is enabled
 */
#if defined(WBCRYPTO_ENTROPY_NV_SEED)
#if !defined(WBCRYPTO_PLATFORM_NO_STD_FUNCTIONS) && defined(WBCRYPTO_FS_IO)
/* Internal standard platform definitions */
int wbcrypto_platform_std_nv_seed_read( unsigned char *buf, size_t buf_len );
int wbcrypto_platform_std_nv_seed_write( unsigned char *buf, size_t buf_len );
#endif

#if defined(WBCRYPTO_PLATFORM_NV_SEED_ALT)
extern int (*wbcrypto_nv_seed_read)( unsigned char *buf, size_t buf_len );
extern int (*wbcrypto_nv_seed_write)( unsigned char *buf, size_t buf_len );

/**
 * \brief   Set your own seed file writing/reading functions
 *
 * \param   nv_seed_read_func   the seed reading function implementation
 * \param   nv_seed_write_func  the seed writing function implementation
 *
 * \return              0
 */
int wbcrypto_platform_set_nv_seed(
            int (*nv_seed_read_func)( unsigned char *buf, size_t buf_len ),
            int (*nv_seed_write_func)( unsigned char *buf, size_t buf_len )
            );
#else
#if defined(WBCRYPTO_PLATFORM_NV_SEED_READ_MACRO) && \
    defined(WBCRYPTO_PLATFORM_NV_SEED_WRITE_MACRO)
#define wbcrypto_nv_seed_read    WBCRYPTO_PLATFORM_NV_SEED_READ_MACRO
#define wbcrypto_nv_seed_write   WBCRYPTO_PLATFORM_NV_SEED_WRITE_MACRO
#else
#define wbcrypto_nv_seed_read    wbcrypto_platform_std_nv_seed_read
#define wbcrypto_nv_seed_write   wbcrypto_platform_std_nv_seed_write
#endif
#endif /* WBCRYPTO_PLATFORM_NV_SEED_ALT */
#endif /* WBCRYPTO_ENTROPY_NV_SEED */

#if !defined(WBCRYPTO_PLATFORM_SETUP_TEARDOWN_ALT)

/**
 * \brief   Platform context structure
 *
 * \note    This structure may be used to assist platform-specific
 *          setup/teardown operations.
 */
typedef struct {
    char dummy; /**< Placeholder member as empty structs are not portable */
}
wbcrypto_platform_context;

#else

#endif /* !WBCRYPTO_PLATFORM_SETUP_TEARDOWN_ALT */

/**
 * \brief   Perform any platform initialisation operations
 *
 * \param   ctx     mbed TLS context
 *
 * \return  0 if successful
 *
 * \note    This function is intended to allow platform specific initialisation,
 *          and should be called before any other library functions. Its
 *          implementation is platform specific, and by default, unless platform
 *          specific code is provided, it does nothing.
 *
 *          Its use and whether its necessary to be called is dependent on the
 *          platform.
 */
int wbcrypto_platform_setup( wbcrypto_platform_context *ctx );
/**
 * \brief   Perform any platform teardown operations
 *
 * \param   ctx     mbed TLS context
 *
 * \note    This function should be called after every other mbed TLS module has
 *          been correctly freed using the appropriate free function.
 *          Its implementation is platform specific, and by default, unless
 *          platform specific code is provided, it does nothing.
 *
 *          Its use and whether its necessary to be called is dependent on the
 *          platform.
 */
void wbcrypto_platform_teardown( wbcrypto_platform_context *ctx );

#ifdef __cplusplus
}
#endif

#endif /* platform.h */
