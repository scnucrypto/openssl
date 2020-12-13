#ifndef HEADER_wbcrypto_rand_H
#define HEADER_wbcrypto_rand_H

/*
Random Module

Sample:
void *ctx;
int arr[30];
memset(arr, 0, sizeof(arr));
wbcrypto_rand_init(&ctx);
wbcrypto_rand_seed(ctx, NULL, 0);
wbcrypto_rand_rand_int_array(ctx, arr, 30);
wbcrypto_rand_free(ctx);

*/

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute ((visibility("default")))
#endif

typedef struct wbcrypto_rand_context wbcrypto_rand_context;

// Init Random Context
EXPORT
int wbcrypto_rand_init(wbcrypto_rand_context **ctx);

// Set or reset a seed
EXPORT
int wbcrypto_rand_seed(wbcrypto_rand_context* ctx, unsigned char *seed_buf, size_t buf_size);

EXPORT
int wbcrypto_rand_seed_with_option(wbcrypto_rand_context *ctx, unsigned char *seed_buf, size_t buf_size, int options);

// Rand a list of Number
EXPORT
int wbcrypto_rand_rand(wbcrypto_rand_context *ctx, void *output, size_t size);

EXPORT
int wbcrypto_rand_rand_with_add(wbcrypto_rand_context *ctx, void *output, size_t size,
                              const unsigned char *additional,
                              size_t add_len);

// Release random context
EXPORT
void wbcrypto_rand_free(wbcrypto_rand_context *ctx);

// Shuffle unsigned char array
EXPORT
int wbcrypto_rand_shuffle_u8(unsigned char *list, int len);

// Rand a list of int32 (if ctx==NULL, then init a global ctx)
EXPORT
int wbcrypto_rand_list(wbcrypto_rand_context* ctx, int *list, int len);

// ERROR define
#define WBCRYPTO_RAND_ERROR_HASH_ALGO_NOT_FOUND -0xF101
#define WBCRYPTO_RAND_ERROR_NOT_INITIAL -0xF102
#define WBCRYPTO_RAND_ERROR_NOT_SEEDED -0xF103
#define WBCRYPTO_RAND_ERROR_OUT_SIZE_TO_LARGE -0xF104
#define WBCRYPTO_RAND_ERROR_INVLIAD_SIZE -0xF105

// OPTION define
#define WBCRYPTO_RAND_DISABLE_TIME 0x1
#define WBCRYPTO_RAND_DISABLE_URANDOM 0x2

#ifdef TARGET_PLATFORM_ANDROID
#define WBCRYPTO_RAND_DISABLE_ANDROID_INFO 0x10
#endif

#ifdef WBCRYPTO_RAND_ENABLE_SEED_IOS_SENSOR
#define WBCRYPTO_RAND_DISABLE_IOS_SENSOR 0x40
#endif

// OTHER define
#define WBCRYPTO_RAND_MAX_BYTES_COUNT 1024
#define WBCRYPTO_RAND_MAX_INT_COUNT (1024/4)

#ifdef __cplusplus
}
#endif

#endif
