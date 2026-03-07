#ifndef _DEFINE_TYPES_H
#define _DEFINE_TYPES_H

#include <except.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>

#if defined(RP_MALLOC_H)
#	define memalign rp_memalign
#	define malloc rp_malloc
#	define calloc rp_calloc
#	define realloc rp_realloc
#	define free rpfree
#	define free_final rp_free
#endif

/* Unsigned types. */
typedef unsigned char u8;
/* Unsigned types. */
typedef unsigned short u16;
/* Unsigned types. */
typedef unsigned int u32;
/* Unsigned types. */
typedef unsigned long long u64;

/* Signed types. */
typedef signed char s8;
/* Signed types. */
typedef signed short s16;
/* Signed types. */
typedef signed int s32;
/* Signed types. */
typedef signed long long s64;

/* Regular types. */
typedef char i8;
/* Regular types. */
typedef short i16;
/* Regular types. */
typedef int i32;
/* Regular types. */
typedef long long i64;

/* Floating point types. */
typedef float f32;
/* Double floating point types. */
typedef double f64;

/* Boolean types. */
typedef u8 b8;
/* Boolean types. */
typedef u32 b32;

/* Void pointer types. */
typedef void *void_t;
/* Const void pointer types. */
typedef const void *const_t;

/* Char pointer types. */
typedef char *string;
/* Const char pointer types. */
typedef const char *string_t;
/* Unsigned char pointer types. */
typedef unsigned char *u_string;
/* Const unsigned char pointer types. */
typedef const unsigned char *u_string_t;
/* Const unsigned char types. */
typedef const unsigned char u_char_t;

/* Unsigned int, raii ~result id~ type. */
typedef u32 rid_t;

typedef void (*call_t)(void);
typedef void (*func_args_t)(void_t, ...);
typedef struct hash_s hash_t;
typedef struct hash_pair_s hash_pair_t;
typedef struct map_s _map_t;
typedef struct map_item_s map_item_t;
typedef struct map_iterator_s map_iter_t;
typedef values_t template_t;
typedef char cacheline_pad_t[__ATOMIC_CACHE_LINE];

typedef enum {
	DATA_ERR = DATA_INVALID,
	DATA_HTTPINFO = (DATA_FILEINFO + DATA_PTR),
	DATA_MAP_VALUE,
	DATA_MAP_ITER,
	DATA_MAP_ARR,
} data_types_ex;

#ifndef __cplusplus
#	define nullptr NULL
#endif

/**
 * Simple macro for making sure memory addresses are aligned
 * to the nearest power of two
 */
#ifndef align_up
#define align_up(num, align) (((num) + ((align)-1)) & ~((align)-1))
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
                      ((type *) ((char *)(ptr) - offsetof(type, member)))
#endif

#ifndef C_API
 /* Public API qualifier. */
#   define C_API extern
#endif

#ifndef FORCEINLINE
  #if defined(_MSC_VER) && !defined(__clang__)
    #define FORCEINLINE __forceinline
  #elif defined(__GNUC__)
    #if defined(__STRICT_ANSI__)
      #define FORCEINLINE __inline__ __attribute__((always_inline))
    #else
      #define FORCEINLINE inline __attribute__((always_inline))
    #endif
  #elif defined(__BORLANDC__) || defined(__DMC__) || defined(__SC__) || defined(__WATCOMC__) || defined(__LCC__) ||  defined(__DECC)
    #define FORCEINLINE __inline
  #else /* No inline support. */
    #define FORCEINLINE
  #endif
#endif
#endif /* _DEFINE_TYPES_H */
