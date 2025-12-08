#ifndef C_ATOMICS_H
#define C_ATOMICS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(__has_feature)
#	define __has_feature(x) 0
#endif

#if !defined(__has_builtin)
#	define __has_builtin(x) 0
#endif

#if !defined(__GNUC_PREREQ__)
#	if defined(__GNUC__) && defined(__GNUC_MINOR__)
#		define __GNUC_PREREQ__(maj, min)	((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#	else
#		define __GNUC_PREREQ__(maj, min) 0
#	endif
#endif

#if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)))
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Wlong-long"
#	if defined(__clang__)
#		pragma GCC diagnostic ignored "-Wc++11-long-long"
#	endif
#endif

#if defined(_WIN32)
#	include <intrin.h>
#   define make_atomic(type, var)  typedef volatile type var;
#else
#	if defined(__APPLE__)
#		define make_atomic(type, var)  typedef volatile type var;
#	else
#   	define make_atomic(type, var)  typedef volatile _Atomic(type)var;
#	endif
#endif

/* Architecture Detection */
#if !defined(ATOMIC_64BIT) && !defined(ATOMIC_32BIT)
#	ifdef _WIN32
#		ifdef _WIN64
#			define ATOMIC_64BIT
#			define ATOMIC_HAS_64
#		else
#			define ATOMIC_32BIT
#			define ATOMIC_HAS_32
#		endif
#	endif
#endif

#if !defined(ATOMIC_64BIT) && !defined(ATOMIC_32BIT)
#	ifdef __GNUC__
#		ifdef __LP64__
#			define ATOMIC_64BIT
#		else
#			define ATOMIC_32BIT
#		endif
#	endif
#endif

#if !defined(ATOMIC_64BIT) && !defined(ATOMIC_32BIT)
#	if INTPTR_MAX == INT64_MAX
#		define ATOMIC_64BIT
#	else
#		define ATOMIC_32BIT
#	endif
#endif

#if defined(__x86_64__) || defined(_M_X64)
#	define ATOMIC_X64
#elif defined(__i386) || defined(_M_IX86) || defined(__i386__)
#	define ATOMIC_X86
#elif defined(__arm64) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM64)
#	define ATOMIC_ARM64
#elif defined(__arm__) || defined(_M_ARM)
#	define ATOMIC_ARM32
#elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(_ARCH_PPC64)
#	define ATOMIC_PPC64
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__) || defined(__powerpc) || defined(__ppc) || defined(_ARCH_PPC)
#	define ATOMIC_PPC32
#endif

#if defined(ATOMIC_ARM32) || defined(ATOMIC_ARM64)
#	define ATOMIC_ARM
#endif
/* End Architecture Detection */

#if !defined(__CLANG_ATOMICS) && !defined(__GNUC_ATOMICS)
#	if __has_feature(c_atomic)
#		define __CLANG_ATOMICS
#	elif __GNUC_PREREQ__(4, 7)
#		define __GNUC_ATOMICS
#	elif defined(_WIN32)
#		define __WIN32_ATOMICS
#	elif !defined(__GNUC__)
#		error "stdatomic.h does not support your compiler"
#	endif
#endif

/*
 * 7.17.2 Initialization.
 */

#if defined(__WIN32_ATOMICS)
/* initializes an existing atomic object */
#	define atomic_init atomic_store
#	define ATOMIC_VAR_INIT	{0}
#	define ATOMIC_FLAG_INIT	{0}
#elif defined(__CLANG_ATOMICS)
#	define ATOMIC_VAR_INIT(value)          (value)
/* initializes an existing atomic object */
#	define atomic_init(obj, value)         __c11_atomic_init(obj, value)
#	define ATOMIC_FLAG_INIT                ATOMIC_VAR_INIT(0)
#else
#	define ATOMIC_VAR_INIT(value)          { 0 }
#	define ATOMIC_FLAG_INIT                ATOMIC_VAR_INIT(0)
/* initializes an existing atomic object */
#	define atomic_init atomic_store
#endif

/*
 * Clang and recent GCC both provide predefined macros for the memory
 * orderings.  If we are using a compiler that doesn't define them, use the
 * clang values - these will be ignored in the fallback path.
 */

#ifndef __ATOMIC_RELAXED
#	define __ATOMIC_RELAXED                0
#endif
#ifndef __ATOMIC_CONSUME
#	define __ATOMIC_CONSUME                1
#endif
#ifndef __ATOMIC_ACQUIRE
#	define __ATOMIC_ACQUIRE                2
#endif
#ifndef __ATOMIC_RELEASE
#	define __ATOMIC_RELEASE                3
#endif
#ifndef __ATOMIC_ACQ_REL
#	define __ATOMIC_ACQ_REL                4
#endif
#ifndef __ATOMIC_SEQ_CST
#	define __ATOMIC_SEQ_CST                5
#endif

/*
 * 7.17.3 Order and consistency.
 *
 * The memory_order_* constants that denote the barrier behaviour of the
 * atomic operations.
 */

#ifndef _STDATOMIC_H
	typedef enum {
		memory_order_relaxed = __ATOMIC_RELAXED,
		memory_order_consume = __ATOMIC_CONSUME,
		memory_order_acquire = __ATOMIC_ACQUIRE,
		memory_order_release = __ATOMIC_RELEASE,
		memory_order_acq_rel = __ATOMIC_ACQ_REL,
		memory_order_seq_cst = __ATOMIC_SEQ_CST,
	} atomic_memory_order;
#endif

/* Inline */
#if defined(_MSC_VER)
#   define ATOMICS_INLINE __forceinline
#elif defined(__GNUC__)
#	if defined(__STRICT_ANSI__) || !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
#		define ATOMICS_INLINE __inline__ __attribute__((always_inline))
#	else
#		define ATOMICS_INLINE inline __attribute__((always_inline))
#	endif
#elif defined(__WATCOMC__) || defined(__DMC__)
#	define ATOMICS_INLINE __inline
#else
#	define ATOMICS_INLINE
#endif
/* End Inline */

/*
 * 7.17.5 Lock-free property.
 */

#if defined(__TINYC__) || defined(_MSC_VER)
/* indicates whether the atomic object is lock-free */
#define atomic_is_lock_free(obj) 	(sizeof((obj)) <= sizeof(void *))
#elif defined(__CLANG_ATOMICS)
/* indicates whether the atomic object is lock-free */
#define atomic_is_lock_free(obj)	__c11_atomic_is_lock_free(sizeof(obj))
#elif defined(__GNUC_ATOMICS)
/* indicates whether the atomic object is lock-free */
#define atomic_is_lock_free(obj)	__atomic_is_lock_free(obj)
#else
/* indicates whether the atomic object is lock-free */
#define atomic_is_lock_free(obj)	(sizeof((obj)) <= sizeof(void *))
#endif

/*
 * 7.17.6 Atomic integer types.
 */

#ifndef _STDATOMIC_H
	make_atomic(bool, atomic_bool)
	make_atomic(char, atomic_char)
	make_atomic(char, atomic_schar)
	make_atomic(unsigned char, atomic_uchar)
	make_atomic(signed short, atomic_short)
	make_atomic(unsigned short, atomic_ushort)
	make_atomic(signed int, atomic_int)
	make_atomic(unsigned int, atomic_uint)
	make_atomic(signed long, atomic_long)
	make_atomic(unsigned long, atomic_ulong)
	make_atomic(signed long long, atomic_llong)
	make_atomic(unsigned long long, atomic_ullong)
	make_atomic(intptr_t, atomic_intptr_t)
	make_atomic(uintptr_t, atomic_uintptr_t)
	make_atomic(intmax_t, atomic_intmax_t)
	make_atomic(uintmax_t, atomic_uintmax_t)

	/* Sized Types */
	typedef   signed char	atomic_int8;
	typedef unsigned char	atomic_uint8;
	typedef   signed short	atomic_int16;
	typedef unsigned short	atomic_uint16;
	typedef   signed int	atomic_int32;
	typedef unsigned int	atomic_uint32;
#if defined(_MSC_VER) && !defined(__clang__)
	typedef   signed __int64    atomic_int64;
	typedef unsigned __int64    atomic_uint64;
#else
	typedef   signed long long  atomic_int64;
	typedef unsigned long long  atomic_uint64;
#endif
	typedef atomic_char	atomic_flag;
#endif

#if !defined(_STDATOMIC_H) && (defined(_WIN32) || defined(__APPLE__))
	make_atomic(size_t, atomic_size_t)
	make_atomic(ptrdiff_t, atomic_ptrdiff_t)
#elif !defined(_STDATOMIC_H)
	make_atomic(__SIZE_TYPE__, atomic_size_t)
	make_atomic(__PTRDIFF_TYPE__, atomic_ptrdiff_t)
#endif
make_atomic(void *, atomic_ptr_t)

typedef long long llong;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ullong;

#if (defined(_MSC_VER) /*&& !defined(__clang__)*/) || defined(__WATCOMC__) || defined(__DMC__)
#if _MSC_VER < 1600 && defined(ATOMIC_X86)   /* 1600 = Visual Studio 2010 */
#define ATOMIC_MSVC_USE_INLINED_ASSEMBLY
#endif
#if _MSC_VER < 1600
#undef ATOMIC_HAS_8
#undef ATOMIC_HAS_16
#endif

static ATOMICS_INLINE bool __stdcall __atomic_exchange_explicit_8(atomic_flag *dst, char src, atomic_memory_order order) {
	(void)order;
	return (bool)_InterlockedExchange8((volatile char *)dst, (char)src);
}

static ATOMICS_INLINE long __stdcall __atomic_exchange_explicit_32(atomic_long *dst, long src, atomic_memory_order order) {
	(void)order;
	return _InterlockedExchange((atomic_long *)dst, (long)src);
}

static ATOMICS_INLINE llong __stdcall __atomic_exchange_explicit_64(atomic_llong *dst, llong src, atomic_memory_order order) {
	(void)order;
	return _InterlockedExchange64((atomic_llong *)dst, (llong)src);
}

/* atomic_exchange_explicit */
#if defined(ATOMIC_HAS_32)
	static ATOMICS_INLINE long __stdcall __atomic_exchange_explicit(atomic_long *dst, long src, atomic_memory_order order) {
		return __atomic_exchange_explicit_32(dst, src, order);
	}
#else
	static ATOMICS_INLINE llong __stdcall __atomic_exchange_explicit(atomic_llong *dst, llong src, atomic_memory_order order) {
		return __atomic_exchange_explicit_64((atomic_llong *)dst, (llong)src, order);
	}
#endif

/* generic memory order-dependent fence synchronization primitive */
#define atomic_thread_fence(order)   MemoryBarrier()
#define atomic_compiler_fence()      atomic_thread_fence(memory_order_seq_cst)
/* fence between a thread and a signal handler executed in the same thread */
#define atomic_signal_fence(order)   _ReadWriteBarrier()

	static ATOMICS_INLINE long __stdcall __atomic_fetch_add_32(atomic_long *dst, long src, atomic_memory_order order) {
		(void)order;
		return _InterlockedExchangeAdd((atomic_long *)dst, (long)src);
	}

	static ATOMICS_INLINE long __stdcall __atomic_load_32(atomic_long *ptr, atomic_memory_order order) {
		(void)order;
		return _InterlockedCompareExchange((atomic_long *)ptr, (long)0, (long)0);
	}

	static ATOMICS_INLINE bool __stdcall __atomic_compare_exchange_strong_32(atomic_long *a, long *cmp, long xchg, atomic_memory_order mo) {
		long cmpv = *cmp;
		long prev = (long)_InterlockedCompareExchange((atomic_long *)a, (long)xchg, (long)cmpv);
		if (prev == cmpv)
			return true;
		*cmp = prev;
		return false;
	}

#define atomic_store_explicit_32(object, desired, order)	(void)__atomic_exchange_explicit_32((atomic_long*)object, desired, order)
#define atomic_fetch_add_explicit_32(object, operand, order)	__atomic_fetch_add_32(object, operand, order)
#define atomic_compare_exchange_weak_explicit_32(obj, expected, desired, succ, fail)	\
    __atomic_compare_exchange_strong_32(obj, expected, desired, succ)
#if defined(ATOMIC_HAS_32)
	static ATOMICS_INLINE long __stdcall __atomic_load_explicit(atomic_long *ptr, atomic_memory_order order) {
		(void)order;
		return __atomic_load_32((atomic_long *)ptr, (long)0, (long)0);
	}

	static ATOMICS_INLINE long __stdcall __atomic_fetch_add_explicit(atomic_ptr_t *dst, long src, atomic_memory_order order) {
		return __atomic_fetch_add_32(dst, src, order);
	}

	static ATOMICS_INLINE long __stdcall __atomic_fetch_sub_explicit(atomic_ptr_t *dst, long src, atomic_memory_order order) {
		return __atomic_fetch_add_explicit(dst, -(long)src, order);
	}

	static ATOMICS_INLINE bool __stdcall __atomic_compare_exchange_strong_explicit(atomic_long *a, long *cmp, long xchg, atomic_memory_order mo) {
		return __atomic_compare_exchange_strong_32(a, cmp, xchg, mo);
	}

/* stores a value in an atomic object */
#define atomic_store_explicit(obj, desired, order)  	(void)_InterlockedExchange((atomic_long*)obj, (long)desired)
/* atomic bitwise AND */
#define atomic_fetch_and_explicit(dst, mask, order)		_InterlockedAnd((atomic_long *)dst, (long)mask)
/* atomic bitwise OR */
#define atomic_fetch_or_explicit(dst, mask, order)		_InterlockedOr((atomic_long *)dst, (long)mask)
/* atomic bitwise exclusive OR */
#define atomic_fetch_xor_explicit(dst, mask, order)		_InterlockedXor((atomic_long *)dst, (long)mask)
#else
	static ATOMICS_INLINE llong __stdcall __atomic_load_explicit(atomic_llong *ptr, atomic_memory_order order) {
		(void)order;
		return _InterlockedCompareExchange64((atomic_llong *)ptr, (llong)0, (llong)0);
	}

	static ATOMICS_INLINE llong __stdcall __atomic_fetch_add_explicit(atomic_ptr_t *dst, llong src, atomic_memory_order order) {
		(void)order;
		return _InterlockedExchangeAdd64((atomic_llong *)dst, (llong)src);
	}

	static ATOMICS_INLINE llong __stdcall __atomic_fetch_sub_explicit(atomic_ptr_t *dst, llong src, atomic_memory_order order) {
		return __atomic_fetch_add_explicit(dst, -(llong)src, order);
	}

	static ATOMICS_INLINE bool __stdcall __atomic_compare_exchange_strong_explicit(atomic_llong *a, llong *cmp, llong xchg, atomic_memory_order mo) {
		llong cmpv = *cmp;
		llong prev = _InterlockedCompareExchange64((atomic_llong *)a, (llong)xchg, (llong)cmpv);
		if (prev == cmpv)
			return true;
		*cmp = prev;
		return false;
	}
/* stores a value in an atomic object */
#define atomic_store_explicit(object, desired, order)	(void)_InterlockedExchange64((atomic_llong*)object, (llong)desired)
/* atomic bitwise AND */
#define atomic_fetch_and_explicit(dst, mask, order)		_InterlockedAnd64((atomic_llong *)dst, (llong)mask)
/* atomic bitwise OR */
#define atomic_fetch_or_explicit(dst, mask, order)		_InterlockedOr64((atomic_llong *)dst, (llong)mask)
/* atomic bitwise exclusive OR */
#define atomic_fetch_xor_explicit(dst, mask, order)		_InterlockedXor64((atomic_llong *)dst, (llong)mask)
#endif

/* sets an atomic_flag to true and returns the old value */
#define atomic_flag_test_and_set_explicit(ptr, order)	(bool)_InterlockedExchange8((atomic_flag*)ptr, (char)1)
/* reads an atomic_flag */
#define atomic_flag_load_explicit(ptr, order)			(bool)_InterlockedCompareExchange8((atomic_flag*)ptr, 0, 0)
/* sets an atomic_flag to false */
#define atomic_flag_clear_explicit(ptr, order)			(bool)_InterlockedExchange8((atomic_flag*)ptr, 0)
/* swaps a value with an atomic object if the old value is what is expected, otherwise reads the old value */
#define atomic_compare_exchange_strong_explicit(dst, expected, desired, successOrder, failureOrder)	\
		__atomic_compare_exchange_strong_explicit(dst, (void*)expected, desired, successOrder)

/* swaps a value with an atomic object if the old value is what is expected, otherwise reads the old value */
#define atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail)					\
    	atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, fail)

/* reads a value from an atomic object */
#define atomic_load_explicit(object, order)				__atomic_load_explicit((atomic_ullong *)object, order)
#define atomic_load_explicit_32(object, order)			__atomic_load_32((atomic_long *)object, order)
/* swaps a value with the value of an atomic object */
#define atomic_exchange_explicit(object, desired, order)	        \
		__atomic_exchange_explicit((atomic_ullong *)object, (atomic_ullong)desired, order)

/* atomic addition */
#define atomic_fetch_add_explicit(obj, arg, order)		__atomic_fetch_add_explicit((atomic_ptr_t *)obj, arg, order)
/* atomic subtraction */
#define atomic_fetch_sub_explicit(obj, arg, order)		__atomic_fetch_sub_explicit((atomic_ptr_t *)obj, arg, order)
#elif defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7)))
/* Modern GCC atomic built-ins. */
#define ATOMIC_HAS_NATIVE_COMPARE_EXCHANGE
#define ATOMIC_HAS_NATIVE_IS_LOCK_FREE

#define atomic_compiler_fence()                              __asm__ __volatile__("":::"memory")
/* generic memory order-dependent fence synchronization primitive */
#define atomic_thread_fence(order)                           __atomic_thread_fence(order)
/* fence between a thread and a signal handler executed in the same thread */
#define atomic_signal_fence(order)                           __atomic_signal_fence(order)

/* swaps a value with an atomic object if the old value is what is expected, otherwise reads the old value */
#define atomic_compare_exchange_strong_explicit(dst, expected, desired, successOrder, failureOrder)		\
		__atomic_compare_exchange_n(dst, expected, desired, 0, successOrder, failureOrder)

/* swaps a value with an atomic object if the old value is what is expected, otherwise reads the old value */
#define atomic_compare_exchange_weak_explicit(dst, expected, desired, successOrder, failureOrder)		\
		__atomic_compare_exchange_n(dst, expected, desired, 1, successOrder, failureOrder)
#define atomic_compare_exchange_weak_explicit_32(obj, expected, desired, succ, fail)					\
    	atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail)
#define atomic_load_explicit(object, order)				__atomic_load_n(object, order)
#define atomic_load_explicit_32(object, order)			atomic_load_explicit(object, order)
#define atomic_exchange_explicit(dst, src, order)		__atomic_exchange_n(dst, src, order)

/* sets an atomic_flag to true and returns the old value */
#define atomic_flag_test_and_set_explicit(dst, order)	(bool)__atomic_test_and_set(dst, order)
/* sets an atomic_flag to false */
#define atomic_flag_clear_explicit(dst, order)			__atomic_clear(dst, order)
/* reads an atomic_flag */
#define atomic_flag_load_explicit(ptr, order)			atomic_load_explicit(ptr, order)
/* stores a value in an atomic object */
#define atomic_store_explicit(object, desired, order)	__atomic_store_n(object, desired, order)

#define atomic_store_explicit_32(object, desired, order)	atomic_store_explicit(object, desired, order)
#define atomic_fetch_add_explicit(dst, src, order)		__atomic_fetch_add(dst, src, order)
#define atomic_fetch_add_explicit_32(obj, arg, order)	atomic_fetch_add_explicit(obj, arg, order)
#define atomic_fetch_sub_explicit(dst, src, order)		__atomic_fetch_sub(dst, src, order)
#define atomic_fetch_or_explicit(dst, src, order)		__atomic_fetch_or(dst, src, order)
#define atomic_fetch_xor_explicit(dst, src, order)		__atomic_fetch_xor(dst, src, order)
#define atomic_fetch_and_explicit(dst, src, order)		__atomic_fetch_and(dst, src, order)
#else
#define atomic_compiler_fence() __asm__ __volatile__("":::"memory")

#if defined(__GNUC__) && !defined(__APPLE__)
	/* Legacy GCC atomic built-ins. Everything is a full memory barrier. */
/* generic memory order-dependent fence synchronization primitive */
#define atomic_thread_fence(order) __sync_synchronize(), (void)order
#define atomic_compare_exchange_strong_explicit(object, expected,       \
    desired, success, failure) ({                                       \
        __typeof__((object)) __v;                                \
        _Bool __r;                                                      \
        __v = __sync_val_compare_and_swap(object,             \
            *(expected), desired);                                      \
        __r = *(expected) == __v;                                       \
        *(expected) = __v;                                              \
        __r;                                                            \
})

#define atomic_compare_exchange_weak_explicit(object, expected,         \
    desired, success, failure)                                          \
        atomic_compare_exchange_strong_explicit(object, expected,       \
                desired, success, failure)
#define atomic_compare_exchange_weak_explicit_32(obj, expected, desired, succ, fail)	\
    atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail)
#if __has_builtin(__sync_swap)
#define atomic_exchange_explicit(object, desired, order)                \
        __sync_swap(object, desired)
#else
#define atomic_exchange_explicit(object, desired, order) ({             \
        __typeof__((object)) __v;										\
        __v = __sync_lock_test_and_set(object, desired);				\
        __sync_synchronize();                                           \
        __v;                                                            \
})
#endif
#define atomic_fetch_add_explicit(object, operand, order)               \
        __sync_fetch_and_add(object, operand)
#define atomic_fetch_add_explicit_32(object, operand, order)	atomic_fetch_add_explicit(object, operand, order)
#define atomic_fetch_and_explicit(object, operand, order)               \
        __sync_fetch_and_and(object, operand)
#define atomic_fetch_or_explicit(object, operand, order)                \
        __sync_fetch_and_or(object, operand)
#define atomic_fetch_sub_explicit(object, operand, order)               \
        __sync_fetch_and_sub(object, operand)
#define atomic_fetch_xor_explicit(object, operand, order)               \
        __sync_fetch_and_xor(object, operand)
#define atomic_load_explicit(object, order)                             \
        __sync_fetch_and_add(object, 0)

#define atomic_load_explicit_32(object, order)			atomic_load_explicit(object, order)
/* stores a value in an atomic object */
#define atomic_store_explicit(object, desired, order) do {              \
        __sync_synchronize();                                           \
        (object) = desired;                                    \
        __sync_synchronize();                                           \
} while (0)
#define atomic_store_explicit_32(object, desired, order)			atomic_store_explicit(object, desired, order)

#else
#if defined(ATOMIC_X86)
/* generic memory order-dependent fence synchronization primitive */
#define atomic_thread_fence(order) __asm__ __volatile__("lock; addl $0, (%%esp)" ::: "memory", "cc")
#elif defined(ATOMIC_X64)
/* generic memory order-dependent fence synchronization primitive */
#define atomic_thread_fence(order) __asm__ __volatile__("lock; addq $0, (%%rsp)" ::: "memory", "cc")
#elif !defined(__TINYC__)
#error Unsupported architecture. Please submit a feature request.
#endif

/* compare_and_swap() */
	static ATOMICS_INLINE long __atomic_cas_32(atomic_long *dst, atomic_uint32 expected, atomic_uint32 desired) {
		atomic_uint32 result;

#if defined(ATOMIC_X86) || defined(ATOMIC_X64)
#if defined(__TINYC__) && defined(_WIN32) && defined(__arm__) && !defined(_MSC_VER)
		result = (long)atomic_compare_exchange_strong((atomic_long *)dst, (long *)&expected, (long)desired);
#else
		__asm__ __volatile__("lock; cmpxchg %3, %0" : "+m"(*dst), "=a"(result) : "a"(expected), "d"(desired) : "cc");
#endif
#elif defined(__TINYC__)
		result = (long)atomic_compare_exchange_strong((atomic_long *)dst, (long *)&expected, (long)desired);
#else
#error Unsupported architecture. Please submit a feature request.
#endif

		return result;
	}

	static ATOMICS_INLINE llong __atomic_cas_64(atomic_llong *dst, llong expected, llong desired) {
		llong result;

#if defined(ATOMIC_X86)
	/*
	We can't use the standard CMPXCHG here because x86 does not support it with 64-bit values. We need to instead use CMPXCHG8B
	which is a bit harder to use. The annoying part with this is the use of the -fPIC compiler switch which requires the EBX
	register never be modified. The problem is that CMPXCHG8B requires us to write our desired value to it. I'm resolving this
	by just pushing and popping the EBX register manually.
	*/
		atomic_uint32 resultEAX;
		atomic_uint32 resultEDX;
#if defined(__TINYC__) && defined(_WIN32) && defined(__arm__) && !defined(_MSC_VER)
		result = (atomic_uint64)atomic_compare_exchange_strong((atomic_ulong *)dst, (unsigned long *)&expected, (unsigned long)desired);
#else
		__asm__ __volatile__("push %%ebx; xchg %5, %%ebx; lock; cmpxchg8b %0; pop %%ebx" : "+m"(*dst), "=a"(resultEAX), "=d"(resultEDX) : "a"(expected & 0xFFFFFFFF), "d"(expected >> 32), "r"(desired & 0xFFFFFFFF), "c"(desired >> 32) : "cc");
		result = ((atomic_uint64)resultEDX << 32) | resultEAX;
#endif
#elif defined(ATOMIC_X64)
		__asm__ __volatile__("lock; cmpxchg %3, %0" : "+m"(*dst), "=a"(result) : "a"(expected), "d"(desired) : "cc");
#elif defined(__TINYC__)
		result = (atomic_uint64)atomic_compare_exchange_strong((atomic_ulong *)dst, (unsigned long *)&expected, (unsigned long)desired);
#else
#error Unsupported architecture. Please submit a feature request.
#endif

		return result;
	}


	/* exchange() */
	static ATOMICS_INLINE atomic_uint8 atomic_exchange_explicit_8(volatile atomic_uint8 *dst, atomic_uint8 src, atomic_memory_order order) {
		atomic_uint8 result = 0;

		(void)order;

#if defined(ATOMIC_X86) || defined(ATOMIC_X64)
#if defined(__TINYC__) && defined(_WIN32) && defined(__arm__) && !defined(_MSC_VER)
		result = (atomic_uint8)atomic_exchange_explicit((atomic_uchar *)dst, (unsigned char)src, order);
#else
		__asm__ __volatile__("lock; xchg %1, %0" : "+m"(*dst), "=a"(result) : "a"(src));
#endif
#elif defined(__TINYC__)
		result = (atomic_uint8)atomic_exchange_explicit((atomic_uchar *)dst, (unsigned char)src, order);
#else
#error Unsupported architecture. Please submit a feature request.
#endif

		return result;
	}

	static ATOMICS_INLINE atomic_uint32 atomic_exchange_explicit_32(volatile atomic_uint32 *dst, atomic_uint32 src, atomic_memory_order order) {
		atomic_uint32 result;

		(void)order;

#if defined(ATOMIC_X86) || defined(ATOMIC_X64)
#if defined(__TINYC__) && defined(_WIN32) && defined(__arm__) && !defined(_MSC_VER)
		result = (atomic_uint32)atomic_exchange_explicit((atomic_uint *)dst, (unsigned int)src, order);
#else
		__asm__ __volatile__("lock; xchg %1, %0" : "+m"(*dst), "=a"(result) : "a"(src));
#endif
#elif defined(__TINYC__)
		result = (atomic_uint32)atomic_exchange_explicit((atomic_uint *)dst, (unsigned int)src, order);
#else
#error Unsupported architecture. Please submit a feature request.
#endif

		return result;
	}

	static ATOMICS_INLINE llong __atomic_exchange_explicit(atomic_llong *dst, llong src, atomic_memory_order order) {
		llong result;

		(void)order;

#if defined(ATOMIC_X86)
		do {
			result = *dst;
		} while (__atomic_cas_32(dst, result, src) != result);
#elif defined(ATOMIC_X64)
#if defined(__TINYC__) && defined(_WIN32) && defined(__arm__) && !defined(_MSC_VER)
		result = (llong)atomic_exchange_explicit((atomic_long *)dst, (long)src, order);
#else
		__asm__ __volatile__("lock; xchg %1, %0" : "+m"(*dst), "=a"(result) : "a"(src));
#endif
#elif defined(__TINYC__)
		result = (llong)atomic_exchange_explicit((atomic_llong *)dst, (llong)src, order);
#else
#error Unsupported architecture. Please submit a feature request.
#endif

		return result;
	}


	/* fetch_add() */
	static ATOMICS_INLINE atomic_uint8 atomic_fetch_add_explicit_8(volatile atomic_uint8 *dst, atomic_uint8 src, atomic_memory_order order) {
		atomic_uint8 result;

		(void)order;

#if defined(ATOMIC_X86) || defined(ATOMIC_X64)
#if defined(__TINYC__) && defined(_WIN32) && defined(__arm__) && !defined(_MSC_VER)
		result = (atomic_uint8)atomic_fetch_add_explicit((atomic_uchar *)dst, (unsigned char)src, order);
#else
		__asm__ __volatile__("lock; xadd %1, %0" : "+m"(*dst), "=a"(result) : "a"(src) : "cc");
#endif
#elif defined(__TINYC__)
		result = (atomic_uint8)atomic_fetch_add_explicit((atomic_uchar *)dst, (unsigned char)src, order);
#else
#error Unsupported architecture. Please submit a feature request.
#endif

		return result;
	}

	static ATOMICS_INLINE atomic_uint32 atomic_fetch_add_explicit_32(volatile atomic_uint32 *dst, atomic_uint32 src, atomic_memory_order order) {
		atomic_uint32 result;

		(void)order;

#if defined(ATOMIC_X86) || defined(ATOMIC_X64)
#if defined(__TINYC__) && defined(_WIN32) && defined(__arm__) && !defined(_MSC_VER)
		result = (atomic_uint32)atomic_fetch_add_explicit((atomic_uint *)dst, (unsigned int)src, order);
#else
		__asm__ __volatile__("lock; xadd %1, %0" : "+m"(*dst), "=a"(result) : "a"(src) : "cc");
#endif
#elif defined(__TINYC__)
		result = (atomic_uint16)atomic_fetch_add_explicit((atomic_uint *)dst, (unsigned int)src, order);
#else
#error Unsupported architecture. Please submit a feature request.
#endif

		return result;
	}

	static ATOMICS_INLINE atomic_uint64 __atomic_fetch_add_explicit(volatile atomic_uint64 *dst, atomic_uint64 src, atomic_memory_order order) {
#if defined(ATOMIC_X64)
		atomic_uint64 result;

		(void)order;

#if defined(__TINYC__) && defined(_WIN32) && defined(__arm__) && !defined(_MSC_VER)
		result = (atomic_uint64)atomic_fetch_add_explicit((atomic_ulong *)dst, (unsigned long)src, order);
#else
		__asm__ __volatile__("lock; xadd %1, %0" : "+m"(*dst), "=a"(result) : "a"(src) : "cc");
#endif

		return result;
#elif defined(__TINYC__)
		return (atomic_uint64)atomic_fetch_add_explicit((atomic_ulong *)dst, (unsigned long)src, order);
#endif
	}
#endif

/* fence between a thread and a signal handler executed in the same thread */
#define atomic_signal_fence(order)	atomic_thread_fence(order)

#define atomic_store_explicit(dst, src, order)            (void)__atomic_exchange_explicit(dst, src, order)
#define atomic_store_explicit_32(object, desired, order)	atomic_store_explicit(object, desired, order)
#define atomic_test_and_set_explicit(dst, order)          __atomic_exchange_explicit(dst, 1, order)
#define atomic_clear_explicit(dst, order)                 __atomic_exchange_explicit(dst, 0, order)

/* sets an atomic_flag to true and returns the old value */
#define atomic_flag_test_and_set_explicit(ptr, order)        (bool)atomic_test_and_set_explicit(ptr, order)
/* sets an atomic_flag to false */
#define atomic_flag_clear_explicit(ptr, order)               atomic_clear_explicit(ptr, order)
/* reads an atomic_flag */
#define atomic_flag_load_explicit(ptr, order)                atomic_load_explicit(ptr, order)
#endif

	/* Spinlock */
	typedef atomic_bool	atomic_spinlock;
	static ATOMICS_INLINE void atomic_spinlock_lock(atomic_spinlock *pSpinlock) {
		for (;;) {
			if (!atomic_flag_test_and_set_explicit(pSpinlock, memory_order_acquire))
				break;

			while (atomic_flag_load_explicit(pSpinlock, memory_order_relaxed))
				;
		}
	}

	static ATOMICS_INLINE void atomic_spinlock_unlock(atomic_spinlock *pSpinlock) {
		atomic_flag_clear_explicit(pSpinlock, memory_order_release);
	}

#ifdef _WIN32
	static ATOMICS_INLINE bool __stdcall __atomic_cas_32(atomic_long *a, long *cmp, long set) {
#if defined(__TINYC__) && defined(_WIN32) && (defined(__arm__) || defined(__i386__)) && !defined(_MSC_VER)
		return (bool)atomic_compare_exchange_strong((atomic_uint *)a, (unsigned int *)&cmp, set);
#else
		long initial_cmp = *cmp;
		long initial_a = _InterlockedCompareExchange((atomic_long *)a, set, initial_cmp);
		bool ret = (initial_a == initial_cmp);
		if (!ret)
			*cmp = initial_a;

		return ret;
#endif
	}

	static ATOMICS_INLINE bool __stdcall __atomic_cas_64(atomic_llong *a, llong *cmp, llong set) {
#if defined(__TINYC__) && defined(_WIN32) && (defined(__arm__) || defined(__i386__)) && !defined(_MSC_VER)
		return (bool)atomic_compare_exchange_strong((atomic_ulong *)a, (unsigned long *)&cmp, set);
#else
		llong initial_cmp = *cmp;
		llong initial_a = _InterlockedCompareExchange64((atomic_llong *)a, (llong)set, (llong)initial_cmp);
		bool ret = (initial_a == initial_cmp);
		if (!ret)
			*cmp = initial_a;

		return ret;
#endif
	}

	static ATOMICS_INLINE bool __stdcall __atomic_swap(atomic_ptr_t *a, void **cmp, void *set) {
#if defined(__TINYC__) && defined(_WIN32) && (defined(__arm__) || defined(__i386__)) && !defined(_MSC_VER)
		return (bool)atomic_compare_exchange_strong((atomic_uintptr_t *)a, (uintptr_t *)&cmp, (uintptr_t *)&set);
#else
		void *initial_cmp = *cmp;
		void *initial_a = _InterlockedCompareExchangePointer((void *volatile *)a, set, initial_cmp);
		bool ret = (initial_a == initial_cmp);
		if (!ret)
			*cmp = initial_a;

		return ret;
#endif
	}

#define atomic_cas_32(obj, expected, desired) __atomic_cas_32(obj, (long *)expected, (long)desired)
#define atomic_cas(obj, expected, desired) __atomic_cas_64(obj, (llong *)expected, (llong)desired)
#define atomic_swap(obj, expected, desired) __atomic_swap(obj, (void **)expected, (void *)desired)
#else
#if defined(_STDATOMIC_H)
#   define atomic_cas_32(P, E, D)   atomic_compare_exchange_strong((P), (E), (D))
#   define atomic_cas(P, E, D)  atomic_compare_exchange_strong((P), (E), (D))
#   define atomic_swap(P, E, D) atomic_compare_exchange_strong((P), (E), (D))
#else
#   define atomic_cas_32(P, E, D)  __atomic_compare_exchange_n((P), (E), (D), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#   define atomic_cas(P, E, D)  __atomic_compare_exchange_n((P), (E), (D), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#   define atomic_swap(P, E, D)    __atomic_compare_exchange_n((P), (E), (D), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#endif
#endif

/* reads a value from an atomic object then cast to type */
#define atomic_get(type, obj)	(type)atomic_load_explicit(obj, memory_order_seq_cst)
#define atomic_lock(mutex)		atomic_spinlock_lock((atomic_spinlock *)mutex)
#define atomic_unlock(mutex)	atomic_spinlock_unlock((atomic_spinlock *)mutex)

#if !defined(_STDATOMIC_H)
/* reads an atomic_flag */
#define atomic_flag_load(ptr)				atomic_flag_load_explicit((atomic_flag *)ptr, memory_order_seq_cst)
/* sets an atomic_flag to false */
#define atomic_flag_clear(object)			atomic_flag_clear_explicit(object, memory_order_seq_cst)
/* sets an atomic_flag to true and returns the old value */
#define atomic_flag_test_and_set(object)	atomic_flag_test_and_set_explicit(object, memory_order_seq_cst)
/* stores a value in an atomic object */
#define atomic_store(object, desired)		atomic_store_explicit(object, desired, memory_order_seq_cst)
/* reads a value from an atomic object */
#define atomic_load(obj)					atomic_load_explicit(obj, memory_order_seq_cst)
/* swaps a value with the value of an atomic object */
#define atomic_exchange(object, desired)	atomic_exchange_explicit(object, desired, memory_order_seq_cst)
/* swaps a value with an atomic object if the old value is what is expected, otherwise reads the old value */
#define atomic_compare_exchange_strong(object, expected, desired)	\
		atomic_compare_exchange_strong_explicit(object, expected, desired, memory_order_seq_cst, memory_order_seq_cst)
/* swaps a value with an atomic object if the old value is what is expected, otherwise reads the old value */
#define atomic_compare_exchange_weak(object, expected, desired)		\
		atomic_compare_exchange_weak_explicit(object, expected, desired, memory_order_seq_cst, memory_order_seq_cst)
/* atomic addition */
#define atomic_fetch_add(object, operand)	atomic_fetch_add_explicit(object, operand, memory_order_seq_cst)
/* atomic subtraction */
#define atomic_fetch_sub(object, operand)	atomic_fetch_sub_explicit(object, operand, memory_order_seq_cst)
/* atomic bitwise AND */
#define atomic_fetch_and(object, operand)	atomic_fetch_and_explicit(object, operand, memory_order_seq_cst)
/* atomic bitwise OR */
#define atomic_fetch_or(object, operand)  	atomic_fetch_or_explicit(object, operand, memory_order_seq_cst)
/* atomic bitwise exclusive OR */
#define atomic_fetch_xor(object, operand)	atomic_fetch_xor_explicit(object, operand, memory_order_seq_cst)
#endif

#if defined(__arm__) || defined(_M_ARM) || defined(_M_ARM64) || defined(__mips) || defined(__mips__) || defined(__mips64) || defined(__mips32) || defined(__MIPSEL__) || defined(__MIPSEB__) || defined(__sparc__) || defined(__sparc64__) || defined(__sparc_v9__) || defined(__sparcv9) || defined(__riscv) || defined(__ARM64__)
#   define __ATOMIC_PAD_LINE 32
#elif defined(__m68k__)
#   define __ATOMIC_PAD_LINE 16
#elif defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(__ppc__) || defined(__ppc) || defined(__powerpc__) || defined(_M_MPPC) || defined(_M_PPC) ||  defined(__aarch64__)  || defined(__ppc64__) || defined(__powerpc64__) || defined(__arc__)
#   define __ATOMIC_PAD_LINE 128
#elif defined(__s390__) || defined(__s390x__)
#   define __ATOMIC_PAD_LINE 256
#else
#   define __ATOMIC_PAD_LINE 64
#endif

/* The estimated size of the CPU's cache line when atomically updating memory.
 Add this much padding or align to this boundary to avoid atomically-updated
 memory from forcing cache invalidations on near, but non-atomic, memory.

 https://en.wikipedia.org/wiki/False_sharing
 https://github.com/golang/go/search?q=CacheLinePadSize
 https://github.com/ziglang/zig/blob/a69d403cb2c82ce6257bfa1ee7eba52f895c14e7/lib/std/atomic.zig#L445
*/
#define __ATOMIC_CACHE_LINE __ATOMIC_PAD_LINE

#if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)))
#pragma GCC diagnostic pop  /* long long warnings with Clang. */
#endif

#if defined(__cplusplus)
}
#endif
#endif  /* C_ATOMICS_H */
