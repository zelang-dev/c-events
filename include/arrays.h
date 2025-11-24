#ifndef _ARRAY_H
#define _ARRAY_H

#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>

#ifndef C_API
 /* Public API qualifier. */
#   define C_API extern
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(*data_func_t)(void *);
typedef void *(*param_func_t)(param_t);
typedef intptr_t(*intptr_func_t)(intptr_t);
typedef enum {
	DATA_INVALID = -1,
	DATA_NULL,
	DATA_INT,
	DATA_ENUM,
	DATA_INTEGER,
	DATA_UINT,
	DATA_SLONG,
	DATA_LONG,
	DATA_ULONG,
	DATA_LLONG,
	DATA_MAXSIZE,
	DATA_FLOAT,
	DATA_DOUBLE,
	DATA_BOOL,
	DATA_SHORT,
	DATA_USHORT,
	DATA_CHAR,
	DATA_UCHAR,
	DATA_UCHAR_P,
	DATA_CHAR_P,
	DATA_CONST_CHAR,
	DATA_STRING,
	DATA_OBJ,
	DATA_PTR,
	DATA_FUNC,
	DATA_ARRAY
} data_types;

/* Generic simple union storage types. */
typedef union {
	int integer;
	unsigned int u_int;
	int *int_ptr;
	signed long s_long;
	unsigned long u_long;
	long long long_long;
	size_t max_size;
	uintptr_t ulong_long;
	float point;
	double precision;
	bool boolean;
	signed short s_short;
	unsigned short u_short;
	unsigned short *u_short_ptr;
	unsigned char *uchar_ptr;
	signed char schar;
	unsigned char uchar;
	char *char_ptr;
	void *object;
	ptrdiff_t **array;
	char **array_char;
	intptr_t **array_int;
	uintptr_t **array_uint;
	data_func_t func;
} values_t, *param_t, *array_t;

typedef struct {
	data_types type;
	void *value;
} data_t;

typedef struct {
	data_types type;
	values_t value;
	void *extended;
} data_values_t;

typedef struct {
	array_t group;
} task_group_t;

C_API const data_values_t data_values_empty[1];

/* Returns ~empty~ data `array`. */
C_API array_t array(void);

/**
* Creates an `array/container` for arbitrary item types.
*
* - Use standard `index` array ~access~ for retrieval of an `union` storage type.
*
* @param count numbers of parameters, `0` will create ~empty~ `array`.
* @param arguments indexed in given order.
*/
C_API array_t data_of(size_t, ...);
C_API array_t data_ex(size_t, va_list);
C_API array_t data_copy(array_t des, array_t src);
C_API void data_append(array_t, void *);
C_API values_t data_pop(array_t arr);
C_API values_t data_shift(array_t arr);
C_API void data_append_item(array_t arr, ...);
C_API void data_delete(array_t);
C_API void data_remove(array_t, size_t);
C_API array_t data_reset(array_t);
C_API size_t data_queue_size(void);
C_API bool is_data(void *);
C_API data_types data_type(void *self);
C_API bool is_ptr_usable(void *self);

#ifndef $append
#define $append(arr, value) 			data_append((array_t)arr, (void *)value)
#define $append_double(arr, value) 		data_append_item((array_t)arr, DATA_DOUBLE, (double)value)
#define $append_unsigned(arr, value)	data_append_item((array_t)arr, DATA_MAXSIZE, (size_t)value)
#define $append_signed(arr, value) 		data_append_item((array_t)arr, DATA_LLONG, (int64_t)value)
#define $append_string(arr, value) 		data_append_item((array_t)arr, DATA_STRING, (char *)value)
#define $append_func(arr, value) 		data_append_item((array_t)arr, DATA_FUNC, (data_func_t)value)
#define $append_char(arr, value) 		data_append_item((array_t)arr, DATA_CHAR, (char)value)
#define $append_bool(arr, value) 		data_append_item((array_t)arr, DATA_BOOL, (bool)value)
#define $append_short(arr, value) 		data_append_item((array_t)arr, DATA_SHORT, (short)value)
#define $remove(arr, index) 			data_remove((array_t)arr, index)
#define $pop(arr) 						data_pop((array_t)arr)
#define $shift(arr) 					data_shift((array_t)arr)
#define $reset(arr) 					data_reset((array_t)arr)
#define $size(arr) 						data_size((array_t)arr)
#define $erase(arr) 					data_delete((array_t)arr)
#define $capacity(arr) 					data_capacity((array_t)arr)
#endif

C_API bool str_is(const char *str, const char *str2);
C_API bool str_has(const char *text, char *pattern);
C_API int str_pos(const char *text, char *pattern);
C_API char *str_cpy(char *dest, const char *src, size_t len);
C_API char *str_cat(int num_args, ...);
C_API char **str_slice(const char *s, const char *delim, int *count);
C_API char *str_swap(const char *haystack, const char *needle, const char *swap);
C_API char *str_cat_argv(int argc, char **argv, int start, char *delim);

#ifndef casting
	/* Cast ~val~, a `non-pointer` to `pointer` like value,
	makes reference if variable. */
#	define casting(val) (void *)((ptrdiff_t)(val))
#endif

#ifndef Kb
#	define Kb(count) (size_t) (count * 1024)
#endif
#ifndef Mb
#	define Mb(count) (size_t) (count * 1024 * 1024)
#endif
#ifndef Gb
#	define Gb(count) (size_t) (count * 1024 * 1024 * 1024)
#endif

#ifndef kv
#	define kv(key, value) (key), (value)
#endif

#ifndef in
#	define in ,
#endif

#ifndef foreach_xp
#	define foreach_xp(X, A) X A
#endif

#define each_in(X, S) values_t X; int i##X;  \
    for (i##X = 0; i##X < (int)$size(S); i##X++)      \
        if ((X.object = S[i##X].object) || X.object == NULL)
#define each_inback(X, S) values_t X; int i##X; \
    for (i##X = (int)$size(S) - 1; i##X >= 0; i##X--)     \
        if ((X.object = S[i##X].object) || X.object == NULL)

#ifndef foreach
	/* The `foreach(`item `in` array`)` macro, similar to `C#`,
	executes a statement or a block of statements for each element in
	an instance of `array_t` */
#	define foreach(...) foreach_xp(each_in, (__VA_ARGS__))
#endif

#ifndef foreach_back
#	define foreach_back(...) foreach_xp(each_inback, (__VA_ARGS__))
#endif

#ifndef LFLF
#	define LFLF	"\n\n"
#endif
#ifndef LN_CLR
#	define LN_CLR  "\n\033[0K"
#endif
#ifndef CLR_LN
#	define CLR_LN  "\033[0K\n"
#endif
#ifndef CRLF
#	define CRLF	"\r\n"
#endif

#ifdef __cplusplus
}
#endif
#endif /* _ARRAY_H */
