#include "events_internal.h"

#define EVENTS_ARGS_LENGTH 32768

typedef struct array_metadata_s {
	data_types type;
	size_t size;
	size_t capacity;
	free_func destructor;
	events_cacheline_t _pad;
	atomic_spinlock lock;
} array_metadata_t;

static char EVENTS_ARGS[EVENTS_ARGS_LENGTH] = {0};
const data_values_t data_values_empty[1] = {0};

#define array_address(vec) (&((array_metadata_t *)(vec))[-1])
#define array_base(ptr) ((void *)&((array_metadata_t *)(ptr))[1])
#define array_set_context(vec, ptr) array_address(vec)->context = (ptr)
#define array_set_capacity(vec, size) array_address(vec)->capacity = (size)
#define array_set_size(vec, _size) array_address(vec)->size = (_size)
#define array_set_type(vec, _type) array_address(vec)->type = (_type)
#define array_set_destructor(vec, elem_destructor_fn) array_address(vec)->destructor = (elem_destructor_fn)
#define array_destructor(vec) array_address(vec)->destructor
#define array_mutex(vec) array_address(vec)->lock
#define array_length(vec) ((vec) ? array_address(vec)->size : (size_t)0)
#define array_type(vec) ((vec) ? array_address(vec)->type : DATA_INVALID)
#define array_cap(vec) ((vec) ? array_address(vec)->capacity : (size_t)0)
#define array_grow(vec, count)					\
    do {										\
        const size_t cv_sz__ = (count) * sizeof(*(vec)) + sizeof(array_metadata_t);	\
        if (vec) {								\
            void *cv_p1__ = array_address(vec);	\
            void *cv_p2__ = events_realloc(cv_p1__, cv_sz__);	\
            (vec) = array_base(cv_p2__);		\
        } else {								\
            void *cv_p__ = events_malloc(cv_sz__);	\
            (vec) = array_base(cv_p__);			\
            array_set_size((vec), 0);			\
            array_set_destructor((vec), NULL);	\
            array_set_type((vec), DATA_ARRAY);	\
        }										\
        array_set_capacity((vec), (count));		\
    } while (0)

#define array_reserve(vec, n)					\
    do {										\
        size_t reserve = array_cap(vec);		\
        if (reserve < (n)) {					\
            array_grow((vec), (n));				\
        }										\
    } while (0)

#ifndef in
#	define in ,
#endif

#ifndef va_copy
#  ifdef HAVE___VA_COPY
#   define va_copy(dest, src) __va_copy(dest, src)
#  else
#   define va_copy(dest, src) (dest) = (src)
#  endif
#endif

EVENTS_INLINE size_t data_size(array_t v) {
	return array_length(v);
}

EVENTS_INLINE size_t data_capacity(array_t v) {
	return array_cap(v);
}

EVENTS_INLINE atomic_spinlock *data_lock(array_t v) {
	return &array_mutex(v);
}

EVENTS_INLINE void data_reserve(array_t v, size_t capacity) {
	if (v && capacity)
		array_reserve(v, capacity);
}

EVENTS_INLINE void data_remove(array_t arr, size_t i) {
	if (arr) {
		const size_t cv_sz__ = array_length(arr);
		if ((i) < cv_sz__) {
			free_func destructor__ = array_destructor(arr);
			if (destructor__) {
				destructor__(&(arr)[i]);
			}

			array_set_size((arr), cv_sz__ - 1);
			memmove((arr)+(i), (arr)+(i)+1, sizeof(*(arr)) * (cv_sz__ - 1 - (i)));
		}
	}
}

EVENTS_INLINE void data_delete(array_t arr) {
	if (arr) {
		void *p1__ = array_address(arr);
		free_func destructor__ = array_destructor(arr);
		if (destructor__) {
			size_t i__;
			for (i__ = 0; i__ < array_length(arr); ++i__) {
				destructor__(&(arr)[i__]);
			}
		}

		array_set_type(arr, DATA_INVALID);
		events_free(p1__);
	}
}

EVENTS_INLINE void data_append(array_t arr, void *value) {
	size_t size, cv_cap__ = array_cap(arr);
	if (cv_cap__ <= array_length(arr)) {
		size = cv_cap__ << 1;
		array_grow(arr, size);
	}

	arr[array_length(arr)].object = value;
	array_set_size(arr, array_length(arr) + 1);
}

EVENTS_INLINE values_t data_pop(array_t arr) {
	size_t sz = array_length(arr);
	if (sz > 0) {
		values_t val = arr[sz - 1];
		$remove(arr, sz - 1);

		return val;
	}

	return data_values_empty->value;
}

EVENTS_INLINE values_t data_shift(array_t arr) {
	size_t sz = array_length(arr);
	if (sz > 0) {
		values_t val = arr[0];
		$remove(arr, 0);

		return val;
	}

	return data_values_empty->value;
}

void data_append_item(array_t arr, ...) {
	va_list ap;
	data_types n = DATA_INVALID;
	size_t size, cv_cap__ = array_cap(arr), index = array_length(arr);
	if (cv_cap__ <= index) {
		size = cv_cap__ << 1;
		array_grow(arr, size);
	}

	va_start(ap, arr);
	n = va_arg(ap, data_types);
	if (n == DATA_DOUBLE) {
		arr[index].precision = va_arg(ap, double);
	} else if (n == DATA_LLONG) {
		arr[index].long_long = va_arg(ap, int64_t);
	} else if (n == DATA_MAXSIZE) {
		arr[index].max_size = va_arg(ap, size_t);
	} else if (n == DATA_FUNC) {
		arr[index].func = (data_func_t)va_arg(ap, data_func_t);
	} else if (n == DATA_SHORT) {
		arr[index].s_short = (short)va_arg(ap, int);
	} else if (n == DATA_BOOL) {
		arr[index].boolean = (bool)va_arg(ap, int);
	} else if (n == DATA_CHAR) {
		arr[index].schar = (char)va_arg(ap, int);
	} else if (n == DATA_STRING) {
		arr[index].char_ptr = (char *)va_arg(ap, char *);
	} else {
		arr[index].object = va_arg(ap, void *);
	}
	va_end(ap);
	array_set_size(arr, index + 1);
}

EVENTS_INLINE array_t data_copy(array_t des, array_t src) {
	size_t cv_sz___;
	if (src) {
		des = array();
		foreach(x in src)
			$append(des, x.object);
		cv_sz___ = array_length(des);
		array_grow((des), (cv_sz___));
		array_set_type(des, array_type(src));
	}

	return des;
}

EVENTS_INLINE array_t data_reset(array_t vec) {
	if (vec) {
		free_func destructor__ = array_destructor(vec);
		if (destructor__) {
			size_t i__;
			for (i__ = 0; i__ < array_length(vec); ++i__) {
				destructor__(&(vec)[i__]);
			}
		}

		array_set_size(vec, 0);
	}

	return vec;
}

EVENTS_INLINE size_t data_queue_size(void) {
	size_t count = tasks_cpu_count();
	return 1 << ((count > 5) ? 6 : count * 2);
}

array_t data_ex(size_t num_of, va_list ap_copy) {
	va_list ap;
	size_t i;

	array_t params = NULL;
	if (num_of > 0) {
		va_copy(ap, ap_copy);
		params = data_of(0);
		for (i = 0; i < num_of; i++)
			$append(params, va_arg(ap, void *));
		va_end(ap);
	}

	return params;
}

array_t data_of(size_t count, ...) {
	va_list ap;
	size_t i;
	array_t params = NULL;
	size_t size = count ? count + 1 : data_queue_size();
	array_grow(params, size);

	if (count > 0) {
		va_start(ap, count);
		for (i = 0; i < count; i++)
			$append(params, va_arg(ap, void *));
		va_end(ap);
	}

	array_set_type(params, DATA_ARRAY);
	atomic_flag_clear(&array_mutex(params));
	return params;
}

EVENTS_INLINE array_t array(void) {
	return data_of(0);
}

EVENTS_INLINE data_types data_type(void *self) {
	return self == NULL ? DATA_INVALID : ((data_t *)self)->type;
}

EVENTS_INLINE bool is_data(void *params) {
	return (params == NULL || !is_ptr_usable(params))
		? false
		: array_type((array_t)params) == DATA_ARRAY;
}

EVENTS_INLINE bool is_ptr_usable(void *self) {
	return ((ptrdiff_t)self > 0x20000000);
}

EVENTS_INLINE char *str_cpy(char *dest, const char *src, size_t len) {
	return (char *)memcpy(dest, src, (len ? len : strlen(src)));
}

static EVENTS_INLINE char *str_memdup_ex(const void *src, size_t len, bool autofree) {
	void *ptr = events_calloc(1, len + 1);
	if (ptr != NULL) {
		if (autofree)
			defer_free(ptr);
		return (char *)memcpy(ptr, src, len);
	}

	return NULL;
}

EVENTS_INLINE char *str_trim(const char *str, size_t length) {
	return str_memdup_ex(str, length, true);
}

EVENTS_INLINE char *str_trim_at(const char *str, int pos, size_t length) {
	return str_memdup_ex((const void *)((uintptr_t)str + pos), length, true);
}

EVENTS_INLINE char *str_dup(const char *str) {
	return str_trim(str, strlen(str));
}

EVENTS_INLINE char *str_dup_ex(const char *str) {
	return str_memdup_ex(str, strlen(str), false);
}

char *str_cat(int num_args, ...) {
	va_list ap;
	size_t strsize = 0;
	char *res = NULL;
	int i;

	if (num_args > 0) {
		va_start(ap, num_args);
		for (i = 0; i < num_args; i++)
			strsize += strlen(va_arg(ap, char *));
		va_end(ap);

		if ((res = events_calloc(1, strsize + 1)) != NULL) {
			strsize = 0;
			va_start(ap, num_args);
			for (i = 0; i < num_args; i++) {
				char *s = va_arg(ap, char *);
				str_cpy(res + strsize, s, 0);
				strsize += strlen(s);
			}
			va_end(ap);
		}
	}

	return res;
}

static int _str_append(size_t offset, const char *str, size_t len) {
	strncat(EVENTS_ARGS + offset, str, len);
	return offset + len;
}

char *str_cat_argv(int argc, char **argv, int start, char *delim) {
	int i, j, len = 0;
	for (i = start; i < argc; i++) {
		len += strlen(argv[i]) + 1;
	}

	char *str = EVENTS_ARGS;
	for (i = start, j = 0; i < argc; ++i) {
		if (i > start)
			j = _str_append(j, delim, 1);
		j = _str_append(j, argv[i], strlen(argv[i]));
	}

	str[(sizeof(char) * len) - 1] = '\0';
	return str;
}

char *str_swap(const char *haystack, const char *needle, const char *swap) {
	if (!haystack || !needle || !swap)
		return NULL;

	char *result;
	size_t i, cnt = 0;
	size_t newWlen = strlen(swap);
	size_t oldWlen = strlen(needle);

	for (i = 0; haystack[i] != '\0'; i++) {
		if (strstr(&haystack[i], needle) == &haystack[i]) {
			cnt++;
			i += oldWlen - 1;
		}
	}

	if (cnt == 0)
		return NULL;

	result = (char *)events_calloc(1, i + cnt * (newWlen - oldWlen) + 1);
	i = 0;
	while (*haystack) {
		if (strstr(haystack, needle) == haystack) {
			str_cpy(&result[i], swap, newWlen);
			i += newWlen;
			haystack += oldWlen;
		} else {
			result[i++] = *haystack++;
		}
	}

	result[i] = '\0';
	return result;
}

char **str_slice(const char *s, const char *delim, int *count) {
	if ((void *)s == NULL)
		return NULL;

	if ((void *)delim == NULL)
		delim = " ";

	size_t ptrsSize, nbWords = 1, sLen = strlen(s), delimLen = strlen(delim);
	if (sLen == 0)
		return NULL;

	void *data;
	char **ptrs, *_s = (char *)s;
	while ((_s = strstr(_s, delim))) {
		_s += delimLen;
		++nbWords;
	}

	ptrsSize = (nbWords + 1) * sizeof(char *);
	ptrs = data = events_calloc(1, ptrsSize + sLen + 1);

	if (data) {
		*ptrs = _s = str_cpy((char *)data + ptrsSize, s, sLen);
		if (nbWords > 1) {
			while ((_s = strstr(_s, delim))) {
				*_s = '\0';
				_s += delimLen;
				*++ptrs = _s;
			}
		}

		*++ptrs = NULL;
		if (count)
			*count = (int)nbWords;
	}

	return data;
}

static EVENTS_INLINE char *ltrim(char *s) {
	while (isspace(*s)) s++;
	return s;
}

static EVENTS_INLINE char *rtrim(char *s) {
	char *back = s + strlen(s);
	while (isspace(*--back));
	*(back + 1) = '\0';
	return s;
}

EVENTS_INLINE char *trim(char *s) {
	return rtrim(ltrim(s));
}

int str_pos(const char *text, char *pattern) {
	size_t c, d, e, text_length, pattern_length, position = -1;
	if (pattern == NULL || (void *)text == NULL)
		return -1;

	text_length = strlen(text);
	pattern_length = strlen(pattern);

	if (pattern_length > text_length)
		return -1;

	for (c = 0; c <= text_length - pattern_length; c++) {
		position = e = c;
		for (d = 0; d < pattern_length; d++)
			if (pattern[d] == text[e])
				e++;
			else
				break;

		if (d == pattern_length)
			return (int)position;
	}

	return -1;
}

EVENTS_INLINE bool str_has(const char *text, char *pattern) {
	return str_pos(text, pattern) >= 0;
}

EVENTS_INLINE bool str_is(const char *str, const char *str2) {
	return (str != NULL && str2 != NULL) && (strcmp(str, str2) == 0);
}

EVENTS_INLINE bool str_is_empty(const char *str) {
	return is_empty(str) || strlen(str) == 0;
}

#include "getopt.c"