#include "events_internal.h"

#define EVENTS_ARGS_LENGTH 32768

#ifndef max
# define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
# define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

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
		params = arrays(0);
		for (i = 0; i < num_of; i++)
			$append(params, va_arg(ap, void *));
		va_end(ap);
	}

	return params;
}

array_t arrays(size_t count, ...) {
	va_list ap;
	array_t params = NULL;
	size_t i, size = count ? count + 1 : data_queue_size();
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
	return arrays(0);
}

EVENTS_INLINE values_t data_value(void *data) {
	if (data)
		return ((data_values_ex *)data)->value;

	return data_values_empty->value;
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

array_t str_explode(const char *s, const char *delim) {
	if (str_is_empty(s))
		return null;

	if (is_empty(delim))
		delim = " ";

	array_t data = array();
	char *first = null, *_s = (char *)s;
	const char **ptrs;
	bool is_first = true;
	size_t ptrsSize, nbWords = 0, sLen = strlen(s), delimLen = strlen(delim);

	while ((_s = strstr(_s, delim))) {
		_s += delimLen;
		nbWords++;
	}

	if (nbWords > 0) {
		ptrsSize = nbWords * sizeof(char *);
		if (defer_free(ptrs = events_calloc(1, ptrsSize + sLen + 1))) {
			first = _s = str_cpy((char *)ptrs, s, sLen);
			while ((_s = strstr(_s, delim))) {
				*_s = '\0';
				if (is_first) {
					is_first = false;
					$append_string(data, first);
				}

				_s += delimLen;
				$append_string(data, _s);
			}
		} else {
			$delete(data);
			return null;
		}
	}

	return data;
}

char *str_repeat(char *str, int mult) {
	char *result;
	size_t result_len, len = strlen(str);

	if (mult < 0)
		panicking("must be greater than or equal to 0");

	/* Don't waste our time if it's empty */
	/* ... or if the multiplier is zero */
	if (len == 0 || mult == 0)
		return "";

	/* Initialize the result char **/
	result_len = len * mult;
	if (defer_free(result = events_calloc(1, result_len + 1))) {
		/* Heavy optimization for situations where input char *is 1 byte long */
		if (len == 1) {
			memset(result, *str, mult);
		} else {
			const char *s, *ee;
			char *e;
			ptrdiff_t l = 0;
			memcpy(result, str, len);
			s = result;
			e = (char *)s + len;
			ee = s + result_len;

			while (e < ee) {
				l = (e - s) < (ee - e) ? (e - s) : (ee - e);
				memmove(e, s, l);
				e += l;
			}
		}
	}

	return result;
}

char *str_pad(char *str, int length, char *pad, str_pad_type pad_type) {
	size_t pad_str_len, num_pad_chars, i;
	size_t len = 0, left_pad = 0, right_pad = 0, input_len = strlen(str);
	char *result = null;

	if (is_empty(pad)) {
		pad = " ";
		pad_str_len = 1;
	} else {
		pad_str_len = strlen(pad);
	}

	if (!pad_type)
		pad_type = STR_PAD_RIGHT; /* The padding type value */

	/* If resulting char *turns out to be shorter than input string,
	   we simply copy the input and return. */
	if (length < 0 || (size_t)length <= input_len) {
		return str;
	}

	if (pad_str_len == 0) {
		panicking("must be a non-empty string");
	}

	if (pad_type < STR_PAD_LEFT || pad_type > STR_PAD_BOTH) {
		panicking("must be STR_PAD_LEFT, STR_PAD_RIGHT, or STR_PAD_BOTH");
	}

	num_pad_chars = length - input_len;
	if (defer_free(result = events_calloc(1, input_len + num_pad_chars + 1))) {
		/* We need to figure out the left/right padding lengths. */
		switch (pad_type) {
			case STR_PAD_RIGHT:
				left_pad = 0;
				right_pad = num_pad_chars;
				break;

			case STR_PAD_LEFT:
				left_pad = num_pad_chars;
				right_pad = 0;
				break;

			case STR_PAD_BOTH:
				left_pad = num_pad_chars / 2;
				right_pad = num_pad_chars - left_pad;
				break;
		}

		/* First we pad on the left. */
		for (i = 0; i < left_pad; i++)
			result[len++] = pad[i % pad_str_len];

		/* Then we copy the input string. */
		memcpy((result + len), str, input_len);
		len += input_len;

		/* Finally, we pad on the right. */
		for (i = 0; i < right_pad; i++)
			result[len++] = pad[i % pad_str_len];
	}

	return result;
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

static data_types scheme_type(char *scheme) {
	if (str_has("http,tcp,ws,ftp", scheme))
		return DATA_TCP;
	else if (str_has("https,tls,ssl,wss,ftps", scheme))
		return DATA_TLS;
	else if (str_has("file,unix", scheme))
		return DATA_PIPE;
	else if (str_has(scheme, "udp"))
		return DATA_UDP;
	else
		return -DATA_MAXCOUNTER;
}

static const unsigned char tolower_map[256] = {
0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
0x40,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x5b,0x5c,0x5d,0x5e,0x5f,
0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,
0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,
0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
};

#define tolower_ascii(c) (tolower_map[(unsigned char)(c)])

static EVENTS_INLINE int binary_strcasecmp(const char *s1, size_t len1, const char *s2, size_t len2) {
	size_t len;
	int c1, c2;

	if (s1 == s2) return 0;
	len = min(len1, len2);
	while (len--) {
		c1 = tolower_ascii(*(unsigned char *)s1++);
		c2 = tolower_ascii(*(unsigned char *)s2++);
		if (c1 != c2) {
			return c1 - c2;
		}
	}

	return (int)(len1 - len2);
}

#define string_equals_literal_ci(str, c) \
	(strlen(str) == sizeof(c) - 1 && !binary_strcasecmp(str, strlen(str), (c), sizeof(c) - 1))

static EVENTS_INLINE const char *binary_strcspn(const char *s, const char *e, const char *chars) {
	while (*chars) {
		const char *p = memchr(s, *chars, e - s);
		if (p) e = p;
		chars++;
	}
	return e;
}

static EVENTS_INLINE char *replace_ctrl_ex(char *str, size_t len) {
	unsigned char *s = (unsigned char *)str;
	unsigned char *e = (unsigned char *)str + len;
	if (!str) return (null);
	while (s < e) {
		if (iscntrl(*s)) *s = '_';
		s++;
	}

	return (str);
}

static EVENTS_INLINE const void *str_memrchr(const void *s, int c, size_t n) {
	const unsigned char *e;
	if (0 == n) return null;
	for (e = (const unsigned char *)s + n - 1; e >= (const unsigned char *)s; e--)
		if (*e == (const unsigned char)c)
			return (const void *)e;

	return null;
}

static EVENTS_INLINE char *uri_dup(const void *src, size_t len) {
	char *ptr = (char *)events_calloc(1, len + 1);
	return is_empty(ptr) ? null : memcpy(ptr, src, len);
}

void uri_free(uri_t *uri) {
	if ((data_type(uri) > DATA_GENERATOR && data_type(uri) < DATA_WATCH)
		|| (data_type(uri) == -DATA_MAXCOUNTER) && uri->is_rejected) {
		if (uri->is_autofreeable)
			return;

		uri->type = DATA_INVALID;
		uri->port = DATA_NULL;
		uri->is_rejected = false;
		if (!is_empty(uri->scheme))
			events_free(uri->scheme);

		if (!is_empty(uri->user))
			events_free(uri->user);

		if (!is_empty(uri->pass))
			events_free(uri->pass);

		if (!is_empty(uri->host))
			events_free(uri->host);

		if (!is_empty(uri->path))
			events_free(uri->path);

		if (!is_empty(uri->query))
			events_free(uri->query);

		if (!is_empty(uri->fragment))
			events_free(uri->fragment);

		events_free(uri);
	}
}

fileinfo_t *pathinfo(char *filepath) {
	fileinfo_t *file = events_calloc(1, sizeof(fileinfo_t));
	if (defer_free(file)) {
		size_t path_len = strlen(filepath);
		char *dir_name;
		const char *p;
		ptrdiff_t idx;
		dir_name = str_trim(filepath, path_len);
#if defined(__APPLE__) || defined(__MACH__)
		file->dirname = str_dup(dirname(dir_name));
		file->filename = str_dup(basename(dir_name));
		file->base = str_dup(basename((char *)file->dirname));
#else
		dirname(dir_name);
		file->dirname = dir_name;
		file->base = basename((char *)file->dirname);
		file->filename = basename((char *)filepath);
#endif
		p = str_memrchr(file->filename, '.', strlen(file->filename));
		if (p) {
			idx = p - file->filename;
			file->extension = file->filename + idx + 1;
		}

		file->type = DATA_FILEINFO;
	}

	return file;
}

static uri_t *url_parse_ex2(char const *str, size_t length, bool *has_port, bool autofree) {
	char port_buf[6];
	char const *s, *e, *p, *pp, *ue;
	uri_t *ret = events_calloc(1, sizeof(uri_t));
	if (is_empty(ret))
		return null;

	if (autofree)
		defer_free(ret);

	ret->is_rejected = false;
	ret->is_autofreeable = autofree;

	*has_port = 0;
	s = str;
	ue = s + length;


	/* parse scheme */
	if ((e = memchr(s, ':', length)) && e != s) {
		/* validate scheme */
		p = s;
		while (p < e) {
			/* scheme = 1*[ lowalpha | digit | "+" | "-" | "." ] */
			if (!isalpha(*p) && !isdigit(*p) && *p != '+' && *p != '.' && *p != '-') {
				if (e + 1 < ue && e < binary_strcspn(s, ue, "?#")) {
					goto parse_port;
				} else if (s + 1 < ue && *s == '/' && *(s + 1) == '/') { /* relative-scheme URL */
					s += 2;
					e = 0;
					goto parse_host;
				} else {
					goto just_path;
				}
			}
			p++;
		}

		if (e + 1 == ue) { /* only scheme is available */
			ret->scheme = (autofree) ? str_trim(s, (e - s)) : uri_dup(s, (e - s));
			replace_ctrl_ex(ret->scheme, strlen(ret->scheme));
			return ret;
		}

		/*
		 * certain schemas like mailto: and zlib: may not have any / after them
		 * this check ensures we support those.
		 */
		if (*(e + 1) != '/') {
			/* check if the data we get is a port this allows us to
			 * correctly parse things like a.com:80
			 */
			p = e + 1;
			while (p < ue && isdigit(*p)) {
				p++;
			}

			if ((p == ue || *p == '/') && (p - e) < 7) {
				goto parse_port;
			}

			ret->scheme = (autofree) ? str_trim(s, (e - s)) : uri_dup(s, (e - s));
			replace_ctrl_ex(ret->scheme, strlen(ret->scheme));

			s = e + 1;
			goto just_path;
		} else {
			ret->scheme = (autofree) ? str_trim(s, (e - s)) : uri_dup(s, (e - s));
			replace_ctrl_ex(ret->scheme, strlen(ret->scheme));

			if (e + 2 < ue && *(e + 2) == '/') {
				s = e + 3;
				if (string_equals_literal_ci(ret->scheme, "file")) {
					if (e + 3 < ue && *(e + 3) == '/') {
						/* support windows drive letters as in:
						   file:///c:/somedir/file.txt
						*/
						if (e + 5 < ue && *(e + 5) == ':') {
							s = e + 4;
						}
						goto just_path;
					}
				}
			} else {
				s = e + 1;
				goto just_path;
			}
		}
	} else if (e) { /* no scheme; starts with colon: look for port */
	parse_port:
		p = e + 1;
		pp = p;

		while (pp < ue && pp - p < 6 && isdigit(*pp)) {
			pp++;
		}

		if (pp - p > 0 && pp - p < 6 && (pp == ue || *pp == '/')) {
			long port;
			char *end;
			memcpy(port_buf, p, (pp - p));
			port_buf[pp - p] = '\0';
			port = strtol(port_buf, &end, 10);
			if (port >= 0 && port <= 65535 && end != port_buf) {
				*has_port = 1;
				ret->port = (unsigned short)port;
				if (s + 1 < ue && *s == '/' && *(s + 1) == '/') { /* relative-scheme URL */
					s += 2;
				}
			} else {
				ret->is_rejected = true;
				return (autofree) ? NULL : ret;
			}
		} else if (p == pp && pp == ue) {
			ret->is_rejected = true;
			return (autofree) ? NULL : ret;
		} else if (s + 1 < ue && *s == '/' && *(s + 1) == '/') { /* relative-scheme URL */
			s += 2;
		} else {
			goto just_path;
		}
	} else if (s + 1 < ue && *s == '/' && *(s + 1) == '/') { /* relative-scheme URL */
		s += 2;
	} else {
		goto just_path;
	}

parse_host:
	e = binary_strcspn(s, ue, "/?#");

	/* check for login and password */
	if ((p = str_memrchr(s, '@', (e - s)))) {
		if ((pp = memchr(s, ':', (p - s)))) {
			ret->user = (autofree) ? str_trim(s, (pp - s)) : uri_dup(s, (pp - s));
			replace_ctrl_ex(ret->user, strlen(ret->user));

			pp++;
			ret->pass = (autofree) ? str_trim(pp, (p - pp)) : uri_dup(pp, (p - pp));
			replace_ctrl_ex(ret->pass, strlen(ret->pass));
		} else {
			ret->user = (autofree) ? str_trim(s, (p - s)) : uri_dup(s, (p - s));
			replace_ctrl_ex(ret->user, strlen(ret->user));
		}

		s = p + 1;
	}

	/* check for port */
	if (s < ue && *s == '[' && *(e - 1) == ']') {
		/* Short circuit portscan,
		   we're dealing with an
		   IPv6 embedded address */
		p = NULL;
	} else {
		p = str_memrchr(s, ':', (e - s));
	}

	if (p) {
		if (!ret->port) {
			p++;
			if (e - p > 5) { /* port cannot be longer then 5 characters */
				ret->is_rejected = true;
				return (autofree) ? NULL : ret;
			} else if (e - p > 0) {
				long port;
				char *end;
				memcpy(port_buf, p, (e - p));
				port_buf[e - p] = '\0';
				port = strtol(port_buf, &end, 10);
				if (port >= 0 && port <= 65535 && end != port_buf) {
					*has_port = 1;
					ret->port = (unsigned short)port;
				} else {
					ret->is_rejected = true;
					return (autofree) ? NULL : ret;
				}
			}
			p--;
		}
	} else {
		p = e;
	}

	/* check if we have a valid host, if we don't reject the char *as url */
	if ((p - s) < 1) {
		ret->is_rejected = true;
		return (autofree) ? NULL : ret;
	}

	ret->host = (autofree) ? str_trim(s, (p - s)) : uri_dup(s, (p - s));
	replace_ctrl_ex(ret->host, strlen(ret->host));

	if (e == ue) {
		return ret;
	}

	s = e;

just_path:

	e = ue;
	p = memchr(s, '#', (e - s));
	if (p) {
		p++;
		if (p < e) {
			ret->fragment = (autofree) ? str_trim(p, (e - p)) : uri_dup(p, (e - p));
			replace_ctrl_ex(ret->fragment, strlen(ret->fragment));
		}
		e = p - 1;
	}

	p = memchr(s, '?', (e - s));
	if (p) {
		p++;
		if (p < e) {
			ret->query = (autofree) ? str_trim(p, (e - p)) : uri_dup(p, (e - p));
			replace_ctrl_ex(ret->query, strlen(ret->query));
		}
		e = p - 1;
	}

	if (s < e || s == ue) {
		ret->path = (autofree) ? str_trim(s, (e - s)) : uri_dup(s, (e - s));
		replace_ctrl_ex(ret->path, strlen(ret->path));
	}

	return ret;
}

static uri_t *uri_parse_ex(const char *str, size_t length, bool autofree) {
	bool has_port;
	return url_parse_ex2(str, length, &has_port, autofree);
}

uri_t *parse_uri_ex(const char *str) {
	if (str_is_empty(str))
		return null;

	uri_t *uri = uri_parse_ex(str, strlen(str), false);
	uri->type = scheme_type(uri->scheme);
	if (uri->is_rejected || is_empty(uri->host)) {
		uri_free(uri);
		return null;
	}

	return uri;
}

uri_t *parse_uri(const char *url) {
	if (str_is_empty(url))
		return null;

	uri_t *uri = uri_parse_ex(url, strlen(url), true);
	if (!is_empty(uri) && is_empty(uri->host))
		return null;

	if (!is_empty(url))
		uri->type = scheme_type(uri->scheme);

	return uri;
}

static EVENTS_INLINE uint16_t utoa2p(uint64_t x) {
	static const uint8_t pairs[50] = { // 0..49, little endian
		0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
		0x01, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91,
		0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92,
		0x03, 0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83, 0x93,
		0x04, 0x14, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74, 0x84, 0x94,
	};

	uint32_t b50 = -(uint32_t)(x >= 50); // x >= 50 ? ~0 : 0;
	uint32_t x2 = x - (50u & b50);       // x2 = x % 50;
	uint16_t t = pairs[x2] + (b50 & 5);  // t = pairs[x % 50] + 5 in low nibble if x > 50

	// move upper nibble to next byte and add '00'
	return ((t | (t << 4)) & 0x0f0f) | 0x3030;
}

static EVENTS_INLINE void utoa2p_ex(uint64_t x, char *s) {
	uint16_t t = utoa2p(x);
	memcpy(s, &t, sizeof(uint16_t));
}

char *str_itoa(int64_t x) {
	char *buf = scope_local()->scrape;
	// Handle negatives
	bool neg = x < 0;
	*buf = '-'; // Always write
	buf += neg; // But advance only if negative

#if defined(__APPLE__) || defined(__MACH__)
	x = llabs(x);
#else
	x = abs(x);
#endif

	char tmp[20];
	char *p = tmp + 20;

	while (x >= 100) {
		p -= 2;
		utoa2p_ex(x % 100, p);
		x /= 100;
	}

	p -= 2;
	utoa2p_ex(x, p);

	p += x < 10;

	uint32_t len = tmp + 20 - p;

	memcpy(buf, p, 20);
	buf[len] = '\0';

	return buf;
}

#include "getopt.c"