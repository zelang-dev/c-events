/*
`atomic` wait free open addressing hash table implemented in C.

Code associated with the following article:
https://www.andreinc.net/2021/10/02/implementing-hash-tables-in-c-part-1

Modified from https://github.com/nomemory/open-adressing-hash-table-c
*/
#include <hashtable.h>

struct hash_pair_s {
    data_types type;
    void_t value;
	void_t key;
	uint32_t hash;
    template_t *extended;
};

make_atomic(hash_pair_t, atomic_hash_pair_t)
struct hash_s {
	data_types type;
	void_t value;
	dtor_func_t dtor;
    int overriden;
    int is_hashmap;
    key_ops_t key_ops;
    val_ops_t val_ops;
	probe_func probing;
    cacheline_pad_t pad;
    atomic_size_t capacity;
    atomic_size_t size;
    atomic_hash_pair_t **buckets;
};

// Pair related
static hash_pair_t *pair_create(uint32_t hash, const_t key, const_t value, data_types op);
static hash_pair_t *hash_operation(hash_t *, const_t key, const_t value, data_types op);
static void pair_free(hash_pair_t *pair);

enum ret_ops {
    DEL,
    PUT,
    GET
};

static size_t hash_getidx(hash_t *htable, size_t idx, uint32_t hash_val, const_t key, enum ret_ops op);
static FORCEINLINE void hash_grow(hash_t *htable);
static FORCEINLINE bool hash_should_grow(hash_t *htable);
static FORCEINLINE bool hash_is_tombstone(hash_t *htable, size_t idx);
static FORCEINLINE void hash_put_tombstone(hash_t *htable, size_t idx);

static u32 hash_initial_capacity = HASH_INIT_CAPACITY;
static bool hash_initial_override = false;
key_ops_t key_ops_string = {djb2_hash, hash_string_eq, hash_string_cp, free, nullptr};
val_ops_t val_ops_string = {hash_string_eq, hash_string_cp, free, nullptr};

static template_t *value_create(const_t data, data_types op) {
	template_t *value = calloc(1, sizeof(template_t));
	if (is_empty(value))
		panic("calloc() failed");

	switch (op) {
		case DATA_ULONG:
		case DATA_MAXSIZE:
			value->max_size = *(size_t *)data;
			break;
		case DATA_FLOAT:
		case DATA_DOUBLE:
			value->precision = *(double *)data;
			break;
		case DATA_BOOL:
			value->boolean = *(bool *)data;
			break;
		case DATA_UCHAR:
		case DATA_CHAR:
			value->schar = *(char *)data;
			break;
		case DATA_USHORT:
		case DATA_SHORT:
			value->s_short = *(short *)data;
			break;
		case DATA_INT:
		case DATA_LONG:
		case DATA_ENUM:
		case DATA_INTEGER:
			value->s_long = *(long *)data;
			break;
		case DATA_UINT:
		case DATA_SLONG:
		case DATA_LLONG:
			value->long_long = *(int64_t *)data;
			break;
		case DATA_FUNC:
			value->func = (data_func_t)data;
			break;
		case DATA_CHAR_P:
		case DATA_CONST_CHAR:
		case DATA_STRING:
			value->char_ptr = str_dup_ex((string_t)data);
			break;
		case DATA_OBJ:
		case DATA_UCHAR_P:
		case DATA_PTR:
		default:
			value->object = (void_t)data;
			break;
	}

	return value;
}

FORCEINLINE void hashmap_set(hash_t *htable) {
	htable->is_hashmap = true;
}

hash_t *hashtable_init(key_ops_t key_ops, val_ops_t val_ops, probe_func probing, u32 cap) {
	hash_t *htable = calloc(1, sizeof(*htable));
	if (is_empty(htable))
		panic("calloc() failed");

	u32 capacity = cap == 0 ? hash_initial_capacity : cap;
    atomic_init(&htable->size, 0);
    atomic_init(&htable->capacity, capacity);
    htable->overriden = cap != 0;
    htable->val_ops = val_ops;
    htable->key_ops = key_ops;
	htable->probing = probing;
	void_t bucket = calloc(1, sizeof(hash_pair_t *) * capacity);
	if (is_empty(bucket))
		panic("calloc() failed");

	atomic_init(&htable->buckets, bucket);
	htable->dtor = (dtor_func_t)hash_free;
	htable->value = htable;
	htable->type = DATA_HASHTABLE;

    return htable;
}

void pair_free(hash_pair_t *pair) {
	if (!is_empty(pair) && is_valid(pair)) {
		pair->type = DATA_INVALID;
		free((void_t)pair->extended);
		free(pair);
    } else if (!is_empty(pair) && is_type(pair, DATA_NULL)) {
        free(pair);
	}
}

void hash_free(hash_t *htable) {
	if (is_type(htable, DATA_HASHTABLE)) {
		u32 i, capacity = atomic_load(&htable->capacity);
		hash_pair_t **buckets = (hash_pair_t **)atomic_load_explicit(&htable->buckets, memory_order_consume);
		for (i = 0; i < capacity; i++) {
			if (buckets[i] && buckets[i]->key) {
				if (htable->is_hashmap) {
					if (buckets[i]->type == DATA_PTR)
						htable->key_ops._free(buckets[i]->key);
				} else {
					if (buckets[i]->type == DATA_PTR || buckets[i]->type == DATA_OBJ)
						htable->key_ops._free(buckets[i]->key);
				}

				if (!is_empty(buckets[i]->value))
					htable->val_ops._free(buckets[i]->value);
			}

			pair_free(buckets[i]);
		}

		if (buckets)
			free(buckets);

		memset(htable, DATA_INVALID, sizeof(data_types));
		free(htable);
	}
}

static FORCEINLINE void hash_grow(hash_t *htable) {
    u32 i, old_capacity;
    hash_pair_t **old_buckets;
    hash_pair_t *crt_pair;

    atomic_thread_fence(memory_order_acquire);
    old_capacity = atomic_load_explicit(&htable->capacity, memory_order_consume);
    uint64_t new_capacity_64 = old_capacity * HASH_GROWTH_FACTOR;
    if (new_capacity_64 > SIZE_MAX)
        panic("re-size overflow");

    old_buckets = (hash_pair_t **)atomic_load_explicit(&htable->buckets, memory_order_consume);
    atomic_init(&htable->capacity, (size_t)new_capacity_64);
	atomic_init(&htable->size, 0);
	void_t bucket = calloc(1, new_capacity_64 * sizeof(*(old_buckets)));
	if (is_empty(bucket))
		panic("calloc() failed");

	atomic_init(&htable->buckets, bucket);
    for (i = 0; i < old_capacity; i++) {
        crt_pair = old_buckets[i];
        if (!is_empty(crt_pair) && !hash_is_tombstone(htable, i)) {
            hash_operation(htable, crt_pair->key, crt_pair->value, crt_pair->type);
            htable->val_ops._free(crt_pair->value);
            htable->key_ops._free(crt_pair->key);
            pair_free(crt_pair);
        }
    }

    free(old_buckets);
    atomic_thread_fence(memory_order_release);
}

static FORCEINLINE bool hash_should_grow(hash_t *htable) {
    return (atomic_load(&htable->size) / atomic_load(&htable->capacity)) > (htable->overriden ? .95 : HASH_LOAD_FACTOR);
}

hash_pair_t *hash_operation(hash_t *hash, const_t key, const_t value, data_types op) {
    if (hash_should_grow(hash))
        hash_grow(hash);

    uint32_t hash_val = hash->key_ops.hash(key);
    size_t idx = hash_val % (u32)atomic_load_explicit(&hash->capacity, memory_order_relaxed);

    hash_pair_t **buckets = (hash_pair_t **)atomic_load_explicit(&hash->buckets, memory_order_acquire);
    atomic_thread_fence(memory_order_seq_cst);
	if (is_empty(buckets[idx])) {
        // Key doesn't exist & we add it anew
		buckets[idx] = pair_create(
			hash_val,
            hash->key_ops.cp(key, hash->key_ops.arg),
            hash->val_ops.cp(value, hash->val_ops.arg),
            op);
	} else {
		// // Probing for the next good index
        idx = hash_getidx(hash, idx, hash_val, key, PUT);
		if (is_empty(buckets[idx])) {
			buckets[idx] = pair_create(
                hash_val,
                hash->key_ops.cp(key, hash->key_ops.arg),
                hash->val_ops.cp(value, hash->val_ops.arg),
                op);
		} else {
			// Update the existing value
			// Free the old values
            if (buckets[idx]->type == DATA_PTR)
				hash->key_ops._free(buckets[idx]->value);

			free(buckets[idx]->extended);

			// Update the new values
			buckets[idx]->type = op;
			buckets[idx]->extended = value_create(hash->val_ops.cp(value, hash->val_ops.arg), op);
			buckets[idx]->value = buckets[idx]->extended;
            if (op == DATA_PTR)
                buckets[idx]->value = buckets[idx]->extended->object;

            buckets[idx]->hash = hash_val;
            atomic_fetch_sub(&hash->size, 1);
        }
    }

    atomic_store_explicit(&hash->buckets, buckets, memory_order_release);
    atomic_fetch_add(&hash->size, 1);
    return buckets[idx];
}

FORCEINLINE void_t hash_put(hash_t *htable, const_t key, const_t value) {
    return (void_t)hash_operation(htable, key, value, DATA_OBJ);
}

FORCEINLINE void_t hash_put_str(hash_t *htable, const_t key, string value) {
    return hash_operation(htable, key, value, DATA_PTR);
}

FORCEINLINE hash_pair_t *insert_func(hash_t *htable, const_t key, func_args_t value) {
    return hash_operation(htable, key, value, DATA_FUNC);
}

FORCEINLINE hash_pair_t *insert_unsigned(hash_t *htable, const_t key, size_t value) {
    return hash_operation(htable, key, &value, DATA_MAXSIZE);
}

FORCEINLINE hash_pair_t *insert_signed(hash_t *htable, const_t key, int64_t value) {
    return hash_operation(htable, key, &value, DATA_LLONG);
}

FORCEINLINE hash_pair_t *insert_number(hash_t *htable, const_t key, long value) {
    return hash_operation(htable, key, &value, DATA_LONG);
}

FORCEINLINE hash_pair_t *insert_double(hash_t *htable, const_t key, double value) {
    return hash_operation(htable, key, &value, DATA_DOUBLE);
}

FORCEINLINE hash_pair_t *insert_string(hash_t *htable, const_t key, string value) {
	return hash_operation(htable, key, value, DATA_CONST_CHAR);
}

FORCEINLINE hash_pair_t *insert_bool(hash_t *htable, const_t key, bool value) {
    return hash_operation(htable, key, &value, DATA_BOOL);
}

FORCEINLINE hash_pair_t *insert_char(hash_t *htable, const_t key, char value) {
    return hash_operation(htable, key, &value, DATA_CHAR);
}

FORCEINLINE hash_pair_t *insert_short(hash_t *htable, const_t key, short value) {
    return hash_operation(htable, key, &value, DATA_SHORT);
}

void_t hash_replace(hash_t *htable, const_t key, const_t value) {
    if (hash_should_grow(htable))
        hash_grow(htable);

    uint32_t hash_val = htable->key_ops.hash(key);
    size_t sz, idx = hash_val % (u32)atomic_load(&htable->capacity);

    // // Probing for the next good index
    idx = hash_getidx(htable, idx, hash_val, key, PUT);

    hash_pair_t **buckets = (hash_pair_t **)atomic_load_explicit(&htable->buckets, memory_order_acquire);
	atomic_thread_fence(memory_order_seq_cst);

	// Update the new values
	if (buckets[idx]->type == DATA_CONST_CHAR && is_ptr_usable((void_t)value)) {
		sz = (strlen(buckets[idx]->extended->const_char_ptr) + strlen(value)) + 1;
		buckets[idx]->extended->object = realloc(buckets[idx]->extended->object, sz);
		snprintf(buckets[idx]->extended->char_ptr, sz, "%s", (string_t)value);
	} else {
    	buckets[idx]->extended->object = (void_t)value;
	}

    buckets[idx]->value = buckets[idx]->extended;
    atomic_store_explicit(&htable->buckets, buckets, memory_order_release);
    return buckets[idx];
}

static FORCEINLINE bool hash_is_tombstone(hash_t *htable, size_t idx) {
    hash_pair_t *buckets = (hash_pair_t *)atomic_load(&htable->buckets[idx]);
    if (is_empty(buckets))
        return false;

    if (is_empty(buckets->key) && is_empty(buckets->value) && 0 == buckets->hash)
        return true;

    return false;
}

static FORCEINLINE void hash_put_tombstone(hash_t *htable, size_t idx) {
    if (!is_empty(atomic_get(void_t, &htable->buckets[idx]))) {
        hash_pair_t **buckets = (hash_pair_t **)atomic_load_explicit(&htable->buckets, memory_order_acquire);
        atomic_thread_fence(memory_order_seq_cst);
        buckets[idx]->hash = 0;
        buckets[idx]->key = nullptr;
        buckets[idx]->value = nullptr;
        buckets[idx]->type = DATA_NULL;
        atomic_store_explicit(&htable->buckets, buckets, memory_order_release);
    }
}

template_t *hash_get_value(hash_t *htable, const_t key) {
	return (template_t *)hash_get(htable, key);
}

void_t hash_get(hash_t *htable, const_t key) {
    uint32_t hash_val = htable->key_ops.hash(key);
    size_t idx = hash_val % (u32)atomic_load(&htable->capacity);

    if (is_empty(atomic_load(&htable->buckets[idx])))
        return nullptr;

    idx = hash_getidx(htable, idx, hash_val, key, GET);

    return is_empty(atomic_get(void_t, &htable->buckets[idx]))
        ? nullptr
        : (atomic_get(hash_pair_t *, &htable->buckets[idx]))->value;
}

hash_pair_t *hash_get_pair(hash_t *htable, const_t key) {
    uint32_t hash_val = htable->key_ops.hash(key);
    size_t idx = hash_val % (u32)atomic_load(&htable->capacity);

    if (is_empty(atomic_load(&htable->buckets[idx])))
        return nullptr;

    idx = hash_getidx(htable, idx, hash_val, key, GET);

    return is_empty(atomic_get(void_t, &htable->buckets[idx]))
        ? nullptr
        : (atomic_get(hash_pair_t *, &htable->buckets[idx]));
}

FORCEINLINE bool hash_pair_is_null(hash_pair_t *pair) {
    return is_empty(pair) || is_empty(pair->extended) || is_empty(pair->extended->object);
}

FORCEINLINE template_t hash_pair_value(hash_pair_t *pair) {
    if (!hash_pair_is_null(pair))
        return *pair->extended;

	return data_values_empty->value;
}

FORCEINLINE string_t hash_pair_key(hash_pair_t *pair) {
    return (string_t)pair->key;
}

FORCEINLINE data_types hash_pair_type(hash_pair_t *pair) {
    return pair->type;
}

bool hash_has(hash_t *htable, const_t key) {
    uint32_t hash_val = htable->key_ops.hash(key);
    size_t idx = hash_val % (u32)atomic_load(&htable->capacity);

    if (is_empty(atomic_load(&htable->buckets[idx])))
        return false;

    idx = hash_getidx(htable, idx, hash_val, key, GET);

    return is_empty(atomic_get(void_t, &htable->buckets[idx])) ? false : true;
}

void hash_delete(hash_t *htable, const_t key) {
    uint32_t hash_val = htable->key_ops.hash(key);
    size_t idx = hash_val % (u32)atomic_load(&htable->capacity);

    if (is_empty(atomic_load(&htable->buckets[idx])))
        return;

    idx = hash_getidx(htable, idx, hash_val, key, DEL);
    if (is_empty(atomic_get(void_t, &htable->buckets[idx])))
        return;

    hash_pair_t **buckets = (hash_pair_t **)atomic_load_explicit(&htable->buckets, memory_order_acquire);
    atomic_thread_fence(memory_order_seq_cst);
    free(buckets[idx]->extended);
    htable->key_ops._free(buckets[idx]->key);
    if (buckets[idx]->type == DATA_PTR)
        htable->key_ops._free(buckets[idx]->value);

    atomic_store_explicit(&htable->buckets, buckets, memory_order_release);
    atomic_fetch_sub(&htable->size, 1);

    hash_put_tombstone(htable, idx);
}

void hash_printer(hash_t *htable, print_key k, print_val v) {
    hash_pair_t *pair;
    u32 i, capacity = (u32)atomic_load(&htable->capacity);

    printf("Hash Capacity: %zu\n", (size_t)capacity);
    printf("Hash Size: %zu\n", (size_t)atomic_load(&htable->size));

    printf("Hash Buckets:\n");
    hash_pair_t **buckets = (hash_pair_t **)atomic_load(&htable->buckets);
    for (i = 0; i < capacity; i++) {
        pair = buckets[i];
        if (!is_empty(pair)) {
            printf("\tbucket[%d]:\n", i);
            if (hash_is_tombstone(htable, i)) {
                printf("\t\t TOMBSTONE");
            } else {
                printf("\t\thash=%" PRIu32 ", key=", pair->hash);
                k(pair->key);
                printf(", value=");
                v(pair->value);
            }
            printf("\n");
        }
    }
}

void_t hash_iter(hash_t *htable, void_t variable, hash_iter_func func) {
    hash_pair_t *pair;
    u32 i, capacity = (u32)atomic_load(&htable->capacity);
    hash_pair_t **buckets = (hash_pair_t **)atomic_load(&htable->buckets);
    for (i = 0; i < capacity; i++) {
        pair = buckets[i];
        if (!is_empty(pair))
            variable = func(variable, pair->key, pair->value);
    }

    return variable;
}

static size_t hash_getidx(hash_t *htable, size_t idx, uint32_t hash_val,
                          const_t key, enum ret_ops op) {
    do {
        if (op == PUT && hash_is_tombstone(htable, idx))
            break;

        if ((atomic_get(hash_pair_t *, &htable->buckets[idx]))->hash == hash_val &&
            htable->key_ops.eq(key, (atomic_get(hash_pair_t *, &htable->buckets[idx]))->key, htable->key_ops.arg)) {
            break;
        }

        htable->probing(htable, &idx);
    } while (!is_empty(atomic_get(void_t, &htable->buckets[idx])));
    return idx;
}

hash_pair_t *pair_create(uint32_t hash, const_t key, const_t value, data_types op) {
	hash_pair_t *p = calloc(1, sizeof(hash_pair_t));
	if (is_empty(p))
		panic("calloc() failed");

	p->type = op;
    p->extended = value_create(value, op);
    p->hash = hash;
    p->value = p->extended;
    if (op == DATA_PTR)
        p->value = p->extended->object;

    p->key = (void_t)key;

    return p;
}

FORCEINLINE void hash_lp_idx(hash_t *htable, size_t *idx) {
    (*idx)++;
    if ((*idx) == (size_t)atomic_load(&htable->capacity))
        (*idx) = 0;
}

FORCEINLINE bool hash_string_eq(const_t data1, const_t data2, void_t arg) {
    string_t str1 = (string_t)data1;
    string_t str2 = (string_t)data2;
    return !(strcmp(str1, str2)) ? true : false;
}

FORCEINLINE void_t hash_string_cp(const_t data, void_t arg) {
	(void)arg;
	return (void_t)str_dup_ex((string_t)data);
}

// String operations
static FORCEINLINE uint32_t hash_fmix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x3243f6a9U;
    h ^= h >> 16;
    return h;
}

FORCEINLINE uint32_t djb2_hash(const_t data) {
    // djb2
    uint32_t hash = (const uint32_t)5381;
    string_t str = (string_t)data;
    char c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash_fmix32(hash);
}

FORCEINLINE void string_print(const_t data) {
    cout("%s", (string_t)data);
}

static FORCEINLINE void_t plain_cp(const_t data, void_t arg) {
    return (void_t)data;
}

static FORCEINLINE bool plain_eq(const_t data1, const_t data2, void_t arg) {
    return memcmp(data1, data2, sizeof(data2)) == 0;
}

static FORCEINLINE void plain_free(void_t data) {
}

val_ops_t val_ops_value = {plain_eq, plain_cp, plain_free, nullptr};

FORCEINLINE hash_t *hash_create(void) {
    return (hash_t *)hashtable_init(key_ops_string, val_ops_value, hash_lp_idx, 0);
}

FORCEINLINE hash_t *hash_create_ex(u32 size) {
    return (hash_t *)hashtable_init(key_ops_string, val_ops_value, hash_lp_idx, size);
}

FORCEINLINE void hash_set_capacity(u32 buckets) {
    atomic_thread_fence(memory_order_seq_cst);
    hash_initial_capacity = buckets;
    hash_initial_override = true;
}

FORCEINLINE size_t hash_count(hash_t *htable) {
    return (size_t)atomic_load_explicit(&htable->size, memory_order_relaxed);
}

FORCEINLINE size_t hash_capacity(hash_t *htable) {
    return (size_t)atomic_load_explicit(&htable->capacity, memory_order_relaxed);
}

FORCEINLINE hash_pair_t *hash_buckets(hash_t *htable, u32 index) {
    return (hash_pair_t *)atomic_load_explicit(&htable->buckets[index], memory_order_relaxed);
}

FORCEINLINE void hash_print(hash_t *htable) {
    hash_printer(htable, string_print, string_print);
}

FORCEINLINE void hash_print_custom(hash_t *htable, print_key k, print_val v) {
    hash_printer(htable, k, v);
}

FORCEINLINE bool is_type(void_t self, data_types check) {
	return !is_empty(self) && data_type(self) == check;
}

FORCEINLINE bool is_value(void_t self) {
	return (data_type(self) > DATA_NULL) && (data_type(self) < DATA_RESULT);
}

FORCEINLINE bool is_instance(void_t self) {
	return (data_type(self) > DATA_RESULT) && (data_type(self) < DATA_GUARDED_STATUS);
}

FORCEINLINE bool is_valid(void_t self) {
	return is_value(self) || is_instance(self);
}

FORCEINLINE bool is_union(void_t self) {
	return data_type(self) > DATA_FUNC && data_type(self) < DATA_HASHTABLE;
}
