#include <map.h>

struct map_item_s {
	data_types type;
	u32 indic;
	template_t value;
	string_t key;
	map_item_t *prev;
	map_item_t *next;
};

struct map_s {
	data_types type;
	void *value;
	dtor_func_t dtor;
	data_types_ex item_type;
	int is_autofree;
	bool started;
	bool sliced;
	u32 indices;
	u32 num_slices;
	int64_t length;
	hash_t *dict;
	slice_t *slice;
	map_item_t *head;
	map_item_t *tail;
};

struct map_iterator_s {
	data_types type;
	bool forward;
	map_t hash;
	map_item_t *item;
};

static void map_add_pair(map_t hash, hash_pair_t *kv) {
	map_item_t *item = (map_item_t *)calloc(1, sizeof(map_item_t));
	if (is_empty(item))
		panic("calloc() failed");

	if (hash->item_type == DATA_MAP_ARR)
		item->indic = hash->indices;
	else
		item->indic = hash->indices++;

	item->key = hash_pair_key(kv);
	item->value = hash_pair_value(kv);
	item->prev = hash->tail;
	item->next = nullptr;
	item->type = hash_pair_type(kv);

	hash->tail = item;
	hash->length++;

	if (!hash->head)
		hash->head = item;
	else
		item->prev->next = item;
}

static map_t map_for_ex(map_t hash, u32 num_pairs, va_list ap_copy) {
	va_list ap;
	data_types n = DATA_INVALID;
	map_item_t *item;
	hash_pair_t *kv;
	void_t has_it;
	string k;
	u32 i;

	if (is_empty(hash))
		hash = map_create();

	if (num_pairs > 0) {
		hash->item_type = DATA_MAP_VALUE;
		va_copy(ap, ap_copy);
		for (i = 0; i < num_pairs; i++) {
			n = va_arg(ap, data_types);
			k = va_arg(ap, string);
			has_it = hash_get(hash->dict, k);
			if (is_empty(has_it)) {
				if (n == DATA_DOUBLE || n == DATA_FLOAT) {
					kv = insert_double(hash->dict, k, va_arg(ap, double));
				} else if (n == DATA_LONG || n == DATA_INT || n == DATA_INTEGER || n == DATA_ENUM) {
					kv = insert_number(hash->dict, k, va_arg(ap, long));
				} else if (n == DATA_LLONG) {
					kv = insert_signed(hash->dict, k, va_arg(ap, int64_t));
				} else if (n == DATA_MAXSIZE) {
					kv = insert_unsigned(hash->dict, k, va_arg(ap, size_t));
				} else if (n == DATA_FUNC) {
					kv = insert_func(hash->dict, k, va_arg(ap, func_args_t));
				} else if (n == DATA_SHORT) {
					kv = insert_short(hash->dict, k, va_arg(ap, int));
				} else if (n == DATA_BOOL) {
					kv = insert_bool(hash->dict, k, va_arg(ap, int));
				} else if (n == DATA_CHAR) {
					kv = insert_char(hash->dict, k, va_arg(ap, int));
				} else if (n == DATA_STRING) {
					kv = insert_string(hash->dict, k, va_arg(ap, string));
					if (hash->is_autofree)
						defer_free(hash_pair_value(kv).object);
				} else {
					kv = (hash_pair_t *)hash_put(hash->dict, k, va_arg(ap, void_t));
				}

				if (hash->is_autofree)
					defer_free((void_t)hash_pair_key(kv));
				map_add_pair(hash, kv);
			} else {
				for (item = hash->head; item; item = item->next) {
					if (item->value.char_ptr == ((template_t *)has_it)->char_ptr) {
						kv = (hash_pair_t *)hash_replace(hash->dict, k, va_arg(ap, void_t));
						item->value = hash_pair_value(kv);
						item->type = hash_pair_type(kv);
						break;
					}
				}
			}
		}
		va_end(ap);
	}

	return hash;
}

static void slice_free(slice_t array) {
	map_item_t *tmp, *next;
	slice_t each;
	u32 i;

	if (is_empty(array))
		return;

	for (i = 0; i <= array->num_slices; i++) {
		each = array->slice[array->num_slices - i];
		if (each) {
			while (each->head) {
				next = each->head->next;
				tmp = each->head;
				free(tmp);
				each->head = next;
			}
			free(each);
		}
	}

	free(array->slice);
}

static void slice_set(slice_t array, hash_pair_t *p, int64_t index) {
	if (!is_empty(p)) {
		struct map_item_s *item = (struct map_item_s *)calloc(1, sizeof(struct map_item_s));
		if (is_empty(item))
			panic("calloc() failed");

		item->indic = index;
		item->key = hash_pair_key(p);
		item->value = hash_pair_value(p);
		item->prev = array->tail;
		item->next = nullptr;
		item->type = hash_pair_type(p);

		array->tail = item;
		array->length++;

		if (!array->head)
			array->head = item;
		else
			item->prev->next = item;
	}
}

slice_t slice(map_array_t array, int64_t start, int64_t end) {
	if (array->item_type != DATA_MAP_ARR)
		panic("slice() only accept `map_array_t` type!");

	if (array->num_slices % 64 == 0) {
		array->slice = realloc(array->slice, (array->num_slices + 64) * sizeof(array->slice[0]));
		if (array->slice == nullptr)
			panic("realloc() failed");
	}

	slice_t slice = (slice_t)calloc(1, sizeof(_map_t));
	if (is_empty(slice))
		panic("calloc() failed");

	int64_t i, index = 0;
	for (i = start; i < end; i++) {
		slice_set(slice, hash_get_pair(array->dict, str_itoa(i)), index);
		index++;
	}

	slice->sliced = true;
	slice->value = array->value;
	slice->type = array->type;
	slice->dict = array->dict;
	slice->item_type = array->item_type;
	array->slice[array->num_slices++] = slice;
	array->slice[array->num_slices] = nullptr;

	return slice;
}

static string_t slice_find(map_array_t array, int64_t index) {
	struct map_item_s *item;
	if (is_empty(array) || !array->sliced)
		return nullptr;

	for (item = array->head; item != nullptr; item = item->next) {
		if (item->indic == index)
			return item->key;
	}

	return nullptr;
}

FORCEINLINE void slice_put(slice_t hash, int64_t index, void_t value) {
	map_put(hash, slice_find(hash, index), value);
}

FORCEINLINE template_t slice_get(slice_t hash, int64_t index) {
	return map_get(hash, slice_find(hash, index));
}

FORCEINLINE void_t slice_delete(slice_t hash, int64_t index) {
	return map_delete(hash, slice_find(hash, index));
}

map_t map_create(void) {
	map_t hash = (map_t)malloc(sizeof(struct map_s));
	if (is_empty(hash))
		panic("malloc() failed");

	hash->started = false;
	hash->is_autofree = false;
	hash->dict = hash_create_ex(0);
	hashmap_set(hash->dict);
	hash->value = hash->dict;
	hash->dtor = (dtor_func_t)map_free;
	hash->type = DATA_MAP;
	return hash;
}

FORCEINLINE map_t maps(void) {
	map_t hash = map_create();
	hash->is_autofree = true;
	defer(map_free, hash);

	return hash;
}

map_t map_for(u32 num_pairs, ...) {
	va_list argp;
	map_t hash;

	va_start(argp, num_pairs);
	hash = map_for_ex(nullptr, num_pairs, argp);
	va_end(argp);

	return hash;
}

static void map_append(map_array_t hash, data_types type, void_t value) {
	hash_pair_t *kv;

	if (!hash->started) {
		hash->started = true;
		hash->indices = 0;
	} else {
		hash->indices++;
	}

	const_t k = (const_t)str_itoa(hash->indices);
	if (type == DATA_DOUBLE || type == DATA_FLOAT) {
		kv = insert_double(hash->dict, k, *(double *)&value);
	} else if (type == DATA_LONG || type == DATA_INT ||type == DATA_INTEGER || type == DATA_ENUM) {
		kv = insert_number(hash->dict, k, *(long *)&value);
	} else if (type == DATA_LLONG) {
		kv = insert_signed(hash->dict, k, *(int64_t *)&value);
	} else if (type == DATA_MAXSIZE) {
		kv = insert_unsigned(hash->dict, k, *(size_t *)&value);
	} else if (type == DATA_FUNC) {
		kv = insert_func(hash->dict, k, (func_args_t)value);
	} else if (type == DATA_SHORT) {
		kv = insert_short(hash->dict, k, *(short *)&value);
	} else if (type == DATA_BOOL) {
		kv = insert_bool(hash->dict, k, *(bool *)&value);
	} else if (type == DATA_CHAR) {
		kv = insert_char(hash->dict, k, *(char *)&value);
	} else if (type == DATA_STRING) {
		kv = insert_string(hash->dict, k, (string)value);
		defer_free(hash_pair_value(kv).object);
	} else {
		kv = (hash_pair_t *)hash_put(hash->dict, k, value);
	}

	defer_free((void_t)hash_pair_key(kv));
	map_add_pair(hash, kv);
}

map_array_t map_array(array_type type, u32 num_items, ...) {
	map_array_t array = maps();
	va_list argp;
	u32 i;

	array->num_slices = 0;
	array->item_type = DATA_MAP_ARR;
	va_start(argp, num_items);
	for (i = 0; i < num_items; i++)
		map_append(array, type, va_arg(argp, void_t));
	va_end(argp);
	array->value = array;
	return array;
}

void map_free(map_t hash) {
	map_item_t *next;

	if (!hash)
		return;

	if (is_type(hash, DATA_MAP)) {
		hash->type = DATA_INVALID;
		while (hash->head) {
			next = hash->head->next;
			free(hash->head);
			hash->head = next;
		}

		hash_free(hash->dict);
		if (!is_empty(hash->slice))
			slice_free(hash);

		free(hash);
	}
}

void map_push(map_t hash, void_t value) {
	char hash_key[ARRAY_SIZE] = {0};
	hash_pair_t *kv;

	if (!hash->started) {
		hash->started = true;
		hash->indices = 0;
	} else {
		hash->indices++;
	}

	snprintf(hash_key, ARRAY_SIZE,"%d", hash->indices);
	kv = (hash_pair_t *)hash_put(hash->dict, hash_key, value);
	map_add_pair(hash, kv);
}

template_t map_pop(map_t hash) {
	template_t value;
	map_item_t *item;

	if (!hash || !hash->tail)
		return data_values_empty->value;

	item = hash->tail;
	hash->tail = hash->tail->prev;
	hash->length--;

	if (hash->length == 0)
		hash->head = nullptr;

	value = item->value;
	free((void_t)item->key);
	free(item);

	return value;
}

u32 map_shift(map_t hash, void_t value) {
	char hash_key[ARRAY_SIZE] = {0};
	map_item_t *item;
	hash_pair_t *kv;

	if (!hash)
		return -1;

	item = (map_item_t *)calloc(1, sizeof(map_item_t));
	if (is_empty(item))
		panic("calloc() failed");

	item->type = (data_types)DATA_MAP_VALUE;
	item->prev = nullptr;
	item->next = hash->head;
	if (hash->head == nullptr)
		item->indic = 0;
	else
		item->indic = --item->next->indic;

	hash->head = item;
	hash->length++;

	if (!hash->tail)
		hash->tail = item;
	else
		item->next->prev = item;

	snprintf(hash_key, ARRAY_SIZE, "%d", item->indic);
	kv = (hash_pair_t *)hash_put(hash->dict, hash_key, value);
	item->key = hash_pair_key(kv);
	item->value = hash_pair_value(kv);
	item->type = hash_pair_type(kv);

	return item->indic;
}

template_t map_unshift(map_t hash) {
	template_t value;
	map_item_t *item;

	if (!hash || !hash->head)
		return data_values_empty->value;

	item = hash->head;
	hash->head = hash->head->next;
	hash->length--;

	if (hash->length == 0)
		hash->tail = nullptr;

	value = item->value;
	free((void_t)item->key);
	free(item);

	return value;
}

FORCEINLINE size_t map_count(map_t hash) {
	if (hash)
		return hash->length;

	return 0;
}

static FORCEINLINE bool is_equal(void_t mem, void_t mem2) {
	return memcmp(mem, mem2, sizeof(mem2)) == 0;
}

void_t map_remove(map_t hash, void_t value) {
	map_item_t *item;

	if (!hash)
		return nullptr;

	for (item = hash->head; item != nullptr; item = item->next) {
		if (is_equal(item->value.object, value)) {
			hash_delete(hash->dict, item->key);
			if (item->prev)
				item->prev->next = item->next;
			else
				hash->head = item->next;

			if (item->next)
				item->next->prev = item->prev;
			else
				hash->tail = item->prev;

			free(item);
			hash->length--;

			return value;
		}
	}

	return nullptr;
}

FORCEINLINE void_t map_delete(map_t hash, string_t key) {
	if (!hash)
		return nullptr;

	return map_remove(hash, hash_get(hash->dict, key));
}

FORCEINLINE template_t map_get(map_t hash, string_t key) {
	return data_value(hash_get(hash->dict, key));
}

FORCEINLINE void map_put(map_t hash, string_t key, void_t value) {
	map_item_t *item;
	hash_pair_t *kv;
	void_t has_it = hash_get(hash->dict, key);
	if (is_empty(has_it)) {
		kv = (hash_pair_t *)hash_put(hash->dict, key, value);
		map_add_pair(hash, kv);
	} else {
		for (item = hash->head; item; item = item->next) {
			if (item->value.object == ((template_t *)has_it)->object) {
				kv = (hash_pair_t *)hash_replace(hash->dict, key, value);
				item->value = hash_pair_value(kv);
				item->type = hash_pair_type(kv);
				break;
			}
		}
	}
}

map_t map_insert(map_t hash, ...) {
	va_list ap;
	va_start(ap, hash);
	hash = map_for_ex(hash, 1, ap);
	va_end(ap);

	return hash;
}

map_iter_t *iter_create(map_t hash, bool forward) {
	if (hash && hash->head) {
		map_iter_t *iterator;

		iterator = (map_iter_t *)calloc(1, sizeof(map_iter_t));
		if (is_empty(iterator))
			panic("calloc() failed");

		iterator->hash = hash;
		iterator->item = forward ? hash->head : hash->tail;
		iterator->forward = forward;
		iterator->type = (data_types)DATA_MAP_ITER;

		return iterator;
	}

	return nullptr;
}

map_iter_t *iter_next(map_iter_t *iterator) {
	if (iterator) {
		map_item_t *item;

		item = iterator->forward ? iterator->item->next : iterator->item->prev;
		if (item) {
			iterator->item = item;
			return iterator;
		} else {
			free(iterator);
			return nullptr;
		}
	}

	return nullptr;
}

FORCEINLINE template_t iter_value(map_iter_t *iterator) {
	if (iterator)
		return iterator->item->value;

	return data_values_empty->value;
}

FORCEINLINE data_types iter_type(map_iter_t *iterator) {
	if (iterator)
		return iterator->item->type;

	return DATA_INVALID;
}

FORCEINLINE string_t iter_key(map_iter_t *iterator) {
	if (iterator)
		return iterator->item->key;

	return nullptr;
}

map_iter_t *iter_remove(map_iter_t *iterator) {
	map_item_t *item;

	if (!iterator)
		return nullptr;

	item = iterator->forward ? iterator->hash->head : iterator->hash->tail;
	while (item) {
		if (iterator->item == item) {
			if (iterator->hash->head == item)
				iterator->hash->head = item->next;
			else
				item->prev->next = item->next;

			if (iterator->hash->tail == item)
				iterator->hash->tail = item->prev;
			else
				item->next->prev = item->prev;

			iterator->hash->length--;

			iterator->item = iterator->forward ? item->next : item->prev;
			free(item);
			if (iterator->item) {
				return iterator;
			} else {
				free(iterator);
				return nullptr;
			}
		}

		item = iterator->forward ? item->next : item->prev;
	}

	return iterator;
}

void println(u32 num_args, ...) {
	va_list argp;
	void_t arguments;
	array_t variants;
	range_t lists;
	map_t *list;
	data_types type;
	u32 i;

	va_start(argp, num_args);
	for (i = 0; i < num_args; i++) {
		arguments = va_arg(argp, void_t);
		if (is_type(((map_t *)arguments), DATA_MAP)) {
			list = (map_t *)arguments;
			foreach_map(item in list) {
				type = iter_type(item);
				switch (type) {
					case DATA_INT:
					case DATA_ENUM:
					case DATA_LONG:
					case DATA_INTEGER:
						printf("%d ", (int)has(item).integer);
						break;
					case DATA_LLONG:
						printf("%lld ", (long long)has(item).long_long);
						break;
					case DATA_MAXSIZE:
						printf("%zu ", has(item).max_size);
						break;
					case DATA_FLOAT:
						printf("%f ", has(item).point);
						break;
					case DATA_DOUBLE:
						printf("%.6f  ", has(item).precision);
						break;
					case DATA_STRING:
					case DATA_CHAR_P:
					case DATA_CONST_CHAR:
						printf("%s ", has(item).const_char_ptr);
						break;
					case DATA_CHAR:
						printf("%c ", has(item).schar);
						break;
					case DATA_USHORT:
					case DATA_SHORT:
						printf("%hd ", has(item).u_short);
						break;
					case DATA_OBJ:
					case DATA_PTR:
						printf("%p ", has(item).object);
						break;
					case DATA_BOOL:
						printf(has(item).boolean ? "true " : "false ");
						break;
					case DATA_ARRAY:
						variants = (array_t)has(item).object;
						foreach(v in variants)
							printf("%p, ", v.object);
						break;
					case DATA_RANGE:
						lists = (range_t)has(item).object;
						foreach(l in lists)
							printf("%lld, ", l.long_long);
						break;
					case DATA_RANGE_CHAR:
						lists = (range_t)has(item).object;
						foreach(c in lists)
							printf("%c", c.schar);
						break;
					case DATA_INVALID:
					default:
						printf("invalid: type: %d on %p ", type, item);
						break;
				}
			}
		} else if (is_data(arguments)) {
			variants = (array_t)arguments;
			foreach(v in variants)
				printf("%p, ", v.object);
		} else if (is_valid(arguments) || is_union(arguments)) {
			type = data_type(arguments);
			switch (type) {
				case (DATA_STRING):
				case (DATA_CHAR_P):
				case (DATA_CONST_CHAR):
					printf("%s ", data_value(arguments).const_char_ptr);
					break;
				case (DATA_CHAR):
				case (DATA_BOOL):
					printf(data_value(arguments).boolean ? "true " : "false ");
					break;
				case (DATA_INT):
				case (DATA_INTEGER):
					printf("%d ", data_value(arguments).integer);
					break;
				case (DATA_LONG):
					printf("%lu ", data_value(arguments).u_long);
					break;
				case (DATA_MAXSIZE):
				case (DATA_ULONG):
					printf("%zu ", data_value(arguments).max_size);
					break;
				case (DATA_DOUBLE):
					printf("%.6f ", data_value(arguments).precision);
					break;
				case (DATA_FLOAT):
					printf("%f ", data_value(arguments).point);
					break;
				default:
					printf("%p ", data_value(arguments).object);
					break;
			}
		} else {
			printf("%p ", data_value(arguments).object);
		}
	}
	va_end(argp);
	puts("");
}
