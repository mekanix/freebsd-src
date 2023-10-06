#include <sys/nv.h>

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "./nvtree.h"

#define	NVTREE_HEADER_MAGIC	0x6c
#define	NVTREE_HEADER_VERSION	0x00

struct nvtree_header {
	uint8_t		magic;
	uint8_t		version;
	uint8_t		flags;
	uint64_t	descriptors;
	uint64_t	size;
} __packed;

struct nvtpair_header {
	uint8_t		type;
	uint16_t	namesize;
	uint64_t	datasize;
	uint64_t	nitems;
} __packed;

int
attr_name_compare(const nvtpair_t *a1, const nvtpair_t *a2) {
	if (a1 == NULL) {
		if (a2 == NULL) {
			return 0;
		}
		return -1;
	} else if (a2 == NULL) {
		return 1;
	}
	return strcmp(a1->name, a2->name);
}

RB_GENERATE(nvthead_t, nvtpair_t, entry, attr_name_compare)

static nvthead_t *
_nvtree_create(void) {
	nvthead_t *root = NULL;
	root = malloc(sizeof(nvthead_t));
	RB_INIT(root);
	return root;
}

nvtree_t *
nvtree_create(const uint8_t flags) {
	nvtree_t *root = malloc(sizeof(nvtree_t));
	root->head = _nvtree_create();
	root->flags = flags;
	return root;
}

nvtpair_t *
nvtree_pair(const char *name) {
	nvtpair_t *node = malloc(sizeof(nvtpair_t));
	memset(node, 0, sizeof(nvtpair_t));
	if (name != NULL && name[0] != '\0') {
		node->name = strdup(name);
	}
	return node;
}

nvtpair_t *
nvtree_number(const char *name, const uint64_t value) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_NUMBER;
	node->value.num = value;
	return node;
}

nvtpair_t *
nvtree_bool(const char *name, const bool value) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_BOOL;
	node->value.b = value;
	return node;
}

nvtpair_t *
nvtree_string(const char *name, const char *value) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_STRING;
	node->value.string = strdup(value);
	return node;
}

nvtpair_t *
nvtree_null(const char *name) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_NULL;
	return node;
}

nvtpair_t *
nvtree_tree(const char *name) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_NESTED;
	node->value.tree = malloc(sizeof(nvtree_t));
	RB_INIT(node->value.tree);
	return node;
}

nvtpair_t *
nvtree_array(const char *name) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_ARRAY;
	node->value.array = malloc(sizeof(nvtarray_t));
	TAILQ_INIT(node->value.array);
	return node;
}

nvtpair_t *
nvtree_nested(const char *name, const uint8_t flags) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_NESTED;
	node->value.tree = malloc(sizeof(nvthead_t *));
	node->flags = flags;
	return node;
}

static size_t
_nvtree_size(const nvthead_t *p) {
	nvtpair_t *attr = NULL;
	nvtpair_t *node = NULL;
	uint64_t nitems = 0;
	size_t size = sizeof(struct nvtree_header);

	RB_FOREACH(attr, nvthead_t, __DECONST(nvthead_t *, p)) {
		size += sizeof(struct nvtpair_header);
		if (attr->name != NULL) {
			size += strlen(attr->name) + 1;
		}
		if (attr->type & NVTREE_ARRAY) {
			switch(attr->type & ~NVTREE_ARRAY) {
				case NVTREE_BOOL: {
					TAILQ_FOREACH(node, attr->value.array, next) {
						++nitems;
					}
					size += nitems * sizeof(bool);
					break;
				}
				case NVTREE_NUMBER: {
					TAILQ_FOREACH(node, attr->value.array, next) {
						++nitems;
					}
					size += nitems * sizeof(uint64_t);
					break;
				}
				case NVTREE_STRING: {
					TAILQ_FOREACH(node, attr->value.array, next) {
						size += strlen(node->value.string) + 1;
					}
					break;
				}
				case NVTREE_NESTED: {
					TAILQ_FOREACH(node, attr->value.array, next) {
						size += _nvtree_size(node->value.tree) + sizeof(struct nvtpair_header) + 1;
					}
					break;
				}
			}
		} else {
			switch(attr->type) {
				case NVTREE_BOOL: {
					size += sizeof(bool);
					break;
				}
				case NVTREE_NUMBER: {
					size += sizeof(uint64_t);
					break;
				}
				case NVTREE_STRING: {
					size += strlen(attr->value.string) + 1;
					break;
				}
				case NVTREE_NESTED: {
					size += _nvtree_size(attr->value.tree) + sizeof(struct nvtpair_header) + 1;
					break;
				}
			}
		}
	}
	return size;
}

size_t
nvtree_size(const nvtree_t *root) {
	if (root == NULL) {
		return 0;
	}
	return _nvtree_size(root->head);
}

static void *
_nvtree_pack(const nvthead_t *p, uint8_t *buf, size_t size, bool root, uint8_t flags) {
	uint8_t *ptr = NULL;
	nvtpair_t *attr = NULL;
	struct nvtree_header nvt = {0};
	struct nvtpair_header nvp = {0};

	if (p == NULL) {
		return NULL;
	}

	nvt.magic = NVTREE_HEADER_MAGIC;
	nvt.version = NVTREE_HEADER_VERSION;
	nvt.flags = flags;
	nvt.descriptors = 0;
	if (root) {
		nvt.size = size - sizeof(nvt);
	} else {
		nvt.size = size + 1;
	}
	memcpy(buf, &nvt, sizeof(nvt));
	ptr = buf + sizeof(nvt);
	RB_FOREACH(attr, nvthead_t, __DECONST(nvthead_t *, p)) {
		nvp.namesize = strlen(attr->name) + 1;
		nvp.nitems = 0;
		if (attr->type & NVTREE_ARRAY) {
			nvtpair_t *node = NULL;
			nvp.datasize = 0;

			switch(attr->type & ~NVTREE_ARRAY) {
				case NVTREE_BOOL: {
					TAILQ_FOREACH(node, attr->value.array, next) {
						++nvp.nitems;
					}
					nvp.datasize = nvp.nitems * sizeof(bool);
					nvp.type = NV_TYPE_BOOL_ARRAY;
					memcpy(ptr, &nvp, sizeof(nvp));
					ptr += sizeof(nvp);
					memcpy(ptr, attr->name, nvp.namesize);
					ptr += nvp.namesize;
					node = NULL;
					TAILQ_FOREACH(node, attr->value.array, next) {
						memcpy(ptr, &(node->value.b), nvp.datasize);
						ptr += nvp.datasize;
					}
					break;
				}
				case NVTREE_NUMBER: {
					TAILQ_FOREACH(node, attr->value.array, next) {
						++nvp.nitems;
					}
					nvp.datasize = nvp.nitems * sizeof(uint64_t);
					nvp.type = NV_TYPE_NUMBER_ARRAY;
					memcpy(ptr, &nvp, sizeof(nvp));
					ptr += sizeof(nvp);
					memcpy(ptr, attr->name, nvp.namesize);
					ptr += nvp.namesize;
					node = NULL;
					TAILQ_FOREACH(node, attr->value.array, next) {
						memcpy(ptr, &(node->value.num), nvp.datasize);
						ptr += nvp.datasize;
					}
					break;
				}
				case NVTREE_STRING: {
					TAILQ_FOREACH(node, attr->value.array, next) {
						++nvp.nitems;
						nvp.datasize += strlen(node->value.string) + 1;
					}
					nvp.type = NV_TYPE_STRING_ARRAY;
					memcpy(ptr, &nvp, sizeof(nvp));
					ptr += sizeof(nvp);
					memcpy(ptr, attr->name, nvp.namesize);
					ptr += nvp.namesize;
					node = NULL;
					TAILQ_FOREACH(node, attr->value.array, next) {
						size = strlen(node->value.string) + 1;
						memcpy(ptr, node->value.string, size);
						ptr += size;
					}
					break;
				}
				case NVTREE_NESTED: {
					size_t s = 0;
					TAILQ_FOREACH(node, attr->value.array, next) {
						++nvp.nitems;
					}
					nvp.type = NV_TYPE_NVLIST_ARRAY;
					memcpy(ptr, &nvp, sizeof(nvp));
					ptr += sizeof(nvp);
					memcpy(ptr, attr->name, nvp.namesize);
					ptr += nvp.namesize;
					TAILQ_FOREACH(node, attr->value.array, next) {
						s = _nvtree_size(node->value.tree);
						_nvtree_pack(node->value.tree, ptr, s, false, nvt.flags);
						ptr += s;
					}
					break;
				}
			}
		} else if (attr->type & NVTREE_NESTED) {
			uint8_t zero = 0;
			uint8_t *bytes = ptr;

			nvp.type = NV_TYPE_NVLIST;
			ptr += sizeof(nvp);
			memcpy(ptr, attr->name, nvp.namesize);
			ptr += nvp.namesize;
			nvp.datasize = _nvtree_size(attr->value.tree);
			_nvtree_pack(attr->value.tree, ptr, nvp.datasize, false, nvt.flags);
			memcpy(bytes, &nvp, sizeof(nvp));
			ptr += nvp.datasize;
			nvp.type = 0xff;
			nvp.datasize = 0;
			nvp.namesize = 1;
			memcpy(ptr, &nvp, sizeof(nvp));
			ptr += sizeof(nvp);
			memcpy(ptr, &zero, sizeof(zero));
			ptr += sizeof(zero);
		} else {
			switch(attr->type) {
				case NVTREE_NULL: {
					nvp.type = NV_TYPE_NULL;
					nvp.datasize = 0;
					memcpy(ptr, &nvp, sizeof(nvp));
					ptr += sizeof(nvp);
					memcpy(ptr, attr->name, nvp.namesize);
					ptr += nvp.namesize;
					break;
				}
				case NVTREE_BOOL: {
					nvp.type = NV_TYPE_BOOL;
					nvp.datasize = sizeof(bool);
					memcpy(ptr, &nvp, sizeof(nvp));
					ptr += sizeof(nvp);
					memcpy(ptr, attr->name, nvp.namesize);
					ptr += nvp.namesize;
					memcpy(ptr, &attr->value.b, nvp.datasize);
					ptr += nvp.datasize;
					break;
				}
				case NVTREE_NUMBER: {
					nvp.type = NV_TYPE_NUMBER;
					nvp.datasize = sizeof(uint64_t);
					memcpy(ptr, &nvp, sizeof(nvp));
					ptr += sizeof(nvp);
					memcpy(ptr, attr->name, nvp.namesize);
					ptr += nvp.namesize;
					memcpy(ptr, &(attr->value.num), nvp.datasize);
					ptr += nvp.datasize;
					break;
				}
				case NVTREE_STRING: {
					nvp.type = NV_TYPE_STRING;
					nvp.datasize = strlen(attr->value.string) + 1;
					memcpy(ptr, &nvp, sizeof(nvp));
					ptr += sizeof(nvp);
					memcpy(ptr, attr->name, nvp.namesize);
					ptr += nvp.namesize;
					memcpy(ptr, attr->value.string, nvp.datasize);
					ptr += nvp.datasize;
					break;
				}
			}
		}
	}
	return buf;
}

void *
nvtree_pack(const nvtree_t *root, size_t *size) {
	if (root == NULL) {
		*size = 0;
		return NULL;
	}
	*size = nvtree_size(root);
	if (*size == 0) {
		return NULL;
	}
	uint8_t *buf = malloc(*size);
	return _nvtree_pack(root->head, buf, *size, true, root->flags);
}

static int
_nvtree_destroy(nvthead_t *root) {
	nvtpair_t *pair = NULL;
	nvtpair_t *tmppair = NULL;
	nvtpair_t *next = NULL;
	int rc = 0;

	for (pair = RB_MIN(nvthead_t, root); pair != NULL; pair = next) {
		next = RB_NEXT(nvthead_t, root, pair);
		pair = RB_REMOVE(nvthead_t, root, pair);
		if (pair == NULL) {
			return 1;
		}
		if (pair->type & NVTREE_ARRAY) {
			while ((tmppair = TAILQ_FIRST(pair->value.array)) != NULL) {
				TAILQ_REMOVE(pair->value.array, tmppair, next);
				if (pair->type & NVTREE_NESTED) {
					rc = _nvtree_destroy(tmppair->value.tree);
					if (rc < 0) {
						return rc;
					}
				} else if (pair->type & NVTREE_STRING) {
					free(tmppair->value.string);
					tmppair->value.string = NULL;
				}
				if (tmppair->name != NULL) {
					free(tmppair->name);
				}
				free(tmppair);
			}
		} else if (pair->type & NVTREE_NESTED) {
			rc = _nvtree_destroy(pair->value.tree);
			if (rc < 0) {
				return rc;
			}
		} else if (pair->type & NVTREE_STRING) {
			free(pair->value.string);
			pair->value.string = NULL;
		}
		if (pair->name != NULL) {
			free(pair->name);
			pair->name = NULL;
		}
		free(pair);
	}
	return 0;
}

int
nvtree_destroy(nvtree_t *root) {
	int rc = 0;

	if (root == NULL) {
		return -1;
	}
	rc = _nvtree_destroy(root->head);
	free(root);
	return rc;
}

static nvthead_t *
_nvtree_unpack(const uint8_t *buf, size_t size) {
	char *name = NULL;
	nvthead_t *root = NULL;
	nvtpair_t *pair = NULL;
	uint8_t *ptr = __DECONST(uint8_t *, buf);
	struct nvtree_header thead;
	struct nvtpair_header phead;

	if (size < sizeof(thead)) {
		return NULL;
	}
	memcpy(&thead, ptr, sizeof(thead));
	if (thead.magic != NVTREE_HEADER_MAGIC || thead.version != NVTREE_HEADER_VERSION) {
		return NULL;
	}
	ptr += sizeof(thead);
	root = _nvtree_create();
	if (thead.size == 0) {
		return root;
	}
	while (ptr < buf + size) {
		memcpy(&phead, ptr, sizeof(phead));
		ptr += sizeof(phead);
		if (phead.namesize > 0) {
			name = (char *)ptr;
		} else {
			name = NULL;
		}
		ptr += phead.namesize;
		switch(phead.type) {
			case NV_TYPE_NULL: {
				pair = nvtree_null(name);
				if (RB_INSERT(nvthead_t, root, pair) != NULL) {
					goto error;
				}
				break;
			}
			case NV_TYPE_BOOL: {
				bool b;
				memcpy(&b, ptr, sizeof(b));
				pair = nvtree_bool(name, b);
				if (RB_INSERT(nvthead_t, root, pair) != NULL) {
					goto error;
				}
				ptr += sizeof(b);
				break;
			}
			case NV_TYPE_NUMBER: {
				uint64_t num = 0;
				memcpy(&num, ptr, sizeof(num));
				pair = nvtree_number(name, num);
				if (RB_INSERT(nvthead_t, root, pair) != NULL) {
					goto error;
				}
				ptr += sizeof(num);
				break;
			}
			case NV_TYPE_STRING: {
				char *string = (char *)ptr;
				pair = nvtree_string(name, string);
				if (RB_INSERT(nvthead_t, root, pair) != NULL) {
					goto error;
				}
				ptr += strlen(string) + 1;
				break;
			}
			case NV_TYPE_NVLIST: {
				pair = nvtree_nested(name, 0);
				pair->value.tree = _nvtree_unpack(ptr, ptr - buf);
				if (RB_INSERT(nvthead_t, root, pair) != NULL) {
					goto error;
				}
				ptr += _nvtree_size(pair->value.tree);
				break;
			}
			case 0xff: {
				goto done;
				break;
			}
		}
	}

done:
	return root;

error:
	_nvtree_destroy(root);
	return NULL;
}

nvtree_t *
nvtree_unpack(const uint8_t *buf, size_t size) {
	nvtree_t *root = NULL;
	struct nvtree_header thead;

	if (buf == NULL) {
		return NULL;
	}
	if (size == 0) {
		return NULL;
	}
	memcpy(&thead, buf, sizeof(thead));
	root = malloc(sizeof(nvtree_t));
	root->head = _nvtree_unpack(buf, size);
	root->flags = thead.flags;
	return root;
}

nvtpair_t *
nvtree_find(const nvtree_t *root, const char *name) {
	nvtpair_t key = {
		.name = __DECONST(char *, name)
	};
	return RB_FIND(nvthead_t, root->head, &key);
}

nvtpair_t *
nvtree_add(nvtree_t *root, nvtpair_t *pair) {
	return RB_INSERT(nvthead_t, root->head, pair);
}

nvtpair_t *
nvtree_remove(nvtree_t *root, nvtpair_t *pair) {
	return RB_REMOVE(nvthead_t, root->head, pair);
}

nvtpair_t *
nvtree_add_tree(nvtpair_t *tree, nvtpair_t *pair) {
	return RB_INSERT(nvthead_t, tree->value.tree, pair);
}

int
nvtree_add_arr(nvtpair_t *array, nvtpair_t *pair) {
	if (array->type & NVTREE_ARRAY) {
		return -1;
	}
	if ((array->type & ~NVTREE_ARRAY) != pair->type) {
		return -1;
	}
	TAILQ_INSERT_TAIL(array->value.array, pair, next);
	return 0;
}

nvtpair_t *
nvtree_rem_tree(nvtpair_t *tree, nvtpair_t *pair) {
	return RB_REMOVE(nvthead_t, tree->value.tree, pair);
}

int
nvtree_rem_arr(nvtpair_t *array, nvtpair_t *pair) {
	if (array->type & NVTREE_ARRAY) {
		return -1;
	}
	if ((array->type & ~NVTREE_ARRAY) != pair->type) {
		return -1;
	}
	TAILQ_REMOVE(array->value.array, pair, next);
	return 0;
}
