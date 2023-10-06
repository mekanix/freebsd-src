#ifdef _KERNEL
#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/libkern.h>
#else
#include <sys/socket.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <sys/nv.h>
#include <sys/nvtree.h>

#ifdef _KERNEL
MALLOC_DEFINE(M_NVTREE, "nvtree", "kernel nvtree");
#define nvtree_free(m) free((m), M_NVTREE)
#define nvtree_malloc(s) malloc((s), M_NVTREE, M_WAITOK);
#define nvtree_strdup(s) strdup((s), M_NVTREE)
#define nvtree_log(...) uprintf(__VA_ARGS__)
#else
#define nvtree_free(m) free(m)
#define nvtree_malloc(s) malloc(s)
#define nvtree_strdup(s) strdup(s)
#define nvtree_log(...) err(0, __VA_ARGS__)
#endif

#define	NVTREE_HEADER_MAGIC	0x6c
#define	NVTREE_HEADER_VERSION	0x00
#define	NVTREE_SENTINEL_ARRAY	0xfe
#define	NVTREE_SENTINEL_NESTED	0xff

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
			return (0);
		}
		return (-1);
	} else if (a2 == NULL) {
		return (1);
	}
	if (a1->name == NULL) {
		if (a2->name == NULL) {
			return (0);
		}
		return (-1);
	} else if (a2->name == NULL) {
		return (1);
	}
	return (strcmp(a1->name, a2->name));
}

RB_GENERATE(nvtree_t, nvtpair_t, entry, attr_name_compare)

static uint8_t * nvtpair_pack(const nvtpair_t *pair, uint8_t *buf, uint8_t *end, int *fds, size_t *idx);
static nvtpair_t * nvtpair_unpack(uint8_t **buf, const uint8_t *end);

nvtree_t *
nvtree_create(void) {
	nvtree_t *root = nvtree_malloc(sizeof(nvtree_t));
	memset(root, 0, sizeof(nvtree_t));
	RB_INIT(root);
	return (root);
}

nvtpair_t *
nvtree_pair(const char *name) {
	nvtpair_t *node = nvtree_malloc(sizeof(nvtpair_t));
	memset(node, 0, sizeof(nvtpair_t));
	if (name != NULL && name[0] != '\0') {
		node->name = nvtree_strdup(name);
	}
	return (node);
}

nvtpair_t *
nvtree_number(const char *name, uint64_t value) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_NUMBER;
	node->value.num = value;
	return (node);
}

nvtpair_t *
nvtree_bool(const char *name, bool value) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_BOOL;
	node->value.b = value;
	return (node);
}

#ifndef _KERNEL
nvtpair_t *
nvtree_fd(const char *name, int fd) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_DESC;
	node->value.fd = fd;
	// node->value.fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	return (node);
}
#endif

nvtpair_t *
nvtree_string(const char *name, const char *value) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_STRING;
	node->value.string = nvtree_strdup(value);
	return (node);
}

nvtpair_t *
nvtree_null(const char *name) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_NULL;
	return (node);
}

nvtpair_t *
nvtree_array(const char *name, size_t type) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_ARRAY | type;
	node->value.array = nvtree_malloc(sizeof(nvtarray_t));
	TAILQ_INIT(node->value.array);
	return (node);
}

nvtpair_t *
nvtree_nested(const char *name, const nvtree_t *value) {
	nvtpair_t *node = nvtree_pair(name);
	node->type = NVTREE_NESTED;
	if (value == NULL) {
		node->value.tree = nvtree_create();
	} else {
		node->value.tree = __DECONST(nvtree_t *, value);
	}
	return (node);
}

static size_t
nvtpair_namesize(const nvtpair_t *pair) {
	if (pair->name == NULL) {
		return (0);
	}
	return (strlen(pair->name) + 1);
}

static size_t
nvtpair_rawsize(const nvtpair_t *pair) {
	size_t size = 0;
	size_t nitems = 0;
	nvtpair_t *node = NULL;

	if (pair == NULL) {
		return (0);
	}
	if (pair->type & NVTREE_ARRAY) {
		switch(pair->type & ~NVTREE_ARRAY) {
			case NVTREE_BOOL: {
				TAILQ_FOREACH(node, pair->value.array, next) {
					++nitems;
				}
				return (nitems * sizeof(bool));
			}
#ifndef _KERNEL
			case NVTREE_DESC: {
				TAILQ_FOREACH(node, pair->value.array, next) {
					++nitems;
				}
				return (nitems * sizeof(int64_t));
			}
#endif
			case NVTREE_NUMBER: {
				TAILQ_FOREACH(node, pair->value.array, next) {
					++nitems;
				}
				return (nitems * sizeof(uint64_t));
			}
			case NVTREE_STRING: {
				TAILQ_FOREACH(node, pair->value.array, next) {
					size += strlen(node->value.string) + 1;
				}
				return (size);
			}
		}
	} else {
		switch(pair->type) {
			case NVTREE_BOOL: {
				return (sizeof(bool));
			}
#ifndef _KERNEL
			case NVTREE_DESC: {
				return (sizeof(int64_t));
			}
#endif
			case NVTREE_NUMBER: {
				return (sizeof(uint64_t));
			}
			case NVTREE_STRING: {
				return (strlen(pair->value.string) + 1);
			}
		}
	}
	return (size);
}

static size_t
nvtpair_datasize(const nvtpair_t *pair) {
	nvtpair_t *node = NULL;
	size_t size = sizeof(struct nvtpair_header) + nvtpair_namesize(pair);

	if (pair == NULL) {
		return (0);
	}
	// Simple value or array of simple values
	if ((pair->type & ~NVTREE_ARRAY) != NVTREE_NESTED) {
		size += nvtpair_rawsize(pair);
		return (size);
	}

	// Array of nested
	if (pair->type & NVTREE_ARRAY) {
		TAILQ_FOREACH(node, pair->value.array, next) {
			size += nvtpair_datasize(node);
		}
		return (size);
	}

	// Just nested
	RB_FOREACH(node, nvtree_t, pair->value.tree) {
		size += nvtpair_datasize(node);
	}

	// Elements of array do not have name
	if (pair->name) {
		size += sizeof(struct nvtree_header);
	}
	size += sizeof(struct nvtpair_header) + 1;

	return (size);
}

static size_t
pair_to_list_type(const nvtpair_t *pair) {
	if (pair->type & NVTREE_ARRAY) {
		switch(pair->type & ~NVTREE_ARRAY) {
			case NVTREE_BOOL:
				return (NV_TYPE_BOOL_ARRAY);
#ifndef _KERNEL
			case NVTREE_DESC:
				return (NV_TYPE_DESCRIPTOR_ARRAY);
#endif
			case NVTREE_NUMBER:
				return (NV_TYPE_NUMBER_ARRAY);
			case NVTREE_STRING:
				return (NV_TYPE_STRING_ARRAY);
			case NVTREE_NESTED:
				return (NV_TYPE_NVLIST_ARRAY);
		}
	}
	switch(pair->type) {
		case NVTREE_NULL:
			return (NV_TYPE_NULL);
		case NVTREE_BOOL:
			return (NV_TYPE_BOOL);
#ifndef _KERNEL
		case NVTREE_DESC:
			return (NV_TYPE_DESCRIPTOR);
#endif
		case NVTREE_NUMBER:
			return (NV_TYPE_NUMBER);
		case NVTREE_STRING:
			return (NV_TYPE_STRING);
		case NVTREE_NESTED:
			return (NV_TYPE_NVLIST);
	}
	return (0);
}

nvtpair_t *
nvtree_add(nvtree_t *root, nvtpair_t *pair) {
	return (RB_INSERT(nvtree_t, root, pair));
}

nvtpair_t *
nvtree_rm(nvtree_t *root, nvtpair_t *pair) {
	return (RB_REMOVE(nvtree_t, root, pair));
}

static int
nvtree_add_arr(nvtpair_t *array, nvtpair_t *pair) {
	if ((array->type & NVTREE_ARRAY) == 0) {
		return (-1);
	}
	if ((array->type & ~NVTREE_ARRAY) != pair->type) {
		return (-2);
	}
	TAILQ_INSERT_TAIL(array->value.array, pair, next);
	return (0);
}

static nvtpair_t *
nvtree_add_tree(nvtpair_t *tree, nvtpair_t *pair) {
       return (RB_INSERT(nvtree_t, tree->value.tree, pair));
}

static int
nvtree_rm_arr(nvtpair_t *array, nvtpair_t *pair) {
       if ((array->type & NVTREE_ARRAY) == 0) {
               return (-1);
       }
       if ((array->type & ~NVTREE_ARRAY) != pair->type) {
               return (-2);
       }
       TAILQ_REMOVE(array->value.array, pair, next);
       return (0);
}

static nvtpair_t *
nvtree_rm_tree(nvtpair_t *tree, nvtpair_t *pair) {
       return (RB_REMOVE(nvtree_t, tree->value.tree, pair));
}

nvtpair_t *
nvtree_add_pair(nvtpair_t *root, nvtpair_t *pair) {
	if (root == NULL || pair == NULL) {
		return NULL;
	}
	if (root->type == NVTREE_NESTED) {
		nvtree_add_tree(root, pair);
		return pair;
	}
	if ((root->type & ~NVTREE_ARRAY) == pair->type) {
		nvtree_add_arr(root, pair);
		return pair;
	}
	switch (root->type) {
		case NVTREE_BOOL:
#ifndef _KERNEL
		case NVTREE_DESC:
#endif
		case NVTREE_NULL:
		case NVTREE_NUMBER:
		case NVTREE_STRING:
		default:
			return NULL;
	}
	return NULL;
}

nvtpair_t *
nvtree_rm_pair(nvtpair_t *root, nvtpair_t *pair) {
	if (root == NULL || pair == NULL) {
		return NULL;
	}
	switch (root->type) {
		case NVTREE_BOOL:
#ifndef _KERNEL
		case NVTREE_DESC:
#endif
		case NVTREE_NULL:
		case NVTREE_NUMBER:
		case NVTREE_STRING:
		default:
			return NULL;
	}
	if (root->type == NVTREE_NESTED) {
		nvtree_rm_tree(root, pair);
		return pair;
	}
	if ((root->type & ~NVTREE_ARRAY) == pair->type) {
		nvtree_rm_arr(root, pair);
		return pair;
	}
	return NULL;
}

static uint8_t *
nvtpair_pack_data(const nvtpair_t *pair, uint8_t *buf, uint8_t *end, int *fds, size_t *idx) {
	size_t size = 0;
	nvtpair_t *node = NULL;

	if (pair == NULL) {
		return (NULL);
	}
	if (pair->type & NVTREE_ARRAY) {
		TAILQ_FOREACH(node, pair->value.array, next) {
			buf = (uint8_t *)nvtpair_pack(node, buf, end, fds, idx);
			if (buf == NULL) {
				return (NULL);
			}
		}
	} else {
		size = nvtpair_rawsize(pair);
		switch(pair->type) {
			case NVTREE_BOOL: {
				memcpy(buf, &pair->value.b, size);
				buf += size;
				break;
			}
#ifndef _KERNEL
			case NVTREE_DESC: {
				fds[*idx] = pair->value.fd;
				memcpy(buf, idx, size);
				buf += size;
				++(*idx);
				break;
			}
#endif
			case NVTREE_NUMBER: {
				memcpy(buf, &pair->value.num, size);
				buf += size;
				break;
			}
			case NVTREE_STRING: {
				memcpy(buf, pair->value.string, size);
				buf += size;
				break;
			}
			case NVTREE_NESTED: {
				struct nvtree_header header = {};
				struct nvtpair_header pheader = {};
				bool b = false;

				header.magic = NVTREE_HEADER_MAGIC;
				header.version = NVTREE_HEADER_VERSION;
				header.descriptors = 0;
				header.flags = 0;
				header.size = end - buf - sizeof(header);
				memcpy(buf, &header, sizeof(header));
				buf += sizeof(header);
				RB_FOREACH(node, nvtree_t, pair->value.tree) {
					buf = (uint8_t *)nvtpair_pack(node, buf, end, fds, idx);
					if (buf == NULL) {
						return (NULL);
					}
				}
				if (pair->name) {
					pheader.type = NVTREE_SENTINEL_NESTED;
				} else {
					pheader.type = NVTREE_SENTINEL_ARRAY;
				}
				pheader.namesize = 1;
				pheader.datasize = 0;
				pheader.nitems = 0;
				memcpy(buf, &pheader, sizeof(pheader));
				buf += sizeof(pheader);
				memcpy(buf, &b, sizeof(b));
				buf += sizeof(b);
			}
		}
	}
	return (buf);
}

static uint8_t *
nvtpair_pack_header(const nvtpair_t *pair, uint8_t *buf) {
	struct nvtpair_header header = {};
	nvtpair_t *node = NULL;

	if (pair == NULL) {
		return (NULL);
	}

	if (pair->name) {
		header.type = pair_to_list_type(pair);
		header.namesize = nvtpair_namesize(pair);
		header.nitems = 0;
		if (pair->type & NVTREE_ARRAY) {
			TAILQ_FOREACH(node, pair->value.array, next) {
				++header.nitems;
			}
			node = TAILQ_FIRST(pair->value.array);
			header.datasize = nvtpair_rawsize(node) * header.nitems;
		} else if (pair->type == NVTREE_NESTED) {
			header.datasize = sizeof(struct nvtree_header);
			RB_FOREACH(node, nvtree_t, pair->value.tree) {
				header.datasize += nvtpair_datasize(node);
			}
		} else {
			header.datasize = nvtpair_rawsize(pair);
		}
		memcpy(buf, &header, sizeof(header));
		buf += sizeof(header);
		memcpy(buf, pair->name, header.namesize);
		buf += header.namesize;
	}
	return (buf);
}

static uint8_t *
nvtpair_pack(const nvtpair_t *pair, uint8_t *buf, uint8_t *end, int *fds, size_t *idx) {
	buf = nvtpair_pack_header(pair, buf);
	buf = nvtpair_pack_data(pair, buf, end, fds, idx);
	return (buf);
}

size_t
nvtree_size(const nvtree_t *root) {
	nvtpair_t *pair = NULL;
	size_t size = sizeof(struct nvtree_header);

	RB_FOREACH(pair, nvtree_t, __DECONST(nvtree_t *, root)) {
		size += nvtpair_datasize(pair);
	}
	return (size);
}

static size_t
nvtree_descriptors(const nvtree_t *root) {
#ifndef _KERNEL
	size_t nfds = 0;
	nvtpair_t *pair = NULL;
	nvtpair_t *node = NULL;

	RB_FOREACH(pair, nvtree_t, __DECONST(nvtree_t *, root)) {
		if ((pair->type & NVTREE_ARRAY) == NVTREE_DESC) {
			TAILQ_FOREACH(node, pair->value.array, next) {
				++nfds;
			}
		} else if (pair->type == NVTREE_NESTED) {
			nfds += nvtree_descriptors(pair->value.tree);
		} else if (pair->type == NVTREE_DESC) {
			++nfds;
		}
	}
	return (nfds);
#else
	return 0;
#endif
}

static void *
_nvtree_pack(const nvtree_t *root, size_t *size, int *fds, size_t *idx) {
	uint8_t *buf = NULL;
	uint8_t *ptr = NULL;
	uint8_t *end = NULL;
	nvtpair_t *pair = NULL;
	struct nvtree_header header = {};

	*size = nvtree_size(root);
	header.size = *size - sizeof(header);
	header.flags = 0;
	header.descriptors = nvtree_descriptors(root);
	header.magic = NVTREE_HEADER_MAGIC;
	header.version = NVTREE_HEADER_VERSION;
	ptr = buf = nvtree_malloc(*size);
	end = buf + *size;
	memcpy(ptr, &header, sizeof(header));
	ptr += sizeof(header);
	RB_FOREACH(pair, nvtree_t, __DECONST(nvtree_t *, root)) {
		ptr = nvtpair_pack(pair, ptr, end, fds, idx);
		if (ptr == NULL) {
			return (NULL);
		}
	}
	return (buf);
}

void *
nvtree_pack(const nvtree_t *root, size_t *size) {
	size_t idx = 0;

#ifndef _KERNEL
	if (nvtree_descriptors(root) > 0) {
		return (NULL);
	}
#endif
	return (_nvtree_pack(root, size, NULL, &idx));
}

static nvtree_t *
_nvtree_unpack(uint8_t **buf, const uint8_t *end) {
	nvtree_t *root = NULL;
	nvtpair_t *pair = NULL;
	struct nvtree_header head;

	if (*buf + sizeof(head) > end) {
		return (NULL);
	}
	memcpy(&head, *buf, sizeof(head));
	if (head.magic != NVTREE_HEADER_MAGIC || head.version != NVTREE_HEADER_VERSION) {
		return (NULL);
	}
	*buf += sizeof(head);
	root = nvtree_create();
	if (head.size == 0) {
		return (root);
	}
	while (*buf < end) {
		pair = nvtpair_unpack(buf, end);
		if (pair == NULL) {
			break;
		}
		switch (pair->type) {
			case NVTREE_SENTINEL_ARRAY:
			case NVTREE_SENTINEL_NESTED: {
				return (root);
			}
		}
		nvtree_add(root, pair);
	}
	return (root);
}

static nvtpair_t *
nvtpair_unpack(uint8_t **buf, const uint8_t *end) {
	nvtpair_t *pair = NULL;
	struct nvtpair_header phead = {};
	char *name = NULL;

	if (buf == NULL || *buf == NULL || end == NULL || *buf > end) {
		return (NULL);
	}
	if (*buf + sizeof(phead) > end) {
		return (NULL);
	}
	memcpy(&phead, *buf, sizeof(phead));
	*buf += sizeof(phead);
	if (phead.namesize > 0) {
		name = (char *)(*buf);
	} else {
		name = NULL;
	}
	*buf += phead.namesize;
	if (*buf > end) {
		return (NULL);
	}
	switch(phead.type) {
		case NV_TYPE_NULL: {
			pair = nvtree_null(name);
			break;
		}
		case NV_TYPE_BOOL: {
			bool b;
			memcpy(&b, *buf, sizeof(b));
			pair = nvtree_bool(name, b);
			*buf += sizeof(b);
			if (*buf > end) {
				return (NULL);
			}
			break;
		}
		case NV_TYPE_NUMBER: {
			uint64_t num = 0;
			memcpy(&num, *buf, sizeof(num));
			*buf += sizeof(num);
			if (*buf > end) {
				return (NULL);
			}
			pair = nvtree_number(name, num);
			break;
		}
		case NV_TYPE_STRING: {
			char *string = (char *)(*buf);
			pair = nvtree_string(name, string);
			*buf += strlen(string) + 1;
			if (*buf > end) {
				return (NULL);
			}
			break;
		}
		case NV_TYPE_NVLIST: {
			pair = nvtree_pair(name);
			pair->type = NVTREE_NESTED;
			pair->value.tree = _nvtree_unpack(buf, end);
			break;
		}
#ifndef _KERNEL
		case NV_TYPE_DESCRIPTOR: {
			int64_t fd = 0;
			memcpy(&fd, *buf, sizeof(fd));
			*buf += sizeof(fd);
			if (*buf > end) {
				return (NULL);
			}
			pair = nvtree_fd(name, fd);
			break;

		}
		case NV_TYPE_DESCRIPTOR_ARRAY: {
			int64_t fd = 0;
			nvtpair_t *rp = NULL;

			pair = nvtree_array(name, NVTREE_DESC);
			for (uint64_t i = 0; i < phead.nitems; ++i) {
				memcpy(&fd, *buf, sizeof(fd));
				rp = nvtree_fd(NULL, fd);
				*buf += sizeof(fd);
				if (*buf > end) {
					return (NULL);
				}
				nvtree_add_arr(pair, rp);
			}
			break;
		}
#endif
		case NV_TYPE_BOOL_ARRAY: {
			bool b;
			nvtpair_t *rp = NULL;

			pair = nvtree_array(name, NVTREE_BOOL);
			for (uint64_t i = 0; i < phead.nitems; ++i) {
				memcpy(&b, *buf, sizeof(b));
				rp = nvtree_bool(NULL, b);
				*buf += sizeof(b);
				if (*buf > end) {
					return (NULL);
				}
				nvtree_add_arr(pair, rp);
			}
			break;
		}
		case NV_TYPE_NUMBER_ARRAY: {
			uint64_t num = 0;
			nvtpair_t *rp = NULL;

			pair = nvtree_array(name, NVTREE_NUMBER);
			for (uint64_t i = 0; i < phead.nitems; ++i) {
				memcpy(&num, *buf, sizeof(num));
				rp = nvtree_number(NULL, num);
				*buf += sizeof(num);
				if (*buf > end) {
					return (NULL);
				}
				nvtree_add_arr(pair, rp);
			}
			break;
		}
		case NV_TYPE_STRING_ARRAY: {
			char *value = NULL;
			nvtpair_t *rp = NULL;

			pair = nvtree_array(name, NVTREE_STRING);
			for (uint64_t i = 0; i < phead.nitems; ++i) {
				value = (char *)(*buf);
				rp = nvtree_string(NULL, value);
				*buf += strlen(value) + 1;
				if (*buf > end) {
					return (NULL);
				}
				nvtree_add_arr(pair, rp);
			}
			break;
		}
		case NV_TYPE_NVLIST_ARRAY: {
			nvtpair_t *rp = NULL;

			pair = nvtree_array(name, NVTREE_NESTED);
			for (uint64_t i = 0; i < phead.nitems; ++i) {
				rp = nvtree_pair(NULL);
				rp->type = NVTREE_NESTED;
				rp->value.tree = _nvtree_unpack(buf, end);
				if (rp->value.tree == NULL) {
					return (NULL);
				}
				if (*buf > end) {
					return (NULL);
				}
				nvtree_add_arr(pair, rp);
			}
			break;
		}
		case NVTREE_SENTINEL_ARRAY:
		case NVTREE_SENTINEL_NESTED: {
			pair = nvtree_pair(NULL);
			pair->type = phead.type;
			break;
		}
	}
	return (pair);
}

nvtree_t *
nvtree_unpack(const void *buf, size_t size) {
	uint8_t *ptr = __DECONST(uint8_t *, buf);
	uint8_t *end = ptr + size;
	return (_nvtree_unpack(&ptr, end));
}

int
nvtree_destroy(nvtree_t *root) {
	nvtpair_t *pair = NULL;
	nvtpair_t *tmppair = NULL;
	nvtpair_t *next = NULL;
	int rc = 0;

	for (pair = RB_MIN(nvtree_t, root); pair != NULL; pair = next) {
		next = RB_NEXT(nvtree_t, root, pair);
		pair = RB_REMOVE(nvtree_t, root, pair);
		if (pair == NULL) {
			return (1);
		}
		if (pair->type & NVTREE_ARRAY) {
			while ((tmppair = TAILQ_FIRST(pair->value.array)) != NULL) {
				TAILQ_REMOVE(pair->value.array, tmppair, next);
				if (pair->type == NVTREE_NESTED) {
					rc = nvtree_destroy(tmppair->value.tree);
					if (rc < 0) {
						return (rc);
					}
				} else if (pair->type == NVTREE_STRING) {
					nvtree_free(tmppair->value.string);
					tmppair->value.string = NULL;
				}
				if (tmppair->name != NULL) {
					nvtree_free(tmppair->name);
				}
				nvtree_free(tmppair);
			}
		} else if (pair->type == NVTREE_NESTED) {
			rc = nvtree_destroy(pair->value.tree);
			if (rc < 0) {
				return (rc);
			}
		} else if (pair->type == NVTREE_STRING) {
			nvtree_free(pair->value.string);
			pair->value.string = NULL;
		}
		if (pair->name != NULL) {
			nvtree_free(pair->name);
			pair->name = NULL;
		}
		nvtree_free(pair);
	}
	return (0);
}

nvtpair_t *
nvtree_find(const nvtree_t *root, const char *name) {
	nvtpair_t key = {
		.name = __DECONST(char *, name)
	};
	return (RB_FIND(nvtree_t, __DECONST(nvtree_t *, root), &key));
}

static const char *
type_to_string(const nvtpair_t *pair) {
	size_t t = 0;

	if (pair == NULL) {
		return (NULL);
	}
	if (pair->type & NVTREE_ARRAY) {
		t = pair->type & ~NVTREE_ARRAY;
		if (t == NVTREE_NULL) {
			return ("NULL ARRAY");
		}
#ifndef _KERNEL
		if (t == NVTREE_DESC) {
			return ("DESCRIPTOR ARRAY");
		}
#endif
		if (t == NVTREE_NESTED) {
			return ("NESTED ARRAY");
		}
		if (t == NVTREE_NUMBER) {
			return ("NUMBER ARRAY");
		}
		if (t == NVTREE_STRING) {
			return ("STRING ARRAY");
		}
		if (t == NVTREE_BOOL) {
			return ("BOOL ARRAY");
		}
	}
	if (pair->type == NVTREE_NULL) {
		return ("NULL");
	}
#ifndef _KERNEL
	if (pair->type == NVTREE_DESC) {
		return ("DESCRIPTOR");
	}
#endif
	if (pair->type == NVTREE_NESTED) {
		return ("NESTED");
	}
	if (pair->type == NVTREE_NUMBER) {
		return ("NUMBER");
	}
	if (pair->type == NVTREE_STRING) {
		return ("STRING");
	}
	if (pair->type == NVTREE_BOOL) {
		return ("BOOL");
	}
	return ("UNKNOWN");
}

static nvtpair_t *
nvtpair_clone(const nvtpair_t *pair) {
	nvtpair_t *dst = NULL;

	if (pair != NULL) {
		if ((pair->type & NVTREE_ARRAY) == 0) {
			switch (pair->type) {
				case NVTREE_BOOL: {
					dst = nvtree_bool(pair->name, pair->value.b);
					break;
				}
				case NVTREE_NUMBER: {
					dst = nvtree_number(pair->name, pair->value.num);
					break;
				}
				case NVTREE_STRING: {
					dst = nvtree_string(pair->name, pair->value.string);
					break;
				}
				case NVTREE_NULL: {
					dst = nvtree_null(pair->name);
					break;
				}
				case NVTREE_NESTED: {
					nvtpair_t *it = NULL;

					dst = nvtree_nested(pair->name, NULL);
					RB_FOREACH(it, nvtree_t, __DECONST(nvtree_t *, pair->value.tree)) {
						nvtree_add(dst->value.tree, nvtpair_clone(it));
					}
					break;
				}
#ifndef _KERNEL
				case NVTREE_DESC: {
					dst = nvtree_fd(pair->name, pair->value.fd);
					break;
				}
#endif
			}
		} else {
			nvtpair_t *it = NULL;

			dst = nvtree_array(pair->name, pair->type);
			TAILQ_FOREACH(it, pair->value.array, next) {
				nvtree_add_arr(dst, nvtpair_clone(it));
			}
		}
	}
	return (dst);
}

nvtree_t *
nvtree_clone(const nvtree_t *root) {
	nvtree_t *dst = NULL;
	nvtpair_t *node = NULL;

	dst = nvtree_create();
	if (root != NULL) {
		RB_FOREACH(node, nvtree_t, __DECONST(nvtree_t *, root)) {
			nvtree_add(dst, nvtpair_clone(node));
		}
	}
	return (dst);
}

void
nvtree_merge(nvtree_t *dst, const nvtree_t *src, bool overwrite) {
	nvtpair_t *node = NULL;
	nvtpair_t *it = NULL;
	nvtpair_t *tmp = NULL;

	RB_FOREACH(node, nvtree_t, __DECONST(nvtree_t *, src)) {
		tmp = nvtree_find(dst, node->name);
		if (tmp != NULL) {
			if (tmp->type == NVTREE_NESTED && node->type == NVTREE_NESTED) {
				nvtree_merge(tmp->value.tree, node->value.tree, overwrite);
			} else if ((tmp->type & NVTREE_ARRAY) != 0 && (node->type & NVTREE_ARRAY) != 0) {
				TAILQ_FOREACH(it, node->value.array, next) {
					TAILQ_INSERT_TAIL(tmp->value.array, nvtpair_clone(it), next);
				}
			} else if (overwrite) {
				nvtree_rm(dst, tmp);
				nvtree_add(dst, nvtpair_clone(node));
			} else {
				continue;
			}
		} else {
			nvtree_add(dst, nvtpair_clone(node));

		}
	}
}

static bool
nvtree_check_filter(const nvtree_t *data) {
	nvtpair_t *node = NULL;

	if (data == NULL) {
		return false;
	}
	RB_FOREACH(node, nvtree_t, __DECONST(nvtree_t *, data)) {
		if ((node->type & NVTREE_ARRAY) != 0) {
			if ((node->type & ~NVTREE_ARRAY) != NVTREE_BOOL) {
				return false;
			}
		} else {
			switch (node->type) {
				case NVTREE_BOOL:
				case NVTREE_NESTED:
					break;
				default:
					return false;
			}
		}
	}
	return true;
}

nvtree_t *
nvtree_filter(const nvtree_t *root, const nvtree_t *data) {
	nvtree_t *dst = NULL;
	nvtpair_t *node = NULL;
	nvtpair_t *tmp = NULL;

	if (root == NULL) {
		return (NULL);
	}
	if (!nvtree_check_filter(data)) {
		return NULL;
	}
	dst = nvtree_create();
	RB_FOREACH(node, nvtree_t, __DECONST(nvtree_t *, data)) {
		tmp = nvtree_find(root, node->name);
		if (tmp == NULL) {
			goto err;
		}
		nvtree_add(dst, nvtpair_clone(tmp));
	}
	return (dst);
err:
	if (dst != NULL) {
		nvtree_destroy(dst);
	}
	return (NULL);
}

#ifndef _KERNEL
static void
replace_fds(nvtree_t *root, int *fds) {
	nvtpair_t *pair = NULL;
	nvtpair_t *node = NULL;

	RB_FOREACH(pair, nvtree_t, root) {
		if (pair->type == NVTREE_DESC) {
			pair->value.fd = fds[pair->value.fd];
		} else if ((pair->type & NVTREE_ARRAY) == NVTREE_DESC) {
			TAILQ_FOREACH(node, pair->value.array, next) {
				node->value.fd = fds[node->value.fd];
			}
		} else if (pair->type == NVTREE_NESTED) {
			replace_fds(pair->value.tree, fds);
		}
	}
}

nvtree_t *
nvtree_recv(const int sock) {
	int rc = 0;
	int *fds = NULL;
	uint64_t i = 0;
	size_t size = 0;
	nvtree_t *root = NULL;
	void *buf = NULL;
	uint8_t *ptr = NULL;
	uint8_t dummy = 0;
	struct nvtree_header head = {};
	struct msghdr msg = {};
	struct cmsghdr *cmsg = NULL;
	struct iovec iov = {};

	rc = read(sock, &head, sizeof(head));
	if (rc < 0) {
		goto err;
	}
	buf = malloc(head.size);
	memcpy(buf, &head, sizeof(head));
	ptr = buf;
	ptr += sizeof(head);
	size = head.size;
	rc = read(sock, ptr, size);
	if (rc < 0) {
		goto err;
	}
	ptr = buf;
	root = _nvtree_unpack(&ptr, ptr + size + sizeof(head));
	if (root == NULL) {
		goto err;
	}
	free(buf);

	if (head.descriptors > 0) {
		iov.iov_base = &dummy;
		iov.iov_len = sizeof(dummy);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_controllen = head.descriptors * CMSG_SPACE(sizeof(int));
		msg.msg_control = calloc(1, msg.msg_controllen);

		fds = malloc(head.descriptors * sizeof(int));
		if (recvmsg(sock, &msg, 0) == -1) {
			goto err;
		}
		cmsg = CMSG_FIRSTHDR(&msg);
		while (cmsg && i < head.descriptors) {
			unsigned int n;

			if (cmsg->cmsg_level != SOL_SOCKET ||
			    cmsg->cmsg_type != SCM_RIGHTS) {
				errno = EINVAL;
				break;
			}
			n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			if (i + n > head.descriptors) {
				errno = EINVAL;
				break;
			}
			bcopy(CMSG_DATA(cmsg), fds + i, sizeof(int) * n);
			cmsg = CMSG_NXTHDR(&msg, cmsg);
			i += n;
		}
		replace_fds(root, fds);
		free(fds);
	}

	return (root);
err:
	if (buf != NULL) {
		free(buf);
	}
	if (fds != NULL) {
		free(fds);
	}
	if (root != NULL) {
		nvtree_destroy(root);
	}
	return (NULL);
}


int
nvtree_send(const int sock, const nvtree_t *root) {
	int rc = 0;
	size_t size = 0;
	void *buf = NULL;
	int *fds = NULL;
	size_t nfds = 0;
	size_t idx = 0;
	struct msghdr msg = {};
	struct cmsghdr *cmsg = NULL;
	struct iovec iov = {};
	unsigned int i = 0;
	uint8_t dummy = 0;
	int flags = 0;

#ifdef MSG_CMSG_CLOEXEC
	flags = MSG_CMSG_CLOEXEC;
#else
	flags = 0;
#endif

	nfds = nvtree_descriptors(root);
	if (nfds > 0) {
		fds = malloc(nfds * sizeof(int));
	}
	buf = _nvtree_pack(root, &size, fds, &idx);
	if (buf == NULL) {
		goto err;
	}
	rc = write(sock, buf, size);
	if (rc < 0) {
		goto err;
	}
	free(buf);
	if (nfds > 0) {
		int fd = 0;
		iov.iov_base = &dummy;
		iov.iov_len = sizeof(dummy);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_controllen = nfds * CMSG_SPACE(sizeof(int));
		msg.msg_control = calloc(1, msg.msg_controllen);

		if (msg.msg_control == NULL) {
			goto err;
		}
		for (i = 0, cmsg = CMSG_FIRSTHDR(&msg); i < nfds && cmsg != NULL;
		    ++i, cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
			bcopy(&fd, CMSG_DATA(cmsg), sizeof(fd));
		}
		if (sendmsg(sock, &msg, flags) == -1) {
			printf("error %d\n", errno);
			goto err;
		}
	}
	free(fds);
	return (0);
err:
	if (buf != NULL) {
		free(buf);
	}
	if (fds != NULL) {
		free(fds);
	}
	return (-1);
}

static void
_nvtree_dump(FILE *output, nvtree_t *root, size_t depth) {
	nvtpair_t *pair = NULL;
	nvtpair_t *node = NULL;

	RB_FOREACH(pair, nvtree_t, __DECONST(nvtree_t *, root)) {
		for (size_t i = 0; i < depth; ++i) {
			fprintf(output, "  ");
		}
		if (pair->name != NULL) {
			fprintf(output, "%s ", pair->name);
		}
		fprintf(output, "[%s]: ", type_to_string(pair));
		if (pair->type & NVTREE_ARRAY) {
			fprintf(output, "\n");
			TAILQ_FOREACH(node, pair->value.array, next) {
				_nvtree_dump(output, pair->value.tree, depth + 1);
			}
		} else {
			switch (pair->type) {
				case NVTREE_BOOL: {
					fprintf(output, "%d\n", pair->value.b);
					break;
				}
				case NVTREE_DESC: {
					fprintf(output, "%ld\n", pair->value.fd);
					break;
				}
				case NVTREE_NULL: {
					fprintf(output, "NULL\n");
					break;
				}
				case NVTREE_NUMBER: {
					fprintf(output, "%lu\n", pair->value.num);
					break;
				}
				case NVTREE_STRING: {
					fprintf(output, "%s\n", pair->value.string);
					break;
				}
				case NVTREE_NESTED: {
					fprintf(output, "\n");
					_nvtree_dump(output, pair->value.tree, depth + 1);
					break;
				}
			}
		}
	}
}

void
nvtree_dump(FILE *output, const nvtree_t *root) {
	_nvtree_dump(output, __DECONST(nvtree_t *, root), 0);
}
#endif
