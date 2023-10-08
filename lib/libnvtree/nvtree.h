#ifndef	_NVTREE_H_
#define	_NVTREE_H_

#include <sys/queue.h>
#include <sys/tree.h>

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define NVTREE_RO	0x001
#define NVTREE_NODELETE	0x002

#define NVTREE_BOOL	0x010
#define NVTREE_NUMBER	0x020
#define NVTREE_STRING	0x040
#define NVTREE_NULL	0x080
#define NVTREE_SIMPLE	(NVTREE_BOOL | NVTREE_NUMBER | NVTREE_STRING | NVTREE_NULL)

#define NVTREE_ARRAY	0x100
#define NVTREE_NESTED	0x200

struct nvtree_t;
struct nvtpair_t;

typedef union {
	bool b;
	uint64_t num;
	char *string;
	struct nvtree_t *tree;
	struct nvtarray_t *array;
} nvtvalue_t;

typedef struct nvtpair_t {
	TAILQ_ENTRY(nvtpair_t) next;
	RB_ENTRY(nvtpair_t) entry;
	char *name;
	size_t type;
	nvtvalue_t value;
} nvtpair_t;

typedef TAILQ_HEAD(nvtarray_t, nvtpair_t) nvtarray_t;
typedef RB_HEAD(nvtree_t, nvtpair_t) nvtree_t;

__BEGIN_DECLS

int attr_name_compare(const nvtpair_t *a1, const nvtpair_t *a2);
RB_PROTOTYPE(nvtree_t, nvtpair_t, entry, attr_name_compare)

nvtree_t *	nvtree_create	(void);
nvtpair_t *	nvtree_pair	(const char *name);
nvtpair_t *	nvtree_number	(const char *name, const uint64_t value);
nvtpair_t *	nvtree_bool	(const char *name, const bool value);
nvtpair_t *	nvtree_string	(const char *name, const char *value);
nvtpair_t *	nvtree_null	(const char *name);
nvtpair_t *	nvtree_tree	(const char *name);
nvtpair_t *	nvtree_array	(const char *name);
nvtpair_t *	nvtree_nested	(const char *name);
nvtpair_t *	nvtree_find	(const nvtree_t *root, const char *name);
nvtpair_t *	nvtree_add	(nvtree_t *root, nvtpair_t *pair);
nvtpair_t *	nvtree_remove	(nvtree_t *root, nvtpair_t *pair);
size_t		nvtree_size	(const nvtree_t *root);
void *		nvtree_pack	(const nvtree_t *root, size_t *size);
nvtree_t *	nvtree_unpack	(const uint8_t *buf, size_t size);
int		nvtree_destroy	(nvtree_t *root);

__END_DECLS

#endif	/* !_NVTREE_H_ */
