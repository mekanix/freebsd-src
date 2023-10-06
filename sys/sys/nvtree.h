#ifndef	_NVTREE_H_
#define	_NVTREE_H_

#include <sys/queue.h>
#include <sys/tree.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#endif

#define NVTREE_BOOL	0x01
#define NVTREE_NUMBER	0x02
#define NVTREE_STRING	0x03
#define NVTREE_NULL	0x04
#define NVTREE_NESTED	0x05
#ifndef _KERNEL
#define NVTREE_DESC	0x06
#endif

#define NVTREE_ARRAY	0x10

struct nvtree_t;
struct nvtpair_t;

typedef union {
	int64_t fd;
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

// Create/destroy
nvtree_t *	nvtree_create	(void);
int		nvtree_destroy	(nvtree_t *root);

// Pack/unpack related
void *		nvtree_pack	(const nvtree_t *root, size_t *size);
size_t		nvtree_size	(const nvtree_t *root);
nvtree_t *	nvtree_unpack	(const void *buf, size_t size);

// Allocate type
nvtpair_t *	nvtree_array	(const char *name, size_t type);
nvtpair_t *	nvtree_bool	(const char *name, bool value);
#ifndef _KERNEL
nvtpair_t *	nvtree_fd	(const char *name, int fd);
#endif
nvtpair_t *	nvtree_nested	(const char *name, const nvtree_t *value);
nvtpair_t *	nvtree_null	(const char *name);
nvtpair_t *	nvtree_number	(const char *name, uint64_t value);
nvtpair_t *	nvtree_pair	(const char *name);
nvtpair_t *	nvtree_string	(const char *name, const char *value);

// Management
nvtpair_t *	nvtree_add	(nvtree_t *root, nvtpair_t *pair);
nvtpair_t *	nvtree_rm	(nvtree_t *root, nvtpair_t *pair);
nvtpair_t *	nvtree_add_pair	(nvtpair_t *root, nvtpair_t *pair);
nvtpair_t *	nvtree_rm_pair	(nvtpair_t *root, nvtpair_t *pair);

// Utils
nvtpair_t *	nvtree_find	(const nvtree_t *root, const char *name);
void		nvtree_merge	(nvtree_t *dst, const nvtree_t *src, bool overwrite);
nvtree_t *	nvtree_clone	(const nvtree_t *root);
nvtree_t *	nvtree_filter	(const nvtree_t *root, const nvtree_t *data);
#ifndef _KERNEL
nvtree_t *	nvtree_recv	(const int sock);
int		nvtree_send	(const int sock, const nvtree_t *root);
void		nvtree_dump	(FILE *output, const nvtree_t *root);
#endif

__END_DECLS

#endif	/* !_NVTREE_H_ */
