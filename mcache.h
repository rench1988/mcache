#ifndef __MCACHE_H_
#define __MCACHE_H_

#include "ngx_queue.h"
#include "ngx_rbtree.h"

#include <stdint.h>

enum ecode {
	MC_SUCCESS,
	MC_SIZE_LACK,
	MC_MMAP_FAILED,
	MC_UNMAP_FAILED,
	MC_NO_MEMORY,
	MC_NO_SLAB,
	MC_SET_EXISTS,
	MC_KEY_NOEXISTS,
};

const char *estr[] = {
	"success",
	"initialized size is too small"
	"system call \"mmap\" failed",
	"system call \"unmap\" failed",
	"memory insufficient",
	"slab(memory) insufficient",
	"key already exists",
	"key doesnt exists"
};

typedef struct mcache_s        mcache_t;
typedef struct mcache_kv_s     mcache_kv_t;
typedef struct mcache_index_s  mcache_index_t;

struct mcache_s {
	u_char	*addr;
	size_t	 size;
};

struct mcache_index_s {
	ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;
};

struct mcache_kv_s {
	mcache_t 	   *mc;
	mcache_index_t *index;
};


mcache_t   *mcache_init(size_t size, char *err_buf, size_t err_len);
int         mcache_destroy(mcache_t *mc);
void       *mcache_alloc(mcache_t *mc, size_t size);
void       *mcache_alloc_locked(mcache_t *mc, size_t size);
void        mcache_free(mcache_t *mc, void *p);
void        mcache_free_locked(mcache_t *mc, void *p);
const char *mcache_estr(int ecode);

mcache_kv_t  *mcache_kv_init(size_t size, char *err_buf, size_t err_len);
int           mcache_kv_free(mcache_kv_t *kvs);
int           mcache_kv_set(mcache_kv_t *kvs, u_char *key, uint32_t value);
int           mcache_kv_delete(mcache_kv_t *kvs, u_char *key);       



#endif
