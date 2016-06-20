/*
	most code extract from nginx
*/

#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/mman.h>

#include "mcache.h"

#define ngx_pagesize         4096
#define ngx_pagesize_shift   12

#define NGX_SLAB_PAGE_MASK   3
#define NGX_SLAB_PAGE        0
#define NGX_SLAB_BIG         1
#define NGX_SLAB_EXACT       2
#define NGX_SLAB_SMALL       3

#if (__SIZEOF_POINTER__ == 4)

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffff
#define NGX_SLAB_PAGE_START  0x80000000

#define NGX_SLAB_SHIFT_MASK  0x0000000f
#define NGX_SLAB_MAP_MASK    0xffff0000
#define NGX_SLAB_MAP_SHIFT   16

#define NGX_SLAB_BUSY        0xffffffff

#else /* (__SIZEOF_POINTER__ == 8) */

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NGX_SLAB_PAGE_START  0x8000000000000000

#define NGX_SLAB_SHIFT_MASK  0x000000000000000f
#define NGX_SLAB_MAP_MASK    0xffffffff00000000
#define NGX_SLAB_MAP_SHIFT   32

#define NGX_SLAB_BUSY        0xffffffffffffffff

#endif

#define LOOPUP_HIT      0
#define LOOKUP_MISS     1

#define ngx_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

typedef struct ngx_slab_page_s  ngx_slab_page_t;

struct ngx_slab_page_s {
    uintptr_t         slab;
    ngx_slab_page_t  *next;
    uintptr_t         prev;
};

typedef struct {
    u_char                       color;
    u_char                       dummy;
    u_short                      len;
    ngx_queue_t                  queue;

    uint32_t                     value;

    u_char                       data[1];
} mcache_kv_node_t;

typedef struct {
    pthread_mutex_t   lock;

    size_t            min_size;
    size_t            min_shift;

    ngx_slab_page_t  *pages;
    ngx_slab_page_t   free;

    u_char            zero;

    u_char           *start;
    u_char           *end;

    void             *data;
    void             *addr;
} ngx_slab_pool_t;

static uint32_t  crc32_table16[] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};

static unsigned int ngx_slab_max_size;
static unsigned int ngx_slab_exact_size;
static unsigned int ngx_slab_exact_shift;

static void             ngx_slab_init(ngx_slab_pool_t *pool);
static void            *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool, unsigned int pages);
static void             ngx_slab_free(ngx_slab_pool_t *pool, void *p);
static void             ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page, unsigned int pages);

static void              mcache_rbtree_insert_value(ngx_rbtree_node_t *temp, 
                                                   ngx_rbtree_node_t *node, 
                                                   ngx_rbtree_node_t *sentinel);
static int               mcache_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
static uint32_t          mcache_crc32_short(u_char *p, size_t len);
static mcache_kv_node_t *mcache_kvs_lookup(mcache_index_t *index, u_char *data,
                                           size_t len, unsigned int hash);
static void              mcache_lru_expire(mcache_kv_t *kvs);

static void mcache_lru_expire(mcache_kv_t *kvs)
{
    ngx_queue_t                *q;
    ngx_rbtree_node_t          *node;
    ngx_slab_pool_t            *shpool = (ngx_slab_pool_t *)kvs->mc->addr;
    
    mcache_kv_node_t           *kn;

    if (ngx_queue_empty(&kvs->index->queue)) {
        return;
    }

    q = ngx_queue_last(&kvs->index->queue);

    kn = ngx_queue_data(q, mcache_kv_node_t, queue);

    ngx_queue_remove(q);

    node = (ngx_rbtree_node_t *)
                ((u_char *) kn - offsetof(ngx_rbtree_node_t, color));

    ngx_rbtree_delete(&kvs->index->rbtree, node);

    ngx_slab_free(shpool, node);
}


static mcache_kv_node_t*
mcache_kvs_lookup(mcache_index_t *index, u_char *data, size_t len, unsigned int hash)
{
    int rc;

    ngx_rbtree_node_t  *node, *sentinel;

    mcache_kv_node_t   *kvn;

    node = index->rbtree.root;
    sentinel = index->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        kvn = (mcache_kv_node_t *) &node->color;

        rc = mcache_memn2cmp(data, kvn->data, len, (size_t) kvn->len);

        if (rc == 0) {
            return kvn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}

static uint32_t mcache_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = crc32_table16[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = crc32_table16[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}

static int mcache_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2)
{
    size_t     n;
    int        m, z;

    if (n1 <= n2) {
        n = n1;
        z = -1;

    } else {
        n = n2;
        z = 1;
    }

    m = memcmp((const char *)s1, (const char *)s2, n);

    if (m || n1 == n2) {
        return m;
    }

    return z;
}

static void
mcache_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    mcache_kv_node_t            *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (mcache_kv_node_t *) &node->color;
            lrnt = (mcache_kv_node_t *) &temp->color;

            p = (mcache_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static void ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    unsigned int pages)
{
    ngx_slab_page_t  *prev;

    page->slab = pages--;

    if (pages) {
    	memset(&page[1], 0x00, pages * sizeof(ngx_slab_page_t));
    }

    if (page->next) {
        prev = (ngx_slab_page_t *) (page->prev & ~NGX_SLAB_PAGE_MASK);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
}

static void ngx_slab_free(ngx_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    unsigned int      n, type, slot, shift, map;
    ngx_slab_page_t  *slots, *page;

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = page->prev & NGX_SLAB_PAGE_MASK;

    switch (type) {

    case NGX_SLAB_SMALL:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (ngx_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n & (sizeof(uintptr_t) * 8 - 1));
        n /= (sizeof(uintptr_t) * 8);
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) ngx_pagesize - 1));

        if (bitmap[n] & m) {

            if (page->next == NULL) {
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NGX_SLAB_SMALL;
            }

            bitmap[n] &= ~m;

            n = (1 << (ngx_pagesize_shift - shift)) / 8 / (1 << shift);

            if (n == 0) {
                n = 1;
            }

            if (bitmap[0] & ~(((uintptr_t) 1 << n) - 1)) {
                goto done;
            }

            map = (1 << (ngx_pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            for (n = 1; n < map; n++) {
                if (bitmap[n]) {
                    goto done;
                }
            }

            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (ngx_pagesize - 1)) >> ngx_slab_exact_shift);
        size = ngx_slab_exact_size;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            if (slab == NGX_SLAB_BUSY) {
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = ngx_slab_exact_shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NGX_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_BIG:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (ngx_pagesize - 1)) >> shift)
                              + NGX_SLAB_MAP_SHIFT);

        if (slab & m) {

            if (page->next == NULL) {
                slots = (ngx_slab_page_t *)
                                   ((u_char *) pool + sizeof(ngx_slab_pool_t));
                slot = shift - pool->min_shift;

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NGX_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & NGX_SLAB_MAP_MASK) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_PAGE:

        if ((uintptr_t) p & (ngx_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (slab == NGX_SLAB_PAGE_FREE) {
            goto fail;
        }

        if (slab == NGX_SLAB_PAGE_BUSY) {
            goto fail;
        }

        n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
        size = slab & ~NGX_SLAB_PAGE_START;

        ngx_slab_free_pages(pool, &pool->pages[n], size);

        return;
    }

    /* not reached */

    return;

done:

    return;

wrong_chunk:

    goto fail;

chunk_already_free:
	/* TODO */

fail:

    return;
}

static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool, unsigned int pages)
{
    ngx_slab_page_t  *page, *p;

    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {
                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                p = (ngx_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                p = (ngx_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            page->slab = pages | NGX_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = NGX_SLAB_PAGE;

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = NGX_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = NGX_SLAB_PAGE;
                p++;
            }

            return page;
        }
    }

    return NULL;
}

static void ngx_slab_init(ngx_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    int               m;
    unsigned int      i, n, pages;
    ngx_slab_page_t  *slots;

    /* STUB */
    if (ngx_slab_max_size == 0) {
        ngx_slab_max_size = ngx_pagesize / 2;
        ngx_slab_exact_size = ngx_pagesize / (8 * sizeof(uintptr_t));
        for (n = ngx_slab_exact_size; n >>= 1; ngx_slab_exact_shift++) {
            /* void */
        }
    }
    /**/

    pool->min_size = 1 << pool->min_shift;

    p = (u_char *) pool + sizeof(ngx_slab_pool_t);
    size = pool->end - p;

    slots = (ngx_slab_page_t *) p;
    n = ngx_pagesize_shift - pool->min_shift;

    for (i = 0; i < n; i++) {
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
    }

    p += n * sizeof(ngx_slab_page_t);

    pages = (unsigned int) (size / (ngx_pagesize + sizeof(ngx_slab_page_t)));

    memset(p, 0x00, pages * sizeof(ngx_slab_page_t));

    pool->pages = (ngx_slab_page_t *) p;

    pool->free.prev = 0;
    pool->free.next = (ngx_slab_page_t *) p;

    pool->pages->slab = pages;
    pool->pages->next = &pool->free;
    pool->pages->prev = (uintptr_t) &pool->free;

    pool->start = (u_char *)
                  ngx_align_ptr((uintptr_t) p + pages * sizeof(ngx_slab_page_t),
                                 ngx_pagesize);

    m = pages - (pool->end - pool->start) / ngx_pagesize;
    if (m > 0) {
        pages -= m;
        pool->pages->slab = pages;
    }

    pool->zero = '\0';
}

static void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, n, m, mask, *bitmap;
    unsigned int      i, slot, shift, map;
    ngx_slab_page_t  *page, *prev, *slots;

    if (size >= ngx_slab_max_size) {

        page = ngx_slab_alloc_pages(pool, (size >> ngx_pagesize_shift)
                                          + ((size % ngx_pagesize) ? 1 : 0));
        if (page) {
            p = (page - pool->pages) << ngx_pagesize_shift;
            p += (uintptr_t) pool->start;

        } else {
            p = 0;
        }

        goto done;
    }

    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        size = pool->min_size;
        shift = pool->min_shift;
        slot = 0;
    }

    slots = (ngx_slab_page_t *) ((u_char *) pool + sizeof(ngx_slab_pool_t));
    page = slots[slot].next;

    if (page->next != page) {

        if (shift < ngx_slab_exact_shift) {

            do {
                p = (page - pool->pages) << ngx_pagesize_shift;
                bitmap = (uintptr_t *) (pool->start + p);

                map = (1 << (ngx_pagesize_shift - shift))
                          / (sizeof(uintptr_t) * 8);

                for (n = 0; n < map; n++) {

                    if (bitmap[n] != NGX_SLAB_BUSY) {

                        for (m = 1, i = 0; m; m <<= 1, i++) {
                            if ((bitmap[n] & m)) {
                                continue;
                            }

                            bitmap[n] |= m;

                            i = ((n * sizeof(uintptr_t) * 8) << shift)
                                + (i << shift);

                            if (bitmap[n] == NGX_SLAB_BUSY) {
                                for (n = n + 1; n < map; n++) {
                                     if (bitmap[n] != NGX_SLAB_BUSY) {
                                         p = (uintptr_t) bitmap + i;

                                         goto done;
                                     }
                                }

                                prev = (ngx_slab_page_t *)
                                            (page->prev & ~NGX_SLAB_PAGE_MASK);
                                prev->next = page->next;
                                page->next->prev = page->prev;

                                page->next = NULL;
                                page->prev = NGX_SLAB_SMALL;
                            }

                            p = (uintptr_t) bitmap + i;

                            goto done;
                        }
                    }
                }

                page = page->next;

            } while (page);

        } else if (shift == ngx_slab_exact_shift) {

            do {
                if (page->slab != NGX_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if ((page->slab & m)) {
                            continue;
                        }

                        page->slab |= m;

                        if (page->slab == NGX_SLAB_BUSY) {
                            prev = (ngx_slab_page_t *)
                                            (page->prev & ~NGX_SLAB_PAGE_MASK);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NGX_SLAB_EXACT;
                        }

                        p = (page - pool->pages) << ngx_pagesize_shift;
                        p += i << shift;
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);

        } else { /* shift > ngx_slab_exact_shift */

            n = ngx_pagesize_shift - (page->slab & NGX_SLAB_SHIFT_MASK);
            n = 1 << n;
            n = ((uintptr_t) 1 << n) - 1;
            mask = n << NGX_SLAB_MAP_SHIFT;

            do {
                if ((page->slab & NGX_SLAB_MAP_MASK) != mask) {

                    for (m = (uintptr_t) 1 << NGX_SLAB_MAP_SHIFT, i = 0;
                         m & mask;
                         m <<= 1, i++)
                    {
                        if ((page->slab & m)) {
                            continue;
                        }

                        page->slab |= m;

                        if ((page->slab & NGX_SLAB_MAP_MASK) == mask) {
                            prev = (ngx_slab_page_t *)
                                            (page->prev & ~NGX_SLAB_PAGE_MASK);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NGX_SLAB_BIG;
                        }

                        p = (page - pool->pages) << ngx_pagesize_shift;
                        p += i << shift;
                        p += (uintptr_t) pool->start;

                        goto done;
                    }
                }

                page = page->next;

            } while (page);
        }
    }

    page = ngx_slab_alloc_pages(pool, 1);

    if (page) {
        if (shift < ngx_slab_exact_shift) {
            p = (page - pool->pages) << ngx_pagesize_shift;
            bitmap = (uintptr_t *) (pool->start + p);

            s = 1 << shift;
            n = (1 << (ngx_pagesize_shift - shift)) / 8 / s;

            if (n == 0) {
                n = 1;
            }

            bitmap[0] = (2 << n) - 1;

            map = (1 << (ngx_pagesize_shift - shift)) / (sizeof(uintptr_t) * 8);

            for (i = 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;

            slots[slot].next = page;

            p = ((page - pool->pages) << ngx_pagesize_shift) + s * n;
            p += (uintptr_t) pool->start;

            goto done;

        } else if (shift == ngx_slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;

            slots[slot].next = page;

            p = (page - pool->pages) << ngx_pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;

        } else { /* shift > ngx_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;

            slots[slot].next = page;

            p = (page - pool->pages) << ngx_pagesize_shift;
            p += (uintptr_t) pool->start;

            goto done;
        }
    }

    p = 0;

done:

    return (void *) p;
}

const char *mcache_estr(int ecode)
{
	return estr[ecode];
}


mcache_t *mcache_init(size_t size, char err_buf[], size_t err_len)
{
    int  ecode = 0;
    
    mcache_t        *mc;
	
    ngx_slab_pool_t *sp;

	if (size < (8 * ngx_pagesize)) {
        ecode = MC_SIZE_LACK;
        goto failed;
	}

    mc = (mcache_t *)malloc(sizeof(mcache_t));
    if (mc == NULL) {
        ecode = MC_NO_MEMORY;
        goto failed;
    }

	mc->addr = (u_char *) mmap(NULL, mc->size,
                                PROT_READ|PROT_WRITE,
                                MAP_ANON|MAP_SHARED, -1, 0);
    if (mc->addr == MAP_FAILED) {
        ecode = MC_MMAP_FAILED;
        goto failed;
    }

    sp = (ngx_slab_pool_t *) mc->addr;

    sp->end = mc->addr + mc->size;
    sp->min_shift = 3;
    sp->addr = mc->addr;

    pthread_mutex_init(&sp->lock, NULL);

    ngx_slab_init(sp);

    return mc;

failed:
    if (ecode) {
        snprintf(err_buf, err_len, "%s", mcache_estr(ecode));
    }

    return NULL;
}

int mcache_destroy(mcache_t *mc)
{
    int res = 0;
    if (munmap((void *) mc->addr, mc->size) == -1) {
        res = MC_UNMAP_FAILED;
    }

    free(mc);

    return res;
}

void *mcache_alloc(mcache_t *mc, size_t size)
{
	ngx_slab_pool_t *sp = (ngx_slab_pool_t *)mc->addr;
	return ngx_slab_alloc(sp, size);
}

void *mcache_alloc_locked(mcache_t *mc, size_t size)
{
    void  *p;

	ngx_slab_pool_t *sp = (ngx_slab_pool_t *)mc->addr;

	pthread_mutex_lock(&sp->lock);

	p = ngx_slab_alloc(sp, size);

	pthread_mutex_unlock(&sp->lock);

	return p;
}

void mcache_free(mcache_t *mc, void *p)
{
	ngx_slab_pool_t *sp = (ngx_slab_pool_t *)mc->addr;
	return ngx_slab_free(sp, p);
}

void mcache_free_locked(mcache_t *mc, void *p)
{
	ngx_slab_pool_t *sp = (ngx_slab_pool_t *)mc->addr;

	pthread_mutex_lock(&sp->lock);

	ngx_slab_free(sp, p);

	pthread_mutex_unlock(&sp->lock);

	return;
}

mcache_kv_t *mcache_kv_init(size_t size, char *err_buf, size_t err_len)
{
    int ecode = 0;

    mcache_kv_t *kvs;

    ngx_slab_pool_t *sp;

    kvs = (mcache_kv_t *)malloc(sizeof(mcache_kv_t));
    if (kvs == NULL) {
        ecode = MC_NO_MEMORY;
        goto failed;        
    }

    kvs->mc = mcache_init(size, err_buf, err_len);
    if (kvs->mc == NULL) {
        goto failed;
    }

    sp = (ngx_slab_pool_t *) kvs->mc->addr;

    kvs->index = ngx_slab_alloc(sp, sizeof(mcache_index_t));
    if (kvs->index == NULL) {
        ecode = MC_NO_SLAB;
        goto failed;
    }

    ngx_rbtree_init(&kvs->index->rbtree, &kvs->index->sentinel,
                    mcache_rbtree_insert_value);

    ngx_queue_init(&kvs->index->queue);

    return kvs;

failed:
    if (ecode) {
        snprintf(err_buf, err_len, "%s", mcache_estr(ecode));
    }
    return NULL;
}

int mcache_kv_free(mcache_kv_t *kvs)
{
    int res;

    res = mcache_destroy(kvs->mc);

    free(kvs);

    return res;
}

int mcache_kv_set(mcache_kv_t *kvs, u_char *key, uint32_t value)
{
    size_t   len, size;
    uint32_t hash;

    mcache_kv_node_t    *kv_node;

    ngx_rbtree_node_t   *node;
    ngx_slab_pool_t     *sp = (ngx_slab_pool_t *)kvs->mc->addr;

    len  = strlen((char *)key);
    hash = mcache_crc32_short(key, len);

    pthread_mutex_lock(&sp->lock);

    kv_node = mcache_kvs_lookup(kvs->index, key, len, hash);
    if (kv_node) {
        return MC_SET_EXISTS;
    }

    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(mcache_kv_node_t, data)
           + len;

    node = ngx_slab_alloc(sp, size);
    if (node == NULL) {
        mcache_lru_expire(kvs);

        node = ngx_slab_alloc(sp, size);
        if (node == NULL) {
            return MC_NO_SLAB;
        }
    }

    node->key = hash;

    kv_node = (mcache_kv_node_t *) &node->color;
    kv_node->len = len;
    kv_node->value = value;

    (void)memcpy(kv_node->data, key, len);

    ngx_rbtree_insert(&kvs->index->rbtree, node);
    ngx_queue_insert_head(&kvs->index->queue, &kv_node->queue);

    pthread_mutex_unlock(&sp->lock);

    return 0;
}

int mcache_kv_delete(mcache_kv_t *kvs, u_char *key)
{
    size_t   len;
    uint32_t hash;

    mcache_kv_node_t *kv_node;

    ngx_rbtree_node_t  *node;
    ngx_slab_pool_t    *sp = (ngx_slab_pool_t *)kvs->mc->addr;

    len  = strlen((char *)key);
    hash = mcache_crc32_short(key, len);

    pthread_mutex_lock(&sp->lock);

    kv_node = mcache_kvs_lookup(kvs->index, key, len, hash);
    if (kv_node == NULL) {
        return MC_KEY_NOEXISTS;
    }

    node = (ngx_rbtree_node_t *)
                   ((u_char *) kv_node - offsetof(ngx_rbtree_node_t, color));

    ngx_queue_remove(&kv_node->queue);
    ngx_rbtree_delete(&kvs->index->rbtree, node);
    ngx_slab_free(sp, node);

    pthread_mutex_unlock(&sp->lock);

    return 0;
}

