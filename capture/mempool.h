#include <utlist.h>

typedef enum {false, true} bool;

#define MB 1024*1024

typedef struct pool_element {
	char *elt_addr;
	uint64_t elt_size;
	uint64_t elt_wsize;
	struct pool_element *next;
} mpool_elt;

int init_mempool(int elt_num, uint64_t elt_size);
void destroy_mempool(void);
mpool_elt *get_mempool(void);
void put_mempool(mpool_elt *elt);
