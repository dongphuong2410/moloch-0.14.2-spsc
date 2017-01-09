#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "mempool.h"

static char* m_mempool = NULL;
static mpool_elt *mempool_head = NULL;
static uint64_t mempool_insert_cnt = 0;

int init_mempool(int elt_num, uint64_t elt_size) {
	int i;

	printf("elt_num : %d, elt_size : %"PRIu64"\n", elt_num, elt_size);
	m_mempool = malloc(sizeof(char) * (elt_num * elt_size));	
	if (m_mempool == NULL) return 0;

	for (i = 0; i < elt_num; i++) {
		mpool_elt *new_elt = malloc(sizeof(mpool_elt));
		new_elt->elt_addr = m_mempool + (elt_size * i);
		new_elt->elt_size = elt_size;

		//printf("mempool %d , pos : %p\n", i, new_elt->elt_addr);
		LL_APPEND(mempool_head, new_elt);
		mempool_insert_cnt++;
	}

	//printf("mempool_insert_cnt : %d\n", mempool_insert_cnt);
	
	return 1;
}

mpool_elt *get_mempool(void) {
	mpool_elt *head = mempool_head;
	if (mempool_insert_cnt == 0) return NULL;

	LL_DELETE(mempool_head, head);
	mempool_insert_cnt--;
	//printf("mempool_cnt : %d\n", mempool_insert_cnt);
	return head;
}

void put_mempool(mpool_elt *elt) {
	LL_APPEND(mempool_head, elt);
	mempool_insert_cnt++;
}

bool able_check_mempool(void) {
	return (mempool_insert_cnt != 0);
}

void destroy_mempool(void) {
	mpool_elt *elt, *tmp;

	LL_FOREACH_SAFE(mempool_head, elt, tmp) {
		printf("destroy_mempool : %p\n", elt->elt_addr);
		LL_DELETE(mempool_head, elt);
		mempool_insert_cnt--;
		free(elt);
	}

	printf("mempool_insert_cnt : %"PRIu64"\n", mempool_insert_cnt);
	if(m_mempool) free(m_mempool);
}

#if 0
int main(int argc, char **argv) {
	mpool_elt *elt;
	int i;
	int ret = init_mempool(100, MB);

	LL_FOREACH(mempool_head, elt) {
		printf("mempool pos : %p\n", elt->elt_addr);
	}

	printf("--------------------------------------\n");
	for (i = 0; i < 127; i++) {
		mpool_elt *gelt = get_mempool();
		if (gelt) put_mempool(gelt);
	}

	LL_FOREACH(mempool_head, elt) {
		printf("mempool pos : %p\n", elt->elt_addr);
	}

	destroy_mempool();
}
#endif
