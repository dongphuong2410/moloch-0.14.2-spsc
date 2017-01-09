#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>

#include <emmintrin.h>

#include "spsc_ring.h"

#define MAX_THREAD_NUM 8

#if 0
struct sub_thread_st {
	struct spsc_ring_st *r;
	uint64_t thread_id;
	uint64_t dequeue_num;
};

struct insert_thread_st {
	int sub_thread_num;
	struct spsc_ring_st **sub_r;

	uint64_t enqueue_num_per_thread[MAX_THREAD_NUM];
};


static struct sub_thread_st th_stats[MAX_THREAD_NUM];
static struct insert_thread_st ist;
static pthread_t th_id[MAX_THREAD_NUM];
static pthread_t ith_id;

struct spsc_ring_st {
        /** Ring producer status. */
        struct prod {
                uint32_t watermark;      /**< Maximum items before EDQUOT. */
                uint32_t size;           /**< Size of ring. */
                uint32_t mask;           /**< Mask (size-1) of ring. */
                volatile uint32_t head;  /**< Producer head. */
                volatile uint32_t tail;  /**< Producer tail. */
        } prod __rte_cache_aligned;

        /** Ring consumer status. */
        struct cons {
                uint32_t size;           /**< Size of the ring. */
                uint32_t mask;           /**< Mask (size-1) of ring. */
                volatile uint32_t head;  /**< Consumer head. */
                volatile uint32_t tail;  /**< Consumer tail. */
        } cons __rte_cache_aligned;

        void * ring[0] __rte_cache_aligned; /**< Memory space of ring starts here.
                                             not volatile so need to be careful
                                             about compiler re-ordering */
};
#endif

/* return the size of memory occupied by a ring */
inline ssize_t 
spsc_ring_get_memsize(unsigned count)
{
	ssize_t sz; 

	/* count must be a power of 2 */
	if ((!POWEROF2(count)) || (count > SPSC_RING_SZ_MASK )) {
		printf("Requested size is invalid, must be power of 2, and "
				"do not exceed the size limit %u\n", SPSC_RING_SZ_MASK);
		return -1;
	}

	sz = sizeof(struct spsc_ring_st) + count * sizeof(void *);
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);
	return sz;
}

inline int
spsc_ring_init(struct spsc_ring_st *r, unsigned count) {
	/* init the ring structure */
        memset(r, 0, sizeof(*r));
        r->prod.watermark = count;
        r->prod.size = r->cons.size = count;
        r->prod.mask = r->cons.mask = count-1;
        r->prod.head = r->cons.head = 0;
        r->prod.tail = r->cons.tail = 0;

        return 0;
}

struct spsc_ring_st *
spsc_ring_create(unsigned count) {
	ssize_t ring_size;
	struct spsc_ring_st *r;

	ring_size = spsc_ring_get_memsize(count);
        if (ring_size < 0) return NULL;

	r = (struct spsc_ring_st *)malloc(ring_size);
	if (r == NULL) return NULL;

	spsc_ring_init(r, count);
	return r;
}

/**
 * Compiler barrier.
 *
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define compiler_barrier() do {             \
        asm volatile ("" : : : "memory");       \
} while(0)

#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

int spsc_ring_enqueue(struct spsc_ring_st *r, void * const obj) {
	uint32_t prod_head, cons_tail;
        uint32_t prod_next, free_entries;
        uint32_t mask = r->prod.mask;
        int ret;
	
	prod_head = r->prod.head;
        cons_tail = r->cons.tail;
        /* The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * prod_head > cons_tail). So 'free_entries' is always between 0
         * and size(ring)-1. */
        free_entries = mask + cons_tail - prod_head;

	/* check that we have enough room in ring */
	if (unlikely(free_entries == 0)) {
		return -1;
	}

	prod_next = prod_head + 1;
        r->prod.head = prod_next;

        uint32_t idx = prod_head & mask;
	
	r->ring[idx] = obj;
	compiler_barrier();

	/* if we exceed the watermark */
        if (unlikely(((mask + 1) - free_entries + 1) > r->prod.watermark))
		ret = -1;
        else
		ret = 0;

        r->prod.tail = prod_next;
        return ret;
}

int spsc_ring_dequeue(struct spsc_ring_st *r, void **obj) {
	uint32_t cons_head, prod_tail;
        uint32_t cons_next, entries;
        uint32_t mask = r->prod.mask;

        cons_head = r->cons.head;
        prod_tail = r->prod.tail;
        /* The subtraction is done between two unsigned 32bits value
         * (the result is always modulo 32 bits even if we have
         * cons_head > prod_tail). So 'entries' is always between 0
         * and size(ring)-1. */
        entries = prod_tail - cons_head;

	if (entries == 0) {
		return -1;
	}

	cons_next = cons_head + 1;
        r->cons.head = cons_next;

        /* copy in table */
	uint32_t idx = cons_head & mask;
	*obj = r->ring[idx];

	compiler_barrier();

        r->cons.tail = cons_next;
        return 0;
}

/**
 * Return the number of entries in a ring.
 *
 * @param r
 *   A pointer to the ring structure.
 * @return
 *   The number of entries in the ring.
 */
unsigned
spsc_ring_count(const struct spsc_ring_st *r) {
	compiler_barrier();

        uint32_t prod_tail = r->prod.tail;
        uint32_t cons_tail = r->cons.tail;
        return (prod_tail - cons_tail) & r->prod.mask;
}

#if 0
struct test_data {
	time_t time;
	uint64_t idx;
};

void *sub_thread(void *arg) {
	struct sub_thread_st *th_stat = (struct sub_thread_st *)arg;

	while(1) {
		void *void_data = NULL;
		int deq_ret = spsc_ring_dequeue(th_stat->r, &void_data);
		if (deq_ret == 0) {
			struct test_data *rdata = (struct test_data *)void_data;
/*
			printf("thread id : %d, time : %ld, idx : %u\n",
				th_stat->thread_id, rdata->time, rdata->idx);
*/
			free(void_data);
			th_stat->dequeue_num++;
		}
	}
}

void *insert_thread(void* arg) {
	struct insert_thread_st *ist = (struct insert_thread_st *)arg;
	int i;

	while(1) {
		uint64_t idx = 0;

		for(i = 0; i < ist->sub_thread_num; i++) {
			struct test_data *data = malloc(sizeof(struct test_data));

			data->time = time(0);
			data->idx = idx;

			spsc_ring_enqueue(ist->sub_r[i], data);
			ist->enqueue_num_per_thread[i]++;
		}
		idx++;
	}
}

int main(int argc, char **argv) {
	int i;

	ist.sub_r = malloc(sizeof(struct spsc_ring_st *) * MAX_THREAD_NUM);
	ist.sub_thread_num = MAX_THREAD_NUM;
	memset(ist.enqueue_num_per_thread, 0x00, sizeof(ist.enqueue_num_per_thread));

	for (i = 0; i < MAX_THREAD_NUM; i++) {
		th_stats[i].thread_id = i;
		th_stats[i].r = spsc_ring_create(131072);
		if (th_stats[i].r == NULL)
			printf("ring for thread id : %d failed\n", i);

		ist.sub_r[i] = th_stats[i].r;

		th_stats[i].dequeue_num = 0;
		pthread_create(&th_id[i], NULL, sub_thread, &th_stats[i]);
	}

	pthread_create(&ith_id, NULL, insert_thread, &ist);

	while(1) {
		for(i = 0; i < MAX_THREAD_NUM; i++) {
			printf("thread id : %d, enq : %"PRIu64", deq : %"PRIu64"\n",
				i, ist.enqueue_num_per_thread[i], th_stats[i].dequeue_num);
		}
	}
}
#endif
