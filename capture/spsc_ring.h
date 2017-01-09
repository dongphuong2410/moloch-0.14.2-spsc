#include <inttypes.h>
#include <stdio.h>

#define RTE_CACHE_LINE_SIZE 64

/**
 * Force alignment
 */
#define __rte_aligned(a) __attribute__((__aligned__(a)))

/**
 * Force alignment to cache line.
 */
#define __rte_cache_aligned __rte_aligned(RTE_CACHE_LINE_SIZE)

/* true if x is a power of 2 */
#define POWEROF2(x) ((((x)-1) & (x)) == 0)
#define SPSC_RING_SZ_MASK  (unsigned)(0x0fffffff) /**< Ring size mask */

/**
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no
 * bigger than the first parameter. Second parameter must be a
 * power-of-two value.
 */
#define RTE_ALIGN_FLOOR(val, align) \
        (typeof(val))((val) & (~((typeof(val))((align) - 1))))

/**
 * Macro to align a value to a given power-of-two. The resultant value
 * will be of the same type as the first parameter, and will be no lower
 * than the first parameter. Second parameter must be a power-of-two
 * value.
 */
#define RTE_ALIGN_CEIL(val, align) \
        RTE_ALIGN_FLOOR(((val) + ((typeof(val)) (align) - 1)), align)

/**
 * Macro to align a value to a given power-of-two. The resultant
 * value will be of the same type as the first parameter, and
 * will be no lower than the first parameter. Second parameter
 * must be a power-of-two value.
 * This function is the same as RTE_ALIGN_CEIL
 */
#define RTE_ALIGN(val, align) RTE_ALIGN_CEIL(val, align)

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

struct spsc_ring_st *spsc_ring_create(unsigned count);
int spsc_ring_dequeue(struct spsc_ring_st *r, void **obj);
int spsc_ring_enqueue(struct spsc_ring_st *r, void * const obj);
unsigned spsc_ring_count(const struct spsc_ring_st *r);
