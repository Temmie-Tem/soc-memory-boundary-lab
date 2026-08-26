/* Experiment 023 probe: is the DRAM bank relation the same in another region?
 *
 * Experiment 014 recovered a GF(2) bank-selection relation inside one 16 MiB
 * ION `user_contig` allocation. That heap is a 16 MiB CMA window at a fixed
 * base, so PA bits 24 and above never varied and only one region was ever
 * measured. This probe measures the same way in a second carveout.
 *
 * No physical address is needed. For a linear f, a conflict depends on
 * f(a ^ b) == 0, so it is a function of the difference alone. Inside one
 * physically contiguous allocation the PA difference equals the virtual offset
 * difference, so the same differences can be replayed in any contiguous region
 * without knowing where that region starts.
 *
 * The timing core -- the reopen sequence, the barriers, the counter reads, the
 * trimmed mean -- is reproduced from tools/a90_dram_timing_probe.c so the
 * numbers are comparable. Only heap selection and the dropping of physical
 * address binding are new.
 *
 * Read-only: it allocates, maps, reads, and frees. It writes no register, no
 * partition, and no device memory outside its own allocation.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define PROBE_SCHEMA "a90_region_probe_v1"
#define PAGE_BYTES UINT64_C(4096)
#define CACHE_LINE_BYTES 64U
#define PAIR_WARMUPS 17U
#define EVICTION_BYTES (UINT64_C(16) * 1024 * 1024)
#define MAX_PAIRS 128U
#define MAX_REPETITIONS 10001U
#define MAX_DIFFERENCES 96U
#define ION_MAX_HEAPS 64U
#define ION_HEAP_NAME_BYTES 32U

struct ion_allocation_data_uapi {
    uint64_t len;
    uint32_t heap_id_mask;
    uint32_t flags;
    uint32_t fd;
    uint32_t unused;
};
struct ion_heap_data_uapi {
    char name[ION_HEAP_NAME_BYTES];
    uint32_t type;
    uint32_t heap_id;
    uint32_t reserved0, reserved1, reserved2;
};
struct ion_heap_query_uapi {
    uint32_t cnt;
    uint32_t reserved0;
    uint64_t heaps;
    uint32_t reserved1, reserved2;
};
#define ION_IOC_ALLOC _IOWR('I', 0, struct ion_allocation_data_uapi)
#define ION_IOC_HEAP_QUERY _IOWR('I', 8, struct ion_heap_query_uapi)

static volatile uint64_t load_sink;

static inline uint64_t read_cntvct(void)
{
    uint64_t value;
    __asm__ __volatile__("isb\n\tmrs %0, cntvct_el0" : "=r"(value) :: "memory");
    return value;
}

static inline uint64_t read_cntfrq(void)
{
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(value));
    return value;
}

static inline void load_barrier(void)
{
    __asm__ __volatile__("dsb ld\n\tisb" ::: "memory");
}

static int compare_u64(const void *left, const void *right)
{
    const uint64_t a = *(const uint64_t *)left;
    const uint64_t b = *(const uint64_t *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

/* Deltas are signed. Sorting them through the unsigned comparator puts every
 * negative value above every positive one and corrupts the percentiles. */
static int compare_i64(const void *left, const void *right)
{
    const int64_t a = *(const int64_t *)left;
    const int64_t b = *(const int64_t *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

/* Reproduced from Experiment 014: prime, intervene, then time the reopen. */
static uint64_t measure_reopen_once(const uint8_t *prime,
                                    const uint8_t *intervening,
                                    const uint8_t *timed)
{
    uint64_t start, end, accumulator;

    accumulator = *(volatile const uint8_t *)prime;
    load_barrier();
    accumulator ^= *(volatile const uint8_t *)intervening;
    load_barrier();
    start = read_cntvct();
    accumulator ^= *(volatile const uint8_t *)timed;
    load_barrier();
    end = read_cntvct();
    load_sink ^= accumulator;
    return end - start;
}

/* 10% trimmed mean, reported in milli-ticks to survive counter quantisation. */
static int64_t trimmed_mean_milli(uint64_t *samples, size_t count)
{
    size_t trim, index, used = 0;
    uint64_t total = 0;

    qsort(samples, count, sizeof(*samples), compare_u64);
    trim = count / 10;
    for (index = trim; index + trim < count; ++index) {
        total += samples[index];
        ++used;
    }
    if (used == 0)
        return 0;
    return (int64_t)((total * 1000) / used);
}

static int pin_cpu(unsigned int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static void sweep_eviction(uint8_t *eviction, uint8_t value)
{
    size_t index;
    for (index = 0; index < EVICTION_BYTES; index += CACHE_LINE_BYTES)
        *(volatile uint8_t *)(eviction + index) ^= value;
}

int main(int argc, char **argv)
{
    const char *heap_name;
    uint64_t mib, repetitions, pairs;
    unsigned int cpu = 7;
    int ion_fd = -1;
    struct ion_heap_query_uapi query;
    struct ion_heap_data_uapi *heaps = NULL, *selected = NULL;
    struct ion_allocation_data_uapi allocation;
    uint8_t *map = NULL, *eviction = NULL;
    uint64_t bytes;
    uint64_t *relation = NULL, *baseline = NULL;
    int difference_start;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 6) {
        fprintf(stderr,
                "usage: %s <heap-name> <MiB> <repetitions> <pairs> <cpu> "
                "<difference>...\n", argv[0]);
        return 2;
    }
    heap_name = argv[1];
    mib = strtoull(argv[2], NULL, 0);
    repetitions = strtoull(argv[3], NULL, 0);
    pairs = strtoull(argv[4], NULL, 0);
    cpu = (unsigned int)strtoul(argv[5], NULL, 0);
    difference_start = 6;
    if (mib == 0 || repetitions < 3 || repetitions > MAX_REPETITIONS ||
        pairs == 0 || pairs > MAX_PAIRS) {
        fprintf(stderr, "argument out of range\n");
        return 2;
    }
    bytes = mib << 20;
    if ((bytes & (bytes - 1)) != 0) {
        fprintf(stderr, "size must be a power of two for XOR pairing\n");
        return 2;
    }

    if (pin_cpu(cpu) != 0) {
        fprintf(stderr, "pin_cpu: %s\n", strerror(errno));
        return 1;
    }
    printf("{\"schema\":\"%s\",\"type\":\"context\",\"cpu\":%u,"
           "\"cntfrq\":%llu,\"heap\":\"%s\",\"mib\":%llu,"
           "\"repetitions\":%llu,\"pairs\":%llu}\n",
           PROBE_SCHEMA, cpu, (unsigned long long)read_cntfrq(), heap_name,
           (unsigned long long)mib, (unsigned long long)repetitions,
           (unsigned long long)pairs);

    ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (ion_fd < 0) { perror("open /dev/ion"); return 1; }
    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0) { perror("heap query"); return 1; }
    if (query.cnt == 0 || query.cnt > ION_MAX_HEAPS) { fprintf(stderr, "bad heap count\n"); return 1; }
    heaps = calloc(query.cnt, sizeof(*heaps));
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0) { perror("heap data"); return 1; }
    for (uint32_t index = 0; index < query.cnt; ++index) {
        heaps[index].name[ION_HEAP_NAME_BYTES - 1] = '\0';
        if (strcmp(heaps[index].name, heap_name) == 0)
            selected = &heaps[index];
    }
    if (selected == NULL) { fprintf(stderr, "heap %s not found\n", heap_name); return 1; }
    /* Only a physically contiguous heap makes an offset difference equal a
     * physical one. Type 0 is the page-based system heap and is refused. */
    if (selected->type == 0U) {
        fprintf(stderr, "heap %s is the page-based system heap; "
                        "offset differences would not be physical\n", heap_name);
        return 1;
    }
    printf("{\"schema\":\"%s\",\"type\":\"ion_heap\",\"name\":\"%s\","
           "\"heap_type\":%u,\"heap_id\":%u}\n",
           PROBE_SCHEMA, selected->name, selected->type, selected->heap_id);

    memset(&allocation, 0, sizeof(allocation));
    allocation.len = bytes;
    allocation.heap_id_mask = UINT32_C(1) << selected->heap_id;
    allocation.flags = 0;   /* no ION_FLAG_CACHED -> pgprot_writecombine */
    if (ioctl(ion_fd, ION_IOC_ALLOC, &allocation) != 0) { perror("ion alloc"); return 1; }
    map = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, (int)allocation.fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    eviction = mmap(NULL, EVICTION_BYTES, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (eviction == MAP_FAILED) { perror("eviction mmap"); return 1; }
    memset(eviction, 0, EVICTION_BYTES);

    for (uint64_t off = 0; off < bytes; off += PAGE_BYTES)
        *(volatile uint8_t *)(map + off) = 0;

    relation = calloc(repetitions, sizeof(*relation));
    baseline = calloc(repetitions, sizeof(*baseline));

    for (int arg = difference_start; arg < argc && arg - difference_start < (int)MAX_DIFFERENCES; ++arg) {
        uint64_t difference = strtoull(argv[arg], NULL, 0);
        int64_t deltas[MAX_PAIRS];
        size_t used = 0;

        if (difference == 0 || (difference & (PAGE_BYTES - 1)) != 0 || difference >= bytes) {
            printf("{\"schema\":\"%s\",\"type\":\"difference\",\"value\":\"0x%llx\","
                   "\"status\":\"OUT_OF_RANGE\"}\n",
                   PROBE_SCHEMA, (unsigned long long)difference);
            continue;
        }
        for (uint64_t index = 0; index < pairs; ++index) {
            /* The pair must differ by XOR, not by addition: a conflict is
             * f(a ^ b) == 0, and a + d carries into bits the difference does
             * not name. The allocation is a power of two, so a ^ d stays in
             * range whenever a and d do. */
            uint64_t stride = bytes / pairs;
            uint64_t a = (index * stride) & ~(PAGE_BYTES - 1);
            uint64_t b = a ^ difference;
            const uint8_t *pa = map + a;
            const uint8_t *pb = map + b;

            if (a + PAGE_BYTES > bytes || b + PAGE_BYTES > bytes)
                continue;
            sweep_eviction(eviction, (uint8_t)(index + 1));
            for (unsigned int warm = 0; warm < PAIR_WARMUPS; ++warm) {
                (void)measure_reopen_once(pb, pa, pb);
                (void)measure_reopen_once(pa, pa, pa);
            }
            for (uint64_t rep = 0; rep < repetitions; ++rep) {
                /* relation: B -> A -> timed B, and A -> B -> timed A */
                relation[rep] = measure_reopen_once(pb, pa, pb) +
                                measure_reopen_once(pa, pb, pa);
                /* baseline: A -> A -> timed A, and B -> B -> timed B */
                baseline[rep] = measure_reopen_once(pa, pa, pa) +
                                measure_reopen_once(pb, pb, pb);
            }
            deltas[used++] = trimmed_mean_milli(relation, repetitions) -
                             trimmed_mean_milli(baseline, repetitions);
        }
        if (used == 0) {
            printf("{\"schema\":\"%s\",\"type\":\"difference\",\"value\":\"0x%llx\","
                   "\"status\":\"NO_PAIRS\"}\n",
                   PROBE_SCHEMA, (unsigned long long)difference);
            continue;
        }
        qsort(deltas, used, sizeof(*deltas), compare_i64);
        printf("{\"schema\":\"%s\",\"type\":\"difference\",\"value\":\"0x%llx\","
               "\"pairs\":%zu,\"p10\":%lld,\"median\":%lld,\"p90\":%lld}\n",
               PROBE_SCHEMA, (unsigned long long)difference, used,
               (long long)deltas[used / 10],
               (long long)deltas[used / 2],
               (long long)deltas[used - 1 - used / 10]);
    }

    munmap(eviction, EVICTION_BYTES);
    munmap(map, bytes);
    close((int)allocation.fd);
    close(ion_fd);
    free(relation);
    free(baseline);
    free(heaps);
    printf("{\"schema\":\"%s\",\"type\":\"done\"}\n", PROBE_SCHEMA);
    return 0;
}
