/* Verification 022: measure f(PA28).
 *
 * Verification 016 recovered the bank relation over model bits up to PA27 from
 * a 256 MiB allocation.  PA28 needs two addresses differing in only bit 28, so
 * it needs a span exceeding 2^28 -- which 256 MiB is not, by exactly one bit.
 *
 * Two results make this runnable.  Verification 020 measured camera_preview's
 * ceiling at 320 MiB, and Verification 021 proved a full-size allocation
 * consumes the whole carveout: with 320 MiB held, not one 4 KiB page remains,
 * between two 5/5 controls.  The device tree declares that carveout at base
 * 0xC2000000, so offset o is physical 0xC2000000 + o.
 *
 * What changes versus a90_region_probe_r.c
 * ----------------------------------------
 * That probe required a power-of-two allocation, because `a ^ d` only stays in
 * range for free when the size is one, and it had to *solve* for the
 * allocation's offset inside its region behaviourally -- sweeping bits 13..23
 * to measure the alignment it could not read.
 *
 * The base is now known, so alignment is verified rather than solved.  Every
 * candidate pair is checked exactly: PA_a ^ PA_b must equal the difference, or
 * the pair is rejected and counted.  A carry that would smear the difference
 * across bits it does not name cannot enter the sample.  That is strictly
 * stronger than assuming a power-of-two size, and it is what allows a
 * non-power-of-two span to be used at all.
 *
 * The timing core, barriers, warmups, alternation, trimming and divisor are
 * copied verbatim from a90_region_probe_r.c, which copied them verbatim from
 * Experiment 014.  No instrumentation difference is introduced.
 *
 * Read-only: it allocates, maps, reads, and frees.  It writes no register, no
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

#define PROBE_SCHEMA "a90_pa28_probe_v1"
#define PAGE_BYTES UINT64_C(4096)
#define PAGE_SHIFT 12U
#define PAGEMAP_PFN_MASK ((UINT64_C(1) << 55) - 1)
#define PAGEMAP_PRESENT (UINT64_C(1) << 63)
#define CACHE_LINE_BYTES 64U
#define PAIR_WARMUPS 17U
#define EVICTION_BYTES (UINT64_C(16) * 1024 * 1024)
#define MAX_PAIRS 256U
#define MAX_REPETITIONS 10001U
#define MAX_DIFFERENCES 96U
#define OFFSET_SEED UINT64_C(0x5da9f0e3c17b2846)
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

/* Copied verbatim from tools/a90_dram_timing_probe.c so that the timed
 * quantity is instruction-for-instruction the same as Experiment 014's. */
static inline uint64_t read_cntvct(void)
{
    uint64_t value;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(value));
    return value;
}

static inline uint64_t read_cntfrq(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return value;
}

/* 014 uses `dsb ld` with no ISB here.  Experiment 023's extra ISB is the
 * defect being repaired; do not reintroduce it. */
static inline void load_barrier(void)
{
    __asm__ volatile("dsb ld" : : : "memory");
}

static inline void full_barrier(void)
{
    __asm__ volatile("dsb sy\n\tisb" : : : "memory");
}

static int compare_u64(const void *left, const void *right)
{
    const uint64_t a = *(const uint64_t *)left;
    const uint64_t b = *(const uint64_t *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

/* Deltas are signed.  Sorting them through the unsigned comparator puts every
 * negative value above every positive one and corrupts the percentiles. */
static int compare_i64(const void *left, const void *right)
{
    const int64_t a = *(const int64_t *)left;
    const int64_t b = *(const int64_t *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

/* Copied verbatim from Experiment 014: prime, intervene, then time the
 * reopen. */
static uint64_t measure_reopen_once(const uint8_t *prime,
                                    const uint8_t *intervening,
                                    const uint8_t *timed)
{
    uint64_t start;
    uint64_t end;
    uint64_t accumulator;

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

/* Emit whatever /proc/self/pagemap reports for the mapping.  A dma-buf mapped
 * VM_PFNMAP commonly reads back as not-present with a zero PFN; that is a
 * result to be reported, not a failure to be hidden. */
static void emit_pagemap_provenance(const uint8_t *map, uint64_t bytes)
{
    const uint64_t pages = bytes / PAGE_BYTES;
    uint64_t present = 0, nonzero = 0, first_pfn = 0, last_pfn = 0;
    int contiguous = 1, have_first = 0;
    int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        printf("{\"schema\":\"%s\",\"type\":\"pa_provenance\","
               "\"source\":\"pagemap\",\"status\":\"OPEN_FAILED\"}\n",
               PROBE_SCHEMA);
        return;
    }
    for (uint64_t index = 0; index < pages; ++index) {
        const uint64_t va = (uint64_t)(uintptr_t)(map + index * PAGE_BYTES);
        const off_t offset = (off_t)((va >> PAGE_SHIFT) * sizeof(uint64_t));
        uint64_t entry = 0;

        if (pread(fd, &entry, sizeof(entry), offset) != (ssize_t)sizeof(entry))
            break;
        if ((entry & PAGEMAP_PRESENT) != 0)
            ++present;
        const uint64_t pfn = entry & PAGEMAP_PFN_MASK;
        if (pfn != 0) {
            ++nonzero;
            if (!have_first) {
                first_pfn = pfn;
                have_first = 1;
            } else if (pfn != last_pfn + 1) {
                contiguous = 0;
            }
            last_pfn = pfn;
        }
    }
    close(fd);
    printf("{\"schema\":\"%s\",\"type\":\"pa_provenance\","
           "\"source\":\"pagemap\",\"pages\":%llu,\"present\":%llu,"
           "\"nonzero_pfn\":%llu,\"first_pfn\":\"0x%llx\","
           "\"last_pfn\":\"0x%llx\",\"contiguous\":%s,\"status\":\"%s\"}\n",
           PROBE_SCHEMA, (unsigned long long)pages,
           (unsigned long long)present, (unsigned long long)nonzero,
           (unsigned long long)first_pfn, (unsigned long long)last_pfn,
           contiguous ? "true" : "false",
           nonzero == 0 ? "BLIND" : (nonzero == pages && contiguous
                                     ? "RESOLVED" : "PARTIAL"));
}

int main(int argc, char **argv)
{
    const char *heap_name;
    const char *offset_mode;
    const char *ion_path;
    uint64_t mib, repetitions, pairs, base;
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
    if (argc < 9) {
        fprintf(stderr,
                "usage: %s <heap-name> <MiB> <repetitions> <pairs> <cpu> "
                "<offset-mode> <declared-base> <ion-node> <difference>...\n"
                "  offset-mode: stride | spread\n"
                "  declared-base: physical base of the backing carveout\n"
                "  ion-node: path to the ION character device\n",
                argv[0]);
        return 2;
    }
    heap_name = argv[1];
    mib = strtoull(argv[2], NULL, 0);
    repetitions = strtoull(argv[3], NULL, 0);
    pairs = strtoull(argv[4], NULL, 0);
    cpu = (unsigned int)strtoul(argv[5], NULL, 0);
    offset_mode = argv[6];
    base = strtoull(argv[7], NULL, 0);
    ion_path = argv[8];
    difference_start = 9;
    if (strcmp(offset_mode, "stride") != 0 && strcmp(offset_mode, "spread") != 0) {
        fprintf(stderr, "offset-mode must be stride or spread\n");
        return 2;
    }
    if (mib == 0 || repetitions < 3 || repetitions > MAX_REPETITIONS ||
        pairs == 0 || pairs > MAX_PAIRS) {
        fprintf(stderr, "argument out of range\n");
        return 2;
    }
    bytes = mib << 20;
    /* a90_region_probe_r.c required a power of two so that `a ^ d` stayed in
     * range and so that offset XOR equalled physical XOR.  Neither is assumed
     * here: the range check in the pair loop covers the first, and every pair
     * is verified against the declared base for the second.  The base must
     * still be page aligned for page-aligned offsets to mean anything. */
    if ((base & (PAGE_BYTES - 1)) != 0) {
        fprintf(stderr, "declared base must be page aligned\n");
        return 2;
    }

    if (pin_cpu(cpu) != 0) {
        fprintf(stderr, "pin_cpu: %s\n", strerror(errno));
        return 1;
    }
    printf("{\"schema\":\"%s\",\"type\":\"context\",\"cpu\":%u,"
           "\"cntfrq\":%llu,\"heap\":\"%s\",\"mib\":%llu,"
           "\"repetitions\":%llu,\"pairs\":%llu,\"warmups\":%u,"
           "\"order\":\"alternating\",\"barrier\":\"dsb_ld\","
           "\"divisor\":\"kept_times_two\",\"offset_mode\":\"%s\","
           "\"declared_base\":\"0x%llx\"}\n",
           PROBE_SCHEMA, cpu, (unsigned long long)read_cntfrq(), heap_name,
           (unsigned long long)mib, (unsigned long long)repetitions,
           (unsigned long long)pairs, PAIR_WARMUPS, offset_mode,
           (unsigned long long)base);

    /* V2321 has no /dev/ion; the caller creates a temporary node and names it
     * here, so the probe never depends on a path that does not exist. */
    ion_fd = open(ion_path, O_RDONLY | O_CLOEXEC);
    if (ion_fd < 0) { perror("open ion node"); return 1; }
    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0) { perror("heap query"); return 1; }
    if (query.cnt == 0 || query.cnt > ION_MAX_HEAPS) { fprintf(stderr, "bad heap count\n"); return 1; }
    heaps = calloc(query.cnt, sizeof(*heaps));
    if (heaps == NULL) { perror("calloc heaps"); return 1; }
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0) { perror("heap data"); return 1; }
    for (uint32_t index = 0; index < query.cnt; ++index) {
        heaps[index].name[ION_HEAP_NAME_BYTES - 1] = '\0';
        if (strcmp(heaps[index].name, heap_name) == 0)
            selected = &heaps[index];
    }
    if (selected == NULL) { fprintf(stderr, "heap %s not found\n", heap_name); return 1; }
    /* Only a physically contiguous heap makes an offset difference equal a
     * physical one.  Type 0 is the page-based system heap and is refused. */
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
    full_barrier();

    emit_pagemap_provenance(map, bytes);

    relation = calloc(repetitions, sizeof(*relation));
    baseline = calloc(repetitions, sizeof(*baseline));
    if (relation == NULL || baseline == NULL) { perror("calloc samples"); return 1; }

    for (int arg = difference_start; arg < argc && arg - difference_start < (int)MAX_DIFFERENCES; ++arg) {
        uint64_t difference = strtoull(argv[arg], NULL, 0);
        int64_t deltas[MAX_PAIRS];
        size_t used = 0, rejected_range = 0, rejected_carry = 0;

        /* Sub-page differences are allowed.  Offsets `a` are page aligned and
         * the allocation base is at least page aligned, so the low bits of a
         * pair differ by exactly the difference's low bits with no carry, and
         * a bit below PA12 is therefore measured as precisely as one above.
         * Riding such a bit on a large kernel witness keeps the two addresses
         * in different rows, so the conflict question stays well posed. */
        if (difference == 0 || difference >= bytes) {
            printf("{\"schema\":\"%s\",\"type\":\"difference\",\"value\":\"0x%llx\","
                   "\"status\":\"OUT_OF_RANGE\"}\n",
                   PROBE_SCHEMA, (unsigned long long)difference);
            continue;
        }
        for (uint64_t index = 0; index < pairs; ++index) {
            /* The pair must differ by XOR, not by addition: a conflict is
             * f(a ^ b) == 0, and a + d carries into bits the difference does
             * not name.  The allocation is a power of two, so a ^ d stays in
             * range whenever a and d do. */
            uint64_t a, b;

            if (strcmp(offset_mode, "stride") == 0) {
                /* Evenly spaced offsets.  These are multiples of a large
                 * power of two, so adding a base offset smaller than that
                 * spacing never carries -- which makes this mode blind to
                 * the allocation's offset inside its region. */
                a = (index * (bytes / pairs)) & ~(PAGE_BYTES - 1);
            } else {
                /* Offsets that vary in their low bits, so that a nonzero
                 * base offset does produce differing carries and becomes
                 * observable.  A fixed LCG keeps the set reproducible. */
                uint64_t state = OFFSET_SEED + index * UINT64_C(0x9e3779b97f4a7c15);
                state ^= state >> 30;
                state *= UINT64_C(0xbf58476d1ce4e5b9);
                state ^= state >> 27;
                state *= UINT64_C(0x94d049bb133111eb);
                state ^= state >> 31;
                a = (state % (bytes / PAGE_BYTES)) * PAGE_BYTES;
            }
            b = a ^ difference;
            const uint8_t *pa = map + a;
            const uint8_t *pb = map + b;
            size_t trim, kept, rep;
            uint64_t relation_sum = 0, baseline_sum = 0;
            int64_t delta;

            if (a + PAGE_BYTES > bytes || b + PAGE_BYTES > bytes) {
                ++rejected_range;
                continue;
            }
            /* The load-bearing check.  A conflict is f(PA_a ^ PA_b) == 0, so
             * the pair is only evidence about this difference if the physical
             * XOR *is* this difference.  Adding the base can carry, turning a
             * single-bit difference into a multi-bit one that would be scored
             * against the wrong bit.  Verify rather than assume. */
            if (((base + a) ^ (base + b)) != difference) {
                ++rejected_carry;
                continue;
            }
            sweep_eviction(eviction, (uint8_t)(index + 1));
            full_barrier();

            /* Warm all four reopen forms, as 014 does.  Warming only two
             * lets two of the four measured forms enter the sample cold. */
            for (unsigned int warm = 0; warm < PAIR_WARMUPS; ++warm) {
                (void)measure_reopen_once(pb, pa, pb);
                (void)measure_reopen_once(pa, pb, pa);
                (void)measure_reopen_once(pa, pa, pa);
                (void)measure_reopen_once(pb, pb, pb);
            }
            /* Alternate which of the two families is measured first, as 014
             * does, so the row state each leaves behind does not bias the
             * other in one fixed direction. */
            for (rep = 0; rep < repetitions; ++rep) {
                uint64_t r, s;

                if ((rep & 1U) == 0) {
                    r = measure_reopen_once(pb, pa, pb);
                    r += measure_reopen_once(pa, pb, pa);
                    s = measure_reopen_once(pa, pa, pa);
                    s += measure_reopen_once(pb, pb, pb);
                } else {
                    s = measure_reopen_once(pa, pa, pa);
                    s += measure_reopen_once(pb, pb, pb);
                    r = measure_reopen_once(pb, pa, pb);
                    r += measure_reopen_once(pa, pb, pa);
                }
                relation[rep] = r;
                baseline[rep] = s;
            }
            qsort(relation, repetitions, sizeof(*relation), compare_u64);
            qsort(baseline, repetitions, sizeof(*baseline), compare_u64);
            trim = (size_t)repetitions / 10;
            kept = (size_t)repetitions - 2 * trim;
            for (rep = trim; rep < (size_t)repetitions - trim; ++rep) {
                relation_sum += relation[rep];
                baseline_sum += baseline[rep];
            }
            /* 014 divides by `kept * 2` because each sample is the sum of two
             * reopens.  Reporting the undivided difference puts the result on
             * a 2x scale and makes the two experiments incomparable. */
            delta = ((int64_t)relation_sum - (int64_t)baseline_sum) * 1000 /
                    (int64_t)(kept * 2);
            deltas[used++] = delta;
            /* Per-pair output: the analysis solves the allocation's offset
             * inside the region from the pattern of these labels. */
            printf("{\"schema\":\"%s\",\"type\":\"pair\",\"value\":\"0x%llx\","
                   "\"offset\":\"0x%llx\",\"pa_a\":\"0x%llx\",\"pa_b\":\"0x%llx\","
                   "\"pa_xor\":\"0x%llx\",\"delta\":%lld}\n",
                   PROBE_SCHEMA, (unsigned long long)difference,
                   (unsigned long long)a, (unsigned long long)(base + a),
                   (unsigned long long)(base + b),
                   (unsigned long long)((base + a) ^ (base + b)),
                   (long long)delta);
        }
        if (used == 0) {
            printf("{\"schema\":\"%s\",\"type\":\"difference\",\"value\":\"0x%llx\","
                   "\"status\":\"NO_PAIRS\",\"rejected_range\":%zu,"
                   "\"rejected_carry\":%zu}\n",
                   PROBE_SCHEMA, (unsigned long long)difference,
                   rejected_range, rejected_carry);
            continue;
        }
        qsort(deltas, used, sizeof(*deltas), compare_i64);
        printf("{\"schema\":\"%s\",\"type\":\"difference\",\"value\":\"0x%llx\","
               "\"pairs\":%zu,\"rejected_range\":%zu,\"rejected_carry\":%zu,"
               "\"p10\":%lld,\"median\":%lld,\"p90\":%lld}\n",
               PROBE_SCHEMA, (unsigned long long)difference, used,
               rejected_range, rejected_carry,
               (long long)deltas[used / 10],
               (long long)deltas[used / 2],
               (long long)deltas[used - 1 - used / 10]);
    }

    free(relation);
    free(baseline);
    free(heaps);
    munmap(eviction, EVICTION_BYTES);
    munmap(map, bytes);
    close((int)allocation.fd);
    close(ion_fd);
    return 0;
}
