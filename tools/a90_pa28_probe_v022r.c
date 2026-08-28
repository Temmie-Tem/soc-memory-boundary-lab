/* Verification 022R: measure f(PA28) with a fixed, cleanup-attested surface.
 *
 * Verification 016 recovered the bank relation over model bits up to PA27 from
 * a 256 MiB allocation.  PA28 needs two addresses differing in only bit 28, so
 * it needs a span exceeding 2^28 -- which 256 MiB is not, by exactly one bit.
 *
 * Two results make this runnable.  Verification 020 measured camera_preview's
 * ceiling at 320 MiB, and Verification 021 is
 * SUPPORTED_WITHIN_RETAINED_RECEIPT for the bounded observation that a
 * full-size allocation consumes the whole carveout: with 320 MiB held, not
 * one 4 KiB page remains, between two 5/5 controls.  The device tree declares
 * that carveout at base 0xC2000000, so offset o is physical 0xC2000000 + o.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define PROBE_SCHEMA "a90_pa28_probe_v022r_v1"
#define FIXED_ION_PATH "/tmp/a90-native/v022r-ion"
#define EXPECTED_ARGC 20
#define PAGE_BYTES UINT64_C(4096)
#define PAGE_SHIFT 12U
#define PAGEMAP_PFN_MASK ((UINT64_C(1) << 55) - 1)
#define PAGEMAP_PRESENT (UINT64_C(1) << 63)
#define CACHE_LINE_BYTES 64U
#define PAIR_WARMUPS 17U
#define EVICTION_BYTES (UINT64_C(16) * 1024 * 1024)
#define MAX_PAIRS 256U
#define MAX_REPETITIONS 10001U
#define MAX_DIFFERENCES 11U
#define OFFSET_SEED UINT64_C(0x5da9f0e3c17b2846)
#define ION_MAX_HEAPS 64U
#define ION_HEAP_NAME_BYTES 32U
#define EXPECTED_HEAP_NAME "camera_preview"
#define EXPECTED_HEAP_TYPE 10U
#define EXPECTED_HEAP_ID 30U
#define EXPECTED_MIB UINT64_C(320)
#define EXPECTED_BYTES (EXPECTED_MIB * UINT64_C(1024) * UINT64_C(1024))
#define EXPECTED_REPETITIONS 201U
#define EXPECTED_PAIRS 256U
#define EXPECTED_CPU 7U
#define EXPECTED_CNTFRQ UINT64_C(19200000)
#define EXPECTED_BASE UINT64_C(0xc2000000)
#define DIFFERENCE_CONFLICT UINT64_C(0x16000)
#define DIFFERENCE_NEGATIVE UINT64_C(0x2000)
#define DIFFERENCE_PA28_BANK13 UINT64_C(0x10002000)
#define DIFFERENCE_PA28_BANK14 UINT64_C(0x10004000)
#define DIFFERENCE_PA28_BANK13_14 UINT64_C(0x10006000)
#define DIFFERENCE_PA28_BANK15 UINT64_C(0x10008000)
#define DIFFERENCE_PA28_BANK13_15 UINT64_C(0x1000a000)
#define DIFFERENCE_PA28_BANK14_15 UINT64_C(0x1000c000)
#define DIFFERENCE_PA28_BANK13_14_15 UINT64_C(0x1000e000)

/* This order is part of the 022R identification contract.  The repeated
 * controls bracket the seven PA28 candidates and must not be caller-chosen. */
static const uint64_t FIXED_DIFFERENCES[MAX_DIFFERENCES] = {
    DIFFERENCE_CONFLICT,
    DIFFERENCE_NEGATIVE,
    DIFFERENCE_PA28_BANK13,
    DIFFERENCE_PA28_BANK14,
    DIFFERENCE_PA28_BANK13_14,
    DIFFERENCE_PA28_BANK15,
    DIFFERENCE_PA28_BANK13_15,
    DIFFERENCE_PA28_BANK14_15,
    DIFFERENCE_PA28_BANK13_14_15,
    DIFFERENCE_CONFLICT,
    DIFFERENCE_NEGATIVE,
};

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

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (text == NULL || *text == '\0' || text[0] == '-' || text[0] == '+')
        return -1;
    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno == ERANGE || end == text || end == NULL || *end != '\0')
        return -1;
    *value = (uint64_t)parsed;
    return 0;
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
    uint64_t mib, repetitions, pairs, base, value;
    unsigned int cpu = 7;
    int ion_fd = -1;
    int allocation_fd = -1;
    int exit_code = 0;
    int cleanup_failed = 0;
    struct ion_heap_query_uapi query;
    struct ion_heap_data_uapi *heaps = NULL, *selected = NULL;
    struct ion_allocation_data_uapi allocation;
    uint8_t *map = MAP_FAILED, *eviction = MAP_FAILED;
    int map_mapped = 0, eviction_mapped = 0;
    uint64_t bytes;
    uint64_t cntfrq;
    uint64_t *relation = NULL, *baseline = NULL;
    int difference_start;
    unsigned int selected_count = 0;
    int cleanup_attempted = 0;
    int ion_fd_closed = 0, allocation_fd_closed = 0;
    int map_unmapped = 0, eviction_unmapped = 0;
    int heaps_freed = 0, sample_buffers_freed = 0;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != EXPECTED_ARGC) {
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
    if (parse_u64(argv[2], &mib) != 0 ||
        parse_u64(argv[3], &repetitions) != 0 ||
        parse_u64(argv[4], &pairs) != 0 ||
        parse_u64(argv[5], &value) != 0 || value > UINT_MAX) {
        fprintf(stderr, "numeric argument is invalid\n");
        return 2;
    }
    cpu = (unsigned int)value;
    offset_mode = argv[6];
    if (parse_u64(argv[7], &base) != 0) {
        fprintf(stderr, "declared base is invalid\n");
        return 2;
    }
    ion_path = argv[8];
    difference_start = 9;
    if (strcmp(heap_name, EXPECTED_HEAP_NAME) != 0 ||
        mib != EXPECTED_MIB || repetitions != EXPECTED_REPETITIONS ||
        pairs != EXPECTED_PAIRS || cpu != EXPECTED_CPU ||
        strcmp(offset_mode, "spread") != 0 || base != EXPECTED_BASE) {
        fprintf(stderr,
                "022 probe requires camera_preview/320/201/256/7/spread/0xc2000000\n");
        return 2;
    }
    if (strcmp(ion_path, FIXED_ION_PATH) != 0) {
        fprintf(stderr, "ion node must be %s\n", FIXED_ION_PATH);
        return 2;
    }
    bytes = EXPECTED_BYTES;
    /* Validate the complete, ordered difference list before pinning a CPU or
     * opening the ION node.  Exact argc rejects omissions, extras, subsets,
     * reorders, and the bare PA28 bit before any device effect. */
    for (unsigned int index = 0; index < MAX_DIFFERENCES; ++index) {
        if (parse_u64(argv[difference_start + (int)index], &value) != 0 ||
            value != FIXED_DIFFERENCES[index] || value >= bytes) {
            fprintf(stderr, "difference is not the fixed ordered 022R value: %s\n",
                    argv[difference_start + (int)index]);
            return 2;
        }
    }

    if (pin_cpu(cpu) != 0) {
        fprintf(stderr, "pin_cpu: %s\n", strerror(errno));
        return 1;
    }
    cntfrq = read_cntfrq();
    if (cntfrq != EXPECTED_CNTFRQ) {
        fprintf(stderr, "unexpected cntfrq: %llu\n",
                (unsigned long long)cntfrq);
        return 1;
    }
    printf("{\"schema\":\"%s\",\"type\":\"context\",\"cpu\":%u,"
           "\"cntfrq\":%llu,\"heap\":\"%s\",\"mib\":%llu,"
           "\"repetitions\":%llu,\"pairs\":%llu,\"warmups\":%u,"
           "\"order\":\"alternating\",\"barrier\":\"dsb_ld\","
           "\"divisor\":\"kept_times_two\",\"offset_mode\":\"%s\","
           "\"declared_base\":\"0x%llx\"}\n",
           PROBE_SCHEMA, cpu, (unsigned long long)cntfrq, heap_name,
           (unsigned long long)mib, (unsigned long long)repetitions,
           (unsigned long long)pairs, PAIR_WARMUPS, offset_mode,
           (unsigned long long)base);

    /* The bridge creates this exact temporary node; keep the path fixed even
     * after validating the corresponding argv slot above. */
    ion_fd = open(FIXED_ION_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (ion_fd < 0) {
        perror("open ion node");
        exit_code = 1;
        goto cleanup;
    }
    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0) {
        perror("heap query");
        exit_code = 1;
        goto cleanup;
    }
    if (query.cnt == 0 || query.cnt > ION_MAX_HEAPS) {
        fprintf(stderr, "bad heap count\n");
        exit_code = 1;
        goto cleanup;
    }
    heaps = calloc(query.cnt, sizeof(*heaps));
    if (heaps == NULL) {
        perror("calloc heaps");
        exit_code = 1;
        goto cleanup;
    }
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0) {
        perror("heap data");
        exit_code = 1;
        goto cleanup;
    }
    for (uint32_t index = 0; index < query.cnt; ++index) {
        heaps[index].name[ION_HEAP_NAME_BYTES - 1] = '\0';
        if (strcmp(heaps[index].name, heap_name) == 0) {
            selected = &heaps[index];
            ++selected_count;
        }
    }
    if (selected == NULL || selected_count != 1 ||
        selected->type != EXPECTED_HEAP_TYPE ||
        selected->heap_id != EXPECTED_HEAP_ID || selected->heap_id >= 32U) {
        fprintf(stderr,
                "camera_preview heap is absent, duplicated, or differs from type 10/id 30\n");
        exit_code = 1;
        goto cleanup;
    }
    printf("{\"schema\":\"%s\",\"type\":\"ion_heap\",\"name\":\"%s\","
           "\"heap_type\":%u,\"heap_id\":%u}\n",
           PROBE_SCHEMA, selected->name, selected->type, selected->heap_id);

    memset(&allocation, 0, sizeof(allocation));
    allocation.len = bytes;
    allocation.heap_id_mask = UINT32_C(1) << EXPECTED_HEAP_ID;
    allocation.flags = 0;   /* no ION_FLAG_CACHED -> pgprot_writecombine */
    if (ioctl(ion_fd, ION_IOC_ALLOC, &allocation) != 0) {
        perror("ion alloc");
        exit_code = 1;
        goto cleanup;
    }
    if (allocation.fd > (uint32_t)INT_MAX) {
        fprintf(stderr, "ion alloc returned an invalid descriptor\n");
        exit_code = 1;
        goto cleanup;
    }
    allocation_fd = (int)allocation.fd;
    map = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
               allocation_fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        exit_code = 1;
        goto cleanup;
    }
    map_mapped = 1;

    eviction = mmap(NULL, EVICTION_BYTES, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (eviction == MAP_FAILED) {
        perror("eviction mmap");
        exit_code = 1;
        goto cleanup;
    }
    eviction_mapped = 1;
    memset(eviction, 0, EVICTION_BYTES);

    for (uint64_t off = 0; off < bytes; off += PAGE_BYTES)
        *(volatile uint8_t *)(map + off) = 0;
    full_barrier();

    emit_pagemap_provenance(map, bytes);

    relation = calloc(repetitions, sizeof(*relation));
    baseline = calloc(repetitions, sizeof(*baseline));
    if (relation == NULL || baseline == NULL) {
        perror("calloc samples");
        exit_code = 1;
        goto cleanup;
    }

    for (unsigned int difference_index = 0;
         difference_index < MAX_DIFFERENCES; ++difference_index) {
        const int arg = difference_start + (int)difference_index;
        uint64_t difference;
        int64_t deltas[MAX_PAIRS];
        size_t used = 0, rejected_range = 0, rejected_carry = 0;

        /* Sub-page differences are allowed.  Offsets `a` are page aligned and
         * the allocation base is at least page aligned, so the low bits of a
         * pair differ by exactly the difference's low bits with no carry, and
         * a bit below PA12 is therefore measured as precisely as one above.
         * Riding such a bit on a large kernel witness keeps the two addresses
         * in different rows, so the conflict question stays well posed. */
        if (parse_u64(argv[arg], &difference) != 0) {
            fprintf(stderr, "invalid difference: %s\n", argv[arg]);
            exit_code = 41;
            goto cleanup;
        }
        if (difference == 0 || difference >= bytes) {
            printf("{\"schema\":\"%s\",\"type\":\"difference\",\"value\":\"0x%llx\","
                   "\"status\":\"OUT_OF_RANGE\"}\n",
                   PROBE_SCHEMA, (unsigned long long)difference);
            continue;
        }
        for (uint64_t index = 0; index < pairs; ++index) {
            /* The pair must differ by XOR, not by addition: a conflict is
             * f(a ^ b) == 0, and a + d carries into bits the difference does
             * not name.  This allocation is not a power of two, so a ^ d must
             * be checked explicitly for range on every pair. */
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
            size_t trim, kept, rep;
            uint64_t relation_sum = 0, baseline_sum = 0;
            int64_t delta;

            if (a > bytes - PAGE_BYTES || b > bytes - PAGE_BYTES) {
                ++rejected_range;
                continue;
            }
            /* The load-bearing check.  A conflict is f(PA_a ^ PA_b) == 0, so
             * the pair is only evidence about this difference if the physical
             * XOR *is* this difference.  Adding the base can carry, turning a
             * single-bit difference into a multi-bit one that would be scored
             * against the wrong bit.  Verify rather than assume. */
            if (base > UINT64_MAX - a || base > UINT64_MAX - b) {
                ++rejected_carry;
                continue;
            }
            const uint64_t pa_a = base + a;
            const uint64_t pa_b = base + b;
            if ((pa_a ^ pa_b) != difference) {
                ++rejected_carry;
                continue;
            }
            /* Form pointers only after all range and carry checks. */
            const uint8_t *pa = map + a;
            const uint8_t *pb = map + b;
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
                   (unsigned long long)a, (unsigned long long)pa_a,
                   (unsigned long long)pa_b,
                   (unsigned long long)(pa_a ^ pa_b),
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

cleanup:
    /* Every path after a successful ION open arrives here exactly once.  A
     * failed mapping is represented by its *_mapped flag and is never passed
     * to munmap; descriptors are invalidated before close to prevent a second
     * close even if the allocation and ION descriptors ever alias. */
    cleanup_attempted = 1;

    if (relation != NULL) {
        free(relation);
        relation = NULL;
    }
    if (baseline != NULL) {
        free(baseline);
        baseline = NULL;
    }
    sample_buffers_freed = relation == NULL && baseline == NULL;

    if (heaps != NULL) {
        free(heaps);
        heaps = NULL;
    }
    heaps_freed = heaps == NULL;

    if (eviction_mapped) {
        if (munmap(eviction, EVICTION_BYTES) != 0)
            cleanup_failed = 1;
        else {
            eviction_mapped = 0;
            eviction = MAP_FAILED;
        }
    }
    eviction_unmapped = eviction_mapped == 0;

    if (map_mapped) {
        if (munmap(map, bytes) != 0)
            cleanup_failed = 1;
        else {
            map_mapped = 0;
            map = MAP_FAILED;
        }
    }
    map_unmapped = map_mapped == 0;

    if (allocation_fd >= 0) {
        const int descriptor = allocation_fd;
        allocation_fd = -1;
        if (close(descriptor) != 0)
            cleanup_failed = 1;
        else
            allocation_fd_closed = 1;
        if (descriptor == ion_fd) {
            /* This cannot occur for a conforming ION allocator, but keeping
             * the descriptors coupled makes the epilogue double-close-safe. */
            ion_fd = -1;
            ion_fd_closed = allocation_fd_closed;
        }
    } else {
        allocation_fd_closed = 1;
    }

    if (ion_fd >= 0) {
        const int descriptor = ion_fd;
        ion_fd = -1;
        if (close(descriptor) != 0)
            cleanup_failed = 1;
        else
            ion_fd_closed = 1;
    } else if (!ion_fd_closed) {
        /* No descriptor remained to close (for example, open failed before
         * entering the epilogue); that resource obligation is satisfied. */
        ion_fd_closed = 1;
    }

    if (exit_code == 0 && cleanup_failed)
        exit_code = 1;
    if (exit_code != 0)
        return exit_code;

    if (!cleanup_attempted || !ion_fd_closed || !allocation_fd_closed ||
        !map_unmapped || !eviction_unmapped || !heaps_freed ||
        !sample_buffers_freed) {
        fprintf(stderr, "probe cleanup did not release every resource\n");
        return 1;
    }

    printf("{\"schema\":\"%s\",\"type\":\"cleanup\","
           "\"attempted\":true,\"released\":true,"
           "\"ion_fd_closed\":true,\"allocation_fd_closed\":true,"
           "\"map_unmapped\":true,\"eviction_unmapped\":true,"
           "\"heaps_freed\":true,\"sample_buffers_freed\":true,"
           "\"status\":\"PASS\"}\n",
           PROBE_SCHEMA);
    return 0;
}
