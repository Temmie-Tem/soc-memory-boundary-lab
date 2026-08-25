/*
 * Experiment 014 A90 userspace DRAM timing probe.
 *
 * This program touches only experiment-owned normal RAM (anonymous or the
 * non-secure ION system heap) plus /proc/self/pagemap.  It performs no MMIO,
 * SMC, partition, firmware, or protected-memory access.
 * The exact A90 4.14 kernel traps EL0 DC CIVAC and executes the operation in
 * EL1; CNTVCT_EL0 supplies the fixed-frequency timestamp counter.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define PROBE_SCHEMA "a90_dram_timing_probe_v2"
#define PAGE_BYTES UINT64_C(4096)
#define PAGE_SHIFT 12U
#define PAGEMAP_PRESENT (UINT64_C(1) << 63)
#define PAGEMAP_SWAPPED (UINT64_C(1) << 62)
#define PAGEMAP_PFN_MASK ((UINT64_C(1) << 55) - 1)
#define RANK0_BASE UINT64_C(0x80000000)
#define RANK1_BASE UINT64_C(0x140000000)
#define DRAM_END UINT64_C(0x200000000)
#define RANK0_SIZE (RANK1_BASE - RANK0_BASE)
#define RANK1_SIZE (DRAM_END - RANK1_BASE)
#define PIVOT_BIT 20U
#define MAX_DIFFERENCES 96U
#define MAX_MEASURE_PAIRS 128U
#define MAX_REPETITIONS 10001U
/* Exact SM8150 CPUSS slice max_cap is 3072 KiB; use >5x that capacity. */
#define EVICTION_BYTES (UINT64_C(16) * 1024 * 1024)
#define CACHE_LINE_BYTES 64U
#define PAIR_WARMUPS 17U
#define ION_HEAP_TYPE_SYSTEM 0U
#define ION_MAX_HEAPS 64U
#define ION_HEAP_NAME_BYTES 32U
#define ION_DEVICE_PATH "/tmp/a90-native/exp014-ion"
#define KPF_BUDDY_BIT 10U
#define KPAGE_FIRST_PFN (RANK0_BASE >> PAGE_SHIFT)
#define KPAGE_END_PFN (DRAM_END >> PAGE_SHIFT)
#define MAX_FLAG_TRANSITIONS 8192U

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
    uint32_t reserved0;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct ion_heap_query_uapi {
    uint32_t cnt;
    uint32_t reserved0;
    uint64_t heaps;
    uint32_t reserved1;
    uint32_t reserved2;
};

#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC \
    _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data_uapi)
#define ION_IOC_HEAP_QUERY \
    _IOWR(ION_IOC_MAGIC, 8, struct ion_heap_query_uapi)

struct page_record {
    uint64_t pa;
    uint8_t *va;
    uint32_t page_index;
    uint8_t rank;
};

struct pair_record {
    uint8_t *a;
    uint8_t *b;
    uint64_t pa_a;
    uint64_t pa_b;
};

struct pool {
    uint8_t *mapping;
    size_t bytes;
    size_t pages;
    struct page_record *records;
    uint64_t *pagemap_before;
    size_t valid_pages;
    size_t outside_pages;
    size_t nonpresent_pages;
    size_t swapped_pages;
    size_t zero_pfn_pages;
    size_t rank_pages[2];
    uint64_t rank_min[2];
    uint64_t rank_max[2];
    int madvise_rc;
    int madvise_errno;
    int backing_fd;
    const char *backing;
    const char *stability_method;
    uint32_t ion_heap_id;
    char ion_heap_name[ION_HEAP_NAME_BYTES];
    int contiguous_ion;
    uint64_t contiguous_base;
    size_t buddy_removed_pages;
};

static volatile uint64_t load_sink;

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

static inline void cache_clean_invalidate(void *address)
{
    __asm__ volatile("dc civac, %0" : : "r"(address) : "memory");
}

static inline void full_barrier(void)
{
    __asm__ volatile("dsb sy\n\tisb" : : : "memory");
}

static inline void load_barrier(void)
{
    __asm__ volatile("dsb ld" : : : "memory");
}

static int compare_u64(const void *left, const void *right)
{
    const uint64_t a = *(const uint64_t *)left;
    const uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static int compare_i64(const void *left, const void *right)
{
    const int64_t a = *(const int64_t *)left;
    const int64_t b = *(const int64_t *)right;
    return (a > b) - (a < b);
}

static int compare_page(const void *left, const void *right)
{
    const struct page_record *a = left;
    const struct page_record *b = right;
    if (a->pa != b->pa)
        return (a->pa > b->pa) - (a->pa < b->pa);
    return (a->va > b->va) - (a->va < b->va);
}

static int parse_u64(const char *text, uint64_t minimum, uint64_t maximum,
                     uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed < minimum ||
        parsed > maximum)
        return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int pin_cpu(unsigned int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static int read_pagemap_range(void *mapping, size_t pages, uint64_t *entries)
{
    const uint64_t virtual_page = (uint64_t)(uintptr_t)mapping >> PAGE_SHIFT;
    const off_t start = (off_t)(virtual_page * sizeof(uint64_t));
    const size_t wanted = pages * sizeof(uint64_t);
    size_t done = 0;
    int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return -1;
    while (done < wanted) {
        ssize_t got = pread(fd, (uint8_t *)entries + done, wanted - done,
                            start + (off_t)done);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            int saved = got < 0 ? errno : EIO;
            close(fd);
            errno = saved;
            return -1;
        }
        done += (size_t)got;
    }
    return close(fd);
}

static int rank_for_pa(uint64_t pa)
{
    if (pa >= RANK0_BASE && pa < RANK1_BASE)
        return 0;
    if (pa >= RANK1_BASE && pa < DRAM_END)
        return 1;
    return -1;
}

static uint64_t rank_base(unsigned int rank)
{
    return rank == 0 ? RANK0_BASE : RANK1_BASE;
}

static uint64_t rank_size(unsigned int rank)
{
    return rank == 0 ? RANK0_SIZE : RANK1_SIZE;
}

static int read_kpageflags(int fd, uint64_t *flags, size_t count);

static void pool_release(struct pool *pool)
{
    if (pool->mapping != MAP_FAILED && pool->mapping != NULL)
        munmap(pool->mapping, pool->bytes);
    if (pool->backing_fd >= 0)
        close(pool->backing_fd);
    free(pool->records);
    free(pool->pagemap_before);
    memset(pool, 0, sizeof(*pool));
}

static void pool_initialize(struct pool *pool, uint64_t mib,
                            const char *backing)
{
    const uint64_t bytes64 = mib * UINT64_C(1024) * UINT64_C(1024);

    memset(pool, 0, sizeof(*pool));
    pool->mapping = MAP_FAILED;
    pool->backing_fd = -1;
    pool->backing = backing;
    pool->stability_method = "pagemap_before_after";
    pool->bytes = (size_t)bytes64;
    pool->pages = pool->bytes / PAGE_BYTES;
    pool->rank_min[0] = pool->rank_min[1] = UINT64_MAX;
}

static int pool_index_mapping(struct pool *pool)
{
    size_t index;

    errno = 0;
    pool->madvise_rc = madvise(pool->mapping, pool->bytes, MADV_NOHUGEPAGE);
    if (pool->madvise_rc != 0)
        pool->madvise_errno = errno;

    /* One explicit store per page establishes ownership before pagemap read. */
    for (index = 0; index < pool->pages; ++index)
        pool->mapping[index * PAGE_BYTES] = (uint8_t)(index ^ (index >> 8));
    full_barrier();

    pool->records = calloc(pool->pages, sizeof(*pool->records));
    pool->pagemap_before = calloc(pool->pages, sizeof(*pool->pagemap_before));
    if (pool->records == NULL || pool->pagemap_before == NULL)
        return -1;
    if (read_pagemap_range(pool->mapping, pool->pages,
                           pool->pagemap_before) != 0)
        return -1;

    for (index = 0; index < pool->pages; ++index) {
        const uint64_t entry = pool->pagemap_before[index];
        const uint64_t pfn = entry & PAGEMAP_PFN_MASK;
        uint64_t pa;
        int rank;

        if (!(entry & PAGEMAP_PRESENT)) {
            ++pool->nonpresent_pages;
            continue;
        }
        if (entry & PAGEMAP_SWAPPED) {
            ++pool->swapped_pages;
            continue;
        }
        if (pfn == 0) {
            ++pool->zero_pfn_pages;
            continue;
        }
        pa = pfn << PAGE_SHIFT;
        rank = rank_for_pa(pa);
        if (rank < 0) {
            ++pool->outside_pages;
            continue;
        }
        pool->records[pool->valid_pages].pa = pa;
        pool->records[pool->valid_pages].va =
            pool->mapping + index * PAGE_BYTES;
        pool->records[pool->valid_pages].page_index = (uint32_t)index;
        pool->records[pool->valid_pages].rank = (uint8_t)rank;
        ++pool->valid_pages;
        ++pool->rank_pages[rank];
        if (pa < pool->rank_min[rank])
            pool->rank_min[rank] = pa;
        if (pa > pool->rank_max[rank])
            pool->rank_max[rank] = pa;
    }
    qsort(pool->records, pool->valid_pages, sizeof(*pool->records),
          compare_page);
    return 0;
}

static int pool_create_anonymous(struct pool *pool, uint64_t mib)
{
    pool_initialize(pool, mib, "anonymous_cached");
    pool->mapping = mmap(NULL, pool->bytes, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->mapping == MAP_FAILED)
        return -1;
    return pool_index_mapping(pool);
}

static int pool_index_contiguous_ion(struct pool *pool)
{
    size_t index;

    errno = 0;
    pool->madvise_rc = madvise(pool->mapping, pool->bytes, MADV_NOHUGEPAGE);
    if (pool->madvise_rc != 0)
        pool->madvise_errno = errno;
    for (index = 0; index < pool->pages; ++index)
        pool->mapping[index * PAGE_BYTES] = (uint8_t)(index ^ (index >> 8));
    full_barrier();
    pool->records = calloc(pool->pages, sizeof(*pool->records));
    if (pool->records == NULL)
        return -1;
    for (index = 0; index < pool->pages; ++index) {
        const uint64_t pa = pool->contiguous_base + index * PAGE_BYTES;
        const int rank = rank_for_pa(pa);

        if (rank < 0) {
            ++pool->outside_pages;
            continue;
        }
        pool->records[pool->valid_pages].pa = pa;
        pool->records[pool->valid_pages].va =
            pool->mapping + index * PAGE_BYTES;
        pool->records[pool->valid_pages].page_index = (uint32_t)index;
        pool->records[pool->valid_pages].rank = (uint8_t)rank;
        ++pool->valid_pages;
        ++pool->rank_pages[rank];
        if (pa < pool->rank_min[rank])
            pool->rank_min[rank] = pa;
        if (pa > pool->rank_max[rank])
            pool->rank_max[rank] = pa;
    }
    return 0;
}

static int pool_create_ion(struct pool *pool, uint64_t mib,
                           const char *ion_path)
{
    const size_t flag_count = (size_t)(KPAGE_END_PFN - KPAGE_FIRST_PFN);
    struct ion_heap_query_uapi query;
    struct ion_heap_data_uapi *heaps = NULL;
    struct ion_heap_data_uapi *selected = NULL;
    struct ion_allocation_data_uapi allocation;
    uint64_t *before = NULL;
    uint64_t *after = NULL;
    uint32_t *removed_prefix = NULL;
    size_t removed_total = 0;
    size_t best_removed = 0;
    size_t best_start = 0;
    size_t best_ties = 0;
    size_t index;
    int ion_fd = -1;
    int flags_fd = -1;
    int saved_errno;

    pool_initialize(pool, mib, "ion_user_contig_uncached_writecombine");
    pool->stability_method = "dma_buf_contiguous_pin";
    ion_fd = open(ion_path, O_RDONLY | O_CLOEXEC);
    flags_fd = open("/proc/kpageflags", O_RDONLY | O_CLOEXEC);
    if (ion_fd < 0 || flags_fd < 0) {
        saved_errno = errno;
        if (flags_fd >= 0)
            close(flags_fd);
        if (ion_fd >= 0)
            close(ion_fd);
        errno = saved_errno;
        return -1;
    }
    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0)
        goto fail;
    if (query.cnt == 0 || query.cnt > ION_MAX_HEAPS) {
        errno = EPROTO;
        goto fail;
    }
    heaps = calloc(query.cnt, sizeof(*heaps));
    before = calloc(flag_count, sizeof(*before));
    after = calloc(flag_count, sizeof(*after));
    removed_prefix = calloc(flag_count + 1, sizeof(*removed_prefix));
    if (heaps == NULL || before == NULL || after == NULL ||
        removed_prefix == NULL)
        goto fail;
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0)
        goto fail;
    for (index = 0; index < query.cnt; ++index) {
        heaps[index].name[ION_HEAP_NAME_BYTES - 1] = '\0';
        printf("{\"schema\":\"%s\",\"type\":\"ion_heap\","
               "\"name\":\"%s\",\"heap_type\":%u,\"heap_id\":%u}\n",
               PROBE_SCHEMA, heaps[index].name, heaps[index].type,
               heaps[index].heap_id);
        if (strcmp(heaps[index].name, "user_contig") == 0 &&
            heaps[index].type == 4U)
            selected = &heaps[index];
    }
    if (selected == NULL || selected->heap_id >= 32) {
        errno = ENODEV;
        goto fail;
    }
    pool->ion_heap_id = selected->heap_id;
    snprintf(pool->ion_heap_name, sizeof(pool->ion_heap_name), "%s",
             selected->name);
    memset(&allocation, 0, sizeof(allocation));
    allocation.len = pool->bytes;
    allocation.heap_id_mask = UINT32_C(1) << selected->heap_id;
    allocation.flags = 0; /* exact ion_mmap path selects pgprot_writecombine */
    memset(before, 0xa5, flag_count * sizeof(*before));
    memset(after, 0x5a, flag_count * sizeof(*after));
    if (read_kpageflags(flags_fd, before, flag_count) != 0)
        goto fail;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &allocation) != 0)
        goto fail;
    pool->backing_fd = (int)allocation.fd;
    if (read_kpageflags(flags_fd, after, flag_count) != 0)
        goto fail;
    for (index = 0; index < flag_count; ++index) {
        const int before_buddy =
            (before[index] & (UINT64_C(1) << KPF_BUDDY_BIT)) != 0;
        const int after_buddy =
            (after[index] & (UINT64_C(1) << KPF_BUDDY_BIT)) != 0;
        const int was_removed = before_buddy && !after_buddy;

        removed_prefix[index + 1] =
            removed_prefix[index] + (uint32_t)was_removed;
        removed_total += (size_t)was_removed;
    }
    for (index = 0; index + pool->pages <= flag_count; index += 256) {
        const size_t count =
            removed_prefix[index + pool->pages] - removed_prefix[index];

        if (count > best_removed) {
            best_removed = count;
            best_start = index;
            best_ties = 1;
        } else if (count == best_removed) {
            ++best_ties;
        }
    }
    printf("{\"schema\":\"%s\",\"type\":\"ion_cma_window_search\","
           "\"buddy_removed_total\":%zu,\"best_window_removed\":%zu,"
           "\"best_window_ties\":%zu,\"alignment_pages\":256}\n",
           PROBE_SCHEMA, removed_total, best_removed, best_ties);
    if (best_removed < pool->pages / 2 || best_ties != 1) {
        errno = EPROTO;
        goto fail;
    }
    pool->contiguous_ion = 1;
    pool->contiguous_base = (KPAGE_FIRST_PFN + best_start) << PAGE_SHIFT;
    pool->buddy_removed_pages = best_removed;
    printf("{\"schema\":\"%s\",\"type\":\"ion_cma_binding\","
           "\"base\":\"0x%016" PRIx64 "\","
           "\"end_exclusive\":\"0x%016" PRIx64 "\","
           "\"pages\":%zu,\"buddy_removed_pages\":%zu,"
           "\"single_sg_contiguous_source\":true}\n",
           PROBE_SCHEMA, pool->contiguous_base,
           pool->contiguous_base + pool->bytes, pool->pages, best_removed);
    pool->mapping = mmap(NULL, pool->bytes, PROT_READ | PROT_WRITE,
                         MAP_SHARED, pool->backing_fd, 0);
    if (pool->mapping == MAP_FAILED)
        goto fail;
    free(removed_prefix);
    free(after);
    free(before);
    free(heaps);
    close(flags_fd);
    if (close(ion_fd) != 0)
        return -1;
    return pool_index_contiguous_ion(pool);

fail:
    saved_errno = errno;
    free(removed_prefix);
    free(after);
    free(before);
    free(heaps);
    if (flags_fd >= 0)
        close(flags_fd);
    if (ion_fd >= 0)
        close(ion_fd);
    errno = saved_errno;
    return -1;
}

static int pool_create(struct pool *pool, uint64_t mib, const char *ion_path)
{
    if (ion_path != NULL)
        return pool_create_ion(pool, mib, ion_path);
    return pool_create_anonymous(pool, mib);
}

static int read_kpageflags(int fd, uint64_t *flags, size_t count)
{
    const off_t start = (off_t)(KPAGE_FIRST_PFN * sizeof(uint64_t));
    const size_t wanted = count * sizeof(uint64_t);
    size_t done = 0;

    while (done < wanted) {
        ssize_t got = pread(fd, (uint8_t *)flags + done, wanted - done,
                            start + (off_t)done);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            errno = got < 0 ? errno : EIO;
            return -1;
        }
        done += (size_t)got;
    }
    return 0;
}

static int run_ion_kpage_scan(uint64_t mib, const char *requested_heap)
{
    const size_t flag_count = (size_t)(KPAGE_END_PFN - KPAGE_FIRST_PFN);
    struct ion_heap_query_uapi query;
    struct ion_heap_data_uapi *heaps = NULL;
    struct ion_heap_data_uapi *selected = NULL;
    struct ion_allocation_data_uapi allocation;
    uint64_t *before = NULL;
    uint64_t *after = NULL;
    uint32_t *transitions = NULL;
    size_t transition_count = 0;
    size_t changed_count = 0;
    size_t buddy_added_count = 0;
    size_t restored_count = 0;
    size_t index;
    int ion_fd = -1;
    int flags_fd = -1;
    int allocation_fd = -1;
    int result = 60;

    ion_fd = open(ION_DEVICE_PATH, O_RDONLY | O_CLOEXEC);
    flags_fd = open("/proc/kpageflags", O_RDONLY | O_CLOEXEC);
    if (ion_fd < 0 || flags_fd < 0)
        goto out;
    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0 ||
        query.cnt == 0 || query.cnt > ION_MAX_HEAPS) {
        errno = EPROTO;
        goto out;
    }
    heaps = calloc(query.cnt, sizeof(*heaps));
    before = calloc(flag_count, sizeof(*before));
    after = calloc(flag_count, sizeof(*after));
    transitions = calloc(MAX_FLAG_TRANSITIONS, sizeof(*transitions));
    if (heaps == NULL || before == NULL || after == NULL ||
        transitions == NULL)
        goto out;
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0)
        goto out;
    for (index = 0; index < query.cnt; ++index) {
        heaps[index].name[ION_HEAP_NAME_BYTES - 1] = '\0';
        if (strcmp(heaps[index].name, requested_heap) == 0)
            selected = &heaps[index];
    }
    if (selected == NULL || selected->heap_id >= 32 ||
        (selected->type != ION_HEAP_TYPE_SYSTEM && selected->type != 4U)) {
        errno = ENODEV;
        goto out;
    }
    /* Fault both host buffers before the baseline so they cannot contaminate it. */
    memset(before, 0xa5, flag_count * sizeof(*before));
    memset(after, 0x5a, flag_count * sizeof(*after));
    if (read_kpageflags(flags_fd, before, flag_count) != 0)
        goto out;
    memset(&allocation, 0, sizeof(allocation));
    allocation.len = mib * UINT64_C(1024) * UINT64_C(1024);
    allocation.heap_id_mask = UINT32_C(1) << selected->heap_id;
    allocation.flags = 0;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &allocation) != 0)
        goto out;
    allocation_fd = (int)allocation.fd;
    if (read_kpageflags(flags_fd, after, flag_count) != 0)
        goto out;

    for (index = 0; index < flag_count; ++index) {
        const int before_buddy =
            (before[index] & (UINT64_C(1) << KPF_BUDDY_BIT)) != 0;
        const int after_buddy =
            (after[index] & (UINT64_C(1) << KPF_BUDDY_BIT)) != 0;
        if (before[index] != after[index])
            ++changed_count;
        if (!before_buddy && after_buddy)
            ++buddy_added_count;
        if (before_buddy && !after_buddy) {
            if (transition_count >= MAX_FLAG_TRANSITIONS) {
                errno = EOVERFLOW;
                goto out;
            }
            transitions[transition_count++] = (uint32_t)index;
        }
    }
    printf("{\"schema\":\"%s\",\"type\":\"ion_kpage_scan\","
           "\"heap_name\":\"%s\",\"heap_type\":%u,\"heap_id\":%u,"
           "\"allocation_bytes\":%" PRIu64 ",\"first_pfn\":\"0x%08" PRIx64 "\","
           "\"end_pfn_exclusive\":\"0x%08" PRIx64 "\","
           "\"flag_entries\":%zu,\"changed_entries\":%zu,"
           "\"buddy_removed_heads\":%zu,\"buddy_added_heads\":%zu}\n",
           PROBE_SCHEMA, selected->name, selected->type, selected->heap_id,
           allocation.len, KPAGE_FIRST_PFN, KPAGE_END_PFN, flag_count,
           changed_count, transition_count, buddy_added_count);
    for (index = 0; index < transition_count; ++index) {
        const size_t flag_index = transitions[index];
        const uint64_t pfn = KPAGE_FIRST_PFN + flag_index;
        printf("{\"schema\":\"%s\",\"type\":\"buddy_removed\","
               "\"index\":%zu,\"pfn\":\"0x%08" PRIx64 "\","
               "\"pa\":\"0x%016" PRIx64 "\","
               "\"before_flags\":\"0x%016" PRIx64 "\","
               "\"after_flags\":\"0x%016" PRIx64 "\"}\n",
               PROBE_SCHEMA, index, pfn, pfn << PAGE_SHIFT,
               before[flag_index], after[flag_index]);
    }
    if (close(allocation_fd) != 0)
        goto out;
    allocation_fd = -1;
    if (read_kpageflags(flags_fd, before, flag_count) != 0)
        goto out;
    for (index = 0; index < transition_count; ++index) {
        if (before[transitions[index]] &
            (UINT64_C(1) << KPF_BUDDY_BIT))
            ++restored_count;
    }
    printf("{\"schema\":\"%s\",\"type\":\"scan_complete\","
           "\"buddy_removed_heads\":%zu,\"buddy_restored_after_close\":%zu}\n",
           PROBE_SCHEMA, transition_count, restored_count);
    result = 0;

out:
    if (result != 0)
        perror("ion kpage scan");
    if (allocation_fd >= 0)
        close(allocation_fd);
    if (flags_fd >= 0)
        close(flags_fd);
    if (ion_fd >= 0)
        close(ion_fd);
    free(transitions);
    free(after);
    free(before);
    free(heaps);
    return result;
}

static const struct page_record *find_page(const struct pool *pool,
                                           uint64_t page_pa)
{
    size_t low = 0;
    size_t high = pool->valid_pages;

    while (low < high) {
        const size_t middle = low + (high - low) / 2;
        const uint64_t current = pool->records[middle].pa;
        if (current < page_pa)
            low = middle + 1;
        else
            high = middle;
    }
    if (low < pool->valid_pages && pool->records[low].pa == page_pa)
        return &pool->records[low];
    return NULL;
}

static size_t collect_pairs(const struct pool *pool, uint64_t difference,
                            struct pair_record *pairs, size_t maximum)
{
    size_t index;
    size_t count = 0;

    for (index = 0; index < pool->valid_pages && count < maximum; ++index) {
        const struct page_record *a = &pool->records[index];
        const uint64_t base = rank_base(a->rank);
        const uint64_t relative_a = a->pa - base;
        const uint64_t relative_b = relative_a ^ difference;
        const uint64_t page_b_relative = relative_b & ~(PAGE_BYTES - 1);
        const uint64_t byte_b = relative_b & (PAGE_BYTES - 1);
        const struct page_record *b;
        uint64_t pa_b_page;

        if (relative_b >= rank_size(a->rank))
            continue;
        pa_b_page = base + page_b_relative;
        b = find_page(pool, pa_b_page);
        if (b == NULL || b->rank != a->rank)
            continue;
        if (a->pa > pa_b_page ||
            (a->pa == pa_b_page && byte_b == 0))
            continue;
        pairs[count].a = a->va;
        pairs[count].b = b->va + byte_b;
        pairs[count].pa_a = a->pa;
        pairs[count].pa_b = pa_b_page + byte_b;
        ++count;
    }
    return count;
}

static size_t protocol_differences(uint64_t *differences)
{
    static const unsigned int suspects[] = {9, 10, 13, 14, 15};
    size_t count = 0;
    unsigned int bit;
    size_t low;
    size_t high;

    differences[count++] = UINT64_C(1) << 11; /* same-row control */
    differences[count++] = UINT64_C(1) << PIVOT_BIT;
    for (bit = 0; bit < 32; ++bit) {
        uint64_t difference;
        if (bit == PIVOT_BIT)
            continue;
        difference = (UINT64_C(1) << PIVOT_BIT) | (UINT64_C(1) << bit);
        differences[count++] = difference;
    }
    for (low = 0; low < sizeof(suspects) / sizeof(suspects[0]); ++low) {
        for (high = low + 1;
             high < sizeof(suspects) / sizeof(suspects[0]); ++high) {
            differences[count++] = (UINT64_C(1) << PIVOT_BIT) |
                                   (UINT64_C(1) << suspects[low]) |
                                   (UINT64_C(1) << suspects[high]);
        }
    }
    return count;
}

static const char *difference_phase(uint64_t difference)
{
    if (difference == (UINT64_C(1) << 11))
        return "row_hit_control";
    if (difference == (UINT64_C(1) << PIVOT_BIT))
        return "pivot_control";
    if (difference & (difference - 1)) {
        if (__builtin_popcountll(difference) == 3)
            return "phase2";
        return "phase1";
    }
    return "phase1";
}

static void print_pool_summary(const struct pool *pool, const char *mode,
                               uint64_t requested_mib, unsigned int cpu,
                               int mlock_rc, int mlock_errno)
{
    int actual_cpu = sched_getcpu();
    struct rlimit limit;
    uint64_t memlock_soft = 0;
    uint64_t memlock_hard = 0;

    if (getrlimit(RLIMIT_MEMLOCK, &limit) == 0) {
        memlock_soft = limit.rlim_cur == RLIM_INFINITY ? UINT64_MAX : limit.rlim_cur;
        memlock_hard = limit.rlim_max == RLIM_INFINITY ? UINT64_MAX : limit.rlim_max;
    }
    printf("{\"schema\":\"%s\",\"type\":\"header\",\"mode\":\"%s\","
           "\"backing\":\"%s\",\"ion_heap_id\":%u,\"ion_heap_name\":\"%s\","
           "\"contiguous_ion\":%s,\"contiguous_base\":\"0x%016" PRIx64 "\","
           "\"buddy_removed_pages\":%zu,"
           "\"requested_mib\":%" PRIu64 ",\"mapped_bytes\":%zu,"
           "\"pages\":%zu,\"valid_pages\":%zu,\"nonpresent_pages\":%zu,"
           "\"swapped_pages\":%zu,\"zero_pfn_pages\":%zu,"
           "\"outside_pages\":%zu,\"requested_cpu\":%u,\"actual_cpu\":%d,"
           "\"madvise_nohugepage_rc\":%d,\"madvise_nohugepage_errno\":%d,"
           "\"cntfrq_hz\":%" PRIu64 ",\"mlock_rc\":%d,\"mlock_errno\":%d,"
           "\"rlimit_memlock_soft\":%" PRIu64 ",\"rlimit_memlock_hard\":%" PRIu64 "}\n",
           PROBE_SCHEMA, mode, pool->backing, pool->ion_heap_id,
           pool->ion_heap_name, pool->contiguous_ion ? "true" : "false",
           pool->contiguous_base, pool->buddy_removed_pages,
           requested_mib, pool->bytes, pool->pages,
           pool->valid_pages, pool->nonpresent_pages, pool->swapped_pages,
           pool->zero_pfn_pages, pool->outside_pages, cpu, actual_cpu,
           pool->madvise_rc, pool->madvise_errno,
           read_cntfrq(), mlock_rc, mlock_errno, memlock_soft, memlock_hard);
    printf("{\"schema\":\"%s\",\"type\":\"rank\",\"rank\":0,"
           "\"base\":\"0x%016" PRIx64 "\",\"size\":\"0x%016" PRIx64 "\","
           "\"pages\":%zu,\"min_pa\":\"0x%016" PRIx64 "\","
           "\"max_pa\":\"0x%016" PRIx64 "\"}\n",
           PROBE_SCHEMA, RANK0_BASE, RANK0_SIZE, pool->rank_pages[0],
           pool->rank_min[0] == UINT64_MAX ? 0 : pool->rank_min[0],
           pool->rank_pages[0] ? pool->rank_max[0] : 0);
    printf("{\"schema\":\"%s\",\"type\":\"rank\",\"rank\":1,"
           "\"base\":\"0x%016" PRIx64 "\",\"size\":\"0x%016" PRIx64 "\","
           "\"pages\":%zu,\"min_pa\":\"0x%016" PRIx64 "\","
           "\"max_pa\":\"0x%016" PRIx64 "\"}\n",
           PROBE_SCHEMA, RANK1_BASE, RANK1_SIZE, pool->rank_pages[1],
           pool->rank_min[1] == UINT64_MAX ? 0 : pool->rank_min[1],
           pool->rank_pages[1] ? pool->rank_max[1] : 0);
}

static int verify_pagemap_stability(const struct pool *pool, size_t *changed,
                                    size_t *lost)
{
    uint64_t *after = calloc(pool->pages, sizeof(*after));
    size_t index;

    *changed = 0;
    *lost = 0;
    if (pool->contiguous_ion)
        return 0;
    if (after == NULL)
        return -1;
    if (read_pagemap_range(pool->mapping, pool->pages, after) != 0) {
        free(after);
        return -1;
    }
    for (index = 0; index < pool->pages; ++index) {
        const uint64_t before = pool->pagemap_before[index];
        const uint64_t now = after[index];
        if (!(now & PAGEMAP_PRESENT) || (now & PAGEMAP_SWAPPED))
            ++*lost;
        if ((before & (PAGEMAP_PRESENT | PAGEMAP_SWAPPED | PAGEMAP_PFN_MASK)) !=
            (now & (PAGEMAP_PRESENT | PAGEMAP_SWAPPED | PAGEMAP_PFN_MASK)))
            ++*changed;
    }
    free(after);
    return 0;
}

static void sweep_eviction_buffer(uint8_t *eviction, size_t bytes,
                                  uint8_t value)
{
    size_t index;

    for (index = 0; index < bytes; index += CACHE_LINE_BYTES)
        *(volatile uint8_t *)(eviction + index) ^= value;
}

static uint64_t measure_pair_once(const struct pair_record *pair,
                                  int cache_maintenance)
{
    uint64_t start;
    uint64_t end;
    uint64_t accumulator;

    if (cache_maintenance) {
        cache_clean_invalidate(pair->a);
        cache_clean_invalidate(pair->b);
        full_barrier();
    }
    start = read_cntvct();
    accumulator = *(volatile uint8_t *)pair->a;
    load_barrier();
    accumulator ^= *(volatile uint8_t *)pair->b;
    load_barrier();
    end = read_cntvct();
    load_sink ^= accumulator;
    return end - start;
}

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

static int run_smoke(unsigned int cpu, const char *ion_path)
{
    struct pool pool;
    uint64_t samples[129];
    size_t index;
    int mlock_rc;
    int mlock_errno = 0;
    size_t changed;
    size_t lost;

    if (pin_cpu(cpu) != 0) {
        perror("sched_setaffinity");
        return 20;
    }
    if (pool_create(&pool, 1, ion_path) != 0) {
        perror("pool_create");
        pool_release(&pool);
        return 21;
    }
    errno = 0;
    mlock_rc = mlock(pool.mapping, pool.bytes);
    if (mlock_rc != 0)
        mlock_errno = errno;
    print_pool_summary(&pool, "smoke", 1, cpu, mlock_rc, mlock_errno);
    if (pool.valid_pages < 2 || pool.zero_pfn_pages != 0) {
        fprintf(stderr, "pagemap did not expose two usable PFNs\n");
        pool_release(&pool);
        return 22;
    }

    for (index = 0; index < sizeof(samples) / sizeof(samples[0]); ++index) {
        uint8_t *address = pool.records[index % pool.valid_pages].va;
        if (ion_path == NULL) {
            cache_clean_invalidate(address);
            full_barrier();
        }
        samples[index] = read_cntvct();
        load_sink ^= *(volatile uint8_t *)address;
        load_barrier();
        samples[index] = read_cntvct() - samples[index];
    }
    qsort(samples, sizeof(samples) / sizeof(samples[0]), sizeof(samples[0]),
          compare_u64);
    printf("{\"schema\":\"%s\",\"type\":\"smoke\","
           "\"dc_civac_completed\":%s,\"uncached_mapping\":%s,"
           "\"cntvct_monotonic\":true,"
           "\"samples\":129,\"cold_ticks_min\":%" PRIu64 ","
           "\"cold_ticks_median\":%" PRIu64 ",\"cold_ticks_p90\":%" PRIu64 ","
           "\"cold_ticks_max\":%" PRIu64 ",\"sink\":%" PRIu64 "}\n",
           PROBE_SCHEMA, ion_path == NULL ? "true" : "false",
           ion_path == NULL ? "false" : "true", samples[0], samples[64],
           samples[116], samples[128], load_sink);
    if (verify_pagemap_stability(&pool, &changed, &lost) != 0) {
        perror("pagemap stability");
        pool_release(&pool);
        return 23;
    }
    printf("{\"schema\":\"%s\",\"type\":\"stability\","
           "\"method\":\"%s\",\"changed_pages\":%zu,\"lost_pages\":%zu}\n",
           PROBE_SCHEMA, pool.stability_method, changed, lost);
    pool_release(&pool);
    return changed == 0 && lost == 0 ? 0 : 24;
}

static int run_inventory(uint64_t mib, size_t maximum_pairs, unsigned int cpu,
                         const char *ion_path)
{
    struct pool pool;
    struct pair_record *pairs;
    uint64_t differences[MAX_DIFFERENCES];
    size_t difference_count;
    size_t index;
    int mlock_rc;
    int mlock_errno = 0;
    size_t changed;
    size_t lost;

    if (pin_cpu(cpu) != 0) {
        perror("sched_setaffinity");
        return 30;
    }
    if (pool_create(&pool, mib, ion_path) != 0) {
        perror("pool_create");
        pool_release(&pool);
        return 31;
    }
    errno = 0;
    mlock_rc = mlock(pool.mapping, pool.bytes);
    if (mlock_rc != 0)
        mlock_errno = errno;
    print_pool_summary(&pool, "inventory", mib, cpu, mlock_rc, mlock_errno);
    if (pool.valid_pages == 0 || pool.zero_pfn_pages != 0) {
        fprintf(stderr, "pagemap did not expose usable PFNs\n");
        pool_release(&pool);
        return 32;
    }
    pairs = calloc(maximum_pairs, sizeof(*pairs));
    if (pairs == NULL) {
        pool_release(&pool);
        return 33;
    }
    difference_count = protocol_differences(differences);
    for (index = 0; index < difference_count; ++index) {
        size_t pair_count = collect_pairs(&pool, differences[index], pairs,
                                          maximum_pairs);
        printf("{\"schema\":\"%s\",\"type\":\"coverage\","
               "\"phase\":\"%s\",\"difference\":\"0x%08" PRIx64 "\","
               "\"pairs\":%zu,\"capped_at\":%zu}\n",
               PROBE_SCHEMA, difference_phase(differences[index]),
               differences[index], pair_count, maximum_pairs);
    }
    free(pairs);
    if (verify_pagemap_stability(&pool, &changed, &lost) != 0) {
        perror("pagemap stability");
        pool_release(&pool);
        return 34;
    }
    printf("{\"schema\":\"%s\",\"type\":\"stability\","
           "\"method\":\"%s\",\"changed_pages\":%zu,\"lost_pages\":%zu}\n",
           PROBE_SCHEMA, pool.stability_method, changed, lost);
    pool_release(&pool);
    return changed == 0 && lost == 0 ? 0 : 35;
}

static int run_measure(uint64_t mib, size_t repetitions, size_t maximum_pairs,
                       unsigned int cpu, int argc, char **argv,
                       const char *ion_path)
{
    struct pool pool;
    struct pair_record *pairs;
    uint64_t default_differences[MAX_DIFFERENCES];
    uint64_t supplied_differences[MAX_DIFFERENCES];
    uint64_t *differences = default_differences;
    size_t difference_count;
    size_t index;
    int mlock_rc;
    int mlock_errno = 0;
    size_t changed;
    size_t lost;
    uint8_t *eviction = MAP_FAILED;

    if (argc > 0) {
        if ((size_t)argc > MAX_DIFFERENCES) {
            fprintf(stderr, "too many differences\n");
            return 40;
        }
        for (index = 0; index < (size_t)argc; ++index) {
            if (parse_u64(argv[index], 1, UINT32_MAX,
                          &supplied_differences[index]) != 0) {
                fprintf(stderr, "invalid difference: %s\n", argv[index]);
                return 41;
            }
        }
        differences = supplied_differences;
        difference_count = (size_t)argc;
    } else {
        difference_count = protocol_differences(default_differences);
    }

    if (pin_cpu(cpu) != 0) {
        perror("sched_setaffinity");
        return 42;
    }
    if (pool_create(&pool, mib, ion_path) != 0) {
        perror("pool_create");
        pool_release(&pool);
        return 43;
    }
    errno = 0;
    mlock_rc = mlock(pool.mapping, pool.bytes);
    if (mlock_rc != 0)
        mlock_errno = errno;
    print_pool_summary(&pool, "measure", mib, cpu, mlock_rc, mlock_errno);
    if (pool.valid_pages == 0 || pool.zero_pfn_pages != 0) {
        fprintf(stderr, "pagemap did not expose usable PFNs\n");
        pool_release(&pool);
        return 44;
    }
    pairs = calloc(maximum_pairs, sizeof(*pairs));
    if (pairs == NULL) {
        pool_release(&pool);
        return 45;
    }
    if (ion_path == NULL) {
        eviction = mmap(NULL, (size_t)EVICTION_BYTES,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (eviction == MAP_FAILED) {
            perror("eviction mmap");
            free(pairs);
            pool_release(&pool);
            return 46;
        }
        for (index = 0; index < (size_t)EVICTION_BYTES;
             index += CACHE_LINE_BYTES)
            eviction[index] = (uint8_t)index;
        full_barrier();
    }
    for (index = 0; index < difference_count; ++index) {
        uint64_t *samples;
        uint64_t *relation_samples = NULL;
        uint64_t *baseline_samples = NULL;
        uint64_t *pair_medians;
        uint64_t *pair_trimmed_mean_milli;
        int64_t *pair_reopen_delta_milli = NULL;
        size_t pair_count = collect_pairs(&pool, differences[index], pairs,
                                          maximum_pairs);
        size_t pair_index;

        if (pair_count == 0) {
            printf("{\"schema\":\"%s\",\"type\":\"measurement\","
                   "\"phase\":\"%s\",\"difference\":\"0x%08" PRIx64 "\","
                   "\"pairs\":0,\"repetitions\":0,\"status\":\"NO_PAIR\"}\n",
                   PROBE_SCHEMA, difference_phase(differences[index]),
                   differences[index]);
            continue;
        }
        samples = calloc(repetitions, sizeof(*samples));
        pair_medians = calloc(pair_count, sizeof(*pair_medians));
        pair_trimmed_mean_milli =
            calloc(pair_count, sizeof(*pair_trimmed_mean_milli));
        if (ion_path != NULL) {
            relation_samples = calloc(repetitions, sizeof(*relation_samples));
            baseline_samples = calloc(repetitions, sizeof(*baseline_samples));
            pair_reopen_delta_milli =
                calloc(pair_count, sizeof(*pair_reopen_delta_milli));
        }
        if (samples == NULL || pair_medians == NULL ||
            pair_trimmed_mean_milli == NULL ||
            (ion_path != NULL && (relation_samples == NULL ||
                                  baseline_samples == NULL ||
                                  pair_reopen_delta_milli == NULL))) {
            free(samples);
            free(relation_samples);
            free(baseline_samples);
            free(pair_medians);
            free(pair_trimmed_mean_milli);
            free(pair_reopen_delta_milli);
            if (eviction != MAP_FAILED)
                munmap(eviction, (size_t)EVICTION_BYTES);
            free(pairs);
            pool_release(&pool);
            return 47;
        }
        for (pair_index = 0; pair_index < pair_count; ++pair_index) {
            size_t repetition;
            size_t warmup;
            size_t trim;
            size_t kept;
            uint64_t sum = 0;

            /*
             * Evict unknown prior cache state once, then keep this one pair
             * isolated.  The last B row from one iteration becomes the known
             * initial row for the next A->B iteration.  Mixing 64 pairs in one
             * batch would destroy exactly that row-buffer state.
             */
            if (eviction != MAP_FAILED) {
                sweep_eviction_buffer(eviction, (size_t)EVICTION_BYTES,
                                      (uint8_t)(pair_index + index + 1));
                full_barrier();
            }
            for (warmup = 0; warmup < PAIR_WARMUPS; ++warmup)
                (void)measure_pair_once(&pairs[pair_index],
                                        ion_path == NULL);
            for (repetition = 0; repetition < repetitions; ++repetition)
                samples[repetition] = measure_pair_once(
                    &pairs[pair_index], ion_path == NULL);
            qsort(samples, repetitions, sizeof(*samples), compare_u64);
            pair_medians[pair_index] = samples[repetitions / 2];
            trim = repetitions / 10;
            kept = repetitions - 2 * trim;
            for (repetition = trim; repetition < repetitions - trim;
                 ++repetition)
                sum += samples[repetition];
            pair_trimmed_mean_milli[pair_index] = (sum * 1000) / kept;

            if (ion_path != NULL) {
                uint64_t relation_sum = 0;
                uint64_t baseline_sum = 0;

                for (warmup = 0; warmup < PAIR_WARMUPS; ++warmup) {
                    (void)measure_reopen_once(
                        pairs[pair_index].b, pairs[pair_index].a,
                        pairs[pair_index].b);
                    (void)measure_reopen_once(
                        pairs[pair_index].a, pairs[pair_index].b,
                        pairs[pair_index].a);
                    (void)measure_reopen_once(
                        pairs[pair_index].a, pairs[pair_index].a,
                        pairs[pair_index].a);
                    (void)measure_reopen_once(
                        pairs[pair_index].b, pairs[pair_index].b,
                        pairs[pair_index].b);
                }
                for (repetition = 0; repetition < repetitions; ++repetition) {
                    uint64_t relation;
                    uint64_t baseline;

                    if ((repetition & 1U) == 0) {
                        relation = measure_reopen_once(
                            pairs[pair_index].b, pairs[pair_index].a,
                            pairs[pair_index].b);
                        relation += measure_reopen_once(
                            pairs[pair_index].a, pairs[pair_index].b,
                            pairs[pair_index].a);
                        baseline = measure_reopen_once(
                            pairs[pair_index].a, pairs[pair_index].a,
                            pairs[pair_index].a);
                        baseline += measure_reopen_once(
                            pairs[pair_index].b, pairs[pair_index].b,
                            pairs[pair_index].b);
                    } else {
                        baseline = measure_reopen_once(
                            pairs[pair_index].a, pairs[pair_index].a,
                            pairs[pair_index].a);
                        baseline += measure_reopen_once(
                            pairs[pair_index].b, pairs[pair_index].b,
                            pairs[pair_index].b);
                        relation = measure_reopen_once(
                            pairs[pair_index].b, pairs[pair_index].a,
                            pairs[pair_index].b);
                        relation += measure_reopen_once(
                            pairs[pair_index].a, pairs[pair_index].b,
                            pairs[pair_index].a);
                    }
                    relation_samples[repetition] = relation;
                    baseline_samples[repetition] = baseline;
                }
                qsort(relation_samples, repetitions,
                      sizeof(*relation_samples), compare_u64);
                qsort(baseline_samples, repetitions,
                      sizeof(*baseline_samples), compare_u64);
                for (repetition = trim; repetition < repetitions - trim;
                     ++repetition) {
                    relation_sum += relation_samples[repetition];
                    baseline_sum += baseline_samples[repetition];
                }
                pair_reopen_delta_milli[pair_index] =
                    ((int64_t)relation_sum - (int64_t)baseline_sum) * 1000 /
                    (int64_t)(kept * 2);
            }
        }
        qsort(pair_medians, pair_count, sizeof(*pair_medians), compare_u64);
        qsort(pair_trimmed_mean_milli, pair_count,
              sizeof(*pair_trimmed_mean_milli), compare_u64);
        if (pair_reopen_delta_milli != NULL)
            qsort(pair_reopen_delta_milli, pair_count,
                  sizeof(*pair_reopen_delta_milli), compare_i64);
        printf("{\"schema\":\"%s\",\"type\":\"measurement\","
               "\"phase\":\"%s\",\"difference\":\"0x%08" PRIx64 "\","
               "\"pairs\":%zu,\"repetitions_per_pair\":%zu,\"status\":\"OK\","
               "\"method\":\"%s\","
               "\"eviction_bytes\":%" PRIu64 ","
               "\"warmups_per_pair\":%u,"
               "\"pair_median_ticks_min\":%" PRIu64 ","
               "\"pair_median_ticks_p10\":%" PRIu64 ","
               "\"pair_median_ticks_median\":%" PRIu64 ","
               "\"pair_median_ticks_p90\":%" PRIu64 ","
               "\"pair_median_ticks_max\":%" PRIu64 ","
               "\"pair_trimmed_mean_milli_min\":%" PRIu64 ","
               "\"pair_trimmed_mean_milli_p10\":%" PRIu64 ","
               "\"pair_trimmed_mean_milli_median\":%" PRIu64 ","
               "\"pair_trimmed_mean_milli_p90\":%" PRIu64 ","
               "\"pair_trimmed_mean_milli_max\":%" PRIu64 ","
               "\"reopen_delta_available\":%s,"
               "\"pair_reopen_delta_milli_min\":%" PRId64 ","
               "\"pair_reopen_delta_milli_p10\":%" PRId64 ","
               "\"pair_reopen_delta_milli_median\":%" PRId64 ","
               "\"pair_reopen_delta_milli_p90\":%" PRId64 ","
               "\"pair_reopen_delta_milli_max\":%" PRId64 "}\n",
               PROBE_SCHEMA, difference_phase(differences[index]),
               differences[index], pair_count, repetitions,
               ion_path == NULL ? "per_pair_alternating_dc_civac" :
                                  "per_pair_alternating_uncached_ion",
               ion_path == NULL ? EVICTION_BYTES : UINT64_C(0),
               PAIR_WARMUPS, pair_medians[0],
               pair_medians[(pair_count - 1) / 10],
               pair_medians[pair_count / 2],
               pair_medians[((pair_count - 1) * 9) / 10],
               pair_medians[pair_count - 1],
               pair_trimmed_mean_milli[0],
               pair_trimmed_mean_milli[(pair_count - 1) / 10],
               pair_trimmed_mean_milli[pair_count / 2],
               pair_trimmed_mean_milli[((pair_count - 1) * 9) / 10],
               pair_trimmed_mean_milli[pair_count - 1],
               pair_reopen_delta_milli != NULL ? "true" : "false",
               pair_reopen_delta_milli != NULL ?
                   pair_reopen_delta_milli[0] : 0,
               pair_reopen_delta_milli != NULL ?
                   pair_reopen_delta_milli[(pair_count - 1) / 10] : 0,
               pair_reopen_delta_milli != NULL ?
                   pair_reopen_delta_milli[pair_count / 2] : 0,
               pair_reopen_delta_milli != NULL ?
                   pair_reopen_delta_milli[((pair_count - 1) * 9) / 10] : 0,
               pair_reopen_delta_milli != NULL ?
                   pair_reopen_delta_milli[pair_count - 1] : 0);
        free(samples);
        free(relation_samples);
        free(baseline_samples);
        free(pair_medians);
        free(pair_trimmed_mean_milli);
        free(pair_reopen_delta_milli);
    }
    if (eviction != MAP_FAILED)
        munmap(eviction, (size_t)EVICTION_BYTES);
    free(pairs);
    if (verify_pagemap_stability(&pool, &changed, &lost) != 0) {
        perror("pagemap stability");
        pool_release(&pool);
        return 48;
    }
    printf("{\"schema\":\"%s\",\"type\":\"stability\","
           "\"method\":\"%s\",\"changed_pages\":%zu,\"lost_pages\":%zu,"
           "\"sink\":%" PRIu64 "}\n",
           PROBE_SCHEMA, pool.stability_method, changed, lost, load_sink);
    pool_release(&pool);
    return changed == 0 && lost == 0 ? 0 : 49;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage:\n"
            "  %s [ion-]smoke [cpu]\n"
            "  %s [ion-]inventory <MiB> [max_pairs] [cpu]\n"
            "  %s [ion-]measure <MiB> <repetitions> <max_pairs> [cpu] [difference ...]\n"
            "  %s ion-scan <MiB> <system|user_contig>\n",
            program, program, program, program);
}

int main(int argc, char **argv)
{
    uint64_t value;
    unsigned int cpu = 7;
    const char *mode;
    const char *ion_path = NULL;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    mode = argv[1];
    if (strncmp(mode, "ion-", 4) == 0) {
        mode += 4;
        ion_path = ION_DEVICE_PATH;
    }
    if (strcmp(mode, "scan") == 0) {
        uint64_t mib;
        if (ion_path == NULL || argc != 4 ||
            parse_u64(argv[2], 1, 1024, &mib) != 0 ||
            (strcmp(argv[3], "system") != 0 &&
             strcmp(argv[3], "user_contig") != 0)) {
            usage(argv[0]);
            return 2;
        }
        return run_ion_kpage_scan(mib, argv[3]);
    }
    if (strcmp(mode, "smoke") == 0) {
        if (argc > 3 || (argc == 3 &&
            parse_u64(argv[2], 0, CPU_SETSIZE - 1, &value) != 0)) {
            usage(argv[0]);
            return 2;
        }
        if (argc == 3)
            cpu = (unsigned int)value;
        return run_smoke(cpu, ion_path);
    }
    if (strcmp(mode, "inventory") == 0) {
        uint64_t mib;
        uint64_t maximum_pairs = 64;
        if (argc < 3 || argc > 5 ||
            parse_u64(argv[2], 1, 3072, &mib) != 0 ||
            (argc >= 4 && parse_u64(argv[3], 1, MAX_MEASURE_PAIRS,
                                    &maximum_pairs) != 0) ||
            (argc == 5 && parse_u64(argv[4], 0, CPU_SETSIZE - 1,
                                    &value) != 0)) {
            usage(argv[0]);
            return 2;
        }
        if (argc == 5)
            cpu = (unsigned int)value;
        return run_inventory(mib, (size_t)maximum_pairs, cpu, ion_path);
    }
    if (strcmp(mode, "measure") == 0) {
        uint64_t mib;
        uint64_t repetitions;
        uint64_t maximum_pairs;
        int difference_start = 6;
        if (argc < 5 || parse_u64(argv[2], 1, 3072, &mib) != 0 ||
            parse_u64(argv[3], 3, MAX_REPETITIONS, &repetitions) != 0 ||
            parse_u64(argv[4], 1, MAX_MEASURE_PAIRS, &maximum_pairs) != 0) {
            usage(argv[0]);
            return 2;
        }
        if (argc >= 6) {
            if (parse_u64(argv[5], 0, CPU_SETSIZE - 1, &value) != 0) {
                usage(argv[0]);
                return 2;
            }
            cpu = (unsigned int)value;
        } else {
            difference_start = argc;
        }
        return run_measure(mib, (size_t)repetitions,
                           (size_t)maximum_pairs, cpu,
                           argc - difference_start, argv + difference_start,
                           ion_path);
    }
    usage(argv[0]);
    return 2;
}
