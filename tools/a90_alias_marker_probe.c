/* Verification 018: a bounded storage-identity marker probe.
 *
 * This is an allocation-local, write-combine test.  It adapts the published
 * bit-flip marker idea from Louka et al., "Physical Memory Please" (uASC '26)
 * to a Samsung ION dma-buf, but does not claim the paper's physical-address
 * precondition: on this target the physical base/contiguity are not exposed.
 * A candidate that reads the marker after only receiving a sentinel is a
 * single-state non-injective storage result for that exact offset pair.
 *
 * The probe deliberately does not touch MMIO, registers, SMC/EL2/EL3,
 * partitions, protected memory, secure heaps, or memory outside its own
 * allocation.  The second mmap of the same dma-buf supplies a virtual/same-
 * storage control; it is not a topology-alias positive control.  A candidate
 * trial writes sentinels first, then the marker, and reads through the second
 * mapping after `dsb sy` barriers.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define PROBE_SCHEMA "a90_alias_marker_v1"
#define PAGE_BYTES UINT64_C(4096)
#define WORD_BYTES UINT64_C(8)
#define CACHE_LINE_SHIFT 6U
#define TOP_BIT 27U
#define ANCHOR_COUNT 4U
#define TRIAL_COUNT 2U
#define CANDIDATE_BITS (TOP_BIT - CACHE_LINE_SHIFT + 1U)
#define CANDIDATE_COUNT (ANCHOR_COUNT * TRIAL_COUNT * CANDIDATE_BITS)
#define ALLOCATION_MIB 256U
#define ALLOCATION_BYTES (UINT64_C(1024) * UINT64_C(1024) * (uint64_t)ALLOCATION_MIB)
#define ION_HEAP_NAME_BYTES 32U
#define ION_MAX_HEAPS 64U
#define NODE_PATH_BYTES 128U
#define EXPECTED_HEAP_TYPE 10U
#define EXPECTED_HEAP_ID 30U

#define SENTINEL_SALT UINT64_C(0x9e3779b97f4a7c15)
#define MARKER_SALT UINT64_C(0xbf58476d1ce4e5b9)
#define CONTROL_SAME_SALT UINT64_C(0xd1b54a32d192ed03)
#define CONTROL_DISTINCT_SALT UINT64_C(0x2545f4914f6cdd1d)
#define TRIAL_SALT UINT64_C(0xa24baed4963ee407)
#define DEFAULT_SEED UINT64_C(0x5da9f0e3c17b2846)
#define CONTROL_LEFT PAGE_BYTES
#define CONTROL_RIGHT (PAGE_BYTES * UINT64_C(3) + UINT64_C(8))

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

#define ION_IOC_ALLOC _IOWR('I', 0, struct ion_allocation_data_uapi)
#define ION_IOC_HEAP_QUERY _IOWR('I', 8, struct ion_heap_query_uapi)

static const uint64_t anchor_offsets[ANCHOR_COUNT] = {
    UINT64_C(0x0000000), UINT64_C(0x0410b000),
    UINT64_C(0x0713a000), UINT64_C(0x0bcc0000),
};

static inline void full_barrier(void)
{
    __asm__ volatile("dsb sy" : : : "memory");
}

static uint64_t mix(uint64_t value)
{
    value += SENTINEL_SALT;
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static uint64_t sentinel_for(uint64_t offset, uint64_t seed, unsigned int trial)
{
    return mix(offset ^ seed ^ SENTINEL_SALT ^ ((uint64_t)trial * TRIAL_SALT));
}

static uint64_t marker_for(uint64_t anchor, uint64_t seed, unsigned int trial)
{
    return mix(anchor ^ seed ^ MARKER_SALT ^ ((uint64_t)trial * TRIAL_SALT));
}

static uint64_t control_same_marker(uint64_t seed)
{
    return mix(seed ^ CONTROL_SAME_SALT);
}

static uint64_t control_distinct_marker(uint64_t seed)
{
    return mix(CONTROL_LEFT ^ seed ^ CONTROL_DISTINCT_SALT);
}

static uint64_t read_u64(const volatile uint8_t *map, uint64_t offset)
{
    return *(const volatile uint64_t *)(map + offset);
}

static void write_u64(volatile uint8_t *map, uint64_t offset, uint64_t value)
{
    *(volatile uint64_t *)(map + offset) = value;
}

static void prefault_mapping(const volatile uint8_t *map, uint64_t bytes)
{
    volatile uint8_t checksum = 0;
    uint64_t offset;

    /* Populate one PTE per page before reading pagemap.  The checksum is not
     * emitted: this remains an allocation-local provenance aid, not a data
     * collection path. */
    for (offset = 0; offset < bytes; offset += PAGE_BYTES)
        checksum ^= map[offset];
    full_barrier();
    (void)checksum;
}

static void json_string(const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;
    putchar('"');
    while (*cursor != '\0') {
        switch (*cursor) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\b': fputs("\\b", stdout); break;
        case '\f': fputs("\\f", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (*cursor < 0x20U)
                printf("\\u%04x", (unsigned int)*cursor);
            else
                putchar((int)*cursor);
            break;
        }
        ++cursor;
    }
    putchar('"');
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

static int safe_ion_path(const char *path)
{
    static const char prefix[] = "/tmp/a90-native/";
    size_t length;
    size_t index;

    if (path == NULL)
        return 0;
    length = strlen(path);
    if (length == 0 || length >= NODE_PATH_BYTES)
        return 0;
    if (strcmp(path, "/dev/ion") == 0)
        return 1;
    if (strncmp(path, prefix, sizeof(prefix) - 1U) != 0)
        return 0;
    if (path[sizeof(prefix) - 1U] == '\0')
        return 0;
    for (index = sizeof(prefix) - 1U; index < length; ++index) {
        const unsigned char character = (unsigned char)path[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') ||
              character == '.' || character == '_' || character == '-'))
            return 0;
    }
    return 1;
}

static void emit_context(const char *ion_path, uint64_t seed)
{
    printf("{\"schema\":\"%s\",\"type\":\"context\",\"heap\":\"camera_preview\","
           "\"mib\":%u,\"anchors\":%u,\"trials\":%u,\"seed\":\"0x%llx\","
           "\"low_bit\":%u,\"top_bit\":%u,\"algorithm\":\"pmplease_alg2\","
           "\"mapping\":\"write_combine\",\"ion_node\":",
           PROBE_SCHEMA, ALLOCATION_MIB, ANCHOR_COUNT, TRIAL_COUNT,
           (unsigned long long)seed, CACHE_LINE_SHIFT, TOP_BIT);
    json_string(ion_path);
    fputs("}\n", stdout);
}

static void emit_pagemap_provenance(const uint8_t *map, uint64_t bytes)
{
    const uint64_t pages = bytes / PAGE_BYTES;
    uint64_t present = 0;
    uint64_t nonzero = 0;
    uint64_t first_pfn = 0;
    uint64_t last_pfn = 0;
    int have_first = 0;
    int contiguous = 1;
    int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    const int pagemap_opened = fd >= 0;

    if (fd >= 0) {
        uint64_t index;
        for (index = 0; index < pages; ++index) {
            const uint64_t va = (uint64_t)(uintptr_t)(map + index * PAGE_BYTES);
            const off_t file_offset = (off_t)((va >> 12) * sizeof(uint64_t));
            uint64_t entry = 0;
            uint64_t pfn;
            if (pread(fd, &entry, sizeof(entry), file_offset) != (ssize_t)sizeof(entry))
                break;
            if ((entry & (UINT64_C(1) << 63)) != 0)
                ++present;
            pfn = entry & ((UINT64_C(1) << 55) - 1U);
            if (pfn == 0)
                continue;
            ++nonzero;
            if (!have_first) {
                first_pfn = pfn;
                have_first = 1;
            } else if (pfn != last_pfn + 1U) {
                contiguous = 0;
            }
            last_pfn = pfn;
        }
        close(fd);
    }

    printf("{\"schema\":\"%s\",\"type\":\"pa_provenance\","
           "\"source\":\"pagemap\",\"status\":\"%s\",\"pages\":%llu,"
           "\"present\":%llu,\"nonzero_pfn\":%llu,\"first_pfn\":",
           PROBE_SCHEMA,
           !pagemap_opened ? "OPEN_FAILED" :
           (nonzero == 0 ? "BLIND" : "PARTIAL"),
           (unsigned long long)pages, (unsigned long long)present,
           (unsigned long long)nonzero);
    if (have_first)
        printf("\"0x%llx\"", (unsigned long long)first_pfn);
    else
        fputs("\"BLIND\"", stdout);
    fputs(",\"last_pfn\":", stdout);
    if (have_first)
        printf("\"0x%llx\"", (unsigned long long)last_pfn);
    else
        fputs("\"BLIND\"", stdout);
    printf(",\"reported_contiguous\":%s,\"effective_contiguity\":\"UNKNOWN\","
           "\"physical_mapping\":\"UNKNOWN\"}\n",
           nonzero == pages && pages != 0 && contiguous ? "true" : "false");
}

static int validate_layout(uint64_t seed)
{
    uint64_t values[3U + ANCHOR_COUNT * TRIAL_COUNT * (1U + CANDIDATE_BITS)];
    uint64_t offsets[TRIAL_COUNT][ANCHOR_COUNT * CANDIDATE_BITS];
    size_t value_count = 0;
    unsigned int anchor_index;
    unsigned int trial;
    unsigned int bit_index;

    values[value_count++] = control_same_marker(seed);
    values[value_count++] = control_distinct_marker(seed);
    values[value_count++] = sentinel_for(CONTROL_RIGHT, seed, 0);
    for (anchor_index = 0; anchor_index < ANCHOR_COUNT; ++anchor_index) {
        const uint64_t anchor = anchor_offsets[anchor_index];
        if (anchor % PAGE_BYTES != 0 || anchor + WORD_BYTES > ALLOCATION_BYTES)
            return -1;
        for (trial = 0; trial < TRIAL_COUNT; ++trial) {
            values[value_count++] = marker_for(anchor, seed, trial);
            for (bit_index = 0; bit_index < CANDIDATE_BITS; ++bit_index) {
                const unsigned int bit = CACHE_LINE_SHIFT + bit_index;
                const uint64_t candidate = anchor ^ (UINT64_C(1) << bit);
                unsigned int prior;
                values[value_count++] = sentinel_for(candidate, seed, trial);
                if (candidate + WORD_BYTES > ALLOCATION_BYTES)
                    return -1;
                for (prior = 0; prior < anchor_index * CANDIDATE_BITS; ++prior)
                    if (offsets[trial][prior] == candidate)
                        return -1;
                offsets[trial][anchor_index * CANDIDATE_BITS + bit_index] = candidate;
            }
        }
    }
    for (size_t left = 0; left < value_count; ++left)
        for (size_t right = left + 1; right < value_count; ++right)
            if (values[left] == values[right])
                return -1;
    return 0;
}

static void emit_same_storage_control(const volatile uint8_t *map1,
                                      const volatile uint8_t *map2,
                                      uint64_t seed)
{
    const uint64_t marker = control_same_marker(seed);
    const uint64_t observed_before = read_u64(map1, 0);
    uint64_t observed;

    (void)observed_before;
    write_u64((volatile uint8_t *)map1, 0, marker);
    full_barrier();
    observed = read_u64(map2, 0);
    full_barrier();
    printf("{\"schema\":\"%s\",\"type\":\"control\","
           "\"name\":\"same_storage_two_mappings\",\"offset\":\"0x0\","
           "\"different_virtual_addresses\":true,\"marker\":\"0x%llx\","
           "\"observed\":\"0x%llx\",\"verdict\":\"%s\"}\n",
           PROBE_SCHEMA, (unsigned long long)marker,
           (unsigned long long)observed,
           observed == marker ? "ALIAS" : "MISSED");
}

static void emit_distinct_control(const volatile uint8_t *map1,
                                  const volatile uint8_t *map2,
                                  uint64_t seed)
{
    const uint64_t marker = control_distinct_marker(seed);
    const uint64_t expected = sentinel_for(CONTROL_RIGHT, seed, 0);
    uint64_t observed;

    write_u64((volatile uint8_t *)map1, CONTROL_RIGHT, expected);
    full_barrier();
    write_u64((volatile uint8_t *)map1, CONTROL_LEFT, marker);
    full_barrier();
    observed = read_u64(map2, CONTROL_RIGHT);
    full_barrier();
    printf("{\"schema\":\"%s\",\"type\":\"control\","
           "\"name\":\"distinct\",\"left\":\"0x%llx\","
           "\"right\":\"0x%llx\",\"marker\":\"0x%llx\","
           "\"expected\":\"0x%llx\",\"observed\":\"0x%llx\","
           "\"verdict\":\"%s\"}\n",
           PROBE_SCHEMA, (unsigned long long)CONTROL_LEFT,
           (unsigned long long)CONTROL_RIGHT, (unsigned long long)marker,
           (unsigned long long)expected, (unsigned long long)observed,
           observed == marker ? "ALIAS" : "DISTINCT");
}

static void emit_anchor_trial(const volatile uint8_t *map1,
                              const volatile uint8_t *map2,
                              unsigned int anchor_index, unsigned int trial,
                              uint64_t seed, unsigned int *aliases,
                              unsigned int *disturbed,
                              unsigned char verdicts[ANCHOR_COUNT][TRIAL_COUNT][CANDIDATE_BITS],
                              unsigned int *clobbered)
{
    const uint64_t anchor = anchor_offsets[anchor_index];
    const uint64_t marker = marker_for(anchor, seed, trial);
    uint64_t readback;
    unsigned int bit_index;

    /* The sentinel phase must precede the marker phase. */
    for (bit_index = 0; bit_index < CANDIDATE_BITS; ++bit_index) {
        const unsigned int bit = CACHE_LINE_SHIFT + bit_index;
        const uint64_t candidate = anchor ^ (UINT64_C(1) << bit);
        write_u64((volatile uint8_t *)map1, candidate,
                  sentinel_for(candidate, seed, trial));
    }
    full_barrier();
    write_u64((volatile uint8_t *)map1, anchor, marker);
    full_barrier();
    readback = read_u64(map2, anchor);
    full_barrier();
    if (readback != marker)
        ++*clobbered;
    printf("{\"schema\":\"%s\",\"type\":\"anchor\","
           "\"anchor\":\"0x%llx\",\"trial\":%u,\"marker\":\"0x%llx\","
           "\"readback\":\"0x%llx\",\"intact\":%s}\n",
           PROBE_SCHEMA, (unsigned long long)anchor, trial,
           (unsigned long long)marker, (unsigned long long)readback,
           readback == marker ? "true" : "false");

    for (bit_index = 0; bit_index < CANDIDATE_BITS; ++bit_index) {
        const unsigned int bit = CACHE_LINE_SHIFT + bit_index;
        const uint64_t candidate = anchor ^ (UINT64_C(1) << bit);
        const uint64_t expected = sentinel_for(candidate, seed, trial);
        const uint64_t observed = read_u64(map2, candidate);
        const char *verdict;

        full_barrier();
        if (observed == marker) {
            verdict = "ALIAS";
            verdicts[anchor_index][trial][bit_index] = 1;
            ++*aliases;
        } else if (observed != expected) {
            verdict = "DISTURBED";
            verdicts[anchor_index][trial][bit_index] = 2;
            ++*disturbed;
        } else {
            verdict = "DISTINCT";
            verdicts[anchor_index][trial][bit_index] = 0;
        }
        printf("{\"schema\":\"%s\",\"type\":\"candidate\","
               "\"anchor\":\"0x%llx\",\"trial\":%u,\"bit\":%u,"
               "\"candidate\":\"0x%llx\",\"expected\":\"0x%llx\","
               "\"observed\":\"0x%llx\",\"verdict\":\"%s\"}\n",
               PROBE_SCHEMA, (unsigned long long)anchor, trial, bit,
               (unsigned long long)candidate, (unsigned long long)expected,
               (unsigned long long)observed, verdict);
    }
}

int main(int argc, char **argv)
{
    const char *ion_path = "/dev/ion";
    int path_seen = 0;
    uint64_t seed = DEFAULT_SEED;
    int ion_fd = -1;
    int allocation_fd = -1;
    struct ion_heap_query_uapi query;
    struct ion_heap_data_uapi *heaps = NULL;
    struct ion_heap_data_uapi *selected = NULL;
    uint32_t heap_capacity = 0;
    unsigned int selected_count = 0;
    struct ion_allocation_data_uapi allocation;
    uint8_t *map1 = NULL;
    uint8_t *map2 = NULL;
    unsigned int aliases = 0;
    unsigned int disturbed = 0;
    unsigned int clobbered = 0;
    unsigned int trial_disagreements = 0;
    unsigned char verdicts[ANCHOR_COUNT][TRIAL_COUNT][CANDIDATE_BITS] = {{{0}}};
    int exit_code = 1;

    for (int argument = 1; argument < argc; ++argument) {
        if (strcmp(argv[argument], "--ion-node") == 0) {
            if (argument + 1 >= argc || path_seen) {
                fprintf(stderr, "--ion-node needs exactly one path\n");
                goto cleanup;
            }
            ion_path = argv[++argument];
            path_seen = 1;
        } else if (strcmp(argv[argument], "--seed") == 0) {
            if (argument + 1 >= argc || parse_u64(argv[++argument], &seed) != 0) {
                fprintf(stderr, "--seed is not an unsigned integer\n");
                goto cleanup;
            }
        } else if (!path_seen && argv[argument][0] != '-') {
            ion_path = argv[argument];
            path_seen = 1;
        } else {
            fprintf(stderr, "usage: %s [--ion-node PATH] [--seed HEX]\n", argv[0]);
            goto cleanup;
        }
    }
    if (!safe_ion_path(ion_path)) {
        fprintf(stderr, "ion node must be /dev/ion or /tmp/a90-native/<safe-name>\n");
        goto cleanup;
    }
    if (validate_layout(seed) != 0) {
        fprintf(stderr, "deterministic anchor or marker layout is invalid\n");
        goto cleanup;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    emit_context(ion_path, seed);

    ion_fd = open(ion_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (ion_fd < 0) {
        perror("open ion node");
        goto cleanup;
    }
    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0 ||
        query.cnt == 0 || query.cnt > ION_MAX_HEAPS) {
        fprintf(stderr, "ion heap query failed or returned an invalid count: %u\n",
                query.cnt);
        goto cleanup;
    }
    heap_capacity = query.cnt;
    heaps = calloc(query.cnt, sizeof(*heaps));
    if (heaps == NULL) {
        perror("calloc heaps");
        goto cleanup;
    }
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0 ||
        query.cnt != heap_capacity) {
        fprintf(stderr, "ion heap inventory changed during the bounded query\n");
        goto cleanup;
    }
    for (uint32_t index = 0; index < query.cnt; ++index) {
        heaps[index].name[ION_HEAP_NAME_BYTES - 1U] = '\0';
        if (strcmp(heaps[index].name, "camera_preview") == 0) {
            selected = &heaps[index];
            ++selected_count;
        }
    }
    if (selected == NULL || selected_count != 1U ||
        selected->type != EXPECTED_HEAP_TYPE ||
        selected->heap_id != EXPECTED_HEAP_ID) {
        fprintf(stderr, "camera_preview heap is absent, duplicated, or differs from type 10/id 30\n");
        goto cleanup;
    }
    printf("{\"schema\":\"%s\",\"type\":\"ion_heap\",\"name\":",
           PROBE_SCHEMA);
    json_string(selected->name);
    printf(",\"heap_type\":%u,\"heap_id\":%u}\n",
           selected->type, selected->heap_id);

    memset(&allocation, 0, sizeof(allocation));
    allocation.len = ALLOCATION_BYTES;
    allocation.heap_id_mask = UINT32_C(1) << selected->heap_id;
    allocation.flags = 0; /* no ION_FLAG_CACHED: request write-combine mapping */
    if (ioctl(ion_fd, ION_IOC_ALLOC, &allocation) != 0) {
        perror("ion alloc");
        goto cleanup;
    }
    allocation_fd = (int)allocation.fd;
    map1 = mmap(NULL, ALLOCATION_BYTES, PROT_READ | PROT_WRITE,
                MAP_SHARED, allocation_fd, 0);
    if (map1 == MAP_FAILED) {
        map1 = NULL;
        perror("mmap first mapping");
        goto cleanup;
    }
    map2 = mmap(NULL, ALLOCATION_BYTES, PROT_READ | PROT_WRITE,
                MAP_SHARED, allocation_fd, 0);
    if (map2 == MAP_FAILED) {
        map2 = NULL;
        perror("mmap second mapping");
        goto cleanup;
    }
    if (map1 == map2) {
        fprintf(stderr, "ION returned identical virtual mappings\n");
        goto cleanup;
    }
    prefault_mapping(map1, ALLOCATION_BYTES);
    emit_pagemap_provenance(map1, ALLOCATION_BYTES);
    emit_same_storage_control(map1, map2, seed);
    emit_distinct_control(map1, map2, seed);
    for (unsigned int anchor_index = 0; anchor_index < ANCHOR_COUNT; ++anchor_index)
        for (unsigned int trial = 0; trial < TRIAL_COUNT; ++trial)
            emit_anchor_trial(map1, map2, anchor_index, trial, seed,
                              &aliases, &disturbed, verdicts, &clobbered);
    for (unsigned int anchor_index = 0; anchor_index < ANCHOR_COUNT; ++anchor_index)
        for (unsigned int bit_index = 0; bit_index < CANDIDATE_BITS; ++bit_index)
            if (verdicts[anchor_index][0][bit_index] != verdicts[anchor_index][1][bit_index])
                ++trial_disagreements;
    printf("{\"schema\":\"%s\",\"type\":\"summary\",\"anchors\":%u,"
           "\"trials\":%u,\"candidates\":%u,\"bits\":%u,\"aliases\":%u,"
           "\"disturbed\":%u,\"clobbered_anchors\":%u,\"trial_disagreements\":%u,"
           "\"all_anchors_intact\":%s,\"verdict\":\"%s\"}\n",
           PROBE_SCHEMA, ANCHOR_COUNT, TRIAL_COUNT, CANDIDATE_COUNT,
           CANDIDATE_BITS, aliases, disturbed, clobbered, trial_disagreements,
           clobbered == 0 ? "true" : "false",
           aliases != 0 ? "ALIAS_DETECTED" :
           (clobbered != 0 ? "ANCHOR_CLOBBERED" :
            (disturbed != 0 ? "DISTURBANCE" : "NO_ALIAS")));
    exit_code = 0;

cleanup:
    if (map2 != NULL)
        munmap(map2, ALLOCATION_BYTES);
    if (map1 != NULL)
        munmap(map1, ALLOCATION_BYTES);
    if (allocation_fd >= 0)
        close(allocation_fd);
    free(heaps);
    if (ion_fd >= 0)
        close(ion_fd);
    return exit_code;
}
