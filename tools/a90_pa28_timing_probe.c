/* Verification 020N: bounded normal-RAM PA28 timing candidate.
 *
 * This probe is intentionally a new, fixed-shape candidate.  It requests one
 * full 320-MiB allocation from the exact non-secure camera_preview heap
 * (type 10, id 30), then measures only offsets inside that allocation.  The
 * candidate pair is offset 0 and offset 0x10000000, so the tested offset
 * difference is one bit (PA28) if the independently retained 020M/021
 * preconditions hold.
 *
 * There is no command-line surface: all paths, sizes, offsets, repetitions,
 * and controls are compile-time constants.  The only ioctl operations are
 * the read-only heap query and allocation of this process's own normal-RAM
 * buffer.  No physical address is read, no pagemap is opened, and no address
 * outside the allocated buffer is formed.  The cache control uses a separate
 * one-page anonymous cached buffer; it is an instrumentation control, not a
 * physical-address or alias claim.
 *
 * The probe does not access registers, controller apertures, secure services,
 * partitions, firmware, or protected memory.  It writes and reads only its
 * own normal-RAM allocations and releases them on every exit path.
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define PROBE_SCHEMA "a90_pa28_timing_probe_v1"
#define PAGE_BYTES UINT64_C(4096)
#define WORD_BYTES UINT64_C(8)
#define CACHE_LINE_BYTES UINT64_C(64)
#define ALLOCATION_MIB UINT64_C(320)
#define ALLOCATION_BYTES (ALLOCATION_MIB * UINT64_C(1024) * UINT64_C(1024))
#define EXPECTED_HEAP_NAME "camera_preview"
#define EXPECTED_HEAP_TYPE 10U
#define EXPECTED_HEAP_ID 30U
#define EXPECTED_CPU 7U
#define PA28_DIFFERENCE UINT64_C(0x10000000)
#define NEGATIVE_BANK13 (PA28_DIFFERENCE ^ UINT64_C(0x2000))
#define NEGATIVE_BANK14 (PA28_DIFFERENCE ^ UINT64_C(0x4000))
#define PAIR_COUNT 8U
#define REPETITIONS 1001U
#define WARMUPS 17U
#define CACHE_CONTROL_SAMPLES 129U
#define ION_HEAP_NAME_BYTES 32U
#define ION_MAX_HEAPS 64U
#define ION_FLAG_CACHED UINT32_C(1)

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

static const uint64_t PAIR_OFFSETS[PAIR_COUNT] = {
    UINT64_C(0x00000000), UINT64_C(0x00004000),
    UINT64_C(0x00010000), UINT64_C(0x00400000),
    UINT64_C(0x01000000), UINT64_C(0x02000000),
    UINT64_C(0x03000000), UINT64_C(0x03fff000),
};

static volatile uint64_t load_sink;

#if defined(__aarch64__)
static inline uint64_t read_counter(void)
{
    uint64_t value;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(value));
    return value;
}

static inline void load_barrier(void)
{
    __asm__ volatile("dsb ld" : : : "memory");
}

static inline void full_barrier(void)
{
    __asm__ volatile("dsb sy\n\tisb" : : : "memory");
}

static inline void cache_clean_invalidate(const void *address)
{
    __asm__ volatile("dc civac, %0" : : "r"(address) : "memory");
}
#else
static inline uint64_t read_counter(void)
{
    struct timespec now;
    (void)clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) +
           (uint64_t)now.tv_nsec;
}

static inline void load_barrier(void)
{
    __sync_synchronize();
}

static inline void full_barrier(void)
{
    __sync_synchronize();
}

static inline void cache_clean_invalidate(const void *address)
{
    (void)address;
    __sync_synchronize();
}
#endif

static int compare_i64(const void *left, const void *right)
{
    const int64_t a = *(const int64_t *)left;
    const int64_t b = *(const int64_t *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

static int compare_u64(const void *left, const void *right)
{
    const uint64_t a = *(const uint64_t *)left;
    const uint64_t b = *(const uint64_t *)right;
    return a < b ? -1 : (a > b ? 1 : 0);
}

static void json_string(const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    putchar('"');
    while (*cursor != '\0') {
        switch (*cursor) {
        case '"': fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
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

static void emit_abort(const char *reason)
{
    printf("{\"schema\":\"%s\",\"type\":\"abort\","
           "\"reason\":", PROBE_SCHEMA);
    json_string(reason);
    fputs("}\n", stdout);
}

static uint64_t measure_reopen_once(const volatile uint8_t *prime,
                                    const volatile uint8_t *intervening,
                                    const volatile uint8_t *timed)
{
    uint64_t start;
    uint64_t end;
    uint64_t accumulator;

    accumulator = *prime;
    load_barrier();
    accumulator ^= *intervening;
    load_barrier();
    start = read_counter();
    accumulator ^= *timed;
    load_barrier();
    end = read_counter();
    load_sink ^= accumulator;
    return end - start;
}

static int pin_cpu(void)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(EXPECTED_CPU, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static int valid_offset(uint64_t offset)
{
    return offset < ALLOCATION_BYTES &&
           WORD_BYTES <= ALLOCATION_BYTES - offset;
}

static int64_t delta_for_pair(const volatile uint8_t *map,
                              uint64_t offset_a, uint64_t offset_b)
{
    uint64_t relation[REPETITIONS];
    uint64_t baseline[REPETITIONS];
    size_t trim;
    size_t kept;
    uint64_t relation_sum = 0;
    uint64_t baseline_sum = 0;

    for (unsigned int warmup = 0; warmup < WARMUPS; ++warmup) {
        (void)measure_reopen_once(map + offset_b, map + offset_a,
                                   map + offset_b);
        (void)measure_reopen_once(map + offset_a, map + offset_b,
                                   map + offset_a);
        (void)measure_reopen_once(map + offset_a, map + offset_a,
                                   map + offset_a);
        (void)measure_reopen_once(map + offset_b, map + offset_b,
                                   map + offset_b);
    }
    for (size_t repetition = 0; repetition < REPETITIONS; ++repetition) {
        uint64_t relation_value;
        uint64_t baseline_value;

        if ((repetition & 1U) == 0U) {
            relation_value = measure_reopen_once(
                map + offset_b, map + offset_a, map + offset_b);
            relation_value += measure_reopen_once(
                map + offset_a, map + offset_b, map + offset_a);
            baseline_value = measure_reopen_once(
                map + offset_a, map + offset_a, map + offset_a);
            baseline_value += measure_reopen_once(
                map + offset_b, map + offset_b, map + offset_b);
        } else {
            baseline_value = measure_reopen_once(
                map + offset_a, map + offset_a, map + offset_a);
            baseline_value += measure_reopen_once(
                map + offset_b, map + offset_b, map + offset_b);
            relation_value = measure_reopen_once(
                map + offset_b, map + offset_a, map + offset_b);
            relation_value += measure_reopen_once(
                map + offset_a, map + offset_b, map + offset_a);
        }
        relation[repetition] = relation_value;
        baseline[repetition] = baseline_value;
    }
    qsort(relation, REPETITIONS, sizeof(*relation), compare_u64);
    qsort(baseline, REPETITIONS, sizeof(*baseline), compare_u64);
    trim = REPETITIONS / 10U;
    kept = REPETITIONS - trim * 2U;
    for (size_t index = trim; index < REPETITIONS - trim; ++index) {
        relation_sum += relation[index];
        baseline_sum += baseline[index];
    }
    return ((int64_t)relation_sum - (int64_t)baseline_sum) * 1000 /
           (int64_t)(kept * 2U);
}

static int group_measurement(const volatile uint8_t *map,
                             const char *name, uint64_t difference,
                             int64_t *p10, int64_t *median, int64_t *p90)
{
    int64_t values[PAIR_COUNT];

    for (size_t index = 0; index < PAIR_COUNT; ++index) {
        const uint64_t offset_a = PAIR_OFFSETS[index];
        const uint64_t offset_b = offset_a ^ difference;

        if (!valid_offset(offset_a) || !valid_offset(offset_b)) {
            fprintf(stderr, "pair %s exceeds the fixed allocation\n", name);
            return -1;
        }
        values[index] = delta_for_pair(map, offset_a, offset_b);
    }
    qsort(values, PAIR_COUNT, sizeof(*values), compare_i64);
    *p10 = values[PAIR_COUNT / 10U];
    *median = values[PAIR_COUNT / 2U];
    *p90 = values[PAIR_COUNT - 1U - PAIR_COUNT / 10U];
    printf("{\"schema\":\"%s\",\"type\":\"measurement\","
           "\"name\":", PROBE_SCHEMA);
    json_string(name);
    printf(",\"difference\":\"0x%llx\",\"pairs\":%u,"
           "\"repetitions_per_pair\":%u,\"warmups_per_pair\":%u,"
           "\"trim_percent\":10,\"p10\":%" PRId64 ","
           "\"median\":%" PRId64 ",\"p90\":%" PRId64 ","
           "\"status\":\"OK\"}\n",
           (unsigned long long)difference, PAIR_COUNT, REPETITIONS, WARMUPS,
           *p10, *median, *p90);
    return 0;
}

static int cache_control(void)
{
    uint8_t *cached = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t samples[CACHE_CONTROL_SAMPLES];

    if (cached == MAP_FAILED)
        return -1;
    cached[0] = 0x3c;
    cached[CACHE_LINE_BYTES] = 0xa5;
    full_barrier();
    for (size_t index = 0; index < CACHE_CONTROL_SAMPLES; ++index) {
        const uint64_t start = read_counter();
        uint64_t value;

        cache_clean_invalidate(cached);
        cache_clean_invalidate(cached + CACHE_LINE_BYTES);
        full_barrier();
        value = cached[0] ^ cached[CACHE_LINE_BYTES];
        load_barrier();
        samples[index] = read_counter() - start;
        load_sink ^= value;
    }
    qsort(samples, CACHE_CONTROL_SAMPLES, sizeof(*samples), compare_u64);
    printf("{\"schema\":\"%s\",\"type\":\"control\","
           "\"name\":\"cache_maintenance\","
           "\"mapping\":\"anonymous_cached\","
           "\"cache_maintenance\":\"dc_civac\","
           "\"samples\":%u,\"min\":%llu,\"median\":%llu,"
           "\"p90\":%llu,\"status\":\"OK\"}\n",
           PROBE_SCHEMA, CACHE_CONTROL_SAMPLES,
           (unsigned long long)samples[0],
           (unsigned long long)samples[CACHE_CONTROL_SAMPLES / 2U],
           (unsigned long long)samples[CACHE_CONTROL_SAMPLES - 1U -
                                       CACHE_CONTROL_SAMPLES / 10U]);
    munmap(cached, PAGE_BYTES);
    return 0;
}

static int query_heap(int ion_fd, struct ion_heap_data_uapi **selected_out,
                      struct ion_heap_data_uapi **heaps_out)
{
    struct ion_heap_query_uapi query;
    struct ion_heap_data_uapi *heaps;
    struct ion_heap_data_uapi *selected = NULL;
    unsigned int selected_count = 0;

    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0 ||
        query.cnt == 0U || query.cnt > ION_MAX_HEAPS) {
        return -1;
    }
    heaps = calloc(query.cnt, sizeof(*heaps));
    if (heaps == NULL)
        return -1;
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0) {
        free(heaps);
        return -1;
    }
    for (uint32_t index = 0; index < query.cnt; ++index) {
        heaps[index].name[ION_HEAP_NAME_BYTES - 1U] = '\0';
        if (strcmp(heaps[index].name, EXPECTED_HEAP_NAME) == 0) {
            selected = &heaps[index];
            ++selected_count;
        }
    }
    if (selected == NULL || selected_count != 1U ||
        selected->type != EXPECTED_HEAP_TYPE ||
        selected->heap_id != EXPECTED_HEAP_ID) {
        free(heaps);
        return -1;
    }
    *selected_out = selected;
    *heaps_out = heaps;
    return 0;
}

int main(int argc, char **argv)
{
    int ion_fd = -1;
    int allocation_fd = -1;
    uint8_t *map = MAP_FAILED;
    struct ion_heap_data_uapi *selected = NULL;
    struct ion_heap_data_uapi *heaps = NULL;
    struct ion_allocation_data_uapi allocation;
    int64_t same_p10, same_median, same_p90;
    int64_t candidate_p10, candidate_median, candidate_p90;
    int64_t negative13_p10, negative13_median, negative13_p90;
    int64_t negative14_p10, negative14_median, negative14_p90;
    int result = 1;

    (void)argv;
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 1) {
        fprintf(stderr, "this fixed probe accepts no arguments\n");
        return 2;
    }
    if (pin_cpu() != 0) {
        emit_abort("cpu pin failed");
        return 1;
    }
    printf("{\"schema\":\"%s\",\"type\":\"context\","
           "\"heap_name\":\"%s\",\"heap_id\":%u,"
           "\"heap_type\":%u,\"allocation_mib\":%llu,"
           "\"allocation_bytes\":%llu,\"pa28_difference\":\"0x%llx\","
           "\"negative_differences\":[\"0x%llx\",\"0x%llx\"],"
           "\"cpu\":%u,\"repetitions_per_pair\":%u,"
           "\"warmups_per_pair\":%u,\"mapping\":\"ion_uncached_writecombine\","
           "\"barrier\":\"dsb_ld\",\"order\":\"alternating\","
           "\"pagemap\":\"NOT_USED\","
           "\"physical_address_provenance\":\"NOT_COLLECTED\","
           "\"device_writes\":false,\"mmio\":false,\"smc\":false,"
           "\"protected_memory\":false}\n",
           PROBE_SCHEMA, EXPECTED_HEAP_NAME, EXPECTED_HEAP_ID,
           EXPECTED_HEAP_TYPE, (unsigned long long)ALLOCATION_MIB,
           (unsigned long long)ALLOCATION_BYTES,
           (unsigned long long)PA28_DIFFERENCE,
           (unsigned long long)NEGATIVE_BANK13,
           (unsigned long long)NEGATIVE_BANK14, EXPECTED_CPU, REPETITIONS,
           WARMUPS);

    ion_fd = open("/dev/ion", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (ion_fd < 0) {
        emit_abort("open /dev/ion failed");
        goto cleanup;
    }
    if (query_heap(ion_fd, &selected, &heaps) != 0) {
        emit_abort("camera_preview type 10 id 30 heap identity failed");
        goto cleanup;
    }
    printf("{\"schema\":\"%s\",\"type\":\"ion_heap\","
           "\"name\":\"%s\",\"heap_type\":%u,\"heap_id\":%u}\n",
           PROBE_SCHEMA, selected->name, selected->type, selected->heap_id);

    memset(&allocation, 0, sizeof(allocation));
    allocation.len = ALLOCATION_BYTES;
    allocation.heap_id_mask = UINT32_C(1) << EXPECTED_HEAP_ID;
    allocation.flags = 0; /* fixed uncached/write-combine ION mapping */
    if (ioctl(ion_fd, ION_IOC_ALLOC, &allocation) != 0) {
        emit_abort("full 320 MiB camera_preview allocation failed");
        goto cleanup;
    }
    allocation_fd = (int)allocation.fd;
    map = mmap(NULL, ALLOCATION_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED,
               allocation_fd, 0);
    if (map == MAP_FAILED) {
        emit_abort("camera_preview mapping failed");
        goto cleanup;
    }
    printf("{\"schema\":\"%s\",\"type\":\"allocation\","
           "\"heap_id\":%u,\"heap_type\":%u,\"heap_name\":\"%s\","
           "\"flags\":0,\"requested_mib\":%llu,"
           "\"mapped_bytes\":%llu,\"status\":\"OK\"}\n",
           PROBE_SCHEMA, selected->heap_id, selected->type, selected->name,
           (unsigned long long)ALLOCATION_MIB,
           (unsigned long long)ALLOCATION_BYTES);

    for (size_t index = 0; index < PAIR_COUNT; ++index) {
        const uint64_t a = PAIR_OFFSETS[index];
        const uint64_t b = a ^ PA28_DIFFERENCE;
        const uint64_t c = a ^ NEGATIVE_BANK13;
        const uint64_t d = a ^ NEGATIVE_BANK14;

        if (!valid_offset(a) || !valid_offset(b) || !valid_offset(c) ||
            !valid_offset(d)) {
            emit_abort("fixed control offset exceeds allocation");
            goto cleanup;
        }
        *(volatile uint64_t *)(map + a) = UINT64_C(0x13579bdf2468ace0) ^ a;
        *(volatile uint64_t *)(map + b) = UINT64_C(0x2468ace013579bdf) ^ b;
        *(volatile uint64_t *)(map + c) = UINT64_C(0x55aa55aa55aa55aa) ^ c;
        *(volatile uint64_t *)(map + d) = UINT64_C(0xaa55aa55aa55aa55) ^ d;
    }
    full_barrier();

    if (group_measurement(map, "same_offset", 0, &same_p10, &same_median,
                          &same_p90) != 0 ||
        group_measurement(map, "pa28_candidate", PA28_DIFFERENCE,
                          &candidate_p10, &candidate_median,
                          &candidate_p90) != 0 ||
        group_measurement(map, "negative_bank_bit13", NEGATIVE_BANK13,
                          &negative13_p10, &negative13_median,
                          &negative13_p90) != 0 ||
        group_measurement(map, "negative_bank_bit14", NEGATIVE_BANK14,
                          &negative14_p10, &negative14_median,
                          &negative14_p90) != 0 ||
        cache_control() != 0) {
        emit_abort("one or more fixed measurements failed");
        goto cleanup;
    }
    printf("{\"schema\":\"%s\",\"type\":\"summary\","
           "\"candidate\":\"pa28_candidate\","
           "\"same_offset\":\"same_offset\","
           "\"negative_controls\":[\"negative_bank_bit13\","
           "\"negative_bank_bit14\"],\"cache_control\":"
           "\"cache_maintenance\",\"pagemap\":\"NOT_USED\","
           "\"physical_address_claim\":\"NONE\","
           "\"interpretation\":\"HOST_ANALYZER_REQUIRED\","
           "\"status\":\"OK\",\"load_sink\":%llu}\n",
           PROBE_SCHEMA, (unsigned long long)load_sink);
    (void)same_p10;
    (void)same_p90;
    (void)candidate_p10;
    (void)candidate_median;
    (void)candidate_p90;
    (void)negative13_p10;
    (void)negative13_median;
    (void)negative13_p90;
    (void)negative14_p10;
    (void)negative14_median;
    (void)negative14_p90;
    result = 0;

cleanup:
    if (map != MAP_FAILED)
        munmap(map, ALLOCATION_BYTES);
    if (allocation_fd >= 0)
        close(allocation_fd);
    free(heaps);
    if (ion_fd >= 0)
        close(ion_fd);
    return result;
}
