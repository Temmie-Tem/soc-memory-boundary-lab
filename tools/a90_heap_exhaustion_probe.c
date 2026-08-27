/* Does a full-size allocation consume the whole carveout?
 *
 * Verification 020 measured camera_preview's ceiling at 320 MiB, and the device
 * tree publishes camera_mem_region at base 0xC2000000 with size 0x14000000.
 * PA28_UNBLOCKED argued by pigeonhole that a 320 MiB allocation from a 320 MiB
 * carveout must therefore start at the base.  The 020M review held that
 * UNKNOWN, correctly: nothing had shown the allocation actually spans the pool
 * rather than the heap over-committing or the pool being larger than declared.
 *
 * This decides it.  Hold the full-size allocation, then try to allocate
 * anything at all from the same heap.  If nothing fits -- down to one page --
 * the hold consumed the pool.
 *
 * A failure under hold means nothing on its own, so it is bracketed by two
 * controls: the same probe sizes must succeed before the hold is taken and
 * again after it is released.  Without both, an ENOMEM under hold could be any
 * unrelated condition.
 *
 * Writes: none.  Allocations are made and released; nothing is mapped, read or
 * written.  No register, MMIO, SMC, EL2/EL3, protected memory or partition is
 * touched.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SCHEMA "a90_heap_exhaustion_v1"
#define ION_HEAP_NAME_BYTES 32U
#define ION_MAX_HEAPS 64U

struct ion_allocation_data_uapi {
    uint64_t len; uint32_t heap_id_mask, flags, fd, unused;
};
struct ion_heap_data_uapi {
    char name[ION_HEAP_NAME_BYTES];
    uint32_t type, heap_id, reserved0, reserved1, reserved2;
};
struct ion_heap_query_uapi {
    uint32_t cnt, reserved0; uint64_t heaps; uint32_t reserved1, reserved2;
};
#define ION_IOC_ALLOC _IOWR('I', 0, struct ion_allocation_data_uapi)
#define ION_IOC_HEAP_QUERY _IOWR('I', 8, struct ion_heap_query_uapi)

/* Descending to a single page: if even 4 KiB will not fit, the pool is gone. */
static const uint64_t PROBE_BYTES[] = {
    16ULL << 20, 4ULL << 20, 1ULL << 20, 64ULL << 10, 4ULL << 10
};
#define PROBE_N (sizeof(PROBE_BYTES) / sizeof(PROBE_BYTES[0]))

static int ion_fd;
static uint32_t heap_mask;

/* One allocation, immediately released.  Returns 1 on success. */
static int try_alloc(uint64_t bytes, int *out_errno)
{
    struct ion_allocation_data_uapi a;
    memset(&a, 0, sizeof(a));
    a.len = bytes;
    a.heap_id_mask = heap_mask;
    a.flags = 0;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &a) != 0) { *out_errno = errno; return 0; }
    close((int)a.fd);
    *out_errno = 0;
    return 1;
}

static void probe_phase(const char *phase, unsigned *ok_count)
{
    *ok_count = 0;
    for (size_t i = 0; i < PROBE_N; ++i) {
        int e, ok = try_alloc(PROBE_BYTES[i], &e);
        if (ok) ++*ok_count;
        printf("{\"schema\":\"%s\",\"type\":\"probe\",\"phase\":\"%s\","
               "\"bytes\":%llu,\"ok\":%s,\"errno\":%d,\"error\":\"%s\"}\n",
               SCHEMA, phase, (unsigned long long)PROBE_BYTES[i],
               ok ? "true" : "false", e, ok ? "" : strerror(e));
    }
}

int main(int argc, char **argv)
{
    const char *ion_path  = argc > 1 ? argv[1] : "/dev/ion";
    const char *heap_name = argc > 2 ? argv[2] : "camera_preview";
    uint64_t hold_mib     = argc > 3 ? strtoull(argv[3], NULL, 0) : 320;
    struct ion_heap_query_uapi q;
    struct ion_heap_data_uapi *heaps, *sel = NULL;
    struct ion_allocation_data_uapi hold;
    unsigned before = 0, under = 0, after = 0;
    int held, e;

    ion_fd = open(ion_path, O_RDONLY | O_CLOEXEC);
    if (ion_fd < 0) {
        printf("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"open: %s\"}\n",
               SCHEMA, strerror(errno));
        return 1;
    }
    memset(&q, 0, sizeof(q));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &q) != 0 || q.cnt == 0 || q.cnt > ION_MAX_HEAPS) {
        printf("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"heap count\"}\n", SCHEMA);
        return 1;
    }
    heaps = calloc(q.cnt, sizeof(*heaps));
    q.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &q) != 0) {
        printf("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"heap data\"}\n", SCHEMA);
        return 1;
    }
    for (uint32_t i = 0; i < q.cnt; ++i) {
        heaps[i].name[ION_HEAP_NAME_BYTES - 1] = '\0';
        if (strcmp(heaps[i].name, heap_name) == 0) sel = &heaps[i];
    }
    if (sel == NULL) {
        printf("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"heap %s missing\"}\n",
               SCHEMA, heap_name);
        return 1;
    }
    heap_mask = UINT32_C(1) << sel->heap_id;
    printf("{\"schema\":\"%s\",\"type\":\"context\",\"heap\":\"%s\",\"heap_type\":%u,"
           "\"heap_id\":%u,\"hold_mib\":%llu,\"probe_count\":%zu}\n",
           SCHEMA, sel->name, sel->type, sel->heap_id,
           (unsigned long long)hold_mib, PROBE_N);

    /* Control 1: the probe sizes must be allocatable with nothing held. */
    probe_phase("control_before", &before);

    memset(&hold, 0, sizeof(hold));
    hold.len = hold_mib << 20;
    hold.heap_id_mask = heap_mask;
    hold.flags = 0;
    held = ioctl(ion_fd, ION_IOC_ALLOC, &hold) == 0;
    e = held ? 0 : errno;
    printf("{\"schema\":\"%s\",\"type\":\"hold\",\"bytes\":%llu,\"ok\":%s,"
           "\"errno\":%d,\"error\":\"%s\"}\n",
           SCHEMA, (unsigned long long)(hold_mib << 20), held ? "true" : "false",
           e, held ? "" : strerror(e));
    if (!held) {
        printf("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":"
               "\"full-size hold did not allocate\"}\n", SCHEMA);
        return 1;
    }

    /* The question: with the full size held, does anything at all still fit? */
    probe_phase("under_hold", &under);

    close((int)hold.fd);

    /* Control 2: releasing the hold must restore what control 1 saw. */
    probe_phase("control_after", &after);

    printf("{\"schema\":\"%s\",\"type\":\"summary\",\"probe_count\":%zu,"
           "\"control_before_ok\":%u,\"under_hold_ok\":%u,\"control_after_ok\":%u,"
           "\"controls_fired\":%s,\"pool_exhausted\":%s,\"verdict\":\"%s\"}\n",
           SCHEMA, PROBE_N, before, under, after,
           (before == PROBE_N && after == PROBE_N) ? "true" : "false",
           (under == 0) ? "true" : "false",
           (before != PROBE_N || after != PROBE_N) ? "INSTRUMENT_FAILED"
             : (under == 0) ? "HOLD_CONSUMES_POOL" : "HOLD_LEAVES_ROOM");
    close(ion_fd);
    return 0;
}
