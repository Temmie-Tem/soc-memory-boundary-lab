/* Reopen condition 2 asks whether a non-secure contiguous allocation of at
 * least 512 MiB is available.  The claim in docs/REMAINING_ROUTES_2026-08-27.md
 * that camera_preview tops out at 256 MiB was never backed by a retained
 * survey, so this measures it instead of citing it.
 *
 * Safety: this program enumerates every heap but attempts an allocation only
 * on heaps named on the command line.  Allocating from a secure heap drives
 * hyp_assign and a VMID transition, a mandatory pause gate, so the host -- not
 * this program -- decides what is attempted, and that decision stays auditable
 * off-device.  Each successful allocation is released immediately; nothing is
 * mapped, written or read. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SCHEMA "a90_heap_capacity_v1"
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

/* Descending ladder.  512 MiB is the reopen-condition threshold; the rungs
 * above and below it turn a single pass/fail into a located boundary. */
static const unsigned LADDER_MIB[] = {512, 448, 384, 352, 320, 288, 272, 264, 256, 64, 32, 16};
#define LADDER_N (sizeof(LADDER_MIB) / sizeof(LADDER_MIB[0]))

int main(int argc, char **argv)
{
    const char *ion_path = argc > 1 ? argv[1] : "/dev/ion";
    struct ion_heap_query_uapi q;
    struct ion_heap_data_uapi *heaps;
    int fd = open(ion_path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        printf("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"open: %s\"}\n",
               SCHEMA, strerror(errno));
        return 1;
    }
    memset(&q, 0, sizeof(q));
    if (ioctl(fd, ION_IOC_HEAP_QUERY, &q) != 0 || q.cnt == 0 || q.cnt > ION_MAX_HEAPS) {
        printf("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"heap count\"}\n", SCHEMA);
        return 1;
    }
    heaps = calloc(q.cnt, sizeof(*heaps));
    q.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(fd, ION_IOC_HEAP_QUERY, &q) != 0) {
        printf("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"heap data\"}\n", SCHEMA);
        return 1;
    }
    printf("{\"schema\":\"%s\",\"type\":\"count\",\"heaps\":%u,\"attempt_argc\":%d}\n",
           SCHEMA, q.cnt, argc - 2);

    for (uint32_t i = 0; i < q.cnt; ++i) {
        int attempt = 0;
        heaps[i].name[ION_HEAP_NAME_BYTES - 1] = '\0';
        for (int a = 2; a < argc; ++a)
            if (strcmp(argv[a], heaps[i].name) == 0) attempt = 1;
        printf("{\"schema\":\"%s\",\"type\":\"heap\",\"name\":\"%s\",\"heap_type\":%u,"
               "\"heap_id\":%u,\"attempted\":%s}\n",
               SCHEMA, heaps[i].name, heaps[i].type, heaps[i].heap_id,
               attempt ? "true" : "false");
        if (!attempt) continue;

        for (size_t r = 0; r < LADDER_N; ++r) {
            struct ion_allocation_data_uapi alloc;
            int rc, err;
            memset(&alloc, 0, sizeof(alloc));
            alloc.len = (uint64_t)LADDER_MIB[r] << 20;
            alloc.heap_id_mask = UINT32_C(1) << heaps[i].heap_id;
            alloc.flags = 0;
            rc = ioctl(fd, ION_IOC_ALLOC, &alloc);
            err = errno;
            printf("{\"schema\":\"%s\",\"type\":\"attempt\",\"name\":\"%s\","
                   "\"mib\":%u,\"ok\":%s,\"errno\":%d,\"error\":\"%s\"}\n",
                   SCHEMA, heaps[i].name, LADDER_MIB[r], rc == 0 ? "true" : "false",
                   rc == 0 ? 0 : err, rc == 0 ? "" : strerror(err));
            if (rc == 0) close((int)alloc.fd);   /* release immediately */
        }
    }
    close(fd);
    printf("{\"schema\":\"%s\",\"type\":\"done\"}\n", SCHEMA);
    return 0;
}
