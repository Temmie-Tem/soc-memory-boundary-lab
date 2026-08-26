/* Verification 019: does the address-to-DRAM map survive a suspend/resume?
 *
 * This is the cross-state test docs/PRIOR_ART.md defines -- `Me a == Mf t` --
 * in the only form reachable without touching a controller.  Every state
 * change Verification 015 examined was disqualified for one of two reasons:
 * a reboot or power cycle destroys the allocation, so no marker survives it,
 * and the devfreq axis never moved the DDR OPP at all (retracted in b2b5068).
 * Suspend is the first state change that both takes the DRAM controller
 * through a real transition -- self-refresh and power collapse under
 * `mem_sleep = deep` -- and leaves the allocation in place.
 *
 * A single-state marker sweep is blind to a permutation by construction
 * (Verification 018).  Two states are what make one visible: tag every
 * location with its own offset, cross the state change, and read back.  If
 * the map permuted, a location returns some *other* location's tag, and that
 * tag names exactly where it came from.
 *
 * Why it must run detached with the cable out
 * -------------------------------------------
 * Suspend is refused with EBUSY while USB is connected -- measured, with
 * suspend_stats showing an abort before any device or step, i.e. a pending
 * wakeup.  USB is also the bridge, so this program takes no instructions
 * after launch: it waits for the operator to unplug, runs, and leaves its
 * result in a file to be collected after the cable returns.
 *
 * Resume does not depend on anyone pressing a button: a CLOCK_BOOTTIME_ALARM
 * is armed before every suspend attempt, and no attempt is made if it cannot
 * be armed.
 *
 * Writes: tags inside this process's own ION allocation, one string to
 * /sys/power/state, and the result file.  No register, MMIO, SMC, EL2/EL3,
 * protected memory or partition is touched.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define SCHEMA "a90_suspend_permute_v1"
#define TAG_SHIFT 6U                 /* one tag per 64-byte cacheline */
#define TAG_STRIDE (UINT64_C(1) << TAG_SHIFT)
#define MAX_REPORTED 4096U
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

static FILE *out;
static void emit(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vfprintf(out, fmt, ap); va_end(ap);
    fputc('\n', out); fflush(out);
}

static inline void barrier(void) { __asm__ __volatile__("dsb sy" ::: "memory"); }

static uint64_t mix(uint64_t v)
{
    v += UINT64_C(0x9e3779b97f4a7c15);
    v = (v ^ (v >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    v = (v ^ (v >> 27)) * UINT64_C(0x94d049bb133111eb);
    return v ^ (v >> 31);
}
static uint64_t tag_for(uint64_t offset, uint64_t seed) { return mix(offset ^ seed); }

static long long read_ll(const char *path)
{
    char buf[64] = {0}; int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1); close(fd);
    return n > 0 ? atoll(buf) : -1;
}
static double now(clockid_t c)
{ struct timespec t; clock_gettime(c, &t); return t.tv_sec + t.tv_nsec / 1e9; }

static int arm_alarm(int seconds)
{
    struct itimerspec its; struct timespec bt;
    int fd = timerfd_create(CLOCK_BOOTTIME_ALARM, 0);
    if (fd < 0) return -1;
    clock_gettime(CLOCK_BOOTTIME, &bt);
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = bt.tv_sec + seconds;
    its.it_value.tv_nsec = bt.tv_nsec;
    if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL) != 0) {
        close(fd); return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    const char *heap_name = argc > 1 ? argv[1] : "camera_preview";
    uint64_t mib          = argc > 2 ? strtoull(argv[2], NULL, 0) : 256;
    int wait_seconds      = argc > 3 ? atoi(argv[3]) : 45;
    int alarm_seconds     = argc > 4 ? atoi(argv[4]) : 25;
    int attempts          = argc > 5 ? atoi(argv[5]) : 6;
    const char *ion_path  = argc > 6 ? argv[6] : "/dev/ion";
    const char *out_path  = argc > 7 ? argv[7]
                                     : "/tmp/a90-native/v019-permutation.jsonl";
    uint64_t seed = UINT64_C(0x5da9f0e3c17b2846);
    uint64_t bytes = mib << 20, tags = bytes >> TAG_SHIFT;
    int ion_fd, suspended = 0;
    struct ion_heap_query_uapi query;
    struct ion_heap_data_uapi *heaps = NULL, *selected = NULL;
    struct ion_allocation_data_uapi alloc;
    volatile uint8_t *map;
    uint64_t baseline_bad = 0, moved = 0, reported = 0;
    long long ok0, ok1, fail0, fail1;
    double mono0, boot0, mono1, boot1, slept = 0;

    out = fopen(out_path, "w");
    if (out == NULL) return 1;

    emit("{\"schema\":\"%s\",\"type\":\"context\",\"heap\":\"%s\",\"mib\":%llu,"
         "\"tag_stride\":%llu,\"tags\":%llu,\"seed\":\"0x%llx\","
         "\"wait_seconds\":%d,\"alarm_seconds\":%d,\"attempts\":%d}",
         SCHEMA, heap_name, (unsigned long long)mib,
         (unsigned long long)TAG_STRIDE, (unsigned long long)tags,
         (unsigned long long)seed, wait_seconds, alarm_seconds, attempts);

    /* Give the operator time to unplug before anything is allocated. */
    sleep(wait_seconds);
    emit("{\"schema\":\"%s\",\"type\":\"wait_done\"}", SCHEMA);

    ion_fd = open(ion_path, O_RDONLY | O_CLOEXEC);
    if (ion_fd < 0) {
        emit("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"open %s: %s\"}",
             SCHEMA, ion_path, strerror(errno));
        return 1;
    }
    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0 || query.cnt == 0 ||
        query.cnt > ION_MAX_HEAPS) {
        emit("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"heap query\"}", SCHEMA);
        return 1;
    }
    heaps = calloc(query.cnt, sizeof(*heaps));
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0) {
        emit("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"heap data\"}", SCHEMA);
        return 1;
    }
    for (uint32_t i = 0; i < query.cnt; ++i) {
        heaps[i].name[ION_HEAP_NAME_BYTES - 1] = '\0';
        if (strcmp(heaps[i].name, heap_name) == 0) selected = &heaps[i];
    }
    if (selected == NULL || selected->type == 0U) {
        emit("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"heap %s "
             "missing or page-based\"}", SCHEMA, heap_name);
        return 1;
    }
    memset(&alloc, 0, sizeof(alloc));
    alloc.len = bytes;
    alloc.heap_id_mask = UINT32_C(1) << selected->heap_id;
    alloc.flags = 0;                    /* write-combine */
    if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) != 0) {
        emit("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"ion alloc: %s\"}",
             SCHEMA, strerror(errno));
        return 1;
    }
    map = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, (int)alloc.fd, 0);
    if (map == MAP_FAILED) {
        emit("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":\"mmap: %s\"}",
             SCHEMA, strerror(errno));
        return 1;
    }
    emit("{\"schema\":\"%s\",\"type\":\"ion_heap\",\"name\":\"%s\","
         "\"heap_type\":%u,\"heap_id\":%u}",
         SCHEMA, selected->name, selected->type, selected->heap_id);

    for (uint64_t off = 0; off < bytes; off += TAG_STRIDE)
        *(volatile uint64_t *)(map + off) = tag_for(off, seed);
    barrier();

    /* Baseline pass.  This is the instrument gate: if a tag does not read back
     * before the state change, nothing after it may be interpreted. */
    for (uint64_t off = 0; off < bytes; off += TAG_STRIDE)
        if (*(volatile uint64_t *)(map + off) != tag_for(off, seed))
            ++baseline_bad;
    emit("{\"schema\":\"%s\",\"type\":\"baseline\",\"mismatches\":%llu,"
         "\"instrument_ok\":%s}", SCHEMA, (unsigned long long)baseline_bad,
         baseline_bad == 0 ? "true" : "false");
    if (baseline_bad != 0) {
        emit("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":"
             "\"tags did not read back before suspend\"}", SCHEMA);
        return 1;
    }

    ok0 = read_ll("/sys/power/suspend_stats/success");
    fail0 = read_ll("/sys/power/suspend_stats/fail");

    for (int attempt = 0; attempt < attempts && !suspended; ++attempt) {
        int tfd = arm_alarm(alarm_seconds), pfd;
        ssize_t wrote; int werr;
        if (tfd < 0) {
            emit("{\"schema\":\"%s\",\"type\":\"attempt\",\"n\":%d,"
                 "\"skipped\":\"alarm could not be armed\"}", SCHEMA, attempt);
            sleep(5); continue;
        }
        mono0 = now(CLOCK_MONOTONIC); boot0 = now(CLOCK_BOOTTIME);
        pfd = open("/sys/power/state", O_WRONLY);
        if (pfd < 0) {
            emit("{\"schema\":\"%s\",\"type\":\"abort\",\"reason\":"
                 "\"open /sys/power/state: %s\"}", SCHEMA, strerror(errno));
            close(tfd); return 1;
        }
        wrote = write(pfd, "mem", 3); werr = errno;
        close(pfd);
        mono1 = now(CLOCK_MONOTONIC); boot1 = now(CLOCK_BOOTTIME);
        close(tfd);
        slept = (boot1 - boot0) - (mono1 - mono0);
        suspended = slept > 1.0;
        emit("{\"schema\":\"%s\",\"type\":\"attempt\",\"n\":%d,\"write_rc\":%zd,"
             "\"errno\":%d,\"error\":\"%s\",\"monotonic_delta\":%.3f,"
             "\"boottime_delta\":%.3f,\"suspended_seconds\":%.3f,"
             "\"suspended\":%s}",
             SCHEMA, attempt, wrote, wrote < 0 ? werr : 0,
             wrote < 0 ? strerror(werr) : "", mono1 - mono0, boot1 - boot0,
             slept, suspended ? "true" : "false");
        if (!suspended) sleep(8);
    }

    ok1 = read_ll("/sys/power/suspend_stats/success");
    fail1 = read_ll("/sys/power/suspend_stats/fail");
    emit("{\"schema\":\"%s\",\"type\":\"suspend_stats\",\"success_before\":%lld,"
         "\"success_after\":%lld,\"fail_before\":%lld,\"fail_after\":%lld}",
         SCHEMA, ok0, ok1, fail0, fail1);

    /* Read every tag back.  A location holding another location's tag names
     * where its contents came from. */
    barrier();
    for (uint64_t off = 0; off < bytes; off += TAG_STRIDE) {
        uint64_t observed = *(volatile uint64_t *)(map + off);
        if (observed == tag_for(off, seed)) continue;
        ++moved;
        if (reported < MAX_REPORTED) {
            emit("{\"schema\":\"%s\",\"type\":\"moved\",\"offset\":\"0x%llx\","
                 "\"expected\":\"0x%llx\",\"observed\":\"0x%llx\"}",
                 SCHEMA, (unsigned long long)off,
                 (unsigned long long)tag_for(off, seed),
                 (unsigned long long)observed);
            ++reported;
        }
    }

    emit("{\"schema\":\"%s\",\"type\":\"summary\",\"suspend_occurred\":%s,"
         "\"suspended_seconds\":%.3f,\"tags\":%llu,\"moved\":%llu,"
         "\"reported\":%llu,\"verdict\":\"%s\"}",
         SCHEMA, suspended ? "true" : "false", slept,
         (unsigned long long)tags, (unsigned long long)moved,
         (unsigned long long)reported,
         !suspended ? "SUSPEND_NOT_REACHED"
                    : (moved == 0 ? "MAP_INVARIANT" : "MAP_CHANGED"));

    munmap((void *)map, bytes);
    close((int)alloc.fd);
    close(ion_fd);
    fclose(out);
    return 0;
}
