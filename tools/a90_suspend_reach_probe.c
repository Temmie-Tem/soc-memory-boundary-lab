/* Stage 1b: does this system actually suspend, and does it come back?
 *
 * Proof of suspend is direct rather than inferred: CLOCK_BOOTTIME includes
 * time spent suspended and CLOCK_MONOTONIC does not.  If BOOTTIME advances by
 * the alarm interval while MONOTONIC barely moves, the system was really in
 * suspend.  suspend_stats/success is read either side as a second witness.
 *
 * A wake alarm is armed BEFORE the suspend write, so a resume does not depend
 * on anyone pressing a button.  If the alarm cannot be armed, the suspend is
 * not attempted at all.
 *
 * Writes: one string to /sys/power/state, and one result file.  Nothing else.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

static long long read_ll(const char *path)
{
    char buf[64] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    return atoll(buf);
}

static double now(clockid_t clk)
{
    struct timespec ts;
    clock_gettime(clk, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    int seconds = argc > 1 ? atoi(argv[1]) : 20;
    int tfd, pfd;
    struct itimerspec its;
    struct timespec bt;
    double mono0, boot0, mono1, boot1;
    long long ok0, ok1, fail0, fail1;
    char report[1024];

    printf("{\"schema\":\"a90_suspend_reach_v1\",\"type\":\"context\","
           "\"alarm_seconds\":%d}\n", seconds);

    tfd = timerfd_create(CLOCK_BOOTTIME_ALARM, 0);
    if (tfd < 0) {
        printf("{\"schema\":\"a90_suspend_reach_v1\",\"type\":\"abort\","
               "\"reason\":\"CLOCK_BOOTTIME_ALARM unavailable: %s\"}\n",
               strerror(errno));
        return 3;
    }
    clock_gettime(CLOCK_BOOTTIME, &bt);
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = bt.tv_sec + seconds;
    its.it_value.tv_nsec = bt.tv_nsec;
    if (timerfd_settime(tfd, TFD_TIMER_ABSTIME, &its, NULL) != 0) {
        printf("{\"schema\":\"a90_suspend_reach_v1\",\"type\":\"abort\","
               "\"reason\":\"timerfd_settime: %s\"}\n", strerror(errno));
        return 3;
    }
    printf("{\"schema\":\"a90_suspend_reach_v1\",\"type\":\"alarm_armed\","
           "\"clock\":\"CLOCK_BOOTTIME_ALARM\"}\n");
    fflush(stdout);

    ok0 = read_ll("/sys/power/suspend_stats/success");
    fail0 = read_ll("/sys/power/suspend_stats/fail");
    mono0 = now(CLOCK_MONOTONIC);
    boot0 = now(CLOCK_BOOTTIME);

    pfd = open("/sys/power/state", O_WRONLY);
    if (pfd < 0) {
        printf("{\"schema\":\"a90_suspend_reach_v1\",\"type\":\"abort\","
               "\"reason\":\"open /sys/power/state: %s\"}\n", strerror(errno));
        return 3;
    }
    ssize_t written = write(pfd, "mem", 3);
    int werrno = errno;
    close(pfd);

    mono1 = now(CLOCK_MONOTONIC);
    boot1 = now(CLOCK_BOOTTIME);
    ok1 = read_ll("/sys/power/suspend_stats/success");
    fail1 = read_ll("/sys/power/suspend_stats/fail");
    close(tfd);

    snprintf(report, sizeof(report),
             "{\"schema\":\"a90_suspend_reach_v1\",\"type\":\"result\","
             "\"write_rc\":%zd,\"write_errno\":%d,\"write_error\":\"%s\","
             "\"monotonic_delta\":%.3f,\"boottime_delta\":%.3f,"
             "\"suspended_seconds\":%.3f,"
             "\"success_before\":%lld,\"success_after\":%lld,"
             "\"fail_before\":%lld,\"fail_after\":%lld,"
             "\"suspend_occurred\":%s}\n",
             written, written < 0 ? werrno : 0,
             written < 0 ? strerror(werrno) : "",
             mono1 - mono0, boot1 - boot0,
             (boot1 - boot0) - (mono1 - mono0),
             ok0, ok1, fail0, fail1,
             ((boot1 - boot0) - (mono1 - mono0) > 1.0 || ok1 > ok0)
                 ? "true" : "false");

    fputs(report, stdout);
    int rf = open("/tmp/a90-native/v019-suspend-reach.json",
                  O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (rf >= 0) { write(rf, report, strlen(report)); close(rf); }
    return 0;
}
