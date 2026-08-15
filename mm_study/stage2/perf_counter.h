#ifndef PERF_COUNTER_H
#define PERF_COUNTER_H

#include <errno.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * 为保持demand_paging.c中的接口不变，结构仍叫perf_group。
 * 但当前版本不使用真正的perf event group，
 * 而是打开两个相互独立的事件。
 */
struct perf_group {
    int leader_fd;       /* 实际上是cycles fd */
    int instruction_fd;
};

struct perf_counts {
    uint64_t cycles;
    uint64_t instructions;

    /*
     * 简化版本没有请求TOTAL_TIME字段，因此保持为0。
     */
    uint64_t time_enabled;
    uint64_t time_running;
};

static int perf_event_open_syscall(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags)
{
    return (int)syscall(
        SYS_perf_event_open,
        attr,
        pid,
        cpu,
        group_fd,
        flags);
}

static int perf_open_one(
    uint64_t config,
    const char *name)
{
    struct perf_event_attr attr;
    int fd;

    memset(&attr, 0, sizeof(attr));

    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 1;

    /*
     * 同时统计当前线程的用户态和内核态执行。
     *
     * 因此第一次触页时，Linux缺页处理代码也会被统计。
     */
    attr.exclude_user = 0;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 0;
    attr.exclude_host = 0;
    attr.exclude_guest = 0;

    /*
     * 使用最简单的read格式：
     * read(fd, &value, sizeof(value))只返回一个uint64_t。
     */
    attr.read_format = 0;

    fd = perf_event_open_syscall(
        &attr,
        0,      /* 当前线程 */
        -1,     /* 跟随当前线程，不固定CPU */
        -1,     /* 独立事件，不加入group */
        0);     /* 与已验证成功的perf_smoke一致 */

    if (fd < 0) {
        fprintf(stderr,
                "perf_event_open(%s) failed: errno=%d (%s)\n",
                name,
                errno,
                strerror(errno));
    }

    return fd;
}

static void perf_group_close(struct perf_group *group)
{
    if (group->instruction_fd >= 0)
        close(group->instruction_fd);

    if (group->leader_fd >= 0)
        close(group->leader_fd);

    group->instruction_fd = -1;
    group->leader_fd = -1;
}

static int perf_group_open(struct perf_group *group)
{
    group->leader_fd = -1;
    group->instruction_fd = -1;

    group->leader_fd = perf_open_one(
        PERF_COUNT_HW_CPU_CYCLES,
        "cycles");

    if (group->leader_fd < 0)
        return -1;

    group->instruction_fd = perf_open_one(
        PERF_COUNT_HW_INSTRUCTIONS,
        "instructions");

    if (group->instruction_fd < 0) {
        perf_group_close(group);
        return -1;
    }

    return 0;
}

static int perf_reset_fd(int fd, const char *name)
{
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) == -1) {
        fprintf(stderr,
                "PERF_EVENT_IOC_RESET(%s) failed: %s\n",
                name,
                strerror(errno));
        return -1;
    }

    return 0;
}

static int perf_enable_fd(int fd, const char *name)
{
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
        fprintf(stderr,
                "PERF_EVENT_IOC_ENABLE(%s) failed: %s\n",
                name,
                strerror(errno));
        return -1;
    }

    return 0;
}

static int perf_disable_fd(int fd, const char *name)
{
    if (ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) == -1) {
        fprintf(stderr,
                "PERF_EVENT_IOC_DISABLE(%s) failed: %s\n",
                name,
                strerror(errno));
        return -1;
    }

    return 0;
}

static int perf_read_fd(
    int fd,
    const char *name,
    uint64_t *value)
{
    ssize_t bytes_read;

    *value = 0;

    bytes_read = read(fd, value, sizeof(*value));

    if (bytes_read < 0) {
        fprintf(stderr,
                "read(%s) failed: %s\n",
                name,
                strerror(errno));
        return -1;
    }

    if (bytes_read != (ssize_t)sizeof(*value)) {
        fprintf(stderr,
                "read(%s) returned %zd bytes, expected %zu\n",
                name,
                bytes_read,
                sizeof(*value));
        return -1;
    }

    return 0;
}

static int perf_group_start(struct perf_group *group)
{
    if (perf_reset_fd(group->leader_fd, "cycles") != 0)
        return -1;

    if (perf_reset_fd(group->instruction_fd, "instructions") != 0)
        return -1;

    /*
     * 先启动instructions，后启动cycles。
     *
     * 这样cycles的测量窗口更接近真正的测试循环，
     * 不会包含“启动instructions事件”的ioctl开销。
     */
    if (perf_enable_fd(
            group->instruction_fd,
            "instructions") != 0) {
        return -1;
    }

    if (perf_enable_fd(
            group->leader_fd,
            "cycles") != 0) {
        (void)perf_disable_fd(
            group->instruction_fd,
            "instructions");
        return -1;
    }

    return 0;
}

static int perf_group_stop(
    struct perf_group *group,
    struct perf_counts *counts)
{
    memset(counts, 0, sizeof(*counts));

    /*
     * 先停止cycles，使cycle测量窗口尽可能贴近测试循环。
     */
    if (perf_disable_fd(
            group->leader_fd,
            "cycles") != 0) {
        return -1;
    }

    if (perf_disable_fd(
            group->instruction_fd,
            "instructions") != 0) {
        return -1;
    }

    if (perf_read_fd(
            group->leader_fd,
            "cycles",
            &counts->cycles) != 0) {
        return -1;
    }

    if (perf_read_fd(
            group->instruction_fd,
            "instructions",
            &counts->instructions) != 0) {
        return -1;
    }

    counts->time_enabled = 0;
    counts->time_running = 0;

    return 0;
}

#endif
