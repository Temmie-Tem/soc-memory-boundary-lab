/* Verification 030: source-backed ION RBIN scatter/gather oracle.
 *
 * This binary deliberately has no caller-selectable operation.  It pins the
 * native process to CPU 7, verifies the fixed camera_preview heap, opens five
 * fixed self-scoped perf tracepoints around one ION_IOC_ALLOC of exactly
 * 0x14000000 bytes, then disables the tracepoints before parsing their rings.
 * It does not flash, write a partition, access MMIO/SMC, or read protected
 * memory.  A pointer-to-PA answer is never inferred from the expected camera
 * region: without a source-backed runtime relation the result stays UNKNOWN.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PERF_RECORD_THROTTLE
#define PERF_RECORD_THROTTLE 5
#endif
#ifndef PERF_RECORD_UNTHROTTLE
#define PERF_RECORD_UNTHROTTLE 6
#endif

#define ORACLE_SCHEMA "a90_rbin_phys_oracle_v030_v1"
#define FIXED_ION_PATH "/tmp/a90-native/v030-rbin-ion"
#define TRACEFS_ROOT "/sys/kernel/tracing"
#define DEBUGFS_TRACE_ROOT "/sys/kernel/debug/tracing"
#define EVENT_POOL "ion_rbin_pool_alloc_end"
#define EVENT_PARTIAL "ion_rbin_partial_alloc_end"
#define EVENT_START "ion_rbin_alloc_start"
#define EVENT_END "ion_rbin_alloc_end"
#define EVENT_CMA "cma_alloc"
#define PAGE_BYTES UINT64_C(4096)
#define EXPECTED_HEAP "camera_preview"
#define EXPECTED_HEAP_ID 30U
#define EXPECTED_HEAP_TYPE 10U
#define CALIBRATION_HEAP "user_contig"
#define CALIBRATION_HEAP_ID 26U
#define CALIBRATION_HEAP_TYPE 4U
#define CALIBRATION_ALLOCS 3U
#define CALIBRATION_BYTES0 PAGE_BYTES
#define CALIBRATION_BYTES1 (PAGE_BYTES * 2U)
#define CALIBRATION_BYTES2 (PAGE_BYTES * 3U)
#define EXPECTED_BYTES UINT64_C(0x14000000)
#define EXPECTED_CPU 7U
#define EXPECTED_REGION_FIRST UINT64_C(0xc2000000)
#define EXPECTED_REGION_END UINT64_C(0xd6000000)
#define MAX_FORMAT_BYTES (128U * 1024U)
#define MAX_FORMAT_LINE_BYTES 4096U
#define MAX_BTF_BYTES (64U * 1024U * 1024U)
#define MAX_RAW_BYTES 1024U
#define MAX_SEGMENTS ((size_t)(EXPECTED_BYTES / PAGE_BYTES))
#define TRACE_MEMORY_BUDGET (UINT64_C(512) * UINT64_C(1024) * UINT64_C(1024))
#define MAX_RING_PAGES_LIMIT 65536U
#define MAX_CAPTURE_OUTPUT_BYTES (7U * 1024U * 1024U)
#define OUTPUT_RECORD_OVERHEAD 1024U
#define VA_BITS 39U
#define PAGE_PTR_STRIDE_MIN UINT64_C(32)
#define PAGE_PTR_STRIDE_MAX UINT64_C(256)
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

enum field_role {
    FIELD_PAGE = 1,
    FIELD_SIZE = 2,
    FIELD_RESULT = 3,
    FIELD_PFN = 4,
    FIELD_COUNT = 5,
    FIELD_ALIGN = 6,
    FIELD_NAME = 7,
    FIELD_BUFFER = 8,
};

struct field_desc {
    enum field_role role;
    char name[64];
    uint64_t offset;
    uint64_t size;
    int is_signed;
};

struct trace_desc {
    char name[64];
    char id_path[PATH_MAX];
    char format_path[PATH_MAX];
    uint64_t id;
    size_t format_size;
    size_t trace_entry_size;
    unsigned char *format_bytes;
    size_t format_bytes_size;
    struct field_desc page;
    struct field_desc size;
    struct field_desc result;
    struct field_desc pfn;
    struct field_desc count;
    struct field_desc align;
    struct field_desc name_field;
    struct field_desc buffer;
    int has_page;
    int has_size;
    int has_pfn;
    int has_count;
    int has_align;
    int has_name;
    int has_buffer;
    int has_result;
};

struct trace_event {
    uint64_t page_ptr;
    uint64_t size_bytes;
    uint64_t pfn;
    uint64_t count;
    uint64_t align;
    uint64_t heap_name_value;
    uint64_t buffer_ptr;
    int64_t result;
    int has_page;
    int has_size;
    int has_pfn;
    int has_count;
    unsigned int raw_size;
    unsigned char raw[MAX_RAW_BYTES];
};

struct pa_segment {
    uint64_t pfn;
    uint64_t size;
};

struct perf_source {
    struct trace_desc desc;
    int fd;
    void *mapping;
    size_t mapping_size;
    size_t data_offset;
    size_t data_size;
    size_t ring_pages;
    size_t max_record_size;
    size_t allocation_bytes;
    uint64_t tail;
    struct trace_event *events;
    size_t event_capacity;
    size_t event_count;
};

static int parse_decimal_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (text == NULL || *text == '\0' || text[0] == '-' || text[0] == '+')
        return -1;
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno == ERANGE || end == text || end == NULL || *end != '\0')
        return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int reject_symlink_components(const char *path)
{
    char copy[PATH_MAX];
    char current[PATH_MAX];
    char *cursor;
    struct stat info;

    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(copy))
        return -1;
    strcpy(copy, path);
    strcpy(current, "/");
    cursor = copy + 1;
    while (*cursor != '\0') {
        char *slash = strchr(cursor, '/');
        size_t current_len = strlen(current);
        size_t part_len = slash == NULL ? strlen(cursor) : (size_t)(slash - cursor);

        if (part_len == 0) {
            cursor = slash == NULL ? cursor + strlen(cursor) : slash + 1;
            continue;
        }
        if (current_len > 1 && current[current_len - 1] != '/')
            current[current_len++] = '/';
        if (current_len + part_len + 1U >= sizeof(current))
            return -1;
        memcpy(current + current_len, cursor, part_len);
        current[current_len + part_len] = '\0';
        if (lstat(current, &info) == 0 && S_ISLNK(info.st_mode))
            return -1;
        if (slash == NULL)
            break;
        cursor = slash + 1;
    }
    return 0;
}

static int read_regular_file(const char *path, unsigned char **out, size_t *out_size,
                             size_t maximum)
{
    int fd;
    struct stat info;
    unsigned char *buffer = NULL;
    size_t capacity = 4096U;
    size_t used = 0;
    int result = -1;

    if (reject_symlink_components(path) != 0)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 ||
        (uintmax_t)info.st_size > maximum) {
        close(fd);
        return -1;
    }
    if ((uintmax_t)info.st_size > maximum)
        goto close_file;
    if ((size_t)info.st_size > capacity)
        capacity = (size_t)info.st_size;
    buffer = malloc(capacity + 1U);
    if (buffer == NULL) {
        goto close_file;
    }
    for (;;) {
        ssize_t count;
        if (used == capacity) {
            size_t next_capacity;
            unsigned char *grown;
            if (capacity >= maximum) {
                unsigned char extra;
                count = read(fd, &extra, sizeof(extra));
                if (count != 0)
                    goto close_file;
                break;
            }
            if (capacity > maximum / 2U)
                next_capacity = maximum;
            else
                next_capacity = capacity * 2U;
            if (next_capacity <= capacity)
                goto close_file;
            grown = realloc(buffer, next_capacity + 1U);
            if (grown == NULL)
                goto close_file;
            buffer = grown;
            capacity = next_capacity;
        }
        count = read(fd, buffer + used, capacity - used);
        if (count < 0)
            goto close_file;
        if (count == 0)
            break;
        used += (size_t)count;
        if (used > maximum)
            goto close_file;
    }
    buffer[used] = '\0';
    if (close(fd) != 0) {
        free(buffer);
        return -1;
    }
    *out = buffer;
    *out_size = used;
    return 0;

close_file:
    free(buffer);
    (void)close(fd);
    return result;
}

static int path_join(char *out, size_t out_size, const char *root,
                     const char *group, const char *event, const char *leaf)
{
    int count = snprintf(out, out_size, "%s/events/%s/%s/%s", root, group, event, leaf);
    return count > 0 && (size_t)count < out_size ? 0 : -1;
}

static int field_name_role(const char *name)
{
    const char *last = strrchr(name, '.');
    const char *arrow = strstr(name, "__entry->");
    const char *candidate = arrow == NULL ? (last == NULL ? name : last + 1)
                                          : arrow + strlen("__entry->");
    char short_name[64];
    const char *space = strrchr(candidate, ' ');
    size_t length;

    if (space != NULL)
        candidate = space + 1;
    while (*candidate == '*')
        ++candidate;
    length = strcspn(candidate, "[ \t");

    if (length == 0 || length >= sizeof(short_name))
        return 0;
    memcpy(short_name, candidate, length);
    short_name[length] = '\0';
    if (strcmp(short_name, "page") == 0 || strcmp(short_name, "page_ptr") == 0)
        return FIELD_PAGE;
    if (strcmp(short_name, "size") == 0 || strcmp(short_name, "len") == 0 ||
        strcmp(short_name, "length") == 0)
        return FIELD_SIZE;
    if (strcmp(short_name, "ret") == 0 || strcmp(short_name, "retval") == 0 ||
        strcmp(short_name, "result") == 0 || strcmp(short_name, "rc") == 0 ||
        strcmp(short_name, "status") == 0)
        return FIELD_RESULT;
    if (strcmp(short_name, "pfn") == 0)
        return FIELD_PFN;
    if (strcmp(short_name, "count") == 0 || strcmp(short_name, "nr_pages") == 0 ||
        strcmp(short_name, "npages") == 0)
        return FIELD_COUNT;
    if (strcmp(short_name, "align") == 0)
        return FIELD_ALIGN;
    if (strcmp(short_name, "name") == 0 || strcmp(short_name, "cma_name") == 0)
        return FIELD_NAME;
    if (strcmp(short_name, "heap_name") == 0)
        return FIELD_NAME;
    if (strcmp(short_name, "buffer") == 0)
        return FIELD_BUFFER;
    return 0;
}

static int parse_format_line(const char *line, struct field_desc *field)
{
    const char *field_start = strstr(line, "field:");
    const char *offset_start = strstr(line, "offset:");
    const char *size_start = strstr(line, "size:");
    const char *signed_start = strstr(line, "signed:");
    const char *name_start;
    const char *name_end;
    char offset_text[32];
    char size_text[32];
    char signed_text[32];
    uint64_t offset;
    uint64_t size;
    uint64_t signed_value;
    size_t length;
    int role;

    if (field_start == NULL || offset_start == NULL || size_start == NULL ||
        signed_start == NULL)
        return 0;
    name_start = field_start + strlen("field:");
    while (*name_start == ' ' || *name_start == '\t')
        ++name_start;
    name_end = strchr(name_start, ';');
    if (name_end == NULL)
        return -1;
    while (name_end > name_start &&
           (name_end[-1] == ' ' || name_end[-1] == '\t'))
        --name_end;
    length = (size_t)(name_end - name_start);
    if (length == 0 || length >= sizeof(field->name))
        return -1;
    memcpy(field->name, name_start, length);
    field->name[length] = '\0';
    role = field_name_role(field->name);
    if (sscanf(offset_start + strlen("offset:"), "%31[^;]", offset_text) != 1 ||
        sscanf(size_start + strlen("size:"), "%31[^;]", size_text) != 1 ||
        sscanf(signed_start + strlen("signed:"), "%31[^;]", signed_text) != 1 ||
        parse_decimal_u64(offset_text, &offset) != 0 ||
        parse_decimal_u64(size_text, &size) != 0 ||
        parse_decimal_u64(signed_text, &signed_value) != 0 || size == 0 ||
        size > MAX_RAW_BYTES || offset > MAX_RAW_BYTES - size ||
        signed_value > 1U || (role != 0 && size > 8U))
        return -1;
    field->role = (enum field_role)role;
    field->offset = offset;
    field->size = size;
    field->is_signed = signed_value != 0;
    return role;
}

static int declaration_token(const char **cursor, char *token, size_t token_size)
{
    const char *start;
    size_t length;

    if (cursor == NULL || *cursor == NULL || token == NULL || token_size < 2U)
        return -1;
    while (**cursor == ' ' || **cursor == '\t' || **cursor == '\r')
        ++*cursor;
    if (**cursor == '\0')
        return 0;
    if (**cursor == '*' || **cursor == '[' || **cursor == ']') {
        token[0] = **cursor;
        token[1] = '\0';
        ++*cursor;
        return 1;
    }
    if (!(**cursor == '_' || (**cursor >= 'A' && **cursor <= 'Z') ||
          (**cursor >= 'a' && **cursor <= 'z')))
        return -1;
    start = *cursor;
    while (**cursor == '_' || (**cursor >= 'A' && **cursor <= 'Z') ||
           (**cursor >= 'a' && **cursor <= 'z') ||
           (**cursor >= '0' && **cursor <= '9'))
        ++*cursor;
    length = (size_t)(*cursor - start);
    if (length == 0U || length >= token_size)
        return -1;
    memcpy(token, start, length);
    token[length] = '\0';
    return 1;
}

static int declaration_matches(const char *actual, const char *expected)
{
    char actual_token[64];
    char expected_token[64];
    const char *actual_cursor = actual;
    const char *expected_cursor = expected;

    for (;;) {
        int actual_result = declaration_token(&actual_cursor, actual_token,
                                              sizeof(actual_token));
        int expected_result = declaration_token(&expected_cursor, expected_token,
                                                sizeof(expected_token));
        if (actual_result < 0 || expected_result < 0)
            return 0;
        if (actual_result == 0 || expected_result == 0)
            return actual_result == expected_result;
        if (strcmp(actual_token, expected_token) != 0)
            return 0;
    }
}

static const char *expected_field_declaration(const char *event,
                                              enum field_role role)
{
    if (strcmp(event, EVENT_CMA) == 0) {
        switch (role) {
        case FIELD_PAGE:
            return "const struct page * page";
        case FIELD_PFN:
            return "unsigned long pfn";
        case FIELD_COUNT:
            return "unsigned int count";
        case FIELD_ALIGN:
            return "unsigned int align";
        default:
            return NULL;
        }
    }
    if (role == FIELD_NAME)
        return "const char * heap_name";
    if (role == FIELD_BUFFER)
        return "void * buffer";
    if (role == FIELD_SIZE)
        return "unsigned long size";
    if (role == FIELD_PAGE)
        return "void * page";
    return NULL;
}

static uint64_t expected_field_size(const char *event, enum field_role role)
{
    if (strcmp(event, EVENT_CMA) == 0) {
        switch (role) {
        case FIELD_PAGE:
        case FIELD_PFN:
            return 8U;
        case FIELD_COUNT:
        case FIELD_ALIGN:
            return 4U;
        default:
            return 0U;
        }
    }
    switch (role) {
    case FIELD_NAME:
    case FIELD_BUFFER:
    case FIELD_SIZE:
    case FIELD_PAGE:
        return 8U;
    default:
        return 0U;
    }
}

#ifdef A90_RBIN_ORACLE_TEST
/* Host-only seam used by the bounded parser regression.  Production parsing
 * uses the identical temporary-NUL line boundary in load_trace_desc(). */
int a90_test_parse_format_lines(const unsigned char *format, size_t format_size,
                                size_t *recognized_out, size_t *entry_size_out)
{
    const unsigned char *cursor;
    const unsigned char *end_of_format;
    size_t recognized = 0;
    size_t entry_size = 0;
    unsigned int seen_roles = 0;

    if (format == NULL || recognized_out == NULL || entry_size_out == NULL ||
        format_size > MAX_FORMAT_BYTES)
        return -1;
    cursor = format;
    end_of_format = format + format_size;
    while (cursor < end_of_format) {
        const unsigned char *line_end = memchr(cursor, '\n',
                                               (size_t)(end_of_format - cursor));
        size_t line_size = line_end == NULL
                               ? (size_t)(end_of_format - cursor)
                               : (size_t)(line_end - cursor);
        char line_copy[MAX_FORMAT_LINE_BYTES];
        struct field_desc field = {0};
        int role;

        if (line_size >= sizeof(line_copy))
            return -1;
        memcpy(line_copy, cursor, line_size);
        line_copy[line_size] = '\0';
        role = parse_format_line(line_copy, &field);
        if (role < 0)
            return -1;
        if (field.size != 0U) {
            if (field.offset > SIZE_MAX - field.size)
                return -1;
            if ((size_t)(field.offset + field.size) > entry_size)
                entry_size = (size_t)(field.offset + field.size);
        }
        if (role != 0) {
            if ((seen_roles & (1U << (unsigned int)role)) != 0U)
                return -1;
            seen_roles |= 1U << (unsigned int)role;
            ++recognized;
        }
        if (line_end == NULL)
            break;
        cursor = line_end + 1;
    }
    *recognized_out = recognized;
    *entry_size_out = entry_size;
    return 0;
}
#endif

static void free_trace_desc(struct trace_desc *desc)
{
    free(desc->format_bytes);
    desc->format_bytes = NULL;
    desc->format_bytes_size = 0;
}

static int load_trace_desc(struct trace_desc *desc, const char *event)
{
    const char *roots[] = {TRACEFS_ROOT, DEBUGFS_TRACE_ROOT};
    unsigned char *format = NULL;
    size_t format_size = 0;
    unsigned char *id_data = NULL;
    size_t id_size = 0;
    unsigned int root_index;
    char *cursor;
    int found_page = 0;
    int found_size = 0;
    int found_result = 0;
    int found_pfn = 0;
    int found_count = 0;
    int found_align = 0;
    int found_name = 0;
    int found_buffer = 0;
    const char *group = strcmp(event, EVENT_CMA) == 0 ? "cma" : "ion";

    memset(desc, 0, sizeof(*desc));
    if (snprintf(desc->name, sizeof(desc->name), "%s", event) >=
        (int)sizeof(desc->name))
        return -1;
    for (root_index = 0; root_index < sizeof(roots) / sizeof(roots[0]); ++root_index) {
        if (path_join(desc->format_path, sizeof(desc->format_path), roots[root_index],
                      group, event, "format") != 0 ||
            path_join(desc->id_path, sizeof(desc->id_path), roots[root_index], group,
                      event, "id") != 0)
            return -1;
        if (read_regular_file(desc->format_path, &format, &format_size,
                              MAX_FORMAT_BYTES) == 0 &&
            read_regular_file(desc->id_path, &id_data, &id_size, 64U) == 0)
            break;
        free(format);
        free(id_data);
        format = NULL;
        id_data = NULL;
    }
    if (format == NULL || id_data == NULL || format_size == 0 || id_size == 0)
        return -1;
    while (id_size > 0 && (id_data[id_size - 1] == '\n' || id_data[id_size - 1] == '\r' ||
                           id_data[id_size - 1] == ' ' || id_data[id_size - 1] == '\t'))
        --id_size;
    id_data[id_size] = '\0';
    if (parse_decimal_u64((const char *)id_data, &desc->id) != 0 || desc->id == 0) {
        free(format);
        free(id_data);
        return -1;
    }
    desc->format_size = format_size;
    cursor = (char *)format;
    while (cursor < (char *)format + format_size) {
        char *end = memchr(cursor, '\n', (size_t)((char *)format + format_size - cursor));
        size_t line_length = end == NULL
                                 ? (size_t)((char *)format + format_size - cursor)
                                 : (size_t)(end - cursor);
        char line_copy[MAX_FORMAT_LINE_BYTES];
        struct field_desc field = {0};
        int role;

        if (line_length >= sizeof(line_copy)) {
            free(format);
            free(id_data);
            return -1;
        }
        memcpy(line_copy, cursor, line_length);
        line_copy[line_length] = '\0';
        role = parse_format_line(line_copy, &field);
        if (role < 0) {
            free(format);
            free(id_data);
            return -1;
        }
        if (role != 0 &&
            (expected_field_size(event, field.role) != field.size ||
             field.is_signed ||
             !declaration_matches(field.name,
                                  expected_field_declaration(event, field.role)))) {
            free(format);
            free(id_data);
            return -1;
        }
        if (field.size != 0U) {
            if (field.offset > SIZE_MAX - field.size) {
                free(format);
                free(id_data);
                return -1;
            }
            if ((size_t)(field.offset + field.size) > desc->trace_entry_size)
                desc->trace_entry_size = (size_t)(field.offset + field.size);
        }
        if (role == FIELD_PAGE) {
            if (found_page++) {
                free(format);
                free(id_data);
                return -1;
            }
            desc->page = field;
        } else if (role == FIELD_SIZE) {
            if (found_size++) {
                free(format);
                free(id_data);
                return -1;
            }
            desc->size = field;
        } else if (role == FIELD_RESULT) {
            if (found_result++) {
                free(format);
                free(id_data);
                return -1;
            }
            desc->result = field;
            desc->has_result = 1;
        } else if (role == FIELD_PFN) {
            if (found_pfn++) {
                free(format);
                free(id_data);
                return -1;
            }
            desc->pfn = field;
            desc->has_pfn = 1;
        } else if (role == FIELD_COUNT) {
            if (found_count++) {
                free(format);
                free(id_data);
                return -1;
            }
            desc->count = field;
            desc->has_count = 1;
        } else if (role == FIELD_ALIGN) {
            if (found_align++) {
                free(format);
                free(id_data);
                return -1;
            }
            desc->align = field;
            desc->has_align = 1;
        } else if (role == FIELD_NAME) {
            if (found_name++) {
                free(format);
                free(id_data);
                return -1;
            }
            desc->name_field = field;
            desc->has_name = 1;
        } else if (role == FIELD_BUFFER) {
            if (found_buffer++) {
                free(format);
                free(id_data);
                return -1;
            }
            desc->buffer = field;
            desc->has_buffer = 1;
        }
        if (end == NULL)
            break;
        cursor = end + 1;
    }
    desc->format_bytes = malloc(format_size);
    if (desc->format_bytes == NULL) {
        free(format);
        free(id_data);
        return -1;
    }
    memcpy(desc->format_bytes, format, format_size);
    desc->format_bytes_size = format_size;
    free(format);
    free(id_data);
    if (strcmp(event, EVENT_CMA) == 0)
        return found_page && found_pfn && found_count ? 0 : -1;
    if (strcmp(event, EVENT_START) == 0 || strcmp(event, EVENT_END) == 0 ||
        strcmp(event, EVENT_POOL) == 0 || strcmp(event, EVENT_PARTIAL) == 0)
        return found_page && found_size && found_name && found_buffer ? 0 : -1;
    return -1;
}

static int same_field_shape(const struct field_desc *left,
                            const struct field_desc *right)
{
    return left->role == right->role && strcmp(left->name, right->name) == 0 &&
           left->offset == right->offset && left->size == right->size &&
           left->is_signed == right->is_signed;
}

static int same_ion_class_layout(const struct trace_desc *left,
                                 const struct trace_desc *right)
{
    return left->trace_entry_size == right->trace_entry_size &&
           same_field_shape(&left->page, &right->page) &&
           same_field_shape(&left->size, &right->size) &&
           same_field_shape(&left->name_field, &right->name_field) &&
           same_field_shape(&left->buffer, &right->buffer);
}

static uint64_t read_le(const unsigned char *data, size_t size)
{
    uint64_t value = 0;
    size_t index;

    for (index = 0; index < size; ++index)
        value |= ((uint64_t)data[index]) << (index * 8U);
    return value;
}

static int64_t read_signed_le(const unsigned char *data, size_t size)
{
    uint64_t value = read_le(data, size);
    if (size < 8U && (value & (UINT64_C(1) << (size * 8U - 1U))) != 0)
        value |= UINT64_MAX << (size * 8U);
    return (int64_t)value;
}

static int parse_event_raw(const struct trace_desc *desc, const unsigned char *raw,
                           size_t raw_size, struct trace_event *event)
{
    if (raw_size > MAX_RAW_BYTES)
        return -1;
    memset(event, 0, sizeof(*event));
    if (desc->has_page) {
        if (desc->page.offset > raw_size || desc->page.size > raw_size - desc->page.offset ||
            desc->page.size > 8U)
            return -1;
        event->page_ptr = read_le(raw + desc->page.offset, (size_t)desc->page.size);
        event->has_page = 1;
    }
    if (desc->has_size) {
        if (desc->size.offset > raw_size || desc->size.size > raw_size - desc->size.offset ||
            desc->size.size > 8U)
            return -1;
        event->size_bytes = read_le(raw + desc->size.offset, (size_t)desc->size.size);
        event->has_size = 1;
    }
    if (desc->has_pfn) {
        if (desc->pfn.offset > raw_size || desc->pfn.size > raw_size - desc->pfn.offset ||
            desc->pfn.size > 8U)
            return -1;
        event->pfn = read_le(raw + desc->pfn.offset, (size_t)desc->pfn.size);
        event->has_pfn = 1;
    }
    if (desc->has_count) {
        if (desc->count.offset > raw_size || desc->count.size > raw_size - desc->count.offset ||
            desc->count.size > 8U)
            return -1;
        event->count = read_le(raw + desc->count.offset, (size_t)desc->count.size);
        event->has_count = 1;
    }
    if (desc->has_align) {
        if (desc->align.offset > raw_size || desc->align.size > raw_size - desc->align.offset ||
            desc->align.size > 8U)
            return -1;
        event->align = read_le(raw + desc->align.offset, (size_t)desc->align.size);
    }
    if (desc->has_name) {
        if (desc->name_field.offset > raw_size ||
            desc->name_field.size > raw_size - desc->name_field.offset ||
            desc->name_field.size > 8U)
            return -1;
        event->heap_name_value = read_le(raw + desc->name_field.offset,
                                         (size_t)desc->name_field.size);
    }
    if (desc->has_buffer) {
        if (desc->buffer.offset > raw_size ||
            desc->buffer.size > raw_size - desc->buffer.offset ||
            desc->buffer.size > 8U)
            return -1;
        event->buffer_ptr = read_le(raw + desc->buffer.offset,
                                    (size_t)desc->buffer.size);
    }
    if (strcmp(desc->name, EVENT_CMA) == 0) {
        if (!event->has_page || !event->has_pfn || !event->has_count || event->count == 0)
            return -1;
        if (event->count > UINT64_MAX / PAGE_BYTES)
            return -1;
        event->size_bytes = event->count * PAGE_BYTES;
        event->has_size = 1;
    } else if (strcmp(desc->name, EVENT_START) == 0) {
        if (!event->has_size && event->has_count) {
            if (event->count > UINT64_MAX / PAGE_BYTES)
                return -1;
            event->size_bytes = event->count * PAGE_BYTES;
            event->has_size = 1;
        }
    } else if (strcmp(desc->name, EVENT_POOL) == 0) {
        /* A pool miss is an expected failed attempt: the tracepoint carries
         * page=NULL,size=0 before the matching partial allocator succeeds. */
        if (!event->has_page || !event->has_size ||
            ((event->page_ptr == 0) != (event->size_bytes == 0)))
            return -1;
    }
    if (!event->has_size)
        event->size_bytes = 0;
    event->result = 0;
    if (desc->has_result) {
        if (desc->result.offset > raw_size ||
            desc->result.size > raw_size - desc->result.offset || desc->result.size > 8U)
            return -1;
        event->result = desc->result.is_signed
                            ? read_signed_le(raw + desc->result.offset,
                                             (size_t)desc->result.size)
                            : (int64_t)read_le(raw + desc->result.offset,
                                               (size_t)desc->result.size);
        if (event->result != 0)
            return -1;
    }
    event->raw_size = (unsigned int)raw_size;
    memcpy(event->raw, raw, raw_size);
    return 0;
}

static int ring_copy(const struct perf_source *source, uint64_t offset, void *out,
                     size_t size)
{
    const unsigned char *data = (const unsigned char *)source->mapping + source->data_offset;
    size_t position = (size_t)(offset & (uint64_t)(source->data_size - 1U));
    size_t first;

    if (size > source->data_size)
        return -1;
    first = source->data_size - position;
    if (first > size)
        first = size;
    memcpy(out, data + position, first);
    if (first < size)
        memcpy((unsigned char *)out + first, data, size - first);
    return 0;
}

static int parse_perf_ring(struct perf_source *source)
{
    struct perf_event_mmap_page *metadata = (struct perf_event_mmap_page *)source->mapping;
    uint64_t head;
    uint64_t tail;

    head = __atomic_load_n(&metadata->data_head, __ATOMIC_ACQUIRE);
    /* PERF's producer publishes data_head with release semantics.  Acquire
     * it first, then order every data read after that snapshot. */
    __sync_synchronize();
    tail = __atomic_load_n(&metadata->data_tail, __ATOMIC_RELAXED);
    if (head < tail || head - tail > source->data_size)
        return -1;
    while (tail < head) {
        struct perf_event_header header;
        unsigned char *record;
        size_t record_size;

        if (head - tail < sizeof(header) || ring_copy(source, tail, &header, sizeof(header)) != 0)
            return -1;
        record_size = header.size;
        if (record_size < sizeof(header) || record_size > head - tail ||
            record_size > source->data_size || (record_size & 7U) != 0)
            return -1;
        record = malloc(record_size);
        if (record == NULL || ring_copy(source, tail, record, record_size) != 0) {
            free(record);
            return -1;
        }
        if (header.type != PERF_RECORD_SAMPLE) {
            /* LOST, THROTTLE, UNTHROTTLE, and every non-sample record are a
             * hard incident: the allocation's complete SG set is unknown. */
            free(record);
            return -1;
        }
        if (record_size < sizeof(header) + sizeof(uint32_t)) {
            free(record);
            return -1;
        }
        {
            uint32_t raw_size = (uint32_t)read_le(record + sizeof(header), sizeof(raw_size));
            struct trace_event parsed;

            /* PERF_SAMPLE_RAW stores the trace-entry bytes plus its internal
             * alignment pad in the u32 raw_size.  The record has no further
             * padding authority: the ABI size is exactly header(8) + u32(4)
             * + raw_size. */
            if (raw_size == 0 || raw_size > MAX_RAW_BYTES ||
                record_size != sizeof(header) + sizeof(raw_size) + raw_size) {
                free(record);
                return -1;
            }
            if (source->event_count >= source->event_capacity ||
                parse_event_raw(&source->desc,
                                record + sizeof(header) + sizeof(raw_size), raw_size,
                                &parsed) != 0) {
                free(record);
                return -1;
            }
            source->events[source->event_count++] = parsed;
        }
        free(record);
        tail += record_size;
    }
    /* All records are consumed before the release that publishes data_tail. */
    __sync_synchronize();
    __atomic_store_n(&metadata->data_tail, tail, __ATOMIC_RELEASE);
    source->tail = tail;
    return 0;
}

static int align_up_size(size_t value, size_t alignment, size_t *out)
{
    size_t remainder;

    if (alignment == 0U)
        return -1;
    remainder = value % alignment;
    if (remainder != 0U && value > SIZE_MAX - (alignment - remainder))
        return -1;
    *out = value + (alignment - remainder) % alignment;
    return 0;
}

static int reserve_trace_budget(size_t bytes, size_t *used)
{
    if (bytes > TRACE_MEMORY_BUDGET || *used > TRACE_MEMORY_BUDGET - bytes)
        return -1;
    *used += bytes;
    return 0;
}

static int add_output_cost(size_t *total, size_t bytes)
{
    if (total == NULL || bytes > SIZE_MAX - *total)
        return -1;
    *total += bytes;
    return 0;
}

static int add_event_output_cost(size_t *total, const struct trace_event *event)
{
    size_t raw_hex_bytes;

    if (event == NULL || event->raw_size > MAX_RAW_BYTES)
        return -1;
    raw_hex_bytes = (size_t)event->raw_size * 2U;
    return add_output_cost(total, OUTPUT_RECORD_OVERHEAD + raw_hex_bytes);
}

static int estimate_output_bytes(const struct perf_source *sources, size_t count,
                                 const struct trace_event *calibration_events,
                                 size_t calibration_count, size_t *estimate_out)
{
    size_t total = OUTPUT_RECORD_OVERHEAD;
    size_t index;

    if (sources == NULL || count != 5U || calibration_events == NULL ||
        calibration_count != CALIBRATION_ALLOCS || estimate_out == NULL)
        return -1;
    for (index = 0; index < count; ++index) {
        if (sources[index].desc.format_bytes_size >
                (SIZE_MAX - OUTPUT_RECORD_OVERHEAD) / 2U ||
            add_output_cost(&total,
                            OUTPUT_RECORD_OVERHEAD +
                                sources[index].desc.format_bytes_size * 2U) != 0)
            return -1;
        for (size_t event_index = 0;
             event_index < (index == 0U ? calibration_count : sources[index].event_count);
             ++event_index) {
            const struct trace_event *event =
                index == 0U ? &calibration_events[event_index]
                            : &sources[index].events[event_index];
            if (add_event_output_cost(&total, event) != 0)
                return -1;
        }
    }
    if (add_output_cost(&total, 2U * OUTPUT_RECORD_OVERHEAD) != 0)
        return -1;
    *estimate_out = total;
    return 0;
}

static int retain_calibration_events(const struct perf_source *source,
                                     struct trace_event *retained,
                                     size_t retained_capacity,
                                     size_t *retained_count)
{
    if (source == NULL || retained == NULL || retained_count == NULL ||
        retained_capacity < CALIBRATION_ALLOCS ||
        source->events == NULL || source->event_count != CALIBRATION_ALLOCS)
        return -1;
    memcpy(retained, source->events,
           CALIBRATION_ALLOCS * sizeof(*retained));
    *retained_count = CALIBRATION_ALLOCS;
    return 0;
}

static int setup_perf_source(struct perf_source *source, const char *event,
                             size_t page_size, size_t event_capacity,
                             size_t *budget_used)
{
    struct perf_event_attr attr;
    struct perf_event_mmap_page *metadata;
    size_t raw_limit = 0;
    size_t raw_padded;
    size_t max_record_size;
    size_t required_records_bytes;
    size_t required_data_bytes;
    size_t ring_pages = 1U;
    size_t mapping_size;
    size_t event_bytes;

    memset(source, 0, sizeof(*source));
    source->fd = -1;
    if (event_capacity == 0U || event_capacity > MAX_SEGMENTS || budget_used == NULL)
        return -1;
    if (load_trace_desc(&source->desc, event) != 0)
        goto fail;
    /* trace_entry_size was derived from every declared field line, including
     * common fields and fields this oracle does not decode.  Keep that source
     * maximum as the perf-ring sizing authority; narrowing it to only the
     * fields we consume could leave an unbounded suffix unaccounted for. */
    raw_limit = source->desc.trace_entry_size;
    if (raw_limit == 0U || raw_limit > MAX_RAW_BYTES - sizeof(uint32_t) ||
        align_up_size(raw_limit + sizeof(uint32_t), 8U, &raw_padded) != 0 ||
        raw_padded < sizeof(uint32_t))
        goto fail;
    max_record_size = sizeof(struct perf_event_header) + raw_padded;
    if (max_record_size < sizeof(struct perf_event_header) + sizeof(uint32_t) ||
        max_record_size > sizeof(struct perf_event_header) + sizeof(uint32_t) + MAX_RAW_BYTES)
        goto fail;
    if (event_capacity > SIZE_MAX / max_record_size)
        goto fail;
    required_records_bytes = event_capacity * max_record_size;
    required_data_bytes = required_records_bytes;
    if (required_records_bytes > SIZE_MAX - (page_size - 1U))
        goto fail;
    required_records_bytes = (required_records_bytes + page_size - 1U) / page_size;
    while (ring_pages < required_records_bytes) {
        if (ring_pages > MAX_RING_PAGES_LIMIT / 2U)
            goto fail;
        ring_pages *= 2U;
    }
    if (ring_pages > MAX_RING_PAGES_LIMIT || ring_pages > (SIZE_MAX / page_size) - 1U)
        goto fail;
    mapping_size = page_size * (ring_pages + 1U);
    if (event_capacity > SIZE_MAX / sizeof(*source->events))
        goto fail;
    event_bytes = event_capacity * sizeof(*source->events);
    if (mapping_size > SIZE_MAX - event_bytes)
        goto fail;
    source->allocation_bytes = mapping_size + event_bytes;
    if (reserve_trace_budget(source->allocation_bytes, budget_used) != 0)
        goto fail;
    source->event_capacity = event_capacity;
    source->max_record_size = max_record_size;
    source->ring_pages = ring_pages;
    source->events = calloc(source->event_capacity, sizeof(*source->events));
    if (source->events == NULL)
        goto fail_budget;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = source->desc.id;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.disabled = 1;
    attr.exclude_hv = 1;
    attr.wakeup_events = 1;
    source->fd = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (source->fd < 0)
        goto fail_budget;
    source->mapping_size = mapping_size;
    source->mapping = mmap(NULL, source->mapping_size, PROT_READ | PROT_WRITE,
                           MAP_SHARED, source->fd, 0);
    if (source->mapping == MAP_FAILED) {
        source->mapping = NULL;
        close(source->fd);
        source->fd = -1;
        goto fail_budget;
    }
    metadata = (struct perf_event_mmap_page *)source->mapping;
    if (metadata->data_offset < page_size || metadata->data_size == 0 ||
        (metadata->data_size & (metadata->data_size - 1U)) != 0 ||
        metadata->data_offset > source->mapping_size ||
        metadata->data_size > source->mapping_size - metadata->data_offset ||
        (size_t)metadata->data_size < required_data_bytes) {
        munmap(source->mapping, source->mapping_size);
        source->mapping = NULL;
        close(source->fd);
        source->fd = -1;
        goto fail_budget;
    }
    source->data_offset = metadata->data_offset;
    source->data_size = metadata->data_size;
    return 0;

fail_budget:
    if (source->allocation_bytes <= *budget_used)
        *budget_used -= source->allocation_bytes;
    source->allocation_bytes = 0;
fail:
    free(source->events);
    source->events = NULL;
    source->event_capacity = 0;
    free_trace_desc(&source->desc);
    return -1;
}

static int close_perf_source(struct perf_source *source)
{
    int result = 0;
    if (source->mapping != NULL) {
        if (munmap(source->mapping, source->mapping_size) != 0)
            result = -1;
        source->mapping = NULL;
    }
    if (source->fd >= 0) {
        if (close(source->fd) != 0)
            result = -1;
        source->fd = -1;
    }
    free(source->events);
    source->events = NULL;
    source->event_capacity = 0;
    free_trace_desc(&source->desc);
    return result;
}

/* A small BTF walker supplies a source-backed struct page size as an optional
 * cross-check.  Same-run CMA calibration remains the PA authority. */
static int btf_struct_page_size(uint64_t *size_out)
{
    struct btf_header {
        uint16_t magic;
        uint8_t version;
        uint8_t flags;
        uint32_t hdr_len;
        uint32_t type_off;
        uint32_t type_len;
        uint32_t str_off;
        uint32_t str_len;
    } __attribute__((packed));
    unsigned char *data = NULL;
    size_t data_size = 0;
    const struct btf_header *header;
    size_t cursor;
    size_t type_end;

    {
        struct stat info;
        if (lstat("/sys/kernel/btf/vmlinux", &info) != 0) {
            if (errno == ENOENT)
                return 1; /* BTF is absent; same-run CMA remains sufficient. */
            return -1;
        }
        if (!S_ISREG(info.st_mode))
            return -1;
    }

    if (read_regular_file("/sys/kernel/btf/vmlinux", &data, &data_size,
                          MAX_BTF_BYTES) != 0 || data_size < sizeof(*header))
        return -1;
    header = (const struct btf_header *)data;
    if (header->magic != UINT16_C(0xeb9f) || header->version != 1U ||
        header->hdr_len < sizeof(*header) || header->hdr_len > data_size ||
        header->type_off > data_size - header->hdr_len ||
        header->type_len > data_size - header->hdr_len - header->type_off ||
        header->str_off > data_size - header->hdr_len ||
        header->str_len > data_size - header->hdr_len - header->str_off) {
        free(data);
        return -1;
    }
    cursor = (size_t)header->hdr_len + header->type_off;
    type_end = cursor + header->type_len;
    while (cursor + 12U <= type_end) {
        uint32_t name_off;
        uint32_t info;
        uint32_t type_size;
        uint32_t kind;
        uint32_t vlen;
        size_t extra;
        const char *name;

        memcpy(&name_off, data + cursor, sizeof(name_off));
        memcpy(&info, data + cursor + 4U, sizeof(info));
        memcpy(&type_size, data + cursor + 8U, sizeof(type_size));
        kind = info >> 24U;
        vlen = info & UINT32_C(0xffff);
        if (name_off >= header->str_len)
            break;
        name = (const char *)(data + (size_t)header->hdr_len + header->str_off + name_off);
        switch (kind) {
        case 4: /* STRUCT */
        case 5: /* UNION */
            extra = (size_t)vlen * 12U;
            break;
        case 3: /* ARRAY */
            extra = 12U;
            break;
        case 6: /* ENUM */
            extra = (size_t)vlen * 8U;
            break;
        case 19: /* ENUM64 */
            extra = (size_t)vlen * 12U;
            break;
        case 13: /* FUNC_PROTO */
            extra = (size_t)vlen * 8U;
            break;
        case 14: /* VAR */
            extra = 4U;
            break;
        case 15: /* DATASEC */
            extra = (size_t)vlen * 12U;
            break;
        default:
            extra = 0U;
            break;
        }
        if (data == NULL || extra > type_end - cursor - 12U)
            break;
        if (kind == 4U && strcmp(name, "page") == 0 && type_size != 0U) {
            *size_out = type_size;
            free(data);
            return 0;
        }
        cursor += 12U + extra;
    }
    free(data);
    return -1;
}

static int pin_cpu(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(EXPECTED_CPU, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

static int append_event(struct trace_event *events, size_t *count,
                        const struct trace_event *event)
{
    size_t index;
    if (*count >= MAX_SEGMENTS || !event->has_page || !event->has_size ||
        event->page_ptr == 0 || event->size_bytes == 0 ||
        event->size_bytes % PAGE_BYTES != 0 ||
        event->size_bytes > EXPECTED_BYTES)
        return -1;
    for (index = 0; index < *count; ++index) {
        if (events[index].page_ptr == event->page_ptr)
            return -1;
    }
    events[*count] = *event;
    ++*count;
    return 0;
}

static void print_hex(const unsigned char *data, size_t size)
{
    size_t index;
    for (index = 0; index < size; ++index)
        printf("%02x", data[index]);
}

static int enable_perf_source(struct perf_source *source)
{
    struct perf_event_mmap_page *metadata;
    metadata = (struct perf_event_mmap_page *)source->mapping;
    if (ioctl(source->fd, PERF_EVENT_IOC_RESET, 0) != 0 ||
        ioctl(source->fd, PERF_EVENT_IOC_ENABLE, 0) != 0)
        return -1;
    source->event_count = 0;
    source->tail = metadata->data_tail;
    return 0;
}

static int disable_perf_source(struct perf_source *source)
{
    return ioctl(source->fd, PERF_EVENT_IOC_DISABLE, 0);
}

static int ion_alloc_fixed(int ion_fd, uint32_t heap_id, uint64_t bytes, int *fd_out)
{
    struct ion_allocation_data_uapi allocation;

    if (heap_id >= 32U || bytes == 0 || bytes % PAGE_BYTES != 0)
        return -1;
    memset(&allocation, 0, sizeof(allocation));
    allocation.len = bytes;
    allocation.heap_id_mask = UINT32_C(1) << heap_id;
    allocation.flags = 0;
    if (ioctl(ion_fd, ION_IOC_ALLOC, &allocation) != 0 ||
        allocation.fd > (uint32_t)INT_MAX)
        return -1;
    *fd_out = (int)allocation.fd;
    return 0;
}

static int canonical_kernel_pointer(uint64_t value)
{
    const uint64_t upper_mask = UINT64_MAX >> VA_BITS;

    /* V2321 is an arm64 VA_BITS=39 kernel.  Require sign extension of bit 38;
     * broad 48-bit tests are not sufficient for kernel page pointers. */
    return value != 0 && (value >> VA_BITS) == upper_mask;
}

static int derive_affine(const struct trace_event *events, size_t count,
                         uint64_t *slope_out, uint64_t *intercept_out)
{
    uint64_t page0;
    uint64_t page1;
    uint64_t pfn0;
    uint64_t pfn1;
    uint64_t page_delta;
    uint64_t pfn_delta;
    uint64_t product;
    uint64_t intercept;

    if (count != CALIBRATION_ALLOCS)
        return -1;
    page0 = events[0].page_ptr;
    page1 = events[1].page_ptr;
    pfn0 = events[0].pfn;
    pfn1 = events[1].pfn;
    if (!canonical_kernel_pointer(page0) || !canonical_kernel_pointer(page1) ||
        !canonical_kernel_pointer(events[2].page_ptr) || pfn0 == pfn1 ||
        events[0].pfn == events[2].pfn || events[1].pfn == events[2].pfn)
        return -1;
    if (page1 > page0 && pfn1 > pfn0) {
        page_delta = page1 - page0;
        pfn_delta = pfn1 - pfn0;
    } else if (page1 < page0 && pfn1 < pfn0) {
        page_delta = page0 - page1;
        pfn_delta = pfn0 - pfn1;
    } else {
        return -1;
    }
    if (page_delta == 0 || pfn_delta == 0 || page_delta % pfn_delta != 0)
        return -1;
    *slope_out = page_delta / pfn_delta;
    if (*slope_out < PAGE_PTR_STRIDE_MIN || *slope_out > PAGE_PTR_STRIDE_MAX ||
        (*slope_out & (*slope_out - 1U)) != 0)
        return -1;
    if (*slope_out > UINT64_MAX / events[0].pfn)
        return -1;
    product = *slope_out * events[0].pfn;
    if (events[0].page_ptr < product)
        return -1;
    intercept = events[0].page_ptr - product;
    if (*slope_out > UINT64_MAX / events[2].pfn ||
        intercept > UINT64_MAX - *slope_out * events[2].pfn ||
        intercept + *slope_out * events[2].pfn != events[2].page_ptr)
        return -1;
    *intercept_out = intercept;
    return 0;
}

static int pointer_to_pfn(uint64_t page_ptr, uint64_t slope, uint64_t intercept,
                          uint64_t *pfn_out)
{
    uint64_t delta;
    if (!canonical_kernel_pointer(page_ptr) || page_ptr < intercept || slope == 0)
        return -1;
    delta = page_ptr - intercept;
    if (delta % slope != 0)
        return -1;
    *pfn_out = delta / slope;
    return 0;
}

static int compare_pa_segment(const void *left, const void *right)
{
    const struct pa_segment *a = left;
    const struct pa_segment *b = right;

    if (a->pfn < b->pfn)
        return -1;
    if (a->pfn > b->pfn)
        return 1;
    return 0;
}

static int validate_pa_segments(const struct trace_event *events, size_t count,
                                uint64_t slope, uint64_t intercept,
                                uint64_t *first_pa, uint64_t *end_pa,
                                int *contiguous)
{
    struct pa_segment *segments;
    size_t index;
    uint64_t total = 0;

    if (count == 0 || count > MAX_SEGMENTS)
        return -1;
    segments = calloc(count, sizeof(*segments));
    if (segments == NULL)
        return -1;
    for (index = 0; index < count; ++index) {
        uint64_t pfn;
        if (pointer_to_pfn(events[index].page_ptr, slope, intercept, &pfn) != 0 ||
            events[index].size_bytes == 0 || events[index].size_bytes % PAGE_BYTES != 0 ||
            pfn > (UINT64_MAX >> 12U) ||
            events[index].size_bytes > UINT64_MAX - (pfn << 12U) ||
            total > UINT64_MAX - events[index].size_bytes)
            goto fail;
        segments[index].pfn = pfn;
        segments[index].size = events[index].size_bytes;
        total += events[index].size_bytes;
    }
    if (total != EXPECTED_BYTES)
        goto fail;
    qsort(segments, count, sizeof(*segments), compare_pa_segment);
    *first_pa = segments[0].pfn << 12U;
    *end_pa = *first_pa;
    *contiguous = 1;
    for (index = 0; index < count; ++index) {
        uint64_t segment_end;
        if (segments[index].size > UINT64_MAX - (segments[index].pfn << 12U))
            goto fail;
        segment_end = (segments[index].pfn << 12U) + segments[index].size;
        if (index != 0 && (segments[index].pfn << 12U) != *end_pa)
            *contiguous = 0;
        if (segment_end > *end_pa)
            *end_pa = segment_end;
    }
    free(segments);
    return 0;

fail:
    free(segments);
    return -1;
}

static void print_format_descriptor(const struct trace_desc *desc)
{
    printf("{\"schema\":\"%s\",\"type\":\"format\",\"event\":\"%s\",\"id\":%llu,\"format_path\":\"%s\","
           "\"format_size\":%zu,\"has_page\":%s,\"has_size\":%s,"
           "\"has_pfn\":%s,\"has_count\":%s,\"has_heap_name\":%s,"
           "\"has_buffer\":%s,\"format_hex\":\"",
           ORACLE_SCHEMA, desc->name, (unsigned long long)desc->id, desc->format_path,
           desc->format_size, desc->has_page ? "true" : "false",
           desc->has_size ? "true" : "false", desc->has_pfn ? "true" : "false",
           desc->has_count ? "true" : "false", desc->has_name ? "true" : "false",
           desc->has_buffer ? "true" : "false");
    print_hex(desc->format_bytes, desc->format_bytes_size);
    printf("\"}\n");
}

static void print_trace_event(const char *phase, const struct trace_desc *desc,
                              const struct trace_event *event)
{
    char pfn_text[32];
    char count_text[32];
    char heap_name_text[32];
    char buffer_text[32];

    if (event->has_pfn)
        (void)snprintf(pfn_text, sizeof(pfn_text), "\"0x%llx\"",
                       (unsigned long long)event->pfn);
    else
        (void)snprintf(pfn_text, sizeof(pfn_text), "null");
    if (event->has_count)
        (void)snprintf(count_text, sizeof(count_text), "\"0x%llx\"",
                       (unsigned long long)event->count);
    else
        (void)snprintf(count_text, sizeof(count_text), "null");
    if (desc->has_name)
        (void)snprintf(heap_name_text, sizeof(heap_name_text), "\"0x%llx\"",
                       (unsigned long long)event->heap_name_value);
    else
        (void)snprintf(heap_name_text, sizeof(heap_name_text), "null");
    if (desc->has_buffer)
        (void)snprintf(buffer_text, sizeof(buffer_text), "\"0x%llx\"",
                       (unsigned long long)event->buffer_ptr);
    else
        (void)snprintf(buffer_text, sizeof(buffer_text), "null");
    printf("{\"schema\":\"%s\",\"type\":\"event\",\"phase\":\"%s\","
           "\"event\":\"%s\",\"page_ptr\":\"0x%llx\","
           "\"has_page\":%s,\"pfn\":%s,\"pfn_value\":%s,"
           "\"count\":%s,\"count_value\":%s,"
           "\"has_heap_name\":%s,\"heap_name_value\":%s,"
           "\"has_buffer\":%s,\"buffer_ptr\":%s,"
           "\"size_bytes\":%llu,"
           "\"raw_size\":%u,\"raw_hex\":\"",
           ORACLE_SCHEMA, phase, desc->name,
           (unsigned long long)event->page_ptr,
           event->has_page ? "true" : "false",
           event->has_pfn ? "true" : "false",
           pfn_text,
           event->has_count ? "true" : "false",
           count_text,
           desc->has_name ? "true" : "false",
           heap_name_text,
           desc->has_buffer ? "true" : "false",
           buffer_text,
           (unsigned long long)event->size_bytes, event->raw_size);
    print_hex(event->raw, event->raw_size);
    printf("\"}\n");
}

int main(int argc, char **argv)
{
    const char *event_names[] = {
        EVENT_CMA, EVENT_START, EVENT_END, EVENT_POOL, EVENT_PARTIAL
    };
    struct perf_source sources[5];
    int calibration_fds[CALIBRATION_ALLOCS] = {-1, -1, -1};
    int ion_fd = -1;
    int allocation_fd = -1;
    struct ion_heap_query_uapi query;
    struct ion_heap_data_uapi *heaps = NULL;
    struct trace_event *segments = NULL;
    struct trace_event calibration_events[CALIBRATION_ALLOCS];
    size_t calibration_event_count = 0;
    size_t segment_count = 0;
    size_t page_size;
    size_t index;
    uint64_t total = 0;
    uint64_t slope = 0;
    uint64_t intercept = 0;
    uint64_t first_pa = 0;
    uint64_t end_pa = 0;
    uint64_t btf_page_size = 0;
    int btf_present = 0;
    int contiguous = 0;
    int allocation_returned = 0;
    int perf_enabled = 0;
    int perf_disabled = 1;
    int allocation_fd_closed = 1;
    int ion_fd_closed = 1;
    int calibration_fds_closed = 1;
    int perf_unmapped = 1;
    int perf_closed = 1;
    int exit_code = 1;
    int cleanup_failed = 0;
    int output_too_large = 0;
    size_t output_estimate = 0;
    const char *allocation_backend = "unknown";
    size_t trace_memory_used = 0;
    size_t segment_bytes;
    uint64_t allocation_heap_name_value = 0;

    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "Verification 030 has no caller-selectable arguments\n");
        return 2;
    }
    memset(sources, 0, sizeof(sources));
    for (index = 0; index < 5U; ++index)
        sources[index].fd = -1;
    if (MAX_SEGMENTS > SIZE_MAX / sizeof(*segments))
        goto cleanup;
    segment_bytes = MAX_SEGMENTS * sizeof(*segments);
    if (reserve_trace_budget(segment_bytes, &trace_memory_used) != 0)
        goto cleanup;
    segments = calloc(MAX_SEGMENTS, sizeof(*segments));
    if (segments == NULL)
        goto cleanup;
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (pin_cpu() != 0)
        goto cleanup;
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0)
        goto cleanup;
    ion_fd = open(FIXED_ION_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (ion_fd < 0)
        goto cleanup;
    memset(&query, 0, sizeof(query));
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0 || query.cnt == 0 ||
        query.cnt > ION_MAX_HEAPS)
        goto cleanup;
    heaps = calloc(query.cnt, sizeof(*heaps));
    if (heaps == NULL)
        goto cleanup;
    query.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(ion_fd, ION_IOC_HEAP_QUERY, &query) != 0)
        goto cleanup;
    {
        unsigned int camera_count = 0;
        unsigned int calibration_count = 0;
        struct ion_heap_data_uapi *camera = NULL;
        struct ion_heap_data_uapi *calibration = NULL;
        for (uint32_t heap_index = 0; heap_index < query.cnt; ++heap_index) {
            heaps[heap_index].name[ION_HEAP_NAME_BYTES - 1U] = '\0';
            if (strcmp(heaps[heap_index].name, EXPECTED_HEAP) == 0) {
                camera = &heaps[heap_index];
                ++camera_count;
            }
            if (strcmp(heaps[heap_index].name, CALIBRATION_HEAP) == 0) {
                calibration = &heaps[heap_index];
                ++calibration_count;
            }
        }
        if (camera == NULL || camera_count != 1U || camera->type != EXPECTED_HEAP_TYPE ||
            camera->heap_id != EXPECTED_HEAP_ID || calibration == NULL ||
            calibration_count != 1U || calibration->type != CALIBRATION_HEAP_TYPE ||
            calibration->heap_id != CALIBRATION_HEAP_ID)
            goto cleanup;
    }
    if (setup_perf_source(&sources[0], event_names[0], page_size,
                          CALIBRATION_ALLOCS, &trace_memory_used) != 0 ||
        setup_perf_source(&sources[1], event_names[1], page_size, 1U,
                          &trace_memory_used) != 0 ||
        setup_perf_source(&sources[2], event_names[2], page_size, 1U,
                          &trace_memory_used) != 0 ||
        setup_perf_source(&sources[3], event_names[3], page_size, MAX_SEGMENTS,
                          &trace_memory_used) != 0 ||
        setup_perf_source(&sources[4], event_names[4], page_size, MAX_SEGMENTS,
                          &trace_memory_used) != 0)
        goto cleanup;
    /* DEFINE_EVENT(ion_rbin, ...) reuses one class, so all four captured
     * allocation events must expose the same field layout at runtime. */
    for (index = 2; index < 5U; ++index) {
        if (!same_ion_class_layout(&sources[1].desc, &sources[index].desc))
            goto cleanup;
    }
    /* Three distinct held user_contig buffers calibrate page* -> PFN with
     * same-run CMA evidence.  Their descriptors are not closed until RBIN
     * parsing completes, so CMA cannot recycle an observed PFN. */
    if (enable_perf_source(&sources[0]) != 0)
        goto cleanup;
    perf_enabled = 1;
    {
        const uint64_t sizes[CALIBRATION_ALLOCS] = {
            CALIBRATION_BYTES0, CALIBRATION_BYTES1, CALIBRATION_BYTES2
        };
        for (index = 0; index < CALIBRATION_ALLOCS; ++index) {
            if (ion_alloc_fixed(ion_fd, CALIBRATION_HEAP_ID, sizes[index],
                                &calibration_fds[index]) != 0)
                goto cleanup;
        }
    }
    if (disable_perf_source(&sources[0]) != 0)
        goto cleanup;
    perf_enabled = 0;
    if (parse_perf_ring(&sources[0]) != 0 || sources[0].event_count != CALIBRATION_ALLOCS ||
        derive_affine(sources[0].events, sources[0].event_count, &slope, &intercept) != 0)
        goto cleanup;
    {
        const uint64_t expected_counts[CALIBRATION_ALLOCS] = {1U, 2U, 3U};
        for (index = 0; index < CALIBRATION_ALLOCS; ++index) {
            if (!sources[0].events[index].has_count ||
                sources[0].events[index].count != expected_counts[index] ||
                sources[0].events[index].size_bytes !=
                    expected_counts[index] * PAGE_BYTES)
                goto cleanup;
        }
    }
    if (retain_calibration_events(sources, calibration_events,
                                  CALIBRATION_ALLOCS,
                                  &calibration_event_count) != 0)
        goto cleanup;
    {
        int btf_result = btf_struct_page_size(&btf_page_size);
        if (btf_result < 0)
            goto cleanup;
        if (btf_result == 0) {
            btf_present = 1;
            if (btf_page_size != slope)
                goto cleanup;
        }
    }

    /* The five event streams are reset/enabled only for the one camera
     * allocation.  The perf disable calls occur immediately after ioctl
     * returns, before any ring parsing or output derivation. */
    for (index = 1; index < 5U; ++index) {
        if (enable_perf_source(&sources[index]) != 0)
            goto cleanup;
    }
    if (enable_perf_source(&sources[0]) != 0)
        goto cleanup;
    perf_enabled = 1;
    if (ion_alloc_fixed(ion_fd, EXPECTED_HEAP_ID, EXPECTED_BYTES, &allocation_fd) != 0) {
        goto cleanup;
    }
    allocation_returned = 1;
    for (index = 0; index < 5U; ++index) {
        if (disable_perf_source(&sources[index]) != 0)
            goto cleanup;
    }
    perf_enabled = 0;
    for (index = 0; index < 5U; ++index) {
        if (parse_perf_ring(&sources[index]) != 0)
            goto cleanup;
    }
    /* The retained Samsung ion_rbin event class has the same four fields for
     * every event.  ion_rbin_heap.c calls alloc_start/end with
     * (heap->name, buffer, size, NULL); pool_alloc_end with
     * (heap->name, NULL, page_private(page), page); and
     * partial_alloc_end with (NULL, NULL, size, page).  The values below are
     * therefore call-site bindings, not guesses based on an event name. */
    if (sources[1].event_count != 1U || sources[2].event_count != 1U ||
        !sources[1].events[0].has_page || sources[1].events[0].page_ptr != 0 ||
        !sources[1].events[0].has_size || sources[1].events[0].size_bytes != EXPECTED_BYTES ||
        !sources[1].events[0].heap_name_value || !sources[1].events[0].buffer_ptr ||
        !sources[2].events[0].has_page || sources[2].events[0].page_ptr != 0 ||
        !sources[2].events[0].has_size || sources[2].events[0].size_bytes != EXPECTED_BYTES ||
        sources[2].events[0].heap_name_value != sources[1].events[0].heap_name_value ||
        sources[2].events[0].buffer_ptr != sources[1].events[0].buffer_ptr ||
        sources[2].events[0].result != 0)
        goto cleanup;
    allocation_heap_name_value = sources[1].events[0].heap_name_value;
    /* Heap type 10 is RBIN-only.  Any camera-phase CMA record is a source or
     * runtime disagreement, not an alternate allocation backend. */
    if (sources[0].event_count != 0U)
        goto cleanup;
    allocation_backend = "rbin";
    {
        size_t partial_index = 0;
        size_t pool_success = 0;
        size_t pool_misses = 0;
        if (sources[3].event_count == 0U)
            goto cleanup;
        for (index = 0; index < sources[3].event_count; ++index) {
            if (sources[3].events[index].heap_name_value != allocation_heap_name_value ||
                sources[3].events[index].buffer_ptr != 0)
                goto cleanup;
            if (sources[3].events[index].page_ptr == 0 &&
                sources[3].events[index].size_bytes == 0) {
                ++pool_misses;
                if (partial_index >= sources[4].event_count ||
                    sources[4].events[partial_index].heap_name_value != 0 ||
                    sources[4].events[partial_index].buffer_ptr != 0 ||
                    sources[4].events[partial_index].page_ptr == 0 ||
                    sources[4].events[partial_index].size_bytes == 0 ||
                    append_event(segments, &segment_count,
                                 &sources[4].events[partial_index]) != 0)
                    goto cleanup;
                ++partial_index;
                continue;
            }
            if (append_event(segments, &segment_count, &sources[3].events[index]) != 0)
                goto cleanup;
            ++pool_success;
        }
        if (partial_index != sources[4].event_count ||
            pool_misses != partial_index || pool_success + partial_index == 0U)
            goto cleanup;
    }
    if (validate_pa_segments(segments, segment_count, slope, intercept,
                             &first_pa, &end_pa, &contiguous) != 0)
        goto cleanup;
    total = 0;
    for (index = 0; index < segment_count; ++index) {
        if (total > UINT64_MAX - segments[index].size_bytes)
            goto cleanup;
        total += segments[index].size_bytes;
    }
    if (total != EXPECTED_BYTES)
        goto cleanup;
    if (allocation_fd >= 0) {
        int close_result = close(allocation_fd);
        allocation_fd = -1;
        if (close_result != 0) {
            allocation_fd_closed = 0;
            goto cleanup;
        }
    }
    exit_code = 0;

cleanup:
    /* Do not start streaming an allocation-sized transcript until its exact
     * bounded cardinality has been accounted for.  A highly fragmented RBIN
     * result can exceed one bridge frame even though the allocation itself is
     * valid; retain only a compact incomplete-result record in that case. */
    if (exit_code == 0) {
        if (estimate_output_bytes(sources, 5U, calibration_events,
                                  calibration_event_count,
                                  &output_estimate) != 0) {
            /* An arithmetic/bounds failure is itself incomplete evidence;
             * never fall through to an unbounded stream or PA claim. */
            output_estimate = SIZE_MAX;
            output_too_large = 1;
            exit_code = 1;
        } else if (output_estimate > MAX_CAPTURE_OUTPUT_BYTES) {
            output_too_large = 1;
            exit_code = 1;
        } else {
            size_t partial_index = 0;

            printf("{\"schema\":\"%s\",\"type\":\"context\",\"backend\":\"perf_event_open\","
                   "\"scope\":\"pid=0,cpu=-1\",\"cpu\":%u,\"heap\":\"%s\","
                   "\"heap_id\":%u,\"heap_type\":%u,\"calibration_heap\":\"%s\","
                   "\"calibration_heap_id\":%u,\"calibration_heap_type\":%u,"
                   "\"allocation_bytes\":%llu,\"flags\":0}\n",
                   ORACLE_SCHEMA, EXPECTED_CPU, EXPECTED_HEAP, EXPECTED_HEAP_ID,
                   EXPECTED_HEAP_TYPE, CALIBRATION_HEAP, CALIBRATION_HEAP_ID,
                   CALIBRATION_HEAP_TYPE, (unsigned long long)EXPECTED_BYTES);
            for (index = 0; index < 5U; ++index)
                print_format_descriptor(&sources[index].desc);
            for (index = 0; index < calibration_event_count; ++index)
                print_trace_event("calibration", &sources[0].desc,
                                  &calibration_events[index]);
            print_trace_event("allocation", &sources[1].desc, &sources[1].events[0]);
            print_trace_event("allocation", &sources[2].desc, &sources[2].events[0]);
            for (index = 0; index < sources[3].event_count; ++index) {
                print_trace_event("allocation", &sources[3].desc,
                                  &sources[3].events[index]);
                if (sources[3].events[index].page_ptr == 0 &&
                    sources[3].events[index].size_bytes == 0) {
                    print_trace_event("allocation", &sources[4].desc,
                                      &sources[4].events[partial_index]);
                    ++partial_index;
                }
            }
        }
    }
    if (perf_enabled) {
        for (index = 0; index < 5U; ++index)
            if (sources[index].fd >= 0 && disable_perf_source(&sources[index]) != 0)
                cleanup_failed = 1, perf_disabled = 0;
    }
    if (allocation_fd >= 0 && close(allocation_fd) != 0)
        cleanup_failed = 1, allocation_fd_closed = 0;
    allocation_fd = -1;
    for (index = 0; index < CALIBRATION_ALLOCS; ++index) {
        if (calibration_fds[index] >= 0 && close(calibration_fds[index]) != 0)
            cleanup_failed = 1, calibration_fds_closed = 0;
        calibration_fds[index] = -1;
    }
    if (ion_fd >= 0 && close(ion_fd) != 0)
        cleanup_failed = 1, ion_fd_closed = 0;
    ion_fd = -1;
    free(heaps);
    heaps = NULL;
    free(segments);
    segments = NULL;
    for (index = 0; index < 5U; ++index) {
        if (close_perf_source(&sources[index]) != 0) {
            cleanup_failed = 1;
            perf_unmapped = 0;
            perf_closed = 0;
        }
    }
    if (cleanup_failed)
        exit_code = 1;
    if (output_too_large)
        printf("{\"schema\":\"%s\",\"type\":\"result\","
               "\"status\":\"OUTPUT_TOO_LARGE\","
               "\"classification\":\"INCOMPLETE_EVIDENCE\","
               "\"estimated_output_bytes\":%zu,"
               "\"max_output_bytes\":%u,\"allocation_returned\":%s}\n",
               ORACLE_SCHEMA, output_estimate, MAX_CAPTURE_OUTPUT_BYTES,
               allocation_returned ? "true" : "false");
    if (exit_code == 0) {
        const char *classification =
            first_pa == EXPECTED_REGION_FIRST && end_pa == EXPECTED_REGION_END &&
                    contiguous
                ? "EXACT_CAMERA_PREVIEW_RBIN_REGION"
                : "NONEXACT_CAMERA_PREVIEW_RBIN_REGION";
        printf("{\"schema\":\"%s\",\"type\":\"summary\",\"status\":\"PA_BOUND\","
               "\"allocation_backend\":\"%s\",\"event_pool_count\":%zu,"
               "\"event_partial_count\":%zu,\"event_cma_count\":%zu,"
               "\"event_start_count\":%zu,\"event_end_count\":%zu,"
               "\"nents\":%zu,\"total_bytes\":%llu,\"first_pa\":\"0x%llx\","
               "\"end_pa\":\"0x%llx\",\"contiguous\":%s,"
               "\"exact_region_match\":%s,\"classification\":\"%s\","
               "\"affine_slope\":%llu,\"affine_intercept\":\"0x%llx\","
               "\"struct_page_size_source\":\"%s\"}\n",
               ORACLE_SCHEMA, allocation_backend, sources[3].event_count,
               sources[4].event_count, sources[0].event_count, sources[1].event_count,
               sources[2].event_count, segment_count, (unsigned long long)total,
               (unsigned long long)first_pa, (unsigned long long)end_pa,
               contiguous ? "true" : "false",
               first_pa == EXPECTED_REGION_FIRST && end_pa == EXPECTED_REGION_END &&
                       contiguous
                   ? "true"
                   : "false",
               classification, (unsigned long long)slope,
               (unsigned long long)intercept,
               btf_present ? "btf:/sys/kernel/btf/vmlinux" : "same-run-cma-affine");
    }
    printf("{\"schema\":\"%s\",\"type\":\"cleanup\",\"allocation_returned\":%s,"
           "\"perf_disabled\":%s,\"allocation_fd_closed\":%s,\"ion_fd_closed\":%s,"
           "\"calibration_fds_closed\":%s,\"perf_unmapped\":%s,\"perf_closed\":%s,"
           "\"status\":\"%s\"}\n",
           ORACLE_SCHEMA, allocation_returned ? "true" : "false",
           perf_disabled ? "true" : "false", allocation_fd_closed ? "true" : "false",
           ion_fd_closed ? "true" : "false", calibration_fds_closed ? "true" : "false",
           perf_unmapped ? "true" : "false", perf_closed ? "true" : "false",
           exit_code == 0 ? "PASS" : "INCIDENT");
    return exit_code;
}
