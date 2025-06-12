#ifndef NEONENGINE_H
#define NEONENGINE_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define NEON_DEVICE_PATH "/dev/neonengine"
#define NEON_MAGIC 'N'

#define NEON_READ_MEM _IOWR(NEON_MAGIC, 1, struct neon_mem_op)
#define NEON_WRITE_MEM _IOWR(NEON_MAGIC, 2, struct neon_mem_op)
#define NEON_FIND_PATTERN _IOWR(NEON_MAGIC, 3, struct neon_pattern_op)
#define NEON_GET_MAPS _IOWR(NEON_MAGIC, 4, struct neon_maps_op)
#define NEON_PROTECT_MEM _IOWR(NEON_MAGIC, 5, struct neon_protect_op)

struct neon_mem_op {
    pid_t pid;
    unsigned long addr;
    void *buffer;
    size_t size;
    int result;
};

struct neon_pattern_op {
    pid_t pid;
    unsigned long start_addr;
    unsigned long end_addr;
    void *pattern;
    size_t pattern_size;
    unsigned long result_addr;
    int result;
};

struct neon_maps_op {
    pid_t pid;
    void *buffer;
    size_t buffer_size;
    size_t actual_size;
    int result;
};

struct neon_protect_op {
    pid_t pid;
    unsigned long addr;
    size_t size;
    unsigned long prot;
    int result;
};

typedef struct {
    int fd;
    int initialized;
} neon_engine_t;

static neon_engine_t g_neon = {-1, 0};

static inline int neon_init(void) {
    if (g_neon.initialized) {
        return 0;
    }
    
    g_neon.fd = open(NEON_DEVICE_PATH, O_RDWR);
    if (g_neon.fd < 0) {
        return -1;
    }
    
    g_neon.initialized = 1;
    return 0;
}

static inline void neon_cleanup(void) {
    if (g_neon.initialized && g_neon.fd >= 0) {
        close(g_neon.fd);
        g_neon.fd = -1;
        g_neon.initialized = 0;
    }
}

static inline int neon_read_memory(pid_t pid, unsigned long addr, void *buffer, size_t size) {
    struct neon_mem_op op;
    
    if (!g_neon.initialized && neon_init() < 0) {
        return -1;
    }
    
    op.pid = pid;
    op.addr = addr;
    op.buffer = buffer;
    op.size = size;
    
    if (ioctl(g_neon.fd, NEON_READ_MEM, &op) < 0) {
        return -1;
    }
    
    return op.result;
}

static inline int neon_write_memory(pid_t pid, unsigned long addr, const void *buffer, size_t size) {
    struct neon_mem_op op;
    
    if (!g_neon.initialized && neon_init() < 0) {
        return -1;
    }
    
    op.pid = pid;
    op.addr = addr;
    op.buffer = (void*)buffer;
    op.size = size;
    
    if (ioctl(g_neon.fd, NEON_WRITE_MEM, &op) < 0) {
        return -1;
    }
    
    return op.result;
}

static inline unsigned long neon_find_pattern(pid_t pid, unsigned long start_addr, unsigned long end_addr, 
                                            const void *pattern, size_t pattern_size) {
    struct neon_pattern_op op;
    
    if (!g_neon.initialized && neon_init() < 0) {
        return 0;
    }
    
    op.pid = pid;
    op.start_addr = start_addr;
    op.end_addr = end_addr;
    op.pattern = (void*)pattern;
    op.pattern_size = pattern_size;
    op.result_addr = 0;
    
    if (ioctl(g_neon.fd, NEON_FIND_PATTERN, &op) < 0) {
        return 0;
    }
    
    return (op.result == 0) ? op.result_addr : 0;
}

static inline int neon_get_memory_maps(pid_t pid, char *buffer, size_t buffer_size, size_t *actual_size) {
    struct neon_maps_op op;
    
    if (!g_neon.initialized && neon_init() < 0) {
        return -1;
    }
    
    op.pid = pid;
    op.buffer = buffer;
    op.buffer_size = buffer_size;
    op.actual_size = 0;
    
    if (ioctl(g_neon.fd, NEON_GET_MAPS, &op) < 0) {
        return -1;
    }
    
    if (actual_size) {
        *actual_size = op.actual_size;
    }
    
    return op.result;
}

static inline int neon_protect_memory(pid_t pid, unsigned long addr, size_t size, unsigned long prot) {
    struct neon_protect_op op;
    
    if (!g_neon.initialized && neon_init() < 0) {
        return -1;
    }
    
    op.pid = pid;
    op.addr = addr;
    op.size = size;
    op.prot = prot;
    
    if (ioctl(g_neon.fd, NEON_PROTECT_MEM, &op) < 0) {
        return -1;
    }
    
    return op.result;
}

template<typename T>
static inline T neon_read_type(pid_t pid, unsigned long addr) {
    T value;
    if (neon_read_memory(pid, addr, &value, sizeof(T)) == sizeof(T)) {
        return value;
    }
    return T{};
}

template<typename T>
static inline int neon_write_type(pid_t pid, unsigned long addr, const T& value) {
    return neon_write_memory(pid, addr, &value, sizeof(T));
}

static inline int8_t neon_read_int8(pid_t pid, unsigned long addr) {
    return neon_read_type<int8_t>(pid, addr);
}

static inline int16_t neon_read_int16(pid_t pid, unsigned long addr) {
    return neon_read_type<int16_t>(pid, addr);
}

static inline int32_t neon_read_int32(pid_t pid, unsigned long addr) {
    return neon_read_type<int32_t>(pid, addr);
}

static inline int64_t neon_read_int64(pid_t pid, unsigned long addr) {
    return neon_read_type<int64_t>(pid, addr);
}

static inline float neon_read_float(pid_t pid, unsigned long addr) {
    return neon_read_type<float>(pid, addr);
}

static inline double neon_read_double(pid_t pid, unsigned long addr) {
    return neon_read_type<double>(pid, addr);
}

static inline int neon_write_int8(pid_t pid, unsigned long addr, int8_t value) {
    return neon_write_type(pid, addr, value);
}

static inline int neon_write_int16(pid_t pid, unsigned long addr, int16_t value) {
    return neon_write_type(pid, addr, value);
}

static inline int neon_write_int32(pid_t pid, unsigned long addr, int32_t value) {
    return neon_write_type(pid, addr, value);
}

static inline int neon_write_int64(pid_t pid, unsigned long addr, int64_t value) {
    return neon_write_type(pid, addr, value);
}

static inline int neon_write_float(pid_t pid, unsigned long addr, float value) {
    return neon_write_type(pid, addr, value);
}

static inline int neon_write_double(pid_t pid, unsigned long addr, double value) {
    return neon_write_type(pid, addr, value);
}

static inline char* neon_read_string(pid_t pid, unsigned long addr, size_t max_len) {
    char *buffer = (char*)malloc(max_len + 1);
    if (!buffer) return NULL;
    
    int result = neon_read_memory(pid, addr, buffer, max_len);
    if (result <= 0) {
        free(buffer);
        return NULL;
    }
    
    buffer[max_len] = '\0';
    
    size_t actual_len = strnlen(buffer, max_len);
    char *trimmed = (char*)realloc(buffer, actual_len + 1);
    return trimmed ? trimmed : buffer;
}

static inline int neon_write_string(pid_t pid, unsigned long addr, const char* str) {
    return neon_write_memory(pid, addr, str, strlen(str) + 1);
}

typedef struct {
    unsigned long start;
    unsigned long end;
    char perms[5];
} neon_memory_region_t;

static inline neon_memory_region_t* neon_parse_maps(const char* maps_data, size_t* count) {
    if (!maps_data || !count) return NULL;
    
    *count = 0;
    const char* line = maps_data;
    while ((line = strchr(line, '\n')) != NULL) {
        (*count)++;
        line++;
    }
    
    if (*count == 0) return NULL;
    
    neon_memory_region_t* regions = (neon_memory_region_t*)malloc(*count * sizeof(neon_memory_region_t));
    if (!regions) return NULL;
    
    line = maps_data;
    size_t index = 0;
    
    while (line && *line && index < *count) {
        unsigned long start, end;
        char perms[5];
        
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            regions[index].start = start;
            regions[index].end = end;
            strncpy(regions[index].perms, perms, 4);
            regions[index].perms[4] = '\0';
            index++;
        }
        
        line = strchr(line, '\n');
        if (line) line++;
    }
    
    *count = index;
    return regions;
}

static inline neon_memory_region_t* neon_get_readable_regions(pid_t pid, size_t* count) {
    char* buffer = (char*)malloc(65536);
    if (!buffer) return NULL;
    
    size_t actual_size;
    if (neon_get_memory_maps(pid, buffer, 65536, &actual_size) < 0) {
        free(buffer);
        return NULL;
    }
    
    size_t total_count;
    neon_memory_region_t* all_regions = neon_parse_maps(buffer, &total_count);
    free(buffer);
    
    if (!all_regions) return NULL;
    
    neon_memory_region_t* readable_regions = (neon_memory_region_t*)malloc(total_count * sizeof(neon_memory_region_t));
    if (!readable_regions) {
        free(all_regions);
        return NULL;
    }
    
    size_t readable_count = 0;
    for (size_t i = 0; i < total_count; i++) {
        if (all_regions[i].perms[0] == 'r') {
            readable_regions[readable_count] = all_regions[i];
            readable_count++;
        }
    }
    
    free(all_regions);
    *count = readable_count;
    
    if (readable_count == 0) {
        free(readable_regions);
        return NULL;
    }
    
    return (neon_memory_region_t*)realloc(readable_regions, readable_count * sizeof(neon_memory_region_t));
}

static inline neon_memory_region_t* neon_get_writable_regions(pid_t pid, size_t* count) {
    char* buffer = (char*)malloc(65536);
    if (!buffer) return NULL;
    
    size_t actual_size;
    if (neon_get_memory_maps(pid, buffer, 65536, &actual_size) < 0) {
        free(buffer);
        return NULL;
    }
    
    size_t total_count;
    neon_memory_region_t* all_regions = neon_parse_maps(buffer, &total_count);
    free(buffer);
    
    if (!all_regions) return NULL;
    
    neon_memory_region_t* writable_regions = (neon_memory_region_t*)malloc(total_count * sizeof(neon_memory_region_t));
    if (!writable_regions) {
        free(all_regions);
        return NULL;
    }
    
    size_t writable_count = 0;
    for (size_t i = 0; i < total_count; i++) {
        if (all_regions[i].perms[1] == 'w') {
            writable_regions[writable_count] = all_regions[i];
            writable_count++;
        }
    }
    
    free(all_regions);
    *count = writable_count;
    
    if (writable_count == 0) {
        free(writable_regions);
        return NULL;
    }
    
    return (neon_memory_region_t*)realloc(writable_regions, writable_count * sizeof(neon_memory_region_t));
}

static inline unsigned long* neon_scan_memory(pid_t pid, const void* pattern, size_t pattern_size, 
                                            size_t* result_count, size_t max_results) {
    if (!result_count) return NULL;
    *result_count = 0;
    
    size_t region_count;
    neon_memory_region_t* regions = neon_get_readable_regions(pid, &region_count);
    if (!regions) return NULL;
    
    unsigned long* results = (unsigned long*)malloc(max_results * sizeof(unsigned long));
    if (!results) {
        free(regions);
        return NULL;
    }
    
    size_t found_count = 0;
    
    for (size_t i = 0; i < region_count && found_count < max_results; i++) {
        unsigned long addr = neon_find_pattern(pid, regions[i].start, regions[i].end, pattern, pattern_size);
        if (addr != 0) {
            results[found_count] = addr;
            found_count++;
            
            unsigned long next_start = addr + pattern_size;
            while (next_start < regions[i].end && found_count < max_results) {
                addr = neon_find_pattern(pid, next_start, regions[i].end, pattern, pattern_size);
                if (addr == 0) break;
                
                results[found_count] = addr;
                found_count++;
                next_start = addr + pattern_size;
            }
        }
    }
    
    free(regions);
    *result_count = found_count;
    
    if (found_count == 0) {
        free(results);
        return NULL;
    }
    
    return (unsigned long*)realloc(results, found_count * sizeof(unsigned long));
}

static inline unsigned long* neon_scan_int32(pid_t pid, int32_t value, size_t* result_count, size_t max_results) {
    return neon_scan_memory(pid, &value, sizeof(int32_t), result_count, max_results);
}

static inline unsigned long* neon_scan_int64(pid_t pid, int64_t value, size_t* result_count, size_t max_results) {
    return neon_scan_memory(pid, &value, sizeof(int64_t), result_count, max_results);
}

static inline unsigned long* neon_scan_float(pid_t pid, float value, size_t* result_count, size_t max_results) {
    return neon_scan_memory(pid, &value, sizeof(float), result_count, max_results);
}

static inline unsigned long* neon_scan_double(pid_t pid, double value, size_t* result_count, size_t max_results) {
    return neon_scan_memory(pid, &value, sizeof(double), result_count, max_results);
}

static inline unsigned long* neon_scan_string(pid_t pid, const char* str, size_t* result_count, size_t max_results) {
    return neon_scan_memory(pid, str, strlen(str), result_count, max_results);
}

typedef struct {
    unsigned long* addresses;
    size_t count;
    size_t capacity;
} neon_address_list_t;

static inline neon_address_list_t* neon_create_address_list(void) {
    neon_address_list_t* list = (neon_address_list_t*)malloc(sizeof(neon_address_list_t));
    if (!list) return NULL;
    
    list->capacity = 1000;
    list->addresses = (unsigned long*)malloc(list->capacity * sizeof(unsigned long));
    if (!list->addresses) {
        free(list);
        return NULL;
    }
    
    list->count = 0;
    return list;
}

static inline void neon_free_address_list(neon_address_list_t* list) {
    if (list) {
        free(list->addresses);
        free(list);
    }
}

template<typename T>
static inline void neon_filter_addresses(neon_address_list_t* list, pid_t pid, T value) {
    if (!list) return;
    
    size_t write_index = 0;
    for (size_t i = 0; i < list->count; i++) {
        T current_value = neon_read_type<T>(pid, list->addresses[i]);
        if (current_value == value) {
            list->addresses[write_index] = list->addresses[i];
            write_index++;
        }
    }
    list->count = write_index;
}

static inline void neon_filter_int32(neon_address_list_t* list, pid_t pid, int32_t value) {
    neon_filter_addresses(list, pid, value);
}

static inline void neon_filter_int64(neon_address_list_t* list, pid_t pid, int64_t value) {
    neon_filter_addresses(list, pid, value);
}

static inline void neon_filter_float(neon_address_list_t* list, pid_t pid, float value) {
    neon_filter_addresses(list, pid, value);
}

static inline void neon_filter_double(neon_address_list_t* list, pid_t pid, double value) {
    neon_filter_addresses(list, pid, value);
}

typedef struct {
    void* buffer;
    size_t size;
    unsigned long address;
} neon_memory_backup_t;

static inline neon_memory_backup_t* neon_backup_memory(pid_t pid, unsigned long addr, size_t size) {
    neon_memory_backup_t* backup = (neon_memory_backup_t*)malloc(sizeof(neon_memory_backup_t));
    if (!backup) return NULL;
    
    backup->buffer = malloc(size);
    if (!backup->buffer) {
        free(backup);
        return NULL;
    }
    
    if (neon_read_memory(pid, addr, backup->buffer, size) <= 0) {
        free(backup->buffer);
        free(backup);
        return NULL;
    }
    
    backup->size = size;
    backup->address = addr;
    return backup;
}

static inline int neon_restore_memory(pid_t pid, neon_memory_backup_t* backup) {
    if (!backup) return -1;
    
    int result = neon_write_memory(pid, backup->address, backup->buffer, backup->size);
    free(backup->buffer);
    free(backup);
    return result;
}

static inline int neon_patch_memory(pid_t pid, unsigned long addr, const void* patch_data, size_t size, neon_memory_backup_t** backup) {
    if (backup) {
        *backup = neon_backup_memory(pid, addr, size);
    }
    
    return neon_write_memory(pid, addr, patch_data, size);
}

static inline int neon_freeze_memory(pid_t pid, unsigned long addr, size_t size) {
    return neon_protect_memory(pid, addr, size, PROT_READ);
}

static inline int neon_unfreeze_memory(pid_t pid, unsigned long addr, size_t size) {
    return neon_protect_memory(pid, addr, size, PROT_READ | PROT_WRITE);
}

#ifdef __cplusplus
extern "C" {
#endif

int neon_engine_init(void);
void neon_engine_cleanup(void);
int neon_engine_read_memory(pid_t pid, unsigned long addr, void *buffer, size_t size);
int neon_engine_write_memory(pid_t pid, unsigned long addr, const void *buffer, size_t size);
unsigned long neon_engine_find_pattern(pid_t pid, unsigned long start_addr, unsigned long end_addr, const void *pattern, size_t pattern_size);
int neon_engine_get_memory_maps(pid_t pid, char *buffer, size_t buffer_size, size_t *actual_size);
int neon_engine_protect_memory(pid_t pid, unsigned long addr, size_t size, unsigned long prot);

#ifdef __cplusplus
}
#endif

#endif 