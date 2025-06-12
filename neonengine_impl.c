#include "neonengine.h"

int neon_engine_init(void) {
    return neon_init();
}

void neon_engine_cleanup(void) {
    neon_cleanup();
}

int neon_engine_read_memory(pid_t pid, unsigned long addr, void *buffer, size_t size) {
    return neon_read_memory(pid, addr, buffer, size);
}

int neon_engine_write_memory(pid_t pid, unsigned long addr, const void *buffer, size_t size) {
    return neon_write_memory(pid, addr, buffer, size);
}

unsigned long neon_engine_find_pattern(pid_t pid, unsigned long start_addr, unsigned long end_addr, 
                                      const void *pattern, size_t pattern_size) {
    return neon_find_pattern(pid, start_addr, end_addr, pattern, pattern_size);
}

int neon_engine_get_memory_maps(pid_t pid, char *buffer, size_t buffer_size, size_t *actual_size) {
    return neon_get_memory_maps(pid, buffer, buffer_size, actual_size);
}

int neon_engine_protect_memory(pid_t pid, unsigned long addr, size_t size, unsigned long prot) {
    return neon_protect_memory(pid, addr, size, prot);
} 