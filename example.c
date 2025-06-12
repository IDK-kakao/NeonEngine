#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "neonengine.h"

int main(int ac, char **av) {
    pid_t pid = atoi(av[1]);
    
    if (neon_init() < 0) {
        printf("Init err\n");
        return 1;
    }
    
    char mbuf[65536] = {0};
    size_t msz = 0;
    
    if (neon_get_memory_maps(pid, mbuf, sizeof(mbuf), &msz) < 0) {
        neon_cleanup();
        return 1;
    }
    
    printf("Map (%zu b):\n", msz);
    printf("----------------------------------------\n");
    printf("%s\n", mbuf);
    printf("----------------------------------------\n");
    
    size_t rc = 0;
    neon_memory_region_t *rg = neon_get_readable_regions(pid, &rc);
    
    if (rg) {
        for (size_t i = 0; i < 10 && i < rc; i++) {
            printf("Region %zu: 0x%lx - 0x%lx (R: %s)\n", 
                   i, rg[i].start, rg[i].end, rg[i].perms);
            
            if (i < 3 && rg[i].end - rg[i].start >= 64) {
                unsigned char buf[64];
                int r = neon_read_memory(pid, rg[i].start, buf, sizeof(buf));
                
                if (r > 0) {
                    for (int j = 0; j < 16 && j < r; j++) {
                        printf("%02x ", buf[j]);
                    }
                    printf("\n");
                }
            }
        }
        
        if (rc > 10) {
            printf("... and more %zu \n", rc - 10);
        }
        
        free(rg);
    } else {
        printf("Region err\n");
    }
    
    int val = 1248;
    size_t res_cnt = 0;
    unsigned long* res = neon_scan_int32(pid, val, &res_cnt, 100);
    
    if (res) {
        printf("\nSearch int %d:\n", val);
        printf("Found %zu results\n", res_cnt);
        
        for (size_t i = 0; i < res_cnt && i < 10; i++) {
            printf("  Addr 0x%lx\n", res[i]);
        }
        
        if (res_cnt > 10) {
            printf("  ... and more %zu\n", res_cnt - 10);
        }
        
        free(res);
    }
    
    const char* s = "idk";
    res = neon_scan_string(pid, s, &res_cnt, 100);
    
    if (res) {
        printf("\nSearch str '%s':\n", s);
        printf("Found %zu results\n", res_cnt);
        
        for (size_t i = 0; i < res_cnt && i < 10; i++) {
            printf("  Ptr 0x%lx\n", res[i]);
            
            char sbuf[64];
            if (neon_read_memory(pid, res[i], sbuf, sizeof(sbuf) - 1) > 0) {
                sbuf[sizeof(sbuf) - 1] = '\0';
                printf("  Read: %s\n", sbuf);
            }
        }
        
        if (res_cnt > 10) {
            printf("  ... and more %zu\n", res_cnt - 10);
        }
        
        free(res);
    }
    
    neon_cleanup();
    printf("Bye!\n");
    
    return 0;
}
