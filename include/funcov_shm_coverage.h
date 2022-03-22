#ifndef SHMCOV
#define SHMCOV

#include <stdint.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>

#define SHM_ENV_VAR "__AFL_SHM_ID"

#define PATH_MAX 4096
#define BUF_SIZE 1024
#define FUNCOV_MAP_SIZE 65536
#define COV_STRING_MAX 512

typedef struct map_elem {
    unsigned int hit_count ;
    char cov_string[COV_STRING_MAX] ; // "callee,caller,PC"
} map_elem_t ;

typedef struct cov_stat {
    int exit_code ;
    unsigned int fun_coverage ;
    map_elem_t map[FUNCOV_MAP_SIZE] ;
} cov_stat_t ;

typedef enum shm {
    INIT = 0,
    USE
} shm_t ;

unsigned short hash16 (char * key) ;

int get_shm (shm_t type, int type_size) ;
void * attatch_shm (int shm_id) ;
void detatch_shm (void * shm_addr) ;
void remove_shm (int shm_id) ;

#endif