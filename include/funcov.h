#ifndef COVENGINE
#define COVENGINE

#define PATH_MAX 4096
#define BUF_SIZE 1024
#define FUN_NAME_MAX 256

#define LOGNAME "cov.log"

#include "afl-fuzz.h"

#include "funcov_get_coverage.h"
#include "funcov_shm_coverage.h"
#include "funcov_translate_addr.h"

typedef enum input_type { STDIN = 0, ARG_FILENAME } input_type_t ;

typedef struct funcov {
    int shmid ;
    input_type_t input_type ; // => afl->fsrv.use_stdin
    char bin_path[PATH_MAX] ;   /* Executable binary for funcov */
    char input_file[PATH_MAX] ; 
    char out_dir[PATH_MAX] ;
    cov_stat_t * curr_stat ; // shm
} funcov_t ;

typedef struct name_entry {
    u8 exist ;
    char name[FUN_NAME_MAX] ;
} name_entry_t ;

#endif