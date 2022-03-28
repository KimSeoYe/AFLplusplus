#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "../include/afl-fuzz.h"

funcov_t * conf ;

/**
 * TODO.
 * - union & per trace => at the end of the fuzzing campaign.
 *      static cov_stat_t * cov_stats ; // save
 *      static unsigned int * trace_cov ; 
 *      map_elem_t trace_map[FUNCOV_MAP_SIZE] ;
*/

void
remove_shared_mem (afl_state_t * afl)
{
    detatch_shm((void *)(afl->funcov.curr_stat)) ;
    remove_shm(afl->funcov.shmid) ;
}

void
remove_shared_mem_from_conf ()
{
    detatch_shm((void *)(conf->curr_stat)) ;
    remove_shm(conf->shmid) ;
}

void
shm_init (afl_state_t * afl)
{
    afl->funcov.shmid = get_shm(INIT, sizeof(cov_stat_t)) ;
    afl->funcov.curr_stat = attatch_shm(afl->funcov.shmid) ;
    memset(afl->funcov.curr_stat, 0, sizeof(cov_stat_t)) ;
}

void 
funcov_init (afl_state_t * afl)
{
    if (afl->fsrv.use_stdin) afl->funcov.input_type = STDIN ;
    else afl->funcov.input_type = ARG_FILENAME ;

    int position = -1 ;
    for (int i = strlen(afl->fsrv.target_path) - 1; i >= 0; i--) {
        if (afl->fsrv.target_path[i] == '/') {
            position = i ;
            break ;
        }
    }
    if (position > 0) {
        char dir_path[PATH_MAX] ;
        strncpy(dir_path, afl->fsrv.target_path, position) ; 
        dir_path[position] = '\0' ;
        sprintf(afl->funcov.bin_path, "%s/.%s", dir_path, afl->fsrv.target_path + position + 1) ;
    }
    else {
        sprintf(afl->funcov.bin_path, ".%s", afl->fsrv.target_path) ;
    }

    if (access(afl->funcov.bin_path, X_OK) == -1) {
        PFATAL("could not find %s", afl->funcov.bin_path) ;
    }
    
    sprintf(afl->funcov.out_dir, "%s/funcov", afl->out_dir) ;

    shm_init(afl) ;
}


static int stdin_pipe[2] ;
static int stdout_pipe[2] ;
static int stderr_pipe[2] ;

static int child_pid ;

void
timeout_handler (int sig)
{
    if (sig == SIGALRM) {
        perror("timeout") ;
        if (kill(child_pid, SIGINT) == -1) {
            perror("timeout_handler: kill") ;
            remove_shared_mem_from_conf() ;
            exit(1) ;   // Q.
        }
    }
}

void
execute_target (void * mem, u32 len)
{
    alarm(3) ;

    if (conf->input_type == STDIN) {
        u32 s = write(stdin_pipe[1], mem, len) ;
        if (s != len) {
            PFATAL("funcov: short write") ;
        }
    }
    
    close(stdin_pipe[1]) ;

    dup2(stdin_pipe[0], 0) ;
    close(stdin_pipe[0]) ;

    close(stdout_pipe[0]) ;
    close(stderr_pipe[0]) ;

    dup2(stdout_pipe[1], 1) ;
    dup2(stderr_pipe[1], 2) ;

    // TODO. ASAN_OPTION

    if (conf->input_type == STDIN) {
        char * args[] = { conf->bin_path, (char *)0x0 } ;
        if (execv(conf->bin_path, args) == -1) {
            perror("execute_target: execv") ;
            remove_shared_mem_from_conf() ;
            exit(1) ;
        }
    } 
    else if (conf->input_type == ARG_FILENAME) {
        char * args[] = { conf->bin_path, conf->input_file, (char *)0x0 } ;
        if (execv(conf->bin_path, args) == -1) {
            perror("execute_target: execv") ;
            remove_shared_mem_from_conf() ;
            exit(1) ;
        }
    }
}

void
close_pipes ()
{
    close(stdin_pipe[0]) ;
    close(stdin_pipe[1]) ;
    close(stdout_pipe[0]) ;
    close(stdout_pipe[1]) ;
    close(stderr_pipe[0]) ;
    close(stderr_pipe[1]) ;
}

int
run (void * mem, u32 len)
{
    memset(conf->curr_stat, 0, sizeof(cov_stat_t)) ;

    if (pipe(stdin_pipe) != 0) goto pipe_err ;
    if (pipe(stdout_pipe) != 0) goto pipe_err ;
    if (pipe(stderr_pipe) != 0) goto pipe_err ;

    child_pid = fork() ; 

    if (child_pid == 0) {
        execute_target(mem, len) ;
    }
    else if (child_pid > 0) {
        close_pipes() ;
    }
    else {
        perror("run: fork") ;
        exit(1) ;
    }

    int exit_code ;
    wait(&exit_code) ;

    return exit_code ;

pipe_err:
    perror("run: pipe") ;
    remove_shared_mem_from_conf() ;
    exit(1) ;
}

void
parse_file_name (char * file_name, char * long_path)
{
    int position = -1 ;
    for (int i = strlen(long_path) - 1; i >= 0; i--) {
        if (long_path[i] == '/') {
            position = i ;
            break ;
        }
    } 
    if (position >= 0) {
        strcpy(file_name, long_path + position + 1) ;
    } 
    else strcpy(file_name, long_path) ;
}

void
write_covered_funs_csv(char * funcov_dir_path) 
{
    char input_filename[PATH_MAX] ;
    parse_file_name(input_filename, conf->input_file) ; // TODO. tokenize long path
    
    char funcov_file_path[PATH_MAX + 256] ;
    sprintf(funcov_file_path, "%s/%s.csv", funcov_dir_path, input_filename) ;

    FILE * fp = fopen(funcov_file_path, "wb") ;
    if (fp == 0x0) {
        perror("write_covered_funs_csv: fopen") ;
        remove_shared_mem_from_conf() ;
        exit(1) ;
    }

    fprintf(fp, "callee,caller,pc_val\n") ; 
    for (int i = 0; i < FUNCOV_MAP_SIZE; i++) {
        if (conf->curr_stat->map[i].hit_count == 0) continue ;
            
        fprintf(fp, "%s\n", conf->curr_stat->map[i].cov_string) ; 
    }

    fclose(fp) ;
}


int
funcov (afl_state_t * afl, void * mem, u32 len, u8 * seed_path) 
{
    signal(SIGALRM, timeout_handler) ;
    
    strcpy(afl->funcov.input_file, seed_path) ;
    conf = &(afl->funcov) ;
    
    int exit_code = run(mem, len) ;
    conf->curr_stat->exit_code = exit_code ;
    conf->curr_stat->fun_coverage = count_coverage(conf->curr_stat->map) ;

    char funcov_dir_path[PATH_MAX + 32] ;
    sprintf(funcov_dir_path, "%s/funcov_per_seed", conf->out_dir) ;
    write_covered_funs_csv(funcov_dir_path) ;

    return 0 ;
}