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

static config_t conf ;
static cov_stat_t * curr_stat ; // shm

/**
 * TODO.
 * - union & per trace => at the end of the fuzzing campaign.
 *      static cov_stat_t * cov_stats ; // save
 *      static unsigned int * trace_cov ; 
 *      map_elem_t trace_map[FUNCOV_MAP_SIZE] ;
*/

void
remove_shared_mem ()
{
    detatch_shm((void *)curr_stat) ;
    remove_shm(conf.shmid) ;
}

void
shm_init ()
{
    conf.shmid = get_shm(INIT, sizeof(cov_stat_t)) ;
    curr_stat = attatch_shm(conf.shmid) ;
    memset(curr_stat, 0, sizeof(cov_stat_t)) ;
}

void 
funcov_init (afl_state_t * afl, char * seed_path)  // TODO. in afl init...
{
    conf.shmid = afl->funcov_shmid ;

    if (afl->fsrv.use_stdin) conf.input_type = STDIN ;
    else conf.input_type = ARG_FILENAME ;

    strcpy(conf.bin_path, afl->fsrv.target_path) ; 
    for (int i = strlen(afl->fsrv.target_path) - 1; i >= 0; i--) {
        if (conf.bin_path[i] == '/') {
            conf.bin_path[i] = '\0' ;
            break ;
        }
    }
    strcpy(conf.input_file, seed_path) ;
    sprintf(conf.out_dir, "%s/funcov", afl->out_dir) ;
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
            remove_shared_mem() ;
            exit(1) ;   // Q.
        }
    }
}

void
execute_target ()
{
    alarm(3) ;

    FILE * fp = fopen(conf.input_file, "rb") ;
    if (fp == 0x0) {
        perror("execute_target: fopen") ;
        remove_shared_mem() ;
        exit(1) ;
    }

    if (conf.input_type == STDIN) {
        while (!feof(fp)) {
            char buf[BUF_SIZE] ;
            int r_len = fread(buf, 1, sizeof(buf), fp) ;

            char * buf_p = buf ;
            int s ;
            while (r_len > 0 && (s = write(stdin_pipe[1], buf_p, r_len)) > 0) {
                buf_p += s ;
                r_len -= s ;
            }
        }
    }
    fclose(fp) ;
    close(stdin_pipe[1]) ;

    dup2(stdin_pipe[0], 0) ;
    close(stdin_pipe[0]) ;

    close(stdout_pipe[0]) ;
    close(stderr_pipe[0]) ;

    dup2(stdout_pipe[1], 1) ;
    dup2(stderr_pipe[1], 2) ;

    // TODO. ASAN_OPTION

    if (conf.input_type == STDIN) {
        char * args[] = { conf.bin_path, (char *)0x0 } ;
        if (execv(conf.bin_path, args) == -1) {
            perror("execute_target: execv") ;
            remove_shared_mem() ;
            exit(1) ;
        }
    } 
    else if (conf.input_type == ARG_FILENAME) {
        char * args[] = { conf.bin_path, conf.input_file, (char *)0x0 } ;
        if (execv(conf.bin_path, args) == -1) {
            perror("execute_target: execv") ;
            remove_shared_mem() ;
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
run ()
{
    memset(curr_stat, 0, sizeof(cov_stat_t)) ;

    if (pipe(stdin_pipe) != 0) goto pipe_err ;
    if (pipe(stdout_pipe) != 0) goto pipe_err ;
    if (pipe(stderr_pipe) != 0) goto pipe_err ;

    child_pid = fork() ; 

    if (child_pid == 0) {
        execute_target() ;
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
    remove_shared_mem() ;
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
    parse_file_name(input_filename, conf.input_file) ; // TODO. tokenize long path
    
    char funcov_file_path[PATH_MAX + 256] ;
    sprintf(funcov_file_path, "%s/%s.csv", funcov_dir_path, input_filename) ;

    FILE * fp = fopen(funcov_file_path, "wb") ;
    if (fp == 0x0) {
        perror("write_covered_funs_csv: fopen") ;
        remove_shared_mem() ;
        exit(1) ;
    }

    fprintf(fp, "callee,caller,pc_val,called_location\n") ; 
    for (int i = 0; i < FUNCOV_MAP_SIZE; i++) {
        if (curr_stat->map[i].hit_count == 0) continue ;
            
        fprintf(fp, "%s,", curr_stat->map[i].cov_string) ; 
        
        // char location[PATH_MAX] ;
        // if (find_location_info(location, translated_locations, cov_stats[turn].map[i].cov_string) == -1) {
        //     remove_shared_mem() ;
        //     exit(1) ;
        // }
        // fprintf(fp, "%s\n", location) ;
        fprintf(fp, "\n") ;
    }

    fclose(fp) ;
}

// void
// save_final_results ()
// {
//     location_t * translated_locations = (location_t *) malloc(sizeof(location_t) *  FUNCOV_MAP_SIZE) ;
//     if (translated_locations == 0x0) {
//         perror("save_final_results: malloc") ;
//         remove_shared_mem() ;
//         exit(1) ;
//     }
//     memset(translated_locations, 0, sizeof(location_t) * FUNCOV_MAP_SIZE) ;

//     int translate_success = translate_pc_values(translated_locations, curr_stat->fun_coverage, curr_stat->map, conf.bin_path) ;
//     if (translate_success == -1) {
//         remove_shared_mem() ;
//         exit(1) ;
//     }

//     char funcov_dir_path[PATH_MAX + 32] ;
//     sprintf(funcov_dir_path, "%s/funcov_per_seed", conf.out_dir) ;
//     write_covered_funs_csv(funcov_dir_path, translated_locations) ; // TODO. translated_locations

//     free(translated_locations) ;
// }


int
funcov (afl_state_t * afl, u8 * seed_path) 
{
    funcov_init(afl, seed_path) ;
    
    int exit_code = run() ;
    curr_stat->exit_code = exit_code ;
    curr_stat->fun_coverage = count_coverage(curr_stat->map) ;

    char funcov_dir_path[PATH_MAX + 32] ;
    sprintf(funcov_dir_path, "%s/funcov_per_seed", conf.out_dir) ;
    write_covered_funs_csv(funcov_dir_path) ;

    return 0 ;
}