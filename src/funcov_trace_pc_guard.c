#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>

#include "../include/funcov_shm_coverage.h"  

// #define BT_BUF_SIZE 5
#define STR_BUFF 512

static cov_stat_t * curr_stat ; // shm
static int curr_stat_shmid ;

/**
 * README
 * 
 * You need to use "this file" for sanitizer coverage.
 * ...
*/

extern void 
__sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) 
{
	static uint64_t N;  
	if (start == stop || *start) return;  

	for (uint32_t *x = start; x < stop; x++)
		*x = ++N;  

	// curr_stat_shmid = get_shm(CURR_KEY, sizeof(cov_stat_t)) ;
	curr_stat_shmid = get_shm(USE, sizeof(cov_stat_t)) ;
}

/**
 * strings format
 * /home/kimseoye/git/FunCov/test/simple_example/example(negative+0x17) [0x512437]
 * /home/kimseoye/git/FunCov/test/simple_example/example(main+0x1a5) [0x512685]
*/

int
parse_string (char * cov_string, char ** strings)
{
	char callee[PATH_MAX] ;
	char caller[PATH_MAX] ;
	strcpy(callee, strings[2]) ;
	strcpy(caller, strings[3]) ;

	char callee_name[STR_BUFF] ;
	char caller_name[STR_BUFF] ;
	char pc_val[STR_BUFF] ;

	char * tok ;
	char * next ;

	if (strstr(callee, "+") == 0x0 || strstr(caller, "+") == 0x0) return 0 ;

	tok = strtok_r(callee, "(", &next) ;
	tok = strtok_r(NULL, "+", &next) ;
	strcpy(callee_name, tok) ;
	if (strcmp(callee_name, "main") == 0) return 0 ;

	tok = strtok_r(caller, "(", &next) ;
	tok = strtok_r(NULL, "+", &next) ;
	strcpy(caller_name, tok) ;

	tok = strtok_r(NULL, "[", &next) ;
	tok = strtok_r(NULL, "]", &next) ;
	strcpy(pc_val, tok) ;

	sprintf(cov_string, "%s,%s,%s", callee_name, caller_name, pc_val) ;

	return 1 ;
}

void
get_coverage (char * cov_string)
{
	curr_stat = attatch_shm(curr_stat_shmid) ;

	unsigned int id = hash16(cov_string) ;

	int found = 0 ;
	for (int i = 0; i < FUNCOV_MAP_SIZE; i++) {
		if (id >= FUNCOV_MAP_SIZE) {
			id = 0 ;
			continue ;
		}

		if (curr_stat->map[id].hit_count == 0) {
			strcpy(curr_stat->map[id].cov_string, cov_string) ;
			curr_stat->map[id].hit_count++ ;
			found = 1 ;
			break ;
		}
		else if (strcmp(curr_stat->map[id].cov_string, cov_string) == 0) {
			curr_stat->map[id].hit_count++ ;
			found = 1 ;
			break ;
		}
		else id++ ;
	}
	if (!found) {
		perror("get_coverage: map limit") ;
		exit(1) ; 
	}

	detatch_shm(curr_stat) ;
}

extern void 
__sanitizer_cov_trace_pc_guard(uint32_t *guard) 
{
	if (!*guard) return;  

	void * callee = __builtin_return_address(0) ;
	void * caller = __builtin_return_address(1) ;

	char callee_str[STR_BUFF] ;
	__sanitizer_symbolize_pc(callee, "%f", callee_str, sizeof(callee_str)) ;
	char caller_str[STR_BUFF] ;
	__sanitizer_symbolize_pc(caller, "%f,%p", caller_str, sizeof(caller_str)) ;

	char cov_string[STR_BUFF * 2] ;
	sprintf(cov_string, "%s,%s", callee_str, caller_str) ;

	get_coverage(cov_string) ;

	free(strings) ;
}
