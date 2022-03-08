#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "./cJSON.h"

#define BUF_SIZE 1024

void
simple_parse_and_print (char * input)
{
    cJSON * parsed_input = cJSON_Parse(input) ;
    if (parsed_input == 0x0) {
        perror("simple_parse_and_print: cJSON_Parse failed") ;
        return ;
    }

    printf("\n=========================================\n") ;
    printf("PARSE: FORMATTED\n") ;
    printf("=========================================\n") ;
    char * printed = cJSON_Print(parsed_input) ;
    printf("%s\n", printed) ;
    free(printed) ;

    printf("\n=========================================\n") ;
    printf("PARSE: UNFORMATTED\n") ;
    printf("=========================================\n") ;
    printed = cJSON_PrintUnformatted(parsed_input) ;
    printf("%s\n", printed) ;
    free(printed) ;

    cJSON_Delete(parsed_input) ;
}

int
main (int argc, char * argv[])
{
    char * input = (char *) malloc(sizeof(char) * BUF_SIZE) ;
    char c ;
    int input_len ;
    for (input_len = 0; (c = getchar()) != EOF && c != 4; input_len++) {    // 3 : ctrl+D
        if ((input_len + 1) % BUF_SIZE == 0 && input_len != 0) {
            input = realloc(input, sizeof(char) * BUF_SIZE * (BUF_SIZE / (input_len + 1) + 1)) ;
        }
        input[input_len] = c ;
    }
    input[input_len] = 0x0 ;
    
#ifdef DEBUG
    printf("%s", input) ;
#endif

    simple_parse_and_print(input) ;

    return 0 ;
}