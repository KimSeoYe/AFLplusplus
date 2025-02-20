#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

#define BUF_SIZE 1024

static const uint8_t *data;
static size_t dataLen;

static void check_compress_level(uint8_t *compr, size_t comprLen,
                                 uint8_t *uncompr, size_t uncomprLen,
                                 int level) {
  compress2(compr, &comprLen, data, dataLen, level);
  uncompress(uncompr, &uncomprLen, compr, comprLen);

  /* Make sure compress + uncompress gives back the input data. */
  assert(dataLen == uncomprLen);
  assert(0 == memcmp(data, uncompr, dataLen));
}

#define put_byte(s, i, c) {s[i] = (unsigned char)(c);}

static void write_zlib_header(uint8_t *s) {
  unsigned level_flags = 0; /* compression level (0..3) */
  unsigned w_bits = 8; /* window size log2(w_size)  (8..16) */
  unsigned int header = (Z_DEFLATED + ((w_bits-8)<<4)) << 8;
  header |= (level_flags << 6);

  header += 31 - (header % 31);

  /* s is guaranteed to be longer than 2 bytes. */
  put_byte(s, 0, (unsigned char)(header >> 8));
  put_byte(s, 1, (unsigned char)(header & 0xff));
}

static void check_decompress(uint8_t *compr, size_t comprLen) {
  /* We need to write a valid zlib header of size two bytes. Copy the input data
     in a larger buffer. Do not modify the input data to avoid libFuzzer error:
     fuzz target overwrites its const input. */
  size_t copyLen = dataLen + 2;
  uint8_t *copy = (uint8_t *)malloc(copyLen);
  memcpy(copy + 2, data, dataLen);
  write_zlib_header(copy);

  uncompress(compr, &comprLen, copy, copyLen);
  free(copy);
}

int compress_and_decompress(const uint8_t *d, size_t size) {
  /* compressBound does not provide enough space for low compression levels. */
  size_t comprLen = 100 + 2 * compressBound(size);
  size_t uncomprLen = size;
  uint8_t *compr, *uncompr;

  /* Discard inputs larger than 1Mb. */
  static size_t kMaxSize = 1024 * 1024;

  if (size < 1 || size > kMaxSize)
    return 0;

  data = d;
  dataLen = size;
  compr = (uint8_t *)calloc(1, comprLen);
  uncompr = (uint8_t *)calloc(1, uncomprLen);

  check_compress_level(compr, comprLen, uncompr, uncomprLen, 1);
  check_compress_level(compr, comprLen, uncompr, uncomprLen, 3);
  check_compress_level(compr, comprLen, uncompr, uncomprLen, 6);
  check_compress_level(compr, comprLen, uncompr, uncomprLen, 7);

  check_decompress(compr, comprLen);

  free(compr);
  free(uncompr);

  /* This function must return 0. */
  return 0;
}

int main () {
	int buf_block_cnt = 1 ;
    char * input = (char *) malloc(sizeof(char) * BUF_SIZE * buf_block_cnt) ;
    char c ;
    int input_len ;
    for (input_len = 0; (c = getchar()) != EOF && c != 4; input_len++) {    // 4 : ctrl+D
        if ((input_len + 1) % BUF_SIZE == 0 && input_len != 0) {
            buf_block_cnt++;
            input = realloc(input, sizeof(char) * BUF_SIZE * buf_block_cnt) ;
        }
        input[input_len] = c ;
    }

    if (input_len >= BUF_SIZE * buf_block_cnt) {
        input = realloc(input, sizeof(char) * (BUF_SIZE * buf_block_cnt + 1)) ;
    }
    input[input_len] = 0x0 ;
	
	compress_and_decompress((uint8_t *) input, input_len) ;

	return 0 ;
}
