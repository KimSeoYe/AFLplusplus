CC?=gcc
TARGETS=cJSON_example.c 
LIBS=cJSON.c 
OBJS=cJSON.o

all: cJSON_example

.PHONY: cJSON_example
cJSON_example: $(TARGETS) $(LIBS)
	$(CC) -o $@ $(TARGETS) $(LIBS)

clean:
	rm -rf cJSON_example $(OBJS)