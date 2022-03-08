CC=gcc
TARGETS=cJSON_example.c 
LIBS=cJSON.c 
OBJS=cJSON.o

all: $(TARGETS) $(LIBS)
	$(CC) -o $@ $(EXECS) $(TARGETS) $(LIBS) $(CFLAGS)

clean:
	rm -rf $(EXECS) $(OBJS)