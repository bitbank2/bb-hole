CFLAGS=-c -static -ggdb -Wall -O0
#LIBS = -lm -loled96 -lpthread
LIBS = -lm -lpthread

all: bbhole

bbhole: main.o pil_io.o
	$(CC) main.o pil_io.o $(LIBS) -g -o bbhole

pil_io.o: pil_io.c
	$(CC) $(CFLAGS) pil_io.c

main.o: main.c
	$(CC) $(CFLAGS) main.c

clean:
	rm *o bbhole

