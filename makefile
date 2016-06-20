

OBJ := $(wildcard *.o)

libmcache.a: $(OBJ)
	ar rcs libmcache.a $(OBJ)

mcache.o: 
	gcc -c -o mcache.o mcache.c
ngx_rbtree.o:
	gcc -c -o ngx_rbtree.o ngx_rbtree.c
ngx_queue.o:
	gcc -c -o ngx_queue.o ngx_queue.c

.PHONY: clean

clean:
	rm -rf libmcache.a $(OBJ)

