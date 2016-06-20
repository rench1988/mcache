

FLAG = -Wall -Werror -c -o

OBJ = mcache.o ngx_rbtree.o ngx_queue.o

libmcache.a: $(OBJ)
	ar rcs libmcache.a $(OBJ)

mcache.o: 
	gcc $(FLAG) mcache.o mcache.c
ngx_rbtree.o:
	gcc $(FLAG) ngx_rbtree.o ngx_rbtree.c
ngx_queue.o:
	gcc $(FLAG) ngx_queue.o ngx_queue.c

.PHONY: clean

clean:
	rm -rf libmcache.a $(OBJ)

