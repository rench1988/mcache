#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include "mcache.h"

#define MEMSIZE 32 * 1024 * 1024

#define KEY_NUM 100000

#define THREAD_NUM 5

int funtional_test(void)
{
	int          res;
	uint32_t     value;

	char         err_buf[1024];

	fprintf(stderr, "Funtional Test Start...\n");

	mcache_kv_t *kvs;

	kvs = mcache_kv_init(MEMSIZE, err_buf, sizeof(err_buf));
	if (kvs == NULL) {
		fprintf(stderr, "mcache_kv_init failed: %s\n", err_buf);
		exit(-1);
	}

	res = mcache_kv_set(kvs, "test", 77);
	if (res) {
		fprintf(stderr, "mcache_kv_set failed: %s\n", mcache_estr(res));
		exit(-1);
	}

	res = mcache_kv_get(kvs, "test", &value);
	if (res) {
		fprintf(stderr, "mcache_kv_get failed: %s\n", mcache_estr(res));
		exit(-1);		
	}

	assert(mcache_kv_count(kvs) == 1);
	assert(value == 77);

	res = mcache_kv_delete(kvs, "test");
	if (res) {
		fprintf(stderr, "mcache_kv_delete failed: %s\n", mcache_estr(res));
		exit(-1);
	}

	assert(mcache_kv_count(kvs) == 0);

	res = mcache_kv_free(kvs);
	if (res) {
		fprintf(stderr, "mcache_kv_free failed: %s\n", mcache_estr(res));
		exit(-1);
	}

	fprintf(stderr, "Funtional Test Passed!\n");

	return 0;
}

int bench_test(void)
{
	int  i;
	int  res;
	char key[64];
	uint32_t value;

	static const char *key_pre = "key_";

	char         err_buf[1024];

	fprintf(stderr, "Bench Test Start...\n");

	mcache_kv_t *kvs;

	kvs = mcache_kv_init(MEMSIZE, err_buf, sizeof(err_buf));
	if (kvs == NULL) {
		fprintf(stderr, "mcache_kv_init failed: %s\n", err_buf);
		exit(-1);
	}

	for (i = 0; i < KEY_NUM; ++i) {
		sprintf(key, "%s%d", key_pre, i);

		res = mcache_kv_set(kvs, key, i);
		if (res) {
			fprintf(stderr, "mcache_kv_set failed: %s\n", mcache_estr(res));
			exit(-1);
		}

		assert(mcache_kv_count(kvs) == i + 1);
	}

	for (i = 0; i < KEY_NUM; ++i) {
		sprintf(key, "%s%d", key_pre, i);

		res = mcache_kv_get(kvs, key, &value);
		if (res) {
			fprintf(stderr, "mcache_kv_get failed: %s\n", mcache_estr(res));
			exit(-1);
		}
	
		assert(value == i);
	}

	for (i = 0; i < KEY_NUM; ++i) {
		sprintf(key, "%s%d", key_pre, i);

		res = mcache_kv_delete(kvs, key);
		if (res) {
			fprintf(stderr, "mcache_kv_delete failed: %s\n", mcache_estr(res));
			exit(-1);
		}

		assert(mcache_kv_count(kvs) == KEY_NUM - i - 1);
	}

	res = mcache_kv_free(kvs);
	if (res) {
		fprintf(stderr, "mcache_kv_free failed: %s\n", mcache_estr(res));
		exit(-1);
	}

	fprintf(stderr, "Bench Test Passed!\n");

	return 0;
}

typedef struct {
	mcache_kv_t  *kvs;

	int 		  start;
	int 		  end;
} task_t;

void *t_fun(void *arg) {
	task_t *task = (task_t *)arg;

	int  i;
	int  res;
	char key[64];
	uint32_t value;

	static const char *key_pre = "key_";

	mcache_kv_t *kvs = task->kvs;

	for (i = task->start; i <= task->end; ++i) {
		sprintf(key, "%s%d", key_pre, i);

		res = mcache_kv_set(kvs, key, i);
		if (res) {
			fprintf(stderr, "mcache_kv_set failed: %s\n", mcache_estr(res));
			exit(-1);
		}
	}

	for (i = task->start; i <= task->end; ++i) {
		sprintf(key, "%s%d", key_pre, i);

		res = mcache_kv_get(kvs, key, &value);
		if (res) {
			fprintf(stderr, "mcache_kv_get failed: %s\n", mcache_estr(res));
			exit(-1);
		}
	
		assert(value == i);
	}

	for (i = task->start; i <= task->end; ++i) {
		sprintf(key, "%s%d", key_pre, i);

		res = mcache_kv_delete(kvs, key);
		if (res) {
			fprintf(stderr, "mcache_kv_delete failed: %s\n", mcache_estr(res));
			exit(-1);
		}

	}

	return NULL;	
}

int multi_thread_test()
{
	int i;
	int res;
	pthread_t tid[THREAD_NUM];
	task_t *tasks;

	int per_num = KEY_NUM / THREAD_NUM;

	fprintf(stderr, "Multi-Thread Test Start...\n");

	char         err_buf[1024];
	mcache_kv_t *kvs;

	kvs = mcache_kv_init(MEMSIZE, err_buf, sizeof(err_buf));
	if (kvs == NULL) {
		fprintf(stderr, "mcache_kv_init failed: %s\n", err_buf);
		exit(-1);
	}

	tasks = malloc(THREAD_NUM * sizeof(task_t));

	for (i = 0; i < THREAD_NUM; i++) {
		tasks[i].start = per_num * i;
		tasks[i].end = per_num * (i + 1) - 1;
		tasks[i].kvs = kvs;

		res = pthread_create(&tid[i], NULL, t_fun, &tasks[i]);
		if (res) {
			fprintf(stderr, "pthread_create failed\n");
			exit(-1);
		}
	}

	for (i = 0; i < THREAD_NUM; i++) {
		pthread_join(tid[i], NULL);
	}

	assert(mcache_kv_count(kvs) == 0);

	fprintf(stderr, "Multi-Thread Test End...\n");
}


int main(int argc, char const *argv[])
{
	funtional_test();

	bench_test();

	multi_thread_test();

	return 0;
}
