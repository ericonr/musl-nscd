#include <stdlib.h>
#include <pthread.h>

#include "modules.h"

/* consider coalescing getpw* into a single cache; security considerations? */
enum nss_status cache_getpwnam_r(const char *a, struct passwd *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
}

struct pwuid_result {
	uid_t id;
	struct passwd *p;
	char *b;
};
/* a LRU cache is probably the best option? */
struct pwuid_cache {
	pthread_rwlock_t lock;
	struct pwuid_result *res;
	size_t len, size;
};
/* might be more correct/simpler to directly call the cache functions and
 * memcpy passwd into them, but using the cache buffer */
static struct pwuid_cache pwuid_cache = { .lock = PTHREAD_RWLOCK_INITIALIZER, .size = 128 };
enum nss_status cache_getpwuid_r(uid_t id, struct passwd *b, char *c, size_t d, int *e)
{
	enum nss_status ret = NSS_STATUS_NOTFOUND;
	pthread_rwlock_rdlock(&pwuid_cache.lock);
	for(size_t i = 0; i < pwuid_cache.len; i++) {
		if (pwuid_cache.res[i].id == id) {
			/* TODO: implement passwd copy -
			 * alternatively, implement cache awareness so we can just memcpy one
			 * passwd into another and track the buffer appropriately;
			 * we will need some level of cache awareness anyway to deal with *storing* values into the cache */
			ret = NSS_STATUS_SUCCESS;
			goto cleanup;
		}
	}
cleanup:
	pthread_rwlock_unlock(&pwuid_cache.lock);
	return ret;
}

enum nss_status cache_getgrnam_r(const char *a, struct group *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_getgrgid_r(gid_t a, struct group *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_initgroups_dyn(const char *a, gid_t b, long *c, long *d, gid_t **e, long f, int *g)
{
	return NSS_STATUS_NOTFOUND;
}

int init_caches(void)
{
	//if(pthread_rwlock_init(&pwuid_cache.lock, 0)) return -1;
	if(!(pwuid_cache.res = malloc(pwuid_cache.size * sizeof(*pwuid_cache.res)))) return -1;

	return 0;
}
