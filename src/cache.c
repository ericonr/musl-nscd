#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "modules.h"

static int cache = 0;
#define IS_CACHING if(!cache) { *err = 0; return NSS_STATUS_UNAVAIL; }
#define IS_CACHING_FOR_WRITE if(!cache) { return -1; }

/* consider coalescing getpw* into a single cache; security considerations? */
enum nss_status cache_getpwnam_r(const char *a, struct passwd *b, char *c, size_t d, int *err)
{
	IS_CACHING
	return NSS_STATUS_NOTFOUND;
}

struct pwuid_result {
	struct passwd *p;
	char *b;
	/* we don't handle cases where the action isn't ACT_RETURN (ACT_CONTINUE and/or ACT_MERGE?) */
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
enum nss_status cache_getpwuid_r(uid_t id, struct passwd *p, char *a, size_t b, int *err)
{
	IS_CACHING

	enum nss_status ret = NSS_STATUS_NOTFOUND;
	pthread_rwlock_rdlock(&pwuid_cache.lock);
	for(size_t i = 0; i < pwuid_cache.len; i++) {
		if (pwuid_cache.res[i].p->pw_uid == id) {
			puts("match cache");
			memcpy(p, pwuid_cache.res[i].p, sizeof(*p));
			ret = NSS_STATUS_SUCCESS;
			goto cleanup;
		}
	}
cleanup:
	pthread_rwlock_unlock(&pwuid_cache.lock);
	return ret;
}

enum nss_status cache_getgrnam_r(const char *a, struct group *b, char *c, size_t d, int *err)
{
	IS_CACHING
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_getgrgid_r(gid_t a, struct group *b, char *c, size_t d, int *err)
{
	IS_CACHING
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_initgroups_dyn(const char *a, gid_t b, long *c, long *d, gid_t **e, long f, int *err)
{
	IS_CACHING
	return NSS_STATUS_NOTFOUND;
}

struct mod_passwd cache_modp = { .nss_getpwnam_r = cache_getpwnam_r, .nss_getpwuid_r = cache_getpwuid_r };
struct mod_group cache_modg =
	{ .nss_getgrnam_r = cache_getgrnam_r, .nss_getgrgid_r = cache_getgrgid_r, .nss_initgroups_dyn = cache_initgroups_dyn };

int init_caches(void)
{
	//if(pthread_rwlock_init(&pwuid_cache.lock, 0)) return -1;
	if(!(pwuid_cache.res = malloc(pwuid_cache.size * sizeof(*pwuid_cache.res)))) return -1;

	const action on_status[4] = {ACT_RETURN, ACT_CONTINUE, ACT_RETURN, ACT_RETURN};
	memcpy(cache_modp.on_status, on_status, sizeof(on_status));
	memcpy(cache_modg.on_status, on_status, sizeof(on_status));

	cache = 1;

	return 0;
}
