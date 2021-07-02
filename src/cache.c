#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "modules.h"

static int cache = 0;
#define IS_CACHING if(!cache) { *err = 0; return NSS_STATUS_UNAVAIL; }
#define IS_CACHING_FOR_WRITE(storage_buffer) if(!cache) { free(storage_buffer); return -1; }

/* 10 minutes, stored as seconds */
#define CACHE_INVALIDATION_TIME (10 * 60)

/* max cache entries; TODO: make configurable */
#define CACHE_MAX_ENTRIES 100000
#define CACHE_INITIAL_ENTRIES 512

static time_t monotonic_seconds(void)
{
	struct timespec res;
	if(clock_gettime(CLOCK_MONOTONIC, &res)) {
		/* this should never happen; abort? */
		perror("clock_gettime");
		return 0;
	}

	return res.tv_sec;
}

static bool validate_timestamp(time_t t)
{
	return (monotonic_seconds() - t) < CACHE_INVALIDATION_TIME;
}

struct passwd_result {
	struct passwd *p;
	char *b;
	/* for validation */
	time_t t;
};
struct passwd_cache {
	pthread_rwlock_t lock;
	struct passwd_result *res;
	size_t len, size;
};

static struct passwd_cache passwd_cache =
	{ .lock = PTHREAD_RWLOCK_INITIALIZER, .size = CACHE_INITIAL_ENTRIES };

enum nss_status cache_getpwnam_r(const char *name, struct passwd *p, char *buf, size_t buf_len, int *err)
{
	IS_CACHING
	enum nss_status ret = NSS_STATUS_NOTFOUND;

	pthread_rwlock_rdlock(&passwd_cache.lock);

	for(size_t i = 0; i < passwd_cache.len; i++) {
		struct passwd_result *res = &passwd_cache.res[i];
		if (strcmp(res->p->pw_name, name) == 0) {
			if(!validate_timestamp(res->t)) {
				break;
			}
			memcpy(p, passwd_cache.res[i].p, sizeof(*p));
			ret = NSS_STATUS_SUCCESS;
			break;
		}
	}

	pthread_rwlock_unlock(&passwd_cache.lock);
	return ret;
}

enum nss_status cache_getpwuid_r(uid_t id, struct passwd *p, char *buf, size_t buf_len, int *err)
{
	IS_CACHING

	enum nss_status ret = NSS_STATUS_NOTFOUND;

	pthread_rwlock_rdlock(&passwd_cache.lock);

	for(size_t i = 0; i < passwd_cache.len; i++) {
		struct passwd_result *res = &passwd_cache.res[i];
		if (res->p->pw_uid == id) {
			if(!validate_timestamp(res->t)) {
				break;
			}
			memcpy(p, passwd_cache.res[i].p, sizeof(*p));
			ret = NSS_STATUS_SUCCESS;
			break;
		}
	}

	pthread_rwlock_unlock(&passwd_cache.lock);
	return ret;
}

/* increment cache->len and store the index for that new member in index */
bool cache_passwd_increment_len(struct passwd_cache *cache, size_t *index)
{
	/* first simply try to increment len */
	if(cache->len < cache->size) {
		*index = cache->len++;
		return true;
	}

	/* otherwise, try to increase cache size */

	if(cache->size >= CACHE_MAX_ENTRIES)
		return false;

	size_t new_size;
	/* memory growth factor is 1.5x; see socket_handle.c for a similar impl */
	if(cache->size > CACHE_MAX_ENTRIES - cache->size/2)
		new_size = CACHE_MAX_ENTRIES;
	else
		new_size = cache->size + cache->size/2;

	/* XXX: doesn't check for multiplication overflow */
	void *tmp = realloc(cache->res, new_size * sizeof(*cache->res));
	if(!tmp)
		return false;

	cache->size = new_size;
	cache->res = tmp;
	*index = cache->len++;
	return true;
}

/* this function copies the passwd struct p points to and
 * takes ownership of the buffer b points to */
int cache_passwd_add(struct passwd *p, char *b)
{
	IS_CACHING_FOR_WRITE(b);

	int ret = 0;
	/* variables for dealing with duplicates */
	size_t i;
	bool found_outdated = false;

	/* studying the effects of contention on this lock might be important */
	pthread_rwlock_wrlock(&passwd_cache.lock);

	/* check if the new value hasn't been added by another thread */
	for(i = 0; i < passwd_cache.len; i++) {
		struct passwd_result *res = &passwd_cache.res[i];
		/* since the UID is canonical, we only need to look for it to check for duplicates */
		if (res->p->pw_uid == p->pw_uid) {
			/* valid entry */
			if(validate_timestamp(res->t)) {
				goto cleanup;
			}
			/* outdated entry, should be replaced */
			found_outdated = true;
			break;
		}
	}

	/* if we are here, we are necessarily going to add something to the cache */
	struct passwd_result *res;;
	if(found_outdated) {
		res = &passwd_cache.res[i];

		/* we can re-use the cache entry's passwd struct */
		memcpy(res->p, p, sizeof(*p));
		/* but we still need to free its underlying storage */
		free(res->b);
	} else {
		/* TODO: if resizing fails, we can scan the cache for an outdated
		 * entry and overwrite it */
		if(!cache_passwd_increment_len(&passwd_cache, &i))
			goto cleanup;

		res = &passwd_cache.res[i];

		struct passwd *copy = malloc(sizeof(*copy));
		if(!copy) {
			ret = -1;
			goto cleanup;
		}
		memcpy(copy, p, sizeof(*p));

		res->p = copy;
	}
	res->b = b;
	b = 0;
	res->t = monotonic_seconds();

cleanup:
	/* if insertion fails, we should free the buffer */
	free(b);
	pthread_rwlock_unlock(&passwd_cache.lock);
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

#define CACHE_ON_STATUS {ACT_RETURN, ACT_CONTINUE, ACT_CONTINUE, ACT_CONTINUE}
struct mod_passwd cache_modp =
	{ .nss_getpwnam_r = cache_getpwnam_r, .nss_getpwuid_r = cache_getpwuid_r, .on_status = CACHE_ON_STATUS };
struct mod_group cache_modg =
	{ .nss_getgrnam_r = cache_getgrnam_r, .nss_getgrgid_r = cache_getgrgid_r,
	  .nss_initgroups_dyn = cache_initgroups_dyn, .on_status = CACHE_ON_STATUS };

int init_caches(void)
{
	if(!(passwd_cache.res = malloc(passwd_cache.size * sizeof(*passwd_cache.res)))) return -1;

	cache = 1;
	return 0;
}
