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
	#define CACHE passwd_cache
	#define RESULT_TYPE passwd_result
	#define COMPARISON() (strcmp(res->p->pw_name, name) == 0)
	#define ARGUMENT p
	#include "cache_query.h"
}

enum nss_status cache_getpwuid_r(uid_t id, struct passwd *p, char *buf, size_t buf_len, int *err)
{
	#define CACHE passwd_cache
	#define RESULT_TYPE passwd_result
	#define COMPARISON() (res->p->pw_uid == id)
	#define ARGUMENT p
	#include "cache_query.h"
}

/* increment len and store the index for that new member in index */
static bool cache_increment_len(size_t *len, size_t *size, size_t sizeof_element, void **data, size_t *index)
{
	/* first simply try to increment len */
	if(*len < *size) {
		*index = (*len)++;
		return true;
	}

	/* otherwise, try to increase cache size */

	if(*size >= CACHE_MAX_ENTRIES)
		return false;

	size_t new_size;
	/* memory growth factor is 1.5x; see socket_handle.c for a similar impl */
	if(*size > CACHE_MAX_ENTRIES - *size/2)
		new_size = CACHE_MAX_ENTRIES;
	else
		new_size = *size + *size/2;

	/* XXX: doesn't check for multiplication overflow */
	void *tmp = realloc(*data, new_size * sizeof_element);
	if(!tmp)
		return false;

	*size = new_size;
	*data = tmp;
	*index = (*len)++;
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
		void *tmp_pointer = passwd_cache.res;
		if(!cache_increment_len(&passwd_cache.len, &passwd_cache.size, sizeof(*passwd_cache.res), &tmp_pointer, &i))
			goto cleanup;
		passwd_cache.res = tmp_pointer;

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

struct group_result {
	struct group *g;
	char *b;
	/* for validation */
	time_t t;
};
struct group_cache {
	pthread_rwlock_t lock;
	struct group_result *res;
	size_t len, size;
};

static struct group_cache group_cache =
	{ .lock = PTHREAD_RWLOCK_INITIALIZER, .size = CACHE_INITIAL_ENTRIES };

enum nss_status cache_getgrnam_r(const char *name, struct group *g, char *buf, size_t buf_len, int *err)
{
	#define CACHE group_cache
	#define RESULT_TYPE group_result
	#define COMPARISON() (strcmp(res->g->gr_name, name) == 0)
	#define ARGUMENT g
	#include "cache_query.h"
}

enum nss_status cache_getgrgid_r(gid_t id, struct group *g, char *buf, size_t buf_len, int *err)
{
	#define CACHE group_cache
	#define RESULT_TYPE group_result
	#define COMPARISON() (res->g->gr_gid == id)
	#define ARGUMENT g
	#include "cache_query.h"
}

/* this function copies the group struct p points to and
 * takes ownership of the buffer b points to */
int cache_group_add(struct group *g, char *b)
{
	IS_CACHING_FOR_WRITE(b);

	int ret = 0;
	/* variables for dealing with duplicates */
	size_t i;
	bool found_outdated = false;

	/* studying the effects of contention on this lock might be important */
	pthread_rwlock_wrlock(&group_cache.lock);

	/* TODO: store the index for the oldest entry, use it if we don't replace
	 * an old one of our own */

	/* check if the new value hasn't been added by another thread */
	for(i = 0; i < group_cache.len; i++) {
		struct group_result *res = &group_cache.res[i];
		/* since the GID is canonical, we only need to look for it to check for duplicates */
		if (res->g->gr_gid == g->gr_gid) {
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
	struct group_result *res;;
	if(found_outdated) {
		res = &group_cache.res[i];

		/* we can re-use the cache entry's group struct */
		memcpy(res->g, g, sizeof(*g));
		/* but we still need to free its underlying storage */
		free(res->b);
	} else {
		/* TODO: if resizing fails, we can scan the cache for an outdated
		 * entry and overwrite it */
		void *tmp_pointer = group_cache.res;
		if(!cache_increment_len(&group_cache.len, &group_cache.size, sizeof(*group_cache.res), &tmp_pointer, &i))
			goto cleanup;
		group_cache.res = tmp_pointer;

		res = &group_cache.res[i];

		struct group *copy = malloc(sizeof(*copy));
		if(!copy) {
			ret = -1;
			/* TODO: fix wrong value for len */
			goto cleanup;
		}
		memcpy(copy, g, sizeof(*g));

		res->g = copy;
	}
	res->b = b;
	b = 0;
	res->t = monotonic_seconds();

cleanup:
	/* if insertion fails, we should free the buffer */
	free(b);
	pthread_rwlock_unlock(&group_cache.lock);
	return ret;
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
	if(!(group_cache.res = malloc(group_cache.size * sizeof(*group_cache.res)))) return -1;

	cache = 1;
	return 0;
}
