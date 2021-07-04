IS_CACHING_FOR_WRITE(BUFFER);

int ret = 0;
/* variables for dealing with duplicates */
size_t i;
bool found_outdated = false;

/* studying the effects of contention on this lock might be important */
pthread_rwlock_wrlock(&CACHE.lock);

/* TODO: store the index for the oldest entry, use it if we don't replace
 * an old one of our own */

/* check if the new value hasn't been added by another thread */
for(i = 0; i < CACHE.len; i++) {
	struct RESULT_TYPE *res = &CACHE.res[i];
	/* since the ID is canonical, we only need to look for it to check for duplicates */
	if (COMPARISON()) {
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
struct RESULT_TYPE *res;;
if(found_outdated) {
	res = &CACHE.res[i];

	/* we can re-use the cache entry's passwd struct */
	memcpy(res->ARGUMENT, ARGUMENT, sizeof(*ARGUMENT));
	/* but we still need to free its underlying storage */
	free(res->b);
} else {
	/* TODO: if resizing fails, we can scan the cache for an outdated
	 * entry and overwrite it */
	void *tmp_pointer = CACHE.res;
	if(!cache_increment_len(&CACHE.len, &CACHE.size, sizeof(*CACHE.res), &tmp_pointer, &i))
		goto cleanup;
	CACHE.res = tmp_pointer;

	res = &CACHE.res[i];

	DATA_TYPE *copy = malloc(sizeof(*copy));
	if(!copy) {
		/* TODO: fix wrong value for len if allocation fails */
		ret = -1;
		goto cleanup;
	}
	memcpy(copy, ARGUMENT, sizeof(*ARGUMENT));

	res->ARGUMENT = copy;
}
res->b = b;
b = 0;
res->t = monotonic_seconds();

cleanup:
pthread_rwlock_unlock(&CACHE.lock);
/* if insertion fails, we should free the buffer */
free(b);
return ret;

#undef BUFFER
#undef CACHE
#undef RESULT_TYPE
#undef DATA_TYPE
#undef COMPARISON
#undef ARGUMENT
