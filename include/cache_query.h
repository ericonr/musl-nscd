IS_CACHING

enum nss_status ret = NSS_STATUS_NOTFOUND;

pthread_rwlock_rdlock(&CACHE.lock);

for(size_t i = 0; i < CACHE.len; i++) {
	struct RESULT_TYPE *res = &CACHE.res[i];
	if (COMPARISON()) {
		if(!validate_timestamp(res->t)) {
			break;
		}
		char **new_buf = (void *)buf;
		*new_buf = malloc(res->l);
		if(!*new_buf) {
			*err = errno;
			break;
		}
		COPY_FUNCTION(ARGUMENT, *new_buf, &CACHE.res[i].ARGUMENT, CACHE.res[i].b, res->l);
		ret = NSS_STATUS_SUCCESS;
		break;
	}
}

pthread_rwlock_unlock(&CACHE.lock);
return ret;

/* avoid polluting lines after this file is included */
#undef CACHE
#undef RESULT_TYPE
#undef COMPARISON
#undef ARGUMENT
#undef COPY_FUNCTION
