#include "modules.h"

enum nss_status cache_getpwnam_r(const char *a, struct passwd *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_getpwuid_r(uid_t a, struct passwd *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
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
