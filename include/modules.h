#ifndef MODULES_H
#define MODULES_H

#include <pwd.h>
#include <grp.h>
#include "nss.h"
#include "parse.h"
#include "list.h"

typedef enum nss_status (*nss_getgrnam_r)(const char*, struct group*, char*, size_t, int*);
typedef enum nss_status (*nss_getgrgid_r)(gid_t, struct group*, char*, size_t, int*);
typedef enum nss_status (*nss_initgroups_dyn)(const char*, gid_t, long*, long*, gid_t**, long, int*);
typedef enum nss_status (*nss_getpwnam_r)(const char*, struct passwd*, char*, size_t, int*);
typedef enum nss_status (*nss_getpwuid_r)(uid_t, struct passwd*, char*, size_t, int*);

struct mod_group {
	nss_getgrnam_r nss_getgrnam_r;
	nss_getgrgid_r nss_getgrgid_r;
	nss_initgroups_dyn nss_initgroups_dyn;
	action on_status[4];
	link_t link;
};

struct mod_passwd {
	nss_getpwnam_r nss_getpwnam_r;
	nss_getpwuid_r nss_getpwuid_r;
	action on_status[4];
	link_t link;
};

extern list_t passwd_mods;
extern list_t group_mods;

extern struct mod_passwd cache_modp;
extern struct mod_group cache_modg;

enum nss_status cache_getpwnam_r(const char *, struct passwd *, char *, size_t, int *);
enum nss_status cache_getpwuid_r(uid_t, struct passwd *, char *, size_t, int *);
enum nss_status cache_getgrnam_r(const char *, struct group *, char *, size_t, int *);
enum nss_status cache_getgrgid_r(gid_t, struct group *, char *, size_t, int *);
enum nss_status cache_initgroups_dyn(const char *, gid_t, long *, long *, gid_t **, long , int *);
int init_caches(void);

#endif
