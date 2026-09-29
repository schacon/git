#include "test-tool.h"
#include "hash.h"

#if defined(SHA1_DC) && !defined(DC_SHA1_EXTERNAL) && !defined(DC_SHA1_NO_ACCEL)
#include "sha1dc-accel/sha1.h"
#define HAVE_SHA1DC_ACCEL
#endif

int cmd__sha1(int ac, const char **av)
{
#ifdef HAVE_SHA1DC_ACCEL
	const char *backend = getenv("GIT_TEST_SHA1DC_BACKEND");

	if (backend && sha1dc_accel_select(backend))
		die("sha1dc backend '%s' is not available", backend);
#endif
	return cmd_hash_impl(ac, av, GIT_HASH_SHA1, 0);
}

int cmd__sha1_is_sha1dc(int argc UNUSED, const char **argv UNUSED)
{
#ifdef platform_SHA_IS_SHA1DC
	return 0;
#endif
	return 1;
}

/*
 * Lists the implementations of collision-detecting SHA-1 this build and
 * CPU can use, which GIT_TEST_SHA1DC_BACKEND selects for "test-tool sha1".
 */
int cmd__sha1dc_backends(int argc UNUSED, const char **argv UNUSED)
{
#ifdef HAVE_SHA1DC_ACCEL
	const char *const *names;

	for (names = sha1dc_accel_backends(); *names; names++)
		puts(*names);
#endif
	return 0;
}

int cmd__sha1_unsafe(int ac, const char **av)
{
	return cmd_hash_impl(ac, av, GIT_HASH_SHA1, 1);
}
