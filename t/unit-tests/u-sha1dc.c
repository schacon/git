#include "unit-test.h"
#include "hash.h"

/*
 * Tests sha1dc-accel/ against sha1dc/, which it must agree with exactly.
 */
#if defined(SHA1_DC) && !defined(DC_SHA1_EXTERNAL) && !defined(DC_SHA1_NO_ACCEL)
#define HAVE_SHA1DC_ACCEL

#include "sha1dc-accel/sha1.h"

static uint64_t rng_state;

static void rng_seed(uint64_t seed)
{
	rng_state = seed * 2 + 1;
}

static uint32_t rng(void)
{
	/* xorshift64* */
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * 0x2545F4914F6CDD1DULL) >> 32);
}

/*
 * Hashes `buf` with sha1dc/ and with sha1dc-accel/ under the same settings
 * and checks that both agree. Returns whether they found a collision.
 */
static int check_same(const unsigned char *buf, size_t len, int split,
		      int safe_hash, int ubc, int reduced_round)
{
	SHA1_CTX want_ctx, got_ctx;
	unsigned char want[20], got[20];
	int want_coll, got_coll;

	SHA1DCInit(&want_ctx);
	SHA1DCSetSafeHash(&want_ctx, safe_hash);
	SHA1DCSetUseUBC(&want_ctx, ubc);
	SHA1DCSetDetectReducedRoundCollision(&want_ctx, reduced_round);
	got_ctx = want_ctx;

	SHA1DCUpdate(&want_ctx, (const char *)buf, len);
	want_coll = SHA1DCFinal(want, &want_ctx);

	sha1dc_accel_update(&got_ctx, buf, split);
	sha1dc_accel_update(&got_ctx, buf + split, len - split);
	got_coll = sha1dc_accel_final(got, &got_ctx);

	cl_assert_equal_i(got_coll, want_coll);
	cl_assert(!memcmp(got, want, sizeof(want)));
	return got_coll;
}

static void every_backend_agrees_with_sha1dc(void)
{
	const char *const *names = sha1dc_accel_backends();
	unsigned char buf[4200];
	const char *orig = sha1dc_accel_backend();

	for (; *names; names++) {
		size_t i;

		cl_assert_equal_i(sha1dc_accel_select(*names), 0);
		rng_seed(1);
		for (i = 0; i < sizeof(buf); i++)
			buf[i] = rng();

		for (i = 0; i < 600; i++) {
			size_t len = i < 200 ? i : rng() % (sizeof(buf) - 16);
			size_t off = rng() % 16;
			size_t split = len ? rng() % (len + 1) : 0;
			/*
			 * Without the filter, every block is recompressed
			 * for all 32 DVs, which must not find anything in
			 * random data either.
			 */
			int ubc = i % 5 != 4;

			cl_assert_equal_i(check_same(buf + off, len, split,
						     i & 1, ubc, i % 3 == 0), 0);
		}
	}
	cl_assert_equal_i(sha1dc_accel_select(orig), 0);
}

#endif /* HAVE_SHA1DC_ACCEL */

#ifdef HAVE_SHA1DC_ACCEL
#define RUN_OR_SKIP(fn) fn()
#else
#define RUN_OR_SKIP(fn) cl_skip()
#endif

void test_sha1dc__every_backend_agrees_with_sha1dc(void)
{
	RUN_OR_SKIP(every_backend_agrees_with_sha1dc);
}
