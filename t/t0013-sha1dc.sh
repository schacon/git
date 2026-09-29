#!/bin/sh

test_description='test sha1 collision detection'

. ./test-lib.sh
TEST_DATA="$TEST_DIRECTORY/t0013"

test_lazy_prereq SHA1_IS_SHA1DC 'test-tool sha1-is-sha1dc'

if ! test_have_prereq SHA1_IS_SHA1DC
then
	skip_all='skipping sha1 collision tests, not using sha1collisiondetection'
	test_done
fi

test_expect_success 'test-sha1 detects shattered pdf' '
	test_must_fail test-tool sha1 <"$TEST_DATA/shattered-1.pdf" 2>err &&
	test_grep collision err &&
	test_grep 38762cf7f55934b34d179ae6a4c80cadccbb7f0a err
'

test_expect_success 'test-sha1 detects SHA-mbles chosen-prefix collision' '
	test_must_fail test-tool sha1 <"$TEST_DATA/sha-mbles-1.bin" 2>err &&
	test_grep collision err &&
	test_grep 8ac60ba76f1999a1ab70223f225aefdc78d4ddc0 err
'

# Each implementation of the detection this build and CPU can use.
for backend in $(test-tool sha1dc-backends)
do
	test_expect_success "$backend: detects collisions" '
		test_must_fail env GIT_TEST_SHA1DC_BACKEND=$backend \
			test-tool sha1 <"$TEST_DATA/shattered-1.pdf" 2>err &&
		test_grep 38762cf7f55934b34d179ae6a4c80cadccbb7f0a err &&
		test_must_fail env GIT_TEST_SHA1DC_BACKEND=$backend \
			test-tool sha1 <"$TEST_DATA/sha-mbles-1.bin" 2>err &&
		test_grep 8ac60ba76f1999a1ab70223f225aefdc78d4ddc0 err
	'

	test_expect_success "$backend: hashes like the others" '
		test-tool genrandom "$backend" 100000 >data &&
		GIT_TEST_SHA1DC_BACKEND=$backend test-tool sha1 <data >actual &&
		test-tool sha1 <data >expect &&
		test_cmp expect actual
	'
done

test_done
