/*
 * The unavoidable-bitconditions (UBC) check of SHA-1 collision detection,
 * in one form per instruction set.
 *
 * GENERATED FILE -- DO NOT EDIT. It is the output of the code generator of
 * the "sha1dc" Rust crate by Sam Reis, with a C emitter added:
 *
 *   https://github.com/srijs/sha1dc (commit 426b4afd)
 *
 * Its solver picks, for each instruction set, a basis of Stevens and
 * Shumow's unavoidable bitconditions that fills vector lanes well. A
 * prefix of vector groups runs on every block; the few blocks that survive
 * it run a scalar tail.
 * See sha1.c in this directory.
 *
 * To regenerate it, apply codegen-c-emitter.patch from this directory to
 * that commit of the crate and run, from its top directory:
 *
 *   cargo run --release -p sha1dc-codegen -- --c ubc_check.c \
 *	"https://github.com/srijs/sha1dc (commit 426b4afd)"
 *
 * Every form returns the same mask as ubc_check() in sha1dc/ubc_check.c.
 * The code generator is licensed under the MIT license (or Apache-2.0),
 * like the original sha1collisiondetection.
 */

#include "../git-compat-util.h"
#include "internal.h"

#define DV_I_43_0_BIT ((uint32_t)1 << 0)
#define DV_I_44_0_BIT ((uint32_t)1 << 1)
#define DV_I_45_0_BIT ((uint32_t)1 << 2)
#define DV_I_46_0_BIT ((uint32_t)1 << 3)
#define DV_I_46_2_BIT ((uint32_t)1 << 4)
#define DV_I_47_0_BIT ((uint32_t)1 << 5)
#define DV_I_47_2_BIT ((uint32_t)1 << 6)
#define DV_I_48_0_BIT ((uint32_t)1 << 7)
#define DV_I_48_2_BIT ((uint32_t)1 << 8)
#define DV_I_49_0_BIT ((uint32_t)1 << 9)
#define DV_I_49_2_BIT ((uint32_t)1 << 10)
#define DV_I_50_0_BIT ((uint32_t)1 << 11)
#define DV_I_50_2_BIT ((uint32_t)1 << 12)
#define DV_I_51_0_BIT ((uint32_t)1 << 13)
#define DV_I_51_2_BIT ((uint32_t)1 << 14)
#define DV_I_52_0_BIT ((uint32_t)1 << 15)
#define DV_II_45_0_BIT ((uint32_t)1 << 16)
#define DV_II_46_0_BIT ((uint32_t)1 << 17)
#define DV_II_46_2_BIT ((uint32_t)1 << 18)
#define DV_II_47_0_BIT ((uint32_t)1 << 19)
#define DV_II_48_0_BIT ((uint32_t)1 << 20)
#define DV_II_49_0_BIT ((uint32_t)1 << 21)
#define DV_II_49_2_BIT ((uint32_t)1 << 22)
#define DV_II_50_0_BIT ((uint32_t)1 << 23)
#define DV_II_50_2_BIT ((uint32_t)1 << 24)
#define DV_II_51_0_BIT ((uint32_t)1 << 25)
#define DV_II_51_2_BIT ((uint32_t)1 << 26)
#define DV_II_52_0_BIT ((uint32_t)1 << 27)
#define DV_II_53_0_BIT ((uint32_t)1 << 28)
#define DV_II_54_0_BIT ((uint32_t)1 << 29)
#define DV_II_55_0_BIT ((uint32_t)1 << 30)
#define DV_II_56_0_BIT ((uint32_t)1 << 31)

struct tail_check {
	uint8_t i, a, j, b, c;
};

struct tail_span {
	uint16_t start;
	uint8_t len;
};

/*
 * Runs the tail checks of each DV still alive in `mask`: bit `a` of w[i]
 * XOR bit `b` of w[j] must equal `c`, or the DV is ruled out.
 */
static inline uint32_t run_tail(const uint32_t *w, uint32_t mask,
				const struct tail_check *checks,
				const struct tail_span *spans)
{
	uint32_t out = mask, rest = mask;
	while (rest) {
		unsigned d = sha1dc_ctz(rest);
		const struct tail_check *c = checks + spans[d].start;
		const struct tail_check *end = c + spans[d].len;
		rest &= rest - 1;
		for (; c < end; c++) {
			if ((((w[c->i] >> c->a) ^ (w[c->j] >> c->b)) & 1) != c->c) {
				out &= ~((uint32_t)1 << d);
				break;
			}
		}
	}
	return out;
}

/* scalar form */

static inline uint32_t scalar_prefix(const uint32_t *w)
{
	uint32_t mask = 0xFFFFFFFF;
	mask &= ((((w[44] >> 29) ^ (w[45] >> 29)) & 1) - 1)
		| ~(DV_I_48_0_BIT | DV_I_51_0_BIT | DV_I_52_0_BIT | DV_II_45_0_BIT | DV_II_46_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT);
	mask &= ((((w[46] >> 29) ^ (w[47] >> 29)) & 1) - 1)
		| ~(DV_I_43_0_BIT | DV_I_50_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT | DV_II_52_0_BIT | DV_II_53_0_BIT);
	mask &= ((((w[45] >> 4) ^ (w[48] >> 29)) & 1) - 1)
		| ~(DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_49_0_BIT | DV_II_54_0_BIT);
	mask &= ((((w[49] >> 29) ^ (w[50] >> 29)) & 1) - 1)
		| ~(DV_I_46_0_BIT | DV_II_45_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT);
	mask &= ((((w[40] >> 29) ^ (w[41] >> 29)) & 1) - 1)
		| ~(DV_I_44_0_BIT | DV_I_47_0_BIT | DV_I_48_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_56_0_BIT);
	mask &= (0 - (((w[36] >> 1) ^ (w[37] >> 6)) & 1))
		| ~(DV_I_47_2_BIT | DV_I_50_2_BIT | DV_II_46_2_BIT);
	mask &= ((((w[47] >> 29) ^ (w[48] >> 29)) & 1) - 1)
		| ~(DV_I_44_0_BIT | DV_I_51_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT | DV_II_53_0_BIT | DV_II_54_0_BIT);
	mask &= (0 - (((w[39] >> 1) ^ (w[40] >> 6)) & 1))
		| ~(DV_I_46_2_BIT | DV_I_50_2_BIT | DV_II_49_2_BIT);
	mask &= (0 - (((w[40] >> 1) ^ (w[41] >> 6)) & 1))
		| ~(DV_I_47_2_BIT | DV_I_51_2_BIT | DV_II_50_2_BIT);
	mask &= (0 - (((w[41] >> 1) ^ (w[42] >> 6)) & 1))
		| ~(DV_I_48_2_BIT | DV_II_46_2_BIT | DV_II_51_2_BIT);
	mask &= ((((w[43] >> 4) ^ (w[46] >> 29)) & 1) - 1)
		| ~(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT | DV_II_47_0_BIT | DV_II_52_0_BIT);
	mask &= ((((w[46] >> 4) ^ (w[49] >> 29)) & 1) - 1)
		| ~(DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_50_0_BIT | DV_II_55_0_BIT);
	mask &= ((((w[45] >> 6) ^ (w[47] >> 6)) & 1) - 1)
		| ~(DV_I_47_2_BIT | DV_I_49_2_BIT | DV_I_51_2_BIT);
	mask &= ((((w[45] >> 29) ^ (w[46] >> 29)) & 1) - 1)
		| ~(DV_I_49_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_51_0_BIT | DV_II_52_0_BIT);
	mask &= ((((w[44] >> 4) ^ (w[47] >> 29)) & 1) - 1)
		| ~(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT | DV_II_48_0_BIT | DV_II_53_0_BIT);
	mask &= ((((w[48] >> 29) ^ (w[49] >> 29)) & 1) - 1)
		| ~(DV_I_45_0_BIT | DV_I_52_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT);
	mask &= ((((w[44] >> 6) ^ (w[46] >> 6)) & 1) - 1)
		| ~(DV_I_46_2_BIT | DV_I_48_2_BIT | DV_I_50_2_BIT);
	mask &= ((((w[47] >> 4) ^ (w[50] >> 29)) & 1) - 1)
		| ~(DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_51_0_BIT | DV_II_56_0_BIT);
	mask &= (0 - (((w[35] >> 1) ^ (w[36] >> 6)) & 1))
		| ~(DV_I_46_2_BIT | DV_I_49_2_BIT);
	mask &= (0 - (((w[44] >> 1) ^ (w[45] >> 6)) & 1))
		| ~(DV_I_51_2_BIT | DV_II_49_2_BIT);
	mask &= ((((w[42] >> 6) ^ (w[43] >> 1)) & 1) - 1)
		| ~(DV_II_46_2_BIT | DV_II_51_2_BIT);
	mask &= ((((w[37] >> 4) ^ (w[40] >> 29)) & 1) - 1)
		| ~(DV_I_43_0_BIT | DV_I_47_0_BIT | DV_II_46_0_BIT | DV_II_53_0_BIT | DV_II_55_0_BIT);
	mask &= ((((w[41] >> 6) ^ (w[42] >> 1)) & 1) - 1)
		| ~(DV_I_51_2_BIT | DV_II_50_2_BIT);
	mask &= ((((w[40] >> 4) ^ (w[43] >> 29)) & 1) - 1)
		| ~(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_50_0_BIT | DV_II_49_0_BIT | DV_II_56_0_BIT);
	mask &= ((((w[41] >> 4) ^ (w[44] >> 29)) & 1) - 1)
		| ~(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_50_0_BIT);
	mask &= ((((w[52] >> 29) ^ (w[53] >> 29)) & 1) - 1)
		| ~(DV_I_49_0_BIT | DV_II_45_0_BIT | DV_II_48_0_BIT | DV_II_53_0_BIT | DV_II_54_0_BIT);
	mask &= ((((w[40] >> 6) ^ (w[41] >> 1)) & 1) - 1)
		| ~(DV_I_50_2_BIT | DV_II_49_2_BIT);
	mask &= ((((w[46] >> 6) ^ (w[47] >> 1)) & 1) - 1)
		| ~(DV_I_46_2_BIT | DV_II_50_2_BIT);
	mask &= ((((w[47] >> 6) ^ (w[48] >> 1)) & 1) - 1)
		| ~(DV_I_47_2_BIT | DV_II_51_2_BIT);
	mask &= ((((w[42] >> 4) ^ (w[45] >> 29)) & 1) - 1)
		| ~(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT);
	mask &= (0 - (((w[37] >> 1) ^ (w[38] >> 6)) & 1))
		| ~(DV_I_48_2_BIT | DV_I_51_2_BIT);
	mask &= ((((w[43] >> 6) ^ (w[45] >> 6)) & 1) - 1)
		| ~(DV_I_47_2_BIT | DV_I_49_2_BIT);
	mask &= ((((w[53] >> 29) ^ (w[54] >> 29)) & 1) - 1)
		| ~(DV_I_50_0_BIT | DV_II_46_0_BIT | DV_II_49_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT);
	mask &= ((((w[41] >> 29) ^ (w[42] >> 29)) & 1) - 1)
		| ~(DV_I_45_0_BIT | DV_I_48_0_BIT | DV_I_49_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT);
	mask &= ((((w[50] >> 29) ^ (w[51] >> 29)) & 1) - 1)
		| ~(DV_I_47_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT | DV_II_52_0_BIT | DV_II_56_0_BIT);
	mask &= (0 - (((w[61] >> 2) ^ (w[62] >> 7)) & 1))
		| ~(DV_I_46_2_BIT | DV_II_46_2_BIT);
	mask &= ((((w[46] >> 6) ^ (w[48] >> 6)) & 1) - 1)
		| ~(DV_I_48_2_BIT | DV_I_50_2_BIT);
	mask &= ((((w[39] >> 4) ^ (w[42] >> 29)) & 1) - 1)
		| ~(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_49_0_BIT | DV_II_48_0_BIT | DV_II_55_0_BIT);
	mask &= ((((w[43] >> 29) ^ (w[44] >> 29)) & 1) - 1)
		| ~(DV_I_47_0_BIT | DV_I_50_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT);
	mask &= ((((w[47] >> 6) ^ (w[49] >> 6)) & 1) - 1)
		| ~(DV_I_49_2_BIT | DV_I_51_2_BIT);
	mask &= ((((w[51] >> 29) ^ (w[52] >> 29)) & 1) - 1)
		| ~(DV_I_48_0_BIT | DV_II_47_0_BIT | DV_II_52_0_BIT | DV_II_53_0_BIT);
	mask &= (0 - ((w[36] ^ (w[37] >> 5)) & 1))
		| ~(DV_II_49_2_BIT);
	mask &= (0 - ((w[37] ^ (w[38] >> 5)) & 1))
		| ~(DV_II_50_2_BIT);
	mask &= (0 - ((w[38] ^ (w[39] >> 5)) & 1))
		| ~(DV_II_51_2_BIT);
	mask &= ((((w[38] >> 4) ^ (w[41] >> 29)) & 1) - 1)
		| ~(DV_I_44_0_BIT | DV_I_48_0_BIT | DV_II_47_0_BIT | DV_II_54_0_BIT | DV_II_56_0_BIT);
	mask &= ((((w[50] >> 6) ^ (w[51] >> 1)) & 1) - 1)
		| ~(DV_I_50_2_BIT | DV_II_46_2_BIT);
	mask &= ((((w[42] >> 6) ^ (w[44] >> 6)) & 1) - 1)
		| ~(DV_I_46_2_BIT | DV_I_48_2_BIT);
	mask &= ((((w[48] >> 4) ^ (w[51] >> 29)) & 1) - 1)
		| ~(DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_52_0_BIT);
	mask &= ((((w[42] >> 29) ^ (w[43] >> 29)) & 1) - 1)
		| ~(DV_I_46_0_BIT | DV_I_49_0_BIT | DV_I_50_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT);
	mask &= ((((w[54] >> 29) ^ (w[55] >> 29)) & 1) - 1)
		| ~(DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_50_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT);
	mask &= (0 - (((w[38] >> 1) ^ (w[39] >> 6)) & 1))
		| ~(DV_I_49_2_BIT);
	mask &= (0 - (((w[45] >> 1) ^ (w[46] >> 6)) & 1))
		| ~(DV_II_50_2_BIT);
	mask &= (0 - (((w[46] >> 1) ^ (w[47] >> 6)) & 1))
		| ~(DV_II_51_2_BIT);
	mask &= (0 - (((w[50] >> 1) ^ (w[51] >> 6)) & 1))
		| ~(DV_II_49_2_BIT);
	mask &= (0 - (((w[39] >> 4) ^ (w[40] >> 29)) & 1))
		| ~(DV_I_43_0_BIT | DV_II_53_0_BIT | DV_II_55_0_BIT);
	mask &= ((((w[55] >> 29) ^ (w[56] >> 29)) & 1) - 1)
		| ~(DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_51_0_BIT | DV_II_56_0_BIT);
	mask &= ((((w[48] >> 6) ^ (w[50] >> 6)) & 1) - 1)
		| ~(DV_I_50_2_BIT | DV_II_46_2_BIT);
	mask &= ((((w[49] >> 4) ^ (w[52] >> 29)) & 1) - 1)
		| ~(DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_47_0_BIT | DV_II_53_0_BIT);
	mask &= (0 - (((w[40] >> 4) ^ (w[41] >> 29)) & 1))
		| ~(DV_I_44_0_BIT | DV_II_54_0_BIT | DV_II_56_0_BIT);
	mask &= (0 - (((w[41] >> 4) ^ (w[42] >> 29)) & 1))
		| ~(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_II_55_0_BIT);
	mask &= (0 - (((w[42] >> 1) ^ (w[43] >> 6)) & 1))
		| ~(DV_I_49_2_BIT);
	mask &= (0 - (((w[51] >> 1) ^ (w[52] >> 6)) & 1))
		| ~(DV_II_50_2_BIT);
	mask &= (0 - (((w[52] >> 1) ^ (w[53] >> 6)) & 1))
		| ~(DV_II_51_2_BIT);
	mask &= (0 - (((w[62] >> 2) ^ (w[63] >> 7)) & 1))
		| ~(DV_I_47_2_BIT);
	mask &= (0 - (((w[63] >> 2) ^ (w[64] >> 7)) & 1))
		| ~(DV_I_48_2_BIT);
	mask &= ((((w[45] >> 6) ^ (w[46] >> 1)) & 1) - 1)
		| ~(DV_II_49_2_BIT);
	mask &= ((((w[36] >> 4) ^ (w[40] >> 29)) & 1) - 1)
		| ~(DV_I_46_0_BIT | DV_I_49_0_BIT | DV_II_45_0_BIT | DV_II_48_0_BIT);
	mask &= ((((w[50] >> 4) ^ (w[53] >> 29)) & 1) - 1)
		| ~(DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_48_0_BIT | DV_II_54_0_BIT);
	mask &= ((((w[56] >> 29) ^ (w[57] >> 29)) & 1) - 1)
		| ~(DV_II_49_0_BIT | DV_II_52_0_BIT);
	mask &= (0 - (((w[43] >> 4) ^ (w[44] >> 29)) & 1))
		| ~(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT);
	return mask;
}

static const struct tail_check scalar_tail_checks[151] = {
	{ 58, 0, 59, 5, 1 },
	{ 58, 0, 63, 30, 1 },
	{ 61, 1, 62, 6, 1 },
	{ 43, 4, 47, 29, 0 },
	{ 40, 4, 42, 4, 1 },
	{ 42, 4, 44, 4, 1 },
	{ 59, 0, 60, 5, 1 },
	{ 59, 0, 64, 30, 1 },
	{ 62, 1, 63, 6, 1 },
	{ 44, 4, 48, 29, 0 },
	{ 43, 4, 45, 4, 1 },
	{ 60, 0, 61, 5, 1 },
	{ 63, 1, 64, 6, 1 },
	{ 35, 4, 39, 29, 0 },
	{ 40, 4, 42, 4, 1 },
	{ 42, 4, 44, 4, 1 },
	{ 44, 4, 46, 4, 1 },
	{ 61, 0, 62, 5, 1 },
	{ 39, 1, 42, 6, 1 },
	{ 43, 4, 45, 4, 1 },
	{ 45, 4, 47, 4, 1 },
	{ 62, 0, 63, 5, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 40, 1, 43, 6, 1 },
	{ 42, 4, 44, 4, 1 },
	{ 44, 4, 46, 4, 1 },
	{ 46, 4, 48, 4, 1 },
	{ 63, 0, 64, 5, 1 },
	{ 35, 4, 39, 29, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 41, 1, 49, 1, 1 },
	{ 43, 4, 45, 4, 1 },
	{ 45, 4, 47, 4, 1 },
	{ 47, 4, 49, 4, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 38, 1, 40, 1, 1 },
	{ 42, 1, 50, 1, 1 },
	{ 36, 4, 37, 4, 1 },
	{ 44, 4, 46, 4, 1 },
	{ 46, 4, 48, 4, 1 },
	{ 48, 4, 50, 4, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 40, 4, 44, 29, 0 },
	{ 43, 1, 44, 6, 1 },
	{ 37, 4, 38, 4, 1 },
	{ 45, 4, 47, 4, 1 },
	{ 47, 4, 49, 4, 1 },
	{ 52, 29, 55, 29, 1 },
	{ 35, 3, 39, 28, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 41, 4, 45, 29, 0 },
	{ 51, 4, 54, 29, 0 },
	{ 44, 1, 51, 6, 1 },
	{ 44, 1, 52, 1, 1 },
	{ 35, 5, 39, 30, 0 },
	{ 37, 1, 37, 6, 0 },
	{ 38, 4, 39, 4, 1 },
	{ 46, 4, 48, 4, 1 },
	{ 48, 4, 50, 4, 1 },
	{ 53, 29, 56, 29, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 42, 4, 46, 29, 0 },
	{ 52, 4, 55, 29, 0 },
	{ 47, 4, 49, 4, 1 },
	{ 60, 0, 61, 5, 1 },
	{ 63, 1, 64, 6, 1 },
	{ 41, 4, 45, 29, 0 },
	{ 48, 4, 50, 4, 1 },
	{ 61, 0, 62, 5, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 42, 4, 46, 29, 0 },
	{ 47, 1, 48, 6, 1 },
	{ 52, 29, 55, 29, 1 },
	{ 62, 0, 63, 5, 1 },
	{ 35, 3, 39, 28, 0 },
	{ 35, 4, 39, 29, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 51, 4, 54, 29, 0 },
	{ 35, 30, 36, 3, 1 },
	{ 35, 30, 40, 28, 1 },
	{ 52, 29, 55, 29, 1 },
	{ 53, 29, 56, 29, 1 },
	{ 63, 0, 64, 5, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 52, 4, 55, 29, 0 },
	{ 36, 30, 37, 3, 1 },
	{ 36, 30, 41, 28, 1 },
	{ 53, 29, 56, 29, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 40, 4, 44, 29, 0 },
	{ 51, 4, 54, 29, 0 },
	{ 53, 4, 56, 29, 0 },
	{ 36, 0, 41, 30, 1 },
	{ 50, 1, 53, 6, 1 },
	{ 50, 1, 54, 1, 1 },
	{ 37, 30, 38, 3, 1 },
	{ 37, 30, 42, 28, 1 },
	{ 55, 29, 58, 29, 1 },
	{ 38, 4, 42, 29, 0 },
	{ 41, 4, 45, 29, 0 },
	{ 52, 4, 55, 29, 0 },
	{ 54, 4, 57, 29, 0 },
	{ 57, 29, 58, 29, 0 },
	{ 37, 0, 42, 30, 1 },
	{ 51, 1, 54, 6, 1 },
	{ 51, 1, 55, 1, 1 },
	{ 38, 30, 39, 3, 1 },
	{ 38, 30, 43, 28, 1 },
	{ 55, 29, 58, 29, 1 },
	{ 56, 29, 59, 29, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 42, 4, 46, 29, 0 },
	{ 53, 4, 56, 29, 0 },
	{ 55, 4, 58, 29, 0 },
	{ 38, 0, 43, 30, 1 },
	{ 52, 1, 55, 6, 1 },
	{ 52, 1, 56, 1, 1 },
	{ 36, 4, 38, 4, 1 },
	{ 39, 30, 40, 3, 1 },
	{ 39, 30, 44, 28, 1 },
	{ 54, 4, 60, 29, 1 },
	{ 56, 29, 59, 29, 1 },
	{ 40, 4, 44, 29, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 54, 4, 57, 29, 0 },
	{ 56, 4, 59, 29, 0 },
	{ 55, 4, 57, 4, 1 },
	{ 55, 4, 61, 29, 1 },
	{ 41, 3, 45, 28, 0 },
	{ 41, 4, 45, 29, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 55, 4, 58, 29, 0 },
	{ 57, 29, 58, 29, 0 },
	{ 36, 4, 38, 4, 1 },
	{ 42, 3, 46, 28, 0 },
	{ 42, 4, 46, 29, 0 },
	{ 56, 4, 59, 29, 0 },
	{ 56, 4, 58, 29, 0 },
	{ 58, 4, 62, 29, 0 },
	{ 43, 3, 47, 28, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 51, 4, 54, 29, 0 },
	{ 57, 4, 59, 29, 0 },
	{ 59, 4, 63, 29, 0 },
	{ 40, 4, 42, 4, 1 },
	{ 44, 3, 48, 28, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 52, 4, 55, 29, 0 },
	{ 60, 4, 64, 29, 0 }
};

static const struct tail_span scalar_tail_spans[32] = {
	{ 0, 4 },
	{ 4, 6 },
	{ 10, 4 },
	{ 14, 4 },
	{ 18, 1 },
	{ 19, 4 },
	{ 23, 1 },
	{ 24, 6 },
	{ 30, 1 },
	{ 31, 4 },
	{ 35, 2 },
	{ 37, 6 },
	{ 43, 1 },
	{ 44, 8 },
	{ 52, 4 },
	{ 56, 7 },
	{ 63, 4 },
	{ 67, 4 },
	{ 71, 1 },
	{ 72, 7 },
	{ 79, 8 },
	{ 87, 7 },
	{ 94, 3 },
	{ 97, 8 },
	{ 105, 3 },
	{ 108, 8 },
	{ 116, 3 },
	{ 119, 9 },
	{ 128, 7 },
	{ 135, 6 },
	{ 141, 5 },
	{ 146, 5 }
};

static uint32_t scalar_tail(const uint32_t *w, uint32_t mask)
{
	return run_tail(w, mask, scalar_tail_checks, scalar_tail_spans);
}

uint32_t sha1dc_ubc_check_scalar(const uint32_t w[80])
{
	uint32_t mask = scalar_prefix(w);
	/* Every check only clears bits, so an empty mask settles it. */
	if (!mask)
		return 0;
	return scalar_tail(w, mask);
}

/* neon form */

#ifdef SHA1DC_HAVE_NEON

/* The highest index read is 64. */
static uint32_t neon_prefix(const uint32_t *w)
{
	uint32x4_t acc0 = vdupq_n_u32(0), acc1 = vdupq_n_u32(0), acc;
	uint32x2_t folded;

	{
		uint32x4_t lo = vld1q_u32(w + 35);
		uint32x4_t hi = vld1q_u32(w + 36);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 5));
		const uint32_t test[4] = {
			1u << 1,
			1u << 1,
			1u << 1,
			1u << 0
		};
		uint32x4_t set = vtstq_u32(x, vld1q_u32(test));
		const uint32_t dvs[4] = {
			DV_I_46_2_BIT | DV_I_49_2_BIT,
			DV_I_47_2_BIT | DV_I_50_2_BIT | DV_II_46_2_BIT,
			DV_I_48_2_BIT | DV_I_51_2_BIT,
			DV_II_51_2_BIT
		};
		acc0 = vorrq_u32(acc0, vqsubq_u32(vld1q_u32(dvs), set));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 36);
		uint32x4_t hi = vld1q_u32(w + 37);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 5));
		const uint32_t test[4] = {
			1u << 0,
			1u << 0,
			1u << 1,
			1u << 1
		};
		uint32x4_t set = vtstq_u32(x, vld1q_u32(test));
		const uint32_t dvs[4] = {
			DV_II_49_2_BIT,
			DV_II_50_2_BIT,
			DV_I_49_2_BIT,
			DV_I_46_2_BIT | DV_I_50_2_BIT | DV_II_49_2_BIT
		};
		acc1 = vorrq_u32(acc1, vqsubq_u32(vld1q_u32(dvs), set));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 36);
		uint32x4_t hi = vld1q_u32(w + 38);
		uint32x4_t x = veorq_u32(lo, hi);
		const uint32_t test[4] = {
			1u << 4,
			1u << 4,
			1u << 1,
			1u << 4
		};
		uint32x4_t set = vtstq_u32(x, vld1q_u32(test));
		const uint32_t dvs[4] = {
			DV_II_52_0_BIT | DV_II_54_0_BIT,
			DV_I_43_0_BIT | DV_II_53_0_BIT | DV_II_55_0_BIT,
			DV_I_49_2_BIT,
			DV_I_43_0_BIT | DV_I_45_0_BIT | DV_II_55_0_BIT
		};
		acc0 = vorrq_u32(acc0, vqsubq_u32(vld1q_u32(dvs), set));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 36);
		uint32x4_t hi = vld1q_u32(w + 40);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 25));
		const uint32_t test[4] = {
			1u << 4,
			1u << 5,
			1u << 5,
			1u << 5
		};
		uint32x4_t set = vtstq_u32(x, vld1q_u32(test));
		const uint32_t dvs[4] = {
			DV_I_46_0_BIT | DV_I_49_0_BIT | DV_II_45_0_BIT | DV_II_48_0_BIT,
			DV_II_49_2_BIT,
			DV_II_50_2_BIT,
			DV_II_51_2_BIT
		};
		acc1 = vorrq_u32(acc1, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 38);
		uint32x4_t hi = vld1q_u32(w + 40);
		uint32x4_t x = veorq_u32(lo, hi);
		const uint32_t test[4] = {
			1u << 4,
			1u << 1,
			1u << 1,
			1u << 1
		};
		uint32x4_t set = vtstq_u32(x, vld1q_u32(test));
		const uint32_t dvs[4] = {
			DV_I_44_0_BIT | DV_II_54_0_BIT | DV_II_56_0_BIT,
			DV_I_50_2_BIT | DV_II_49_2_BIT,
			DV_I_51_2_BIT | DV_II_50_2_BIT,
			DV_II_46_2_BIT | DV_II_51_2_BIT
		};
		acc0 = vorrq_u32(acc0, vqsubq_u32(vld1q_u32(dvs), set));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 37);
		uint32x4_t hi = vld1q_u32(w + 40);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 25));
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 4));
		const uint32_t dvs[4] = {
			DV_I_43_0_BIT | DV_I_47_0_BIT | DV_II_46_0_BIT | DV_II_53_0_BIT | DV_II_55_0_BIT,
			DV_I_44_0_BIT | DV_I_48_0_BIT | DV_II_47_0_BIT | DV_II_54_0_BIT | DV_II_56_0_BIT,
			DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_49_0_BIT | DV_II_48_0_BIT | DV_II_55_0_BIT,
			DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_50_0_BIT | DV_II_49_0_BIT | DV_II_56_0_BIT
		};
		acc1 = vorrq_u32(acc1, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 40);
		uint32x4_t hi = vld1q_u32(w + 41);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 5));
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 1));
		const uint32_t dvs[4] = {
			DV_I_47_2_BIT | DV_I_51_2_BIT | DV_II_50_2_BIT,
			DV_I_48_2_BIT | DV_II_46_2_BIT | DV_II_51_2_BIT,
			DV_I_49_2_BIT,
			DV_I_50_2_BIT
		};
		acc0 = vorrq_u32(acc0, vqsubq_u32(vld1q_u32(dvs), set));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 40);
		uint32x4_t hi = vld1q_u32(w + 41);
		uint32x4_t x = veorq_u32(lo, hi);
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 29));
		const uint32_t dvs[4] = {
			DV_I_44_0_BIT | DV_I_47_0_BIT | DV_I_48_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_56_0_BIT,
			DV_I_45_0_BIT | DV_I_48_0_BIT | DV_I_49_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT,
			DV_I_46_0_BIT | DV_I_49_0_BIT | DV_I_50_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT,
			DV_I_47_0_BIT | DV_I_50_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT
		};
		acc1 = vorrq_u32(acc1, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 41);
		uint32x4_t hi = vld1q_u32(w + 43);
		uint32x4_t x = veorq_u32(lo, hi);
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 6));
		const uint32_t dvs[4] = {
			DV_I_47_2_BIT,
			DV_I_46_2_BIT | DV_I_48_2_BIT,
			DV_I_47_2_BIT | DV_I_49_2_BIT,
			DV_I_46_2_BIT | DV_I_48_2_BIT | DV_I_50_2_BIT
		};
		acc0 = vorrq_u32(acc0, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 41);
		uint32x4_t hi = vld1q_u32(w + 44);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 25));
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 4));
		const uint32_t dvs[4] = {
			DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_50_0_BIT,
			DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT,
			DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT | DV_II_47_0_BIT | DV_II_52_0_BIT,
			DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT | DV_II_48_0_BIT | DV_II_53_0_BIT
		};
		acc1 = vorrq_u32(acc1, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 44);
		uint32x4_t hi = vld1q_u32(w + 45);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 5));
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 1));
		const uint32_t dvs[4] = {
			DV_I_51_2_BIT | DV_II_49_2_BIT,
			DV_II_50_2_BIT,
			DV_II_51_2_BIT,
			DV_II_46_2_BIT
		};
		acc0 = vorrq_u32(acc0, vqsubq_u32(vld1q_u32(dvs), set));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 44);
		uint32x4_t hi = vld1q_u32(w + 45);
		uint32x4_t x = veorq_u32(lo, hi);
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 29));
		const uint32_t dvs[4] = {
			DV_I_48_0_BIT | DV_I_51_0_BIT | DV_I_52_0_BIT | DV_II_45_0_BIT | DV_II_46_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT,
			DV_I_49_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_51_0_BIT | DV_II_52_0_BIT,
			DV_I_43_0_BIT | DV_I_50_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT | DV_II_52_0_BIT | DV_II_53_0_BIT,
			DV_I_44_0_BIT | DV_I_51_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT | DV_II_53_0_BIT | DV_II_54_0_BIT
		};
		acc1 = vorrq_u32(acc1, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 45);
		uint32x4_t hi = vld1q_u32(w + 46);
		uint32x4_t x = veorq_u32(vshrq_n_u32(lo, 5), hi);
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 1));
		const uint32_t dvs[4] = {
			DV_II_49_2_BIT,
			DV_I_46_2_BIT | DV_II_50_2_BIT,
			DV_I_47_2_BIT | DV_II_51_2_BIT,
			DV_I_48_2_BIT
		};
		acc0 = vorrq_u32(acc0, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 45);
		uint32x4_t hi = vld1q_u32(w + 47);
		uint32x4_t x = veorq_u32(lo, hi);
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 6));
		const uint32_t dvs[4] = {
			DV_I_47_2_BIT | DV_I_49_2_BIT | DV_I_51_2_BIT,
			DV_I_48_2_BIT | DV_I_50_2_BIT,
			DV_I_49_2_BIT | DV_I_51_2_BIT,
			DV_I_50_2_BIT | DV_II_46_2_BIT
		};
		acc1 = vorrq_u32(acc1, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 45);
		uint32x4_t hi = vld1q_u32(w + 47);
		uint32x4_t x = veorq_u32(lo, hi);
		const uint32_t test[4] = {
			1u << 29,
			1u << 29,
			1u << 4,
			1u << 4
		};
		uint32x4_t set = vtstq_u32(x, vld1q_u32(test));
		const uint32_t dvs[4] = {
			DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT,
			DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT,
			DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT,
			DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT
		};
		acc0 = vorrq_u32(acc0, vqsubq_u32(vld1q_u32(dvs), set));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 45);
		uint32x4_t hi = vld1q_u32(w + 48);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 25));
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 4));
		const uint32_t dvs[4] = {
			DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_49_0_BIT | DV_II_54_0_BIT,
			DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_50_0_BIT | DV_II_55_0_BIT,
			DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_51_0_BIT | DV_II_56_0_BIT,
			DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_52_0_BIT
		};
		acc1 = vorrq_u32(acc1, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 48);
		uint32x4_t hi = vld1q_u32(w + 49);
		uint32x4_t x = veorq_u32(lo, hi);
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 29));
		const uint32_t dvs[4] = {
			DV_I_45_0_BIT | DV_I_52_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT,
			DV_I_46_0_BIT | DV_II_45_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT,
			DV_I_47_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT | DV_II_52_0_BIT | DV_II_56_0_BIT,
			DV_I_48_0_BIT | DV_II_47_0_BIT | DV_II_52_0_BIT | DV_II_53_0_BIT
		};
		acc0 = vorrq_u32(acc0, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 52);
		uint32x4_t hi = vld1q_u32(w + 53);
		uint32x4_t x = veorq_u32(lo, hi);
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 29));
		const uint32_t dvs[4] = {
			DV_I_49_0_BIT | DV_II_45_0_BIT | DV_II_48_0_BIT | DV_II_53_0_BIT | DV_II_54_0_BIT,
			DV_I_50_0_BIT | DV_II_46_0_BIT | DV_II_49_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT,
			DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_50_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT,
			DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_51_0_BIT | DV_II_56_0_BIT
		};
		acc1 = vorrq_u32(acc1, vminq_u32(set, vld1q_u32(dvs)));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 52);
		uint32x4_t hi = vld1q_u32(w + 55);
		uint32x4_t x = veorq_u32(lo, hi);
		uint32x4_t set = vtstq_u32(x, vdupq_n_u32(1u << 29));
		const uint32_t dvs[4] = {
			DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT,
			DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT,
			DV_II_49_0_BIT | DV_II_50_0_BIT,
			DV_II_50_0_BIT | DV_II_51_0_BIT
		};
		acc0 = vorrq_u32(acc0, vqsubq_u32(vld1q_u32(dvs), set));
	}

	{
		uint32x4_t lo = vld1q_u32(w + 60);
		uint32x4_t hi = vld1q_u32(w + 61);
		uint32x4_t x = veorq_u32(lo, vshrq_n_u32(hi, 5));
		const uint32_t test[4] = {
			1u << 0,
			1u << 2,
			1u << 2,
			1u << 2
		};
		uint32x4_t set = vtstq_u32(x, vld1q_u32(test));
		const uint32_t dvs[4] = {
			DV_I_45_0_BIT | DV_II_45_0_BIT,
			DV_I_46_2_BIT | DV_II_46_2_BIT,
			DV_I_47_2_BIT,
			DV_I_48_2_BIT
		};
		acc1 = vorrq_u32(acc1, vqsubq_u32(vld1q_u32(dvs), set));
	}

	acc = vorrq_u32(acc0, acc1);
	folded = vorr_u32(vget_low_u32(acc), vget_high_u32(acc));
	return ~vget_lane_u32(vorr_u32(folded, vdup_lane_u32(folded, 1)), 0);
}

SHA1DC_NOINLINE
static uint32_t neon_tail(const uint32_t *w, uint32_t mask)
{
	uint32_t out = mask, fail;
	if (mask & DV_I_46_2_BIT) {
		fail = (((w[39] >> 1) ^ (w[42] >> 6) ^ 1)) & 1;
		out &= ~(fail << 4);
	}
	if (mask & DV_I_51_2_BIT) {
		fail = (((w[44] >> 1) ^ (w[51] >> 6) ^ 1) |
			((w[44] >> 1) ^ (w[52] >> 1) ^ 1) |
			((w[35] >> 5) ^ (w[39] >> 30)) |
			((w[37] >> 1) ^ (w[37] >> 6))) & 1;
		out &= ~(fail << 14);
	}
	if (mask & DV_II_46_2_BIT) {
		fail = (((w[48] >> 6) ^ (w[51] >> 1))) & 1;
		out &= ~(fail << 18);
	}
	if (mask & DV_II_49_2_BIT) {
		fail = (((w[50] >> 1) ^ (w[51] >> 6) ^ 1) |
			((w[50] >> 1) ^ (w[53] >> 6) ^ 1) |
			((w[50] >> 1) ^ (w[54] >> 1) ^ 1)) & 1;
		out &= ~(fail << 22);
	}
	if (mask & DV_II_50_2_BIT) {
		fail = (((w[51] >> 1) ^ (w[52] >> 6) ^ 1) |
			((w[51] >> 1) ^ (w[54] >> 6) ^ 1) |
			((w[51] >> 1) ^ (w[55] >> 1) ^ 1)) & 1;
		out &= ~(fail << 24);
	}
	if (mask & DV_II_51_2_BIT) {
		fail = (((w[52] >> 1) ^ (w[53] >> 6) ^ 1) |
			((w[52] >> 1) ^ (w[55] >> 6) ^ 1) |
			((w[52] >> 1) ^ (w[56] >> 1) ^ 1)) & 1;
		out &= ~(fail << 26);
	}
	if (mask & DV_I_43_0_BIT) {
		fail = (((w[41] >> 4) ^ (w[43] >> 4) ^ 1) |
			(w[58] ^ (w[59] >> 5) ^ 1) |
			(w[58] ^ (w[63] >> 30) ^ 1) |
			((w[61] >> 1) ^ (w[62] >> 6) ^ 1) |
			((w[43] >> 4) ^ (w[47] >> 29))) & 1;
		out &= ~fail;
	}
	if (mask & DV_I_49_2_BIT) {
		fail = (((w[42] >> 1) ^ (w[50] >> 1) ^ 1)) & 1;
		out &= ~(fail << 10);
	}
	if (mask & DV_I_50_2_BIT) {
		fail = (((w[48] >> 6) ^ (w[51] >> 1))) & 1;
		out &= ~(fail << 12);
	}
	if (mask & DV_II_52_0_BIT) {
		fail = (((w[39] >> 30) ^ (w[40] >> 3) ^ 1) |
			((w[39] >> 30) ^ (w[44] >> 28) ^ 1) |
			((w[54] >> 4) ^ (w[56] >> 4) ^ 1) |
			((w[54] >> 4) ^ (w[60] >> 29) ^ 1) |
			((w[56] >> 29) ^ (w[59] >> 29) ^ 1) |
			((w[40] >> 4) ^ (w[44] >> 29)) |
			((w[43] >> 4) ^ (w[47] >> 29)) |
			((w[54] >> 4) ^ (w[57] >> 29)) |
			((w[56] >> 4) ^ (w[59] >> 29))) & 1;
		out &= ~(fail << 27);
	}
	if (mask & DV_II_53_0_BIT) {
		fail = (((w[55] >> 4) ^ (w[57] >> 4) ^ 1) |
			((w[55] >> 4) ^ (w[61] >> 29) ^ 1) |
			((w[41] >> 3) ^ (w[45] >> 28)) |
			((w[41] >> 4) ^ (w[45] >> 29)) |
			((w[44] >> 4) ^ (w[48] >> 29)) |
			((w[49] >> 4) ^ (w[52] >> 29)) |
			((w[55] >> 4) ^ (w[58] >> 29)) |
			((w[55] >> 4) ^ (w[57] >> 29))) & 1;
		out &= ~(fail << 28);
	}
	/* The DVs the prefix leaves rarely alive, behind one guard. */
	if (mask & (DV_I_44_0_BIT | DV_I_45_0_BIT | DV_I_46_0_BIT | DV_I_47_0_BIT | DV_I_48_0_BIT | DV_I_49_0_BIT | DV_I_50_0_BIT | DV_I_51_0_BIT | DV_I_52_0_BIT | DV_II_45_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT)) {
		if (mask & DV_I_44_0_BIT) {
			fail = (((w[40] >> 4) ^ (w[42] >> 4) ^ 1) |
				(w[59] ^ (w[60] >> 5) ^ 1) |
				(w[59] ^ (w[64] >> 30) ^ 1) |
				((w[62] >> 1) ^ (w[63] >> 6) ^ 1) |
				((w[44] >> 4) ^ (w[48] >> 29))) & 1;
			out &= ~(fail << 1);
		}
		if (mask & DV_I_46_0_BIT) {
			fail = (((w[40] >> 4) ^ (w[42] >> 4) ^ 1) |
				((w[44] >> 4) ^ (w[46] >> 4) ^ 1) |
				(w[61] ^ (w[62] >> 5) ^ 1)) & 1;
			out &= ~(fail << 3);
		}
		if (mask & DV_II_51_0_BIT) {
			fail = (((w[38] >> 30) ^ (w[39] >> 3) ^ 1) |
				((w[38] >> 30) ^ (w[43] >> 28) ^ 1) |
				((w[56] >> 29) ^ (w[59] >> 29) ^ 1) |
				((w[39] >> 4) ^ (w[43] >> 29)) |
				((w[42] >> 4) ^ (w[46] >> 29)) |
				((w[53] >> 4) ^ (w[56] >> 29)) |
				((w[55] >> 4) ^ (w[58] >> 29))) & 1;
			out &= ~(fail << 25);
		}
		if (mask & DV_II_54_0_BIT) {
			fail = (((w[42] >> 3) ^ (w[46] >> 28)) |
				((w[42] >> 4) ^ (w[46] >> 29)) |
				((w[50] >> 4) ^ (w[53] >> 29)) |
				((w[56] >> 4) ^ (w[59] >> 29)) |
				((w[56] >> 4) ^ (w[58] >> 29)) |
				((w[58] >> 4) ^ (w[62] >> 29))) & 1;
			out &= ~(fail << 29);
		}
		if (mask & DV_I_45_0_BIT) {
			fail = (((w[41] >> 4) ^ (w[43] >> 4) ^ 1) |
				((w[63] >> 1) ^ (w[64] >> 6) ^ 1) |
				((w[35] >> 4) ^ (w[39] >> 29))) & 1;
			out &= ~(fail << 2);
		}
		if (mask & DV_I_47_0_BIT) {
			fail = (((w[41] >> 4) ^ (w[43] >> 4) ^ 1) |
				((w[45] >> 4) ^ (w[47] >> 4) ^ 1) |
				(w[62] ^ (w[63] >> 5) ^ 1) |
				((w[37] >> 4) ^ (w[41] >> 29))) & 1;
			out &= ~(fail << 5);
		}
		if (mask & DV_I_50_0_BIT) {
			fail = (((w[36] >> 4) ^ (w[37] >> 4) ^ 1) |
				((w[44] >> 4) ^ (w[46] >> 4) ^ 1) |
				((w[46] >> 4) ^ (w[48] >> 4) ^ 1) |
				((w[37] >> 4) ^ (w[41] >> 29)) |
				((w[40] >> 4) ^ (w[44] >> 29)) |
				((w[50] >> 4) ^ (w[53] >> 29))) & 1;
			out &= ~(fail << 11);
		}
		if (mask & DV_I_51_0_BIT) {
			fail = (((w[37] >> 4) ^ (w[38] >> 4) ^ 1) |
				((w[45] >> 4) ^ (w[47] >> 4) ^ 1) |
				((w[35] >> 3) ^ (w[39] >> 28)) |
				((w[38] >> 4) ^ (w[42] >> 29)) |
				((w[41] >> 4) ^ (w[45] >> 29)) |
				((w[49] >> 4) ^ (w[52] >> 29)) |
				((w[51] >> 4) ^ (w[54] >> 29))) & 1;
			out &= ~(fail << 13);
		}
		if (mask & DV_I_52_0_BIT) {
			fail = (((w[38] >> 4) ^ (w[39] >> 4) ^ 1) |
				((w[46] >> 4) ^ (w[48] >> 4) ^ 1) |
				((w[39] >> 4) ^ (w[43] >> 29)) |
				((w[42] >> 4) ^ (w[46] >> 29)) |
				((w[50] >> 4) ^ (w[53] >> 29)) |
				((w[52] >> 4) ^ (w[55] >> 29))) & 1;
			out &= ~(fail << 15);
		}
		if (mask & DV_II_45_0_BIT) {
			fail = (((w[63] >> 1) ^ (w[64] >> 6) ^ 1) |
				((w[41] >> 4) ^ (w[45] >> 29)) |
				((w[49] >> 4) ^ (w[52] >> 29))) & 1;
			out &= ~(fail << 16);
		}
		if (mask & DV_II_46_0_BIT) {
			fail = ((w[61] ^ (w[62] >> 5) ^ 1) |
				((w[37] >> 4) ^ (w[41] >> 29)) |
				((w[42] >> 4) ^ (w[46] >> 29)) |
				((w[50] >> 4) ^ (w[53] >> 29))) & 1;
			out &= ~(fail << 17);
		}
		if (mask & DV_II_47_0_BIT) {
			fail = ((w[62] ^ (w[63] >> 5) ^ 1) |
				((w[35] >> 3) ^ (w[39] >> 28)) |
				((w[35] >> 4) ^ (w[39] >> 29)) |
				((w[38] >> 4) ^ (w[42] >> 29)) |
				((w[43] >> 4) ^ (w[47] >> 29)) |
				((w[49] >> 4) ^ (w[52] >> 29)) |
				((w[51] >> 4) ^ (w[54] >> 29))) & 1;
			out &= ~(fail << 19);
		}
		if (mask & DV_II_49_0_BIT) {
			fail = (((w[36] >> 30) ^ (w[37] >> 3) ^ 1) |
				((w[36] >> 30) ^ (w[41] >> 28) ^ 1) |
				((w[37] >> 4) ^ (w[41] >> 29)) |
				((w[40] >> 4) ^ (w[44] >> 29)) |
				((w[51] >> 4) ^ (w[54] >> 29)) |
				((w[53] >> 4) ^ (w[56] >> 29))) & 1;
			out &= ~(fail << 21);
		}
		if (mask & DV_II_50_0_BIT) {
			fail = (((w[37] >> 30) ^ (w[38] >> 3) ^ 1) |
				((w[37] >> 30) ^ (w[42] >> 28) ^ 1) |
				((w[38] >> 4) ^ (w[42] >> 29)) |
				((w[41] >> 4) ^ (w[45] >> 29)) |
				((w[52] >> 4) ^ (w[55] >> 29)) |
				((w[54] >> 4) ^ (w[57] >> 29))) & 1;
			out &= ~(fail << 23);
		}
		if (mask & DV_II_55_0_BIT) {
			fail = (((w[43] >> 3) ^ (w[47] >> 28)) |
				((w[43] >> 4) ^ (w[47] >> 29)) |
				((w[51] >> 4) ^ (w[54] >> 29)) |
				((w[57] >> 4) ^ (w[59] >> 29)) |
				((w[59] >> 4) ^ (w[63] >> 29))) & 1;
			out &= ~(fail << 30);
		}
		if (mask & DV_II_56_0_BIT) {
			fail = (((w[40] >> 4) ^ (w[42] >> 4) ^ 1) |
				((w[44] >> 3) ^ (w[48] >> 28)) |
				((w[44] >> 4) ^ (w[48] >> 29)) |
				((w[52] >> 4) ^ (w[55] >> 29)) |
				((w[60] >> 4) ^ (w[64] >> 29))) & 1;
			out &= ~(fail << 31);
		}
		if (mask & DV_I_48_0_BIT) {
			fail = (((w[44] >> 4) ^ (w[46] >> 4) ^ 1) |
				((w[46] >> 4) ^ (w[48] >> 4) ^ 1) |
				(w[63] ^ (w[64] >> 5) ^ 1) |
				((w[35] >> 4) ^ (w[39] >> 29)) |
				((w[38] >> 4) ^ (w[42] >> 29))) & 1;
			out &= ~(fail << 7);
		}
		if (mask & DV_II_48_0_BIT) {
			fail = (((w[35] >> 30) ^ (w[36] >> 3) ^ 1) |
				((w[35] >> 30) ^ (w[40] >> 28) ^ 1) |
				(w[63] ^ (w[64] >> 5) ^ 1) |
				((w[39] >> 4) ^ (w[43] >> 29)) |
				((w[44] >> 4) ^ (w[48] >> 29)) |
				((w[50] >> 4) ^ (w[53] >> 29)) |
				((w[52] >> 4) ^ (w[55] >> 29))) & 1;
			out &= ~(fail << 20);
		}
		if (mask & DV_I_49_0_BIT) {
			fail = (((w[45] >> 4) ^ (w[47] >> 4) ^ 1) |
				((w[39] >> 4) ^ (w[43] >> 29)) |
				((w[49] >> 4) ^ (w[52] >> 29))) & 1;
			out &= ~(fail << 9);
		}
	}
	return out;
}

uint32_t sha1dc_ubc_check_neon(const uint32_t w[80])
{
	uint32_t mask = neon_prefix(w);
	/* Every check only clears bits, so an empty mask settles it. */
	if (!mask)
		return 0;
	return neon_tail(w, mask);
}

#endif /* SHA1DC_HAVE_NEON */

/* sse2 form */

#ifdef SHA1DC_HAVE_SSE2

/* The highest index read is 64. */
SHA1DC_TARGET_SSE2
static uint32_t sse2_prefix(const uint32_t *w)
{
	const __m128i zero = _mm_setzero_si128();
	__m128i acc0 = zero, acc1 = zero, acc;

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 35));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 36));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 5));
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 1),
			(int)(1u << 1),
			(int)(1u << 1),
			(int)(1u << 0)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_46_2_BIT | DV_I_49_2_BIT),
			(int)(DV_I_47_2_BIT | DV_I_50_2_BIT | DV_II_46_2_BIT),
			(int)(DV_I_48_2_BIT | DV_I_51_2_BIT),
			(int)(DV_II_51_2_BIT));
		acc0 = _mm_or_si128(acc0, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 36));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 37));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 5));
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 0),
			(int)(1u << 0),
			(int)(1u << 1),
			(int)(1u << 1)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT),
			(int)(DV_I_49_2_BIT),
			(int)(DV_I_46_2_BIT | DV_I_50_2_BIT | DV_II_49_2_BIT));
		acc1 = _mm_or_si128(acc1, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 36));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 38));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 4),
			(int)(1u << 4),
			(int)(1u << 1),
			(int)(1u << 4)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_II_52_0_BIT | DV_II_54_0_BIT),
			(int)(DV_I_43_0_BIT | DV_II_53_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_49_2_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_II_55_0_BIT));
		acc0 = _mm_or_si128(acc0, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 37));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 40));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 25));
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 4));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_43_0_BIT | DV_I_47_0_BIT | DV_II_46_0_BIT | DV_II_53_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_48_0_BIT | DV_II_47_0_BIT | DV_II_54_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_49_0_BIT | DV_II_48_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_50_0_BIT | DV_II_49_0_BIT | DV_II_56_0_BIT));
		acc1 = _mm_or_si128(acc1, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 36));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 40));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 25));
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 4),
			(int)(1u << 5),
			(int)(1u << 5),
			(int)(1u << 5)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_46_0_BIT | DV_I_49_0_BIT | DV_II_45_0_BIT | DV_II_48_0_BIT),
			(int)(DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT),
			(int)(DV_II_51_2_BIT));
		acc0 = _mm_or_si128(acc0, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 38));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 40));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 4),
			(int)(1u << 1),
			(int)(1u << 1),
			(int)(1u << 1)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_44_0_BIT | DV_II_54_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_50_2_BIT | DV_II_49_2_BIT),
			(int)(DV_I_51_2_BIT | DV_II_50_2_BIT),
			(int)(DV_II_46_2_BIT | DV_II_51_2_BIT));
		acc1 = _mm_or_si128(acc1, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 40));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 41));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 5));
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 1));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_47_2_BIT | DV_I_51_2_BIT | DV_II_50_2_BIT),
			(int)(DV_I_48_2_BIT | DV_II_46_2_BIT | DV_II_51_2_BIT),
			(int)(DV_I_49_2_BIT),
			(int)(DV_I_50_2_BIT));
		acc0 = _mm_or_si128(acc0, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 40));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 41));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 29));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_44_0_BIT | DV_I_47_0_BIT | DV_I_48_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_45_0_BIT | DV_I_48_0_BIT | DV_I_49_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT),
			(int)(DV_I_46_0_BIT | DV_I_49_0_BIT | DV_I_50_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT),
			(int)(DV_I_47_0_BIT | DV_I_50_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT));
		acc1 = _mm_or_si128(acc1, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 41));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 44));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 25));
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 4));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_50_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT | DV_II_47_0_BIT | DV_II_52_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT | DV_II_48_0_BIT | DV_II_53_0_BIT));
		acc0 = _mm_or_si128(acc0, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 42));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 44));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 6));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_46_2_BIT | DV_I_48_2_BIT),
			(int)(DV_I_47_2_BIT | DV_I_49_2_BIT),
			(int)(DV_I_46_2_BIT | DV_I_48_2_BIT | DV_I_50_2_BIT),
			(int)(DV_I_47_2_BIT | DV_I_49_2_BIT | DV_I_51_2_BIT));
		acc1 = _mm_or_si128(acc1, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 40));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 44));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 6),
			(int)(1u << 6),
			(int)(1u << 29),
			(int)(1u << 29)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_46_2_BIT),
			(int)(DV_I_47_2_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT));
		acc0 = _mm_or_si128(acc0, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 44));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 45));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 5));
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 1));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_51_2_BIT | DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT),
			(int)(DV_II_51_2_BIT),
			(int)(DV_II_46_2_BIT));
		acc1 = _mm_or_si128(acc1, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 44));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 45));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 29));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_48_0_BIT | DV_I_51_0_BIT | DV_I_52_0_BIT | DV_II_45_0_BIT | DV_II_46_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT),
			(int)(DV_I_49_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_51_0_BIT | DV_II_52_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_50_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT | DV_II_52_0_BIT | DV_II_53_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_51_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT | DV_II_53_0_BIT | DV_II_54_0_BIT));
		acc0 = _mm_or_si128(acc0, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 45));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 46));
		__m128i x = _mm_xor_si128(_mm_srli_epi32(lo, 5), hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 1));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_II_49_2_BIT),
			(int)(DV_I_46_2_BIT | DV_II_50_2_BIT),
			(int)(DV_I_47_2_BIT | DV_II_51_2_BIT),
			(int)(DV_I_48_2_BIT));
		acc1 = _mm_or_si128(acc1, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 45));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 47));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 29),
			(int)(1u << 29),
			(int)(1u << 29),
			(int)(1u << 4)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT),
			(int)(DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT),
			(int)(DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT),
			(int)(DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT));
		acc0 = _mm_or_si128(acc0, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 46));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 48));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 6));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_48_2_BIT | DV_I_50_2_BIT),
			(int)(DV_I_49_2_BIT | DV_I_51_2_BIT),
			(int)(DV_I_50_2_BIT | DV_II_46_2_BIT),
			(int)(DV_I_51_2_BIT));
		acc1 = _mm_or_si128(acc1, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 45));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 48));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 25));
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 4));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_49_0_BIT | DV_II_54_0_BIT),
			(int)(DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_50_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_51_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_52_0_BIT));
		acc0 = _mm_or_si128(acc0, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 48));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 49));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 29));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_45_0_BIT | DV_I_52_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_46_0_BIT | DV_II_45_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_47_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT | DV_II_52_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_48_0_BIT | DV_II_47_0_BIT | DV_II_52_0_BIT | DV_II_53_0_BIT));
		acc1 = _mm_or_si128(acc1, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 49));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 50));
		__m128i x = _mm_xor_si128(_mm_srli_epi32(lo, 5), hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 1));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_49_2_BIT),
			(int)(DV_I_50_2_BIT | DV_II_46_2_BIT),
			(int)(DV_I_51_2_BIT),
			0);
		acc0 = _mm_or_si128(acc0, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 49));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 52));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 25));
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 4));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_47_0_BIT | DV_II_53_0_BIT),
			(int)(DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_48_0_BIT | DV_II_54_0_BIT),
			(int)(DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_49_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_50_0_BIT | DV_II_56_0_BIT));
		acc1 = _mm_or_si128(acc1, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 49));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 53));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 29),
			(int)(1u << 1),
			(int)(1u << 1),
			(int)(1u << 1)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_II_45_0_BIT),
			(int)(DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT),
			(int)(DV_II_51_2_BIT));
		acc0 = _mm_or_si128(acc0, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 52));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 53));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 29));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_49_0_BIT | DV_II_45_0_BIT | DV_II_48_0_BIT | DV_II_53_0_BIT | DV_II_54_0_BIT),
			(int)(DV_I_50_0_BIT | DV_II_46_0_BIT | DV_II_49_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_50_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_51_0_BIT | DV_II_56_0_BIT));
		acc1 = _mm_or_si128(acc1, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 53));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 54));
		__m128i x = _mm_xor_si128(_mm_srli_epi32(lo, 5), hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 1));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT),
			(int)(DV_II_51_2_BIT),
			0);
		acc0 = _mm_or_si128(acc0, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 52));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 55));
		__m128i x = _mm_xor_si128(lo, hi);
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 29));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT),
			(int)(DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT),
			(int)(DV_II_49_0_BIT | DV_II_50_0_BIT),
			(int)(DV_II_50_0_BIT | DV_II_51_0_BIT));
		acc1 = _mm_or_si128(acc1, _mm_and_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 53));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 56));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 25));
		__m128i tested = _mm_and_si128(x, _mm_set1_epi32(1 << 4));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_II_49_0_BIT | DV_II_51_0_BIT),
			(int)(DV_II_50_0_BIT | DV_II_52_0_BIT),
			(int)(DV_II_51_0_BIT | DV_II_53_0_BIT),
			(int)(DV_II_52_0_BIT | DV_II_54_0_BIT));
		acc0 = _mm_or_si128(acc0, _mm_andnot_si128(miss, bits));
	}

	{
		__m128i lo = _mm_loadu_si128((const __m128i *)(w + 60));
		__m128i hi = _mm_loadu_si128((const __m128i *)(w + 61));
		__m128i x = _mm_xor_si128(lo, _mm_srli_epi32(hi, 5));
		__m128i tested = _mm_and_si128(x, _mm_setr_epi32(
			(int)(1u << 0),
			(int)(1u << 2),
			(int)(1u << 2),
			(int)(1u << 2)));
		__m128i miss = _mm_cmpeq_epi32(tested, zero);
		__m128i bits = _mm_setr_epi32(
			(int)(DV_I_45_0_BIT | DV_II_45_0_BIT),
			(int)(DV_I_46_2_BIT | DV_II_46_2_BIT),
			(int)(DV_I_47_2_BIT),
			(int)(DV_I_48_2_BIT));
		acc1 = _mm_or_si128(acc1, _mm_and_si128(miss, bits));
	}

	acc = _mm_or_si128(acc0, acc1);
	acc = _mm_or_si128(acc, _mm_shuffle_epi32(acc, 0x4E));
	acc = _mm_or_si128(acc, _mm_shuffle_epi32(acc, 0xB1));
	return ~(uint32_t)_mm_cvtsi128_si32(acc);
}

static const struct tail_check sse2_tail_checks[97] = {
	{ 41, 4, 43, 4, 1 },
	{ 58, 0, 59, 5, 1 },
	{ 58, 0, 63, 30, 1 },
	{ 61, 1, 62, 6, 1 },
	{ 43, 4, 47, 29, 0 },
	{ 59, 0, 60, 5, 1 },
	{ 59, 0, 64, 30, 1 },
	{ 62, 1, 63, 6, 1 },
	{ 38, 4, 42, 4, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 41, 4, 43, 4, 1 },
	{ 63, 1, 64, 6, 1 },
	{ 35, 4, 39, 29, 0 },
	{ 61, 0, 62, 5, 1 },
	{ 41, 4, 43, 4, 1 },
	{ 45, 4, 47, 4, 1 },
	{ 62, 0, 63, 5, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 46, 4, 48, 4, 1 },
	{ 63, 0, 64, 5, 1 },
	{ 35, 4, 39, 29, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 45, 4, 47, 4, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 45, 4, 49, 4, 0 },
	{ 36, 4, 37, 4, 1 },
	{ 46, 4, 48, 4, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 40, 4, 44, 29, 0 },
	{ 37, 4, 38, 4, 1 },
	{ 45, 4, 47, 4, 1 },
	{ 35, 3, 39, 28, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 41, 4, 45, 29, 0 },
	{ 45, 4, 49, 4, 0 },
	{ 35, 5, 39, 30, 0 },
	{ 37, 1, 37, 6, 0 },
	{ 38, 4, 39, 4, 1 },
	{ 46, 4, 48, 4, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 42, 4, 46, 29, 0 },
	{ 63, 1, 64, 6, 1 },
	{ 41, 4, 45, 29, 0 },
	{ 61, 0, 62, 5, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 42, 4, 46, 29, 0 },
	{ 62, 0, 63, 5, 1 },
	{ 35, 3, 39, 28, 0 },
	{ 35, 4, 39, 29, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 35, 30, 36, 3, 1 },
	{ 35, 30, 40, 28, 1 },
	{ 63, 0, 64, 5, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 36, 30, 37, 3, 1 },
	{ 36, 30, 41, 28, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 40, 4, 44, 29, 0 },
	{ 50, 1, 51, 6, 1 },
	{ 37, 30, 38, 3, 1 },
	{ 37, 30, 42, 28, 1 },
	{ 38, 4, 42, 29, 0 },
	{ 41, 4, 45, 29, 0 },
	{ 51, 1, 52, 6, 1 },
	{ 38, 30, 39, 3, 1 },
	{ 38, 30, 43, 28, 1 },
	{ 56, 29, 59, 29, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 42, 4, 46, 29, 0 },
	{ 52, 1, 53, 6, 1 },
	{ 39, 30, 40, 3, 1 },
	{ 39, 30, 44, 28, 1 },
	{ 54, 4, 56, 4, 1 },
	{ 54, 4, 60, 29, 1 },
	{ 56, 29, 59, 29, 1 },
	{ 40, 4, 44, 29, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 55, 4, 57, 4, 1 },
	{ 55, 4, 61, 29, 1 },
	{ 41, 3, 45, 28, 0 },
	{ 41, 4, 45, 29, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 55, 4, 57, 29, 0 },
	{ 42, 3, 46, 28, 0 },
	{ 42, 4, 46, 29, 0 },
	{ 56, 4, 58, 29, 0 },
	{ 58, 4, 62, 29, 0 },
	{ 43, 3, 47, 28, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 57, 4, 59, 29, 0 },
	{ 59, 4, 63, 29, 0 },
	{ 38, 4, 42, 4, 0 },
	{ 44, 3, 48, 28, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 60, 4, 64, 29, 0 }
};

static const struct tail_span sse2_tail_spans[32] = {
	{ 0, 5 },
	{ 5, 5 },
	{ 10, 3 },
	{ 13, 1 },
	{ 14, 0 },
	{ 14, 4 },
	{ 18, 0 },
	{ 18, 4 },
	{ 22, 0 },
	{ 22, 3 },
	{ 25, 0 },
	{ 25, 4 },
	{ 29, 0 },
	{ 29, 6 },
	{ 35, 2 },
	{ 37, 4 },
	{ 41, 2 },
	{ 43, 3 },
	{ 46, 0 },
	{ 46, 5 },
	{ 51, 5 },
	{ 56, 4 },
	{ 60, 1 },
	{ 61, 4 },
	{ 65, 1 },
	{ 66, 5 },
	{ 71, 1 },
	{ 72, 7 },
	{ 79, 6 },
	{ 85, 4 },
	{ 89, 4 },
	{ 93, 4 }
};

static uint32_t sse2_tail(const uint32_t *w, uint32_t mask)
{
	return run_tail(w, mask, sse2_tail_checks, sse2_tail_spans);
}

SHA1DC_TARGET_SSE2
uint32_t sha1dc_ubc_check_sse2(const uint32_t w[80])
{
	uint32_t mask = sse2_prefix(w);
	/* Every check only clears bits, so an empty mask settles it. */
	if (!mask)
		return 0;
	return sse2_tail(w, mask);
}

#endif /* SHA1DC_HAVE_SSE2 */

/* avx2 form */

#ifdef SHA1DC_HAVE_AVX2

/* The highest index read is 66. */
SHA1DC_TARGET_AVX2
static uint32_t avx2_prefix(const uint32_t *w)
{
	const __m256i zero = _mm256_setzero_si256();
	__m256i acc0 = zero, acc1 = zero;

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 35));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 36));
		__m256i x = _mm256_xor_si256(lo, _mm256_srli_epi32(hi, 5));
		__m256i tested = _mm256_and_si256(x, _mm256_setr_epi32(
			(int)(1u << 1),
			(int)(1u << 1),
			(int)(1u << 1),
			(int)(1u << 0),
			(int)(1u << 1),
			(int)(1u << 1),
			(int)(1u << 1),
			(int)(1u << 1)));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_46_2_BIT | DV_I_49_2_BIT),
			(int)(DV_I_47_2_BIT | DV_I_50_2_BIT | DV_II_46_2_BIT),
			(int)(DV_I_48_2_BIT | DV_I_51_2_BIT),
			(int)(DV_II_51_2_BIT),
			(int)(DV_I_46_2_BIT | DV_I_50_2_BIT | DV_II_49_2_BIT),
			(int)(DV_I_47_2_BIT | DV_I_51_2_BIT | DV_II_50_2_BIT),
			(int)(DV_I_48_2_BIT | DV_II_46_2_BIT | DV_II_51_2_BIT),
			(int)(DV_I_49_2_BIT));
		acc0 = _mm256_or_si256(acc0, _mm256_and_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 36));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 38));
		__m256i x = _mm256_xor_si256(lo, hi);
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 4));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_II_52_0_BIT | DV_II_54_0_BIT),
			(int)(DV_I_43_0_BIT | DV_II_53_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_44_0_BIT | DV_II_54_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT),
			(int)(DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT));
		acc1 = _mm256_or_si256(acc1, _mm256_and_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 37));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 38));
		__m256i x = _mm256_xor_si256(lo, _mm256_srli_epi32(hi, 5));
		__m256i tested = _mm256_and_si256(x, _mm256_setr_epi32(
			(int)(1u << 0),
			(int)(1u << 1),
			0,
			0,
			0,
			0,
			(int)(1u << 1),
			(int)(1u << 1)));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_II_50_2_BIT),
			(int)(DV_I_49_2_BIT),
			0,
			0,
			0,
			0,
			(int)(DV_I_50_2_BIT),
			(int)(DV_I_51_2_BIT | DV_II_49_2_BIT));
		acc0 = _mm256_or_si256(acc0, _mm256_and_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 35));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 39));
		__m256i x = _mm256_xor_si256(lo, _mm256_srli_epi32(hi, 25));
		__m256i tested = _mm256_and_si256(x, _mm256_setr_epi32(
			(int)(1u << 5),
			(int)(1u << 4),
			(int)(1u << 5),
			(int)(1u << 5),
			(int)(1u << 5),
			(int)(1u << 3),
			(int)(1u << 3),
			(int)(1u << 4)));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_51_2_BIT),
			(int)(DV_I_46_0_BIT | DV_I_49_0_BIT | DV_II_45_0_BIT | DV_II_48_0_BIT),
			(int)(DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT),
			(int)(DV_II_51_2_BIT),
			(int)(DV_II_52_0_BIT),
			(int)(DV_II_53_0_BIT),
			(int)(DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT | DV_II_54_0_BIT));
		acc1 = _mm256_or_si256(acc1, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 37));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 40));
		__m256i x = _mm256_xor_si256(lo, _mm256_srli_epi32(hi, 25));
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 4));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_43_0_BIT | DV_I_47_0_BIT | DV_II_46_0_BIT | DV_II_53_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_48_0_BIT | DV_II_47_0_BIT | DV_II_54_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_49_0_BIT | DV_II_48_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_50_0_BIT | DV_II_49_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_50_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT | DV_II_47_0_BIT | DV_II_52_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT | DV_II_48_0_BIT | DV_II_53_0_BIT));
		acc0 = _mm256_or_si256(acc0, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 39));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 40));
		__m256i x = _mm256_xor_si256(_mm256_srli_epi32(lo, 5), hi);
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 1));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_49_2_BIT),
			(int)(DV_I_50_2_BIT | DV_II_49_2_BIT),
			(int)(DV_I_51_2_BIT | DV_II_50_2_BIT),
			(int)(DV_II_46_2_BIT | DV_II_51_2_BIT),
			0,
			0,
			(int)(DV_II_49_2_BIT),
			(int)(DV_I_46_2_BIT | DV_II_50_2_BIT));
		acc1 = _mm256_or_si256(acc1, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 40));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 41));
		__m256i x = _mm256_xor_si256(lo, hi);
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 29));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_44_0_BIT | DV_I_47_0_BIT | DV_I_48_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_45_0_BIT | DV_I_48_0_BIT | DV_I_49_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT),
			(int)(DV_I_46_0_BIT | DV_I_49_0_BIT | DV_I_50_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT),
			(int)(DV_I_47_0_BIT | DV_I_50_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT),
			(int)(DV_I_48_0_BIT | DV_I_51_0_BIT | DV_I_52_0_BIT | DV_II_45_0_BIT | DV_II_46_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT),
			(int)(DV_I_49_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT | DV_II_51_0_BIT | DV_II_52_0_BIT),
			(int)(DV_I_43_0_BIT | DV_I_50_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT | DV_II_52_0_BIT | DV_II_53_0_BIT),
			(int)(DV_I_44_0_BIT | DV_I_51_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT | DV_II_53_0_BIT | DV_II_54_0_BIT));
		acc0 = _mm256_or_si256(acc0, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 40));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 42));
		__m256i x = _mm256_xor_si256(lo, hi);
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 6));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_46_2_BIT),
			(int)(DV_I_47_2_BIT),
			(int)(DV_I_46_2_BIT | DV_I_48_2_BIT),
			(int)(DV_I_47_2_BIT | DV_I_49_2_BIT),
			(int)(DV_I_46_2_BIT | DV_I_48_2_BIT | DV_I_50_2_BIT),
			(int)(DV_I_47_2_BIT | DV_I_49_2_BIT | DV_I_51_2_BIT),
			(int)(DV_I_48_2_BIT | DV_I_50_2_BIT),
			(int)(DV_I_49_2_BIT | DV_I_51_2_BIT));
		acc1 = _mm256_or_si256(acc1, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 45));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 46));
		__m256i x = _mm256_xor_si256(lo, _mm256_srli_epi32(hi, 5));
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 1));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_II_50_2_BIT),
			(int)(DV_II_51_2_BIT),
			(int)(DV_II_46_2_BIT),
			0,
			0,
			(int)(DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT),
			(int)(DV_II_51_2_BIT));
		acc0 = _mm256_or_si256(acc0, _mm256_and_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 45));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 48));
		__m256i x = _mm256_xor_si256(lo, _mm256_srli_epi32(hi, 25));
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 4));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_45_0_BIT | DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_49_0_BIT | DV_II_54_0_BIT),
			(int)(DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_50_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_51_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_52_0_BIT),
			(int)(DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT | DV_II_47_0_BIT | DV_II_53_0_BIT),
			(int)(DV_I_50_0_BIT | DV_I_52_0_BIT | DV_II_46_0_BIT | DV_II_48_0_BIT | DV_II_54_0_BIT),
			(int)(DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_49_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_50_0_BIT | DV_II_56_0_BIT));
		acc1 = _mm256_or_si256(acc1, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 47));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 48));
		__m256i x = _mm256_xor_si256(_mm256_srli_epi32(lo, 5), hi);
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 1));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_47_2_BIT | DV_II_51_2_BIT),
			(int)(DV_I_48_2_BIT),
			(int)(DV_I_49_2_BIT),
			(int)(DV_I_50_2_BIT | DV_II_46_2_BIT),
			(int)(DV_I_51_2_BIT),
			0,
			(int)(DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT));
		acc0 = _mm256_or_si256(acc0, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 47));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 49));
		__m256i x = _mm256_xor_si256(lo, hi);
		__m256i tested = _mm256_and_si256(x, _mm256_setr_epi32(
			(int)(1u << 29),
			(int)(1u << 29),
			(int)(1u << 29),
			(int)(1u << 29),
			(int)(1u << 4),
			(int)(1u << 4),
			(int)(1u << 4),
			(int)(1u << 4)));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_46_0_BIT | DV_I_48_0_BIT | DV_I_50_0_BIT),
			(int)(DV_I_47_0_BIT | DV_I_49_0_BIT | DV_I_51_0_BIT),
			(int)(DV_I_48_0_BIT | DV_I_50_0_BIT | DV_I_52_0_BIT),
			(int)(DV_I_49_0_BIT | DV_I_51_0_BIT | DV_II_45_0_BIT),
			(int)(DV_II_49_0_BIT),
			(int)(DV_II_50_0_BIT),
			(int)(DV_II_51_0_BIT),
			(int)(DV_II_52_0_BIT));
		acc1 = _mm256_or_si256(acc1, _mm256_and_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 48));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 49));
		__m256i x = _mm256_xor_si256(lo, hi);
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 29));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_45_0_BIT | DV_I_52_0_BIT | DV_II_49_0_BIT | DV_II_50_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_46_0_BIT | DV_II_45_0_BIT | DV_II_50_0_BIT | DV_II_51_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_47_0_BIT | DV_II_46_0_BIT | DV_II_51_0_BIT | DV_II_52_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_48_0_BIT | DV_II_47_0_BIT | DV_II_52_0_BIT | DV_II_53_0_BIT),
			(int)(DV_I_49_0_BIT | DV_II_45_0_BIT | DV_II_48_0_BIT | DV_II_53_0_BIT | DV_II_54_0_BIT),
			(int)(DV_I_50_0_BIT | DV_II_46_0_BIT | DV_II_49_0_BIT | DV_II_54_0_BIT | DV_II_55_0_BIT),
			(int)(DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_50_0_BIT | DV_II_55_0_BIT | DV_II_56_0_BIT),
			(int)(DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_51_0_BIT | DV_II_56_0_BIT));
		acc0 = _mm256_or_si256(acc0, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 48));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 50));
		__m256i x = _mm256_xor_si256(lo, hi);
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 6));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_50_2_BIT | DV_II_46_2_BIT),
			(int)(DV_I_51_2_BIT),
			0,
			(int)(DV_II_49_2_BIT),
			(int)(DV_II_50_2_BIT),
			(int)(DV_II_51_2_BIT),
			0,
			0);
		acc1 = _mm256_or_si256(acc1, _mm256_andnot_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 51));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 54));
		__m256i x = _mm256_xor_si256(lo, hi);
		__m256i tested = _mm256_and_si256(x, _mm256_set1_epi32(1 << 29));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_50_0_BIT | DV_II_46_0_BIT | DV_II_47_0_BIT),
			(int)(DV_I_51_0_BIT | DV_II_47_0_BIT | DV_II_48_0_BIT),
			(int)(DV_I_52_0_BIT | DV_II_48_0_BIT | DV_II_49_0_BIT),
			(int)(DV_II_49_0_BIT | DV_II_50_0_BIT),
			(int)(DV_II_50_0_BIT | DV_II_51_0_BIT),
			(int)(DV_II_51_0_BIT | DV_II_52_0_BIT),
			(int)(DV_II_52_0_BIT),
			(int)(DV_II_53_0_BIT));
		acc0 = _mm256_or_si256(acc0, _mm256_and_si256(miss, bits));
	}

	{
		__m256i lo = _mm256_loadu_si256((const __m256i *)(w + 58));
		__m256i hi = _mm256_loadu_si256((const __m256i *)(w + 59));
		__m256i x = _mm256_xor_si256(lo, _mm256_srli_epi32(hi, 5));
		__m256i tested = _mm256_and_si256(x, _mm256_setr_epi32(
			(int)(1u << 0),
			(int)(1u << 0),
			(int)(1u << 0),
			(int)(1u << 2),
			(int)(1u << 2),
			(int)(1u << 2),
			0,
			0));
		__m256i miss = _mm256_cmpeq_epi32(tested, zero);
		__m256i bits = _mm256_setr_epi32(
			(int)(DV_I_43_0_BIT),
			(int)(DV_I_44_0_BIT),
			(int)(DV_I_45_0_BIT | DV_II_45_0_BIT),
			(int)(DV_I_46_2_BIT | DV_II_46_2_BIT),
			(int)(DV_I_47_2_BIT),
			(int)(DV_I_48_2_BIT),
			0,
			0);
		acc1 = _mm256_or_si256(acc1, _mm256_and_si256(miss, bits));
	}

	{
		__m256i both = _mm256_or_si256(acc0, acc1);
		__m128i half = _mm_or_si128(_mm256_castsi256_si128(both),
					      _mm256_extracti128_si256(both, 1));
		half = _mm_or_si128(half, _mm_shuffle_epi32(half, 0x4E));
		half = _mm_or_si128(half, _mm_shuffle_epi32(half, 0xB1));
		return ~(uint32_t)_mm_cvtsi128_si32(half);
	}
}

static const struct tail_check avx2_tail_checks[77] = {
	{ 58, 0, 63, 30, 1 },
	{ 61, 1, 62, 6, 1 },
	{ 43, 4, 47, 29, 0 },
	{ 59, 0, 64, 30, 1 },
	{ 62, 1, 63, 6, 1 },
	{ 44, 4, 48, 29, 0 },
	{ 63, 1, 64, 6, 1 },
	{ 35, 4, 39, 29, 0 },
	{ 61, 0, 62, 5, 1 },
	{ 62, 0, 63, 5, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 63, 0, 64, 5, 1 },
	{ 35, 4, 39, 29, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 39, 4, 43, 29, 0 },
	{ 36, 4, 37, 4, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 40, 4, 44, 29, 0 },
	{ 46, 4, 50, 4, 0 },
	{ 37, 4, 38, 4, 1 },
	{ 35, 3, 39, 28, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 41, 4, 45, 29, 0 },
	{ 37, 1, 37, 6, 0 },
	{ 38, 4, 39, 4, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 46, 4, 50, 4, 0 },
	{ 63, 1, 64, 6, 1 },
	{ 41, 4, 45, 29, 0 },
	{ 61, 0, 62, 5, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 62, 0, 63, 5, 1 },
	{ 35, 3, 39, 28, 0 },
	{ 35, 4, 39, 29, 0 },
	{ 38, 4, 42, 29, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 35, 30, 36, 3, 1 },
	{ 35, 30, 40, 28, 1 },
	{ 63, 0, 64, 5, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 36, 30, 37, 3, 1 },
	{ 36, 30, 41, 28, 1 },
	{ 37, 4, 41, 29, 0 },
	{ 40, 4, 44, 29, 0 },
	{ 36, 0, 37, 5, 1 },
	{ 37, 30, 38, 3, 1 },
	{ 37, 30, 42, 28, 1 },
	{ 38, 4, 42, 29, 0 },
	{ 41, 4, 45, 29, 0 },
	{ 54, 4, 57, 29, 0 },
	{ 38, 30, 39, 3, 1 },
	{ 38, 30, 43, 28, 1 },
	{ 39, 4, 43, 29, 0 },
	{ 55, 4, 58, 29, 0 },
	{ 52, 1, 56, 1, 1 },
	{ 39, 30, 40, 3, 1 },
	{ 40, 4, 44, 29, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 54, 4, 57, 29, 0 },
	{ 56, 4, 59, 29, 0 },
	{ 55, 4, 57, 4, 1 },
	{ 41, 4, 45, 29, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 55, 4, 58, 29, 0 },
	{ 55, 4, 57, 29, 0 },
	{ 42, 3, 46, 28, 0 },
	{ 56, 4, 59, 29, 0 },
	{ 56, 4, 58, 29, 0 },
	{ 58, 4, 62, 29, 0 },
	{ 43, 3, 47, 28, 0 },
	{ 43, 4, 47, 29, 0 },
	{ 57, 4, 59, 29, 0 },
	{ 59, 4, 63, 29, 0 },
	{ 44, 3, 48, 28, 0 },
	{ 44, 4, 48, 29, 0 },
	{ 60, 4, 64, 29, 0 }
};

static const struct tail_span avx2_tail_spans[32] = {
	{ 0, 3 },
	{ 3, 3 },
	{ 6, 2 },
	{ 8, 1 },
	{ 9, 0 },
	{ 9, 2 },
	{ 11, 0 },
	{ 11, 3 },
	{ 14, 0 },
	{ 14, 1 },
	{ 15, 0 },
	{ 15, 4 },
	{ 19, 0 },
	{ 19, 4 },
	{ 23, 1 },
	{ 24, 3 },
	{ 27, 2 },
	{ 29, 2 },
	{ 31, 0 },
	{ 31, 5 },
	{ 36, 5 },
	{ 41, 4 },
	{ 45, 1 },
	{ 46, 5 },
	{ 51, 0 },
	{ 51, 4 },
	{ 55, 1 },
	{ 56, 5 },
	{ 61, 5 },
	{ 66, 4 },
	{ 70, 4 },
	{ 74, 3 }
};

static uint32_t avx2_tail(const uint32_t *w, uint32_t mask)
{
	return run_tail(w, mask, avx2_tail_checks, avx2_tail_spans);
}

SHA1DC_TARGET_AVX2
uint32_t sha1dc_ubc_check_avx2(const uint32_t w[80])
{
	uint32_t mask = avx2_prefix(w);
	/* Every check only clears bits, so an empty mask settles it. */
	if (!mask)
		return 0;
	return avx2_tail(w, mask);
}

#endif /* SHA1DC_HAVE_AVX2 */
