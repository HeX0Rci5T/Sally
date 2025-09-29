#include <linux/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/utils.hh"

#define ROTL(x, bits) (x << bits) | (x >> sizeof(x)*8-bits)

static const __u32 s[64] = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

static const __u32 K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

void MD5_hash(__u8 hash[16], __u8 *msg, __u64 len) {
	__u32 a0=0x67452301, b0=0xefcdab89, c0=0x98badcfe, d0=0x10325476;

	__u16 padding = (56 - (len+1 % 64)) % 64;
	__u64 sz = len+1 + padding + 8;
	__u8 *blocks = new __u8[sz]{};

	memcpy(blocks, msg, len);
	blocks[len] = 0x80;
	*(__u64*)&blocks[len+1+padding] = (len*8) % ~0llu;	// little endian

	for (__u64 i = 0; i < sz; i += 64) {
		__u8 *block = blocks + i;
		__u32 M[16] = {0};
		// Break up ~block into 16 DWORDs
		for (int l = 0; l < 16; l++) {
			M[l] = ((__u32*)block)[l];
		}

		__u32 a=a0, b=b0, c=c0, d=d0;

		for (int j = 0; j < 64; j++) {
			__u32 F, g;
			if (0 <= j && j <= 15) {
				F = (b & c) | (~b & d);
				g = j;
			} else if (16 <= j && j <= 31) {
				F = (d & b) | (~d & c);
				g = (5*j + 1) % 16;
			} else if (32 <= j && j <= 47) {
				F = (b ^ c) ^ d;
				g = (3*j + 5) % 16;
			} else if (48 <= j && j <= 63) {
				F = c ^ (b | ~d);
				g = (7*j) % 16;
			}

			F += a + K[j] + M[g];
			a = d;
			d = c;
			c = b;
			b += ROTL(F, s[j]);
		}

		a0 += a;
		b0 += b;
		c0 += c;
		d0 += d;
	}

	((__u32*)hash)[0] = a0;
	((__u32*)hash)[1] = b0;
	((__u32*)hash)[2] = c0;
	((__u32*)hash)[3] = d0;
	delete blocks;
}