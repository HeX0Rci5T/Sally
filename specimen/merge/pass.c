#include <stdio.h>

#define MERGE_FLAG			"_1Dlsd__"
#define MERGE_PRE_HANDLER	"\x31"
#define MERGE_POST_HANDLER	"\x33"

#define M_PRE_	MERGE_PRE_HANDLER
#define M_POST_	MERGE_POST_HANDLER
#define MERGE(fn, t) __attribute__((section(MERGE_FLAG fn t)))

MERGE("oi", M_PRE_) void fn(int arg) {
	printf("You got fucked  %lx!\n", arg);
}

MERGE("main", M_PRE_) void main_ovrd() {
	printf("DIS IS FROM ME MATE!\n");
}
