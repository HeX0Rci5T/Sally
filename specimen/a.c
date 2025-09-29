#include <stdio.h>

void fn_A() { puts("Yo Ho!!"); }

void fn_B() { fn_A(); }

void main() {
	fn_B();
}