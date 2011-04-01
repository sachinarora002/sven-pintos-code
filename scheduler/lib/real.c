/* functions to make real numbers and operate with them */

#include <stdint.h>
#include "lib/real.h"

int real_make(int num, int denum) {
	
	return ( (num * f) / denum );
}

int real_makeback(int num) {
		
	return (num / f);
}

int real_multiply(int x, int y) {
	
	return ( ((int64_t) x) * y / f );
}

int real_divide (int x, int y) {
	
	return ( ((int64_t) x) * f / y );
}
