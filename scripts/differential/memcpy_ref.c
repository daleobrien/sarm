// Reference driver: libc memcpy.
#include "driver.h"

void copy_bytes(void *dst, const void *src, int64_t len) {
	memcpy(dst, src, (size_t)len);
}
