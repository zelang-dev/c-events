#include <catomics.h>
#if _WIN32
#	define _Atomic volatile
#endif