#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#define __print_array(array, count, el_size) ""
#endif
#include_next <trace/ftrace.h>
