#include <stdio.h>

#include "create.h"

int ebpf_create_entry(ebpf_context_t *ctxt, void *args, size_t args_sz)
{
    return ebpf_call_handler(ctxt, 0, args, args_sz);
}