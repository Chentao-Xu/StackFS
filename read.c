#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <fuse.h>
#include <linux/fuse.h>
#include <fuse_lowlevel.h>
#include <assert.h>
#include <stddef.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/xattr.h>
#include <sys/syscall.h>

#include "ebpf_read.h"
#include "lookup.h"
#include "attr.h"
#include "read.h"

#define gettid getpid
#define ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

// #define DATA_MAX_BLOCK_SIZE  4096    // 4KB

void init_read_stat_map(ebpf_context_t *ctxt) {
    uint32_t key = 0;
    read_stat_t init_val = {
        .cache_time_sum = 0,
        .passthrough_time_sum = 0,
        .cache_cnt = 0,
        .passthrough_cnt = 0,
        .total_cnt = 0,
        .prefer_cache = 0,  // 默认 prefer 直通
    };

    ebpf_data_update(ctxt, &key, sizeof(key), &init_val, sizeof(init_val), 3, 1);
}

int data_insert(ebpf_context_t *ctxt, uint64_t file_handle,
		uint64_t offset, uint64_t size, const char *data)
{
    // printf("enter data_insert: file_handle=0x%lx, offset=%lu, size=%lu\n",
        //    file_handle, offset, size);
	uint64_t aligned_offset = offset & ~(uint64_t)(DATA_MAX_BLOCK_SIZE - 1);
	uint64_t end_offset = (offset + size + DATA_MAX_BLOCK_SIZE - 1) & ~(uint64_t)(DATA_MAX_BLOCK_SIZE - 1);
	uint64_t off, block_start, data_start, copy_size;

    for (off = aligned_offset; off < end_offset; off += DATA_MAX_BLOCK_SIZE) {
        read_data_key_t key = {
            .file_handle = file_handle,
            .offset = off
        };

        read_data_value_t val = {0};

        if (off <= offset) {
            block_start = 0;
            data_start = offset - off;
            copy_size = (off + DATA_MAX_BLOCK_SIZE <= offset + size) ? DATA_MAX_BLOCK_SIZE : offset + size - off;

            val.size = copy_size;
            memcpy(val.data + block_start, data + data_start, copy_size);
            if (off + DATA_MAX_BLOCK_SIZE >= offset + size) {
                val.is_last = 1; // 标记为最后一块
            } else {
                val.is_last = 0; // 不是最后一块
            }

            // printf("Inserting data: file_handle=0x%lx, offset=%lu, size=%u, is_last=%d\n",
                //    file_handle, off, val.size, val.is_last);
            ebpf_data_update(ctxt, &key, sizeof(key), &val, sizeof(val), 2, 1);
            continue;
        }

        int found = ebpf_data_lookup(ctxt, &key, sizeof(key), &val, sizeof(val), 2);

        if (found != 0) {
			continue;
		}

        data_start = (off < offset) ? 0 : (off - offset);
        block_start = (off > offset) ? 0 : (offset - off);
        uint64_t max_copy = (block_start < val.size) ? (val.size - block_start) : 0;
        uint64_t remain = size - data_start;
        copy_size = (remain < max_copy) ? remain : max_copy;

        if (copy_size > 0) {
            memcpy(val.data + block_start, data + data_start, copy_size);
        }

        ebpf_data_update(ctxt, &key, sizeof(key), &val, sizeof(val), 2, 1);
    }

	return 0;
}
