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

// #define MAX_DATA_SIZE  4096    // 4KB

int buf_map_init(ebpf_context_t *ctxt) {

	int ret;
	uint32_t key0 = 0;
	uint32_t key1 = 1;
	char buf[131072] = {0};
	int buf_map_idx = 3;
    int overwrite = 1;

	ret = ebpf_data_update(ctxt, (void *)&key0, sizeof(uint32_t), (void *)&buf, sizeof(char) * 131072, buf_map_idx, overwrite);
	if (ret) {
		ERROR("[%d] \t Failed to insert buf_map key %u: %s\n",
			gettid(), key0, strerror(errno));
		return ret;
	}

	ret = ebpf_data_update(ctxt, (void *)&key1, sizeof(uint32_t), (void *)&buf, sizeof(char) * 131072, buf_map_idx, overwrite);
	if (ret) {
		ERROR("[%d] \t Failed to insert buf_map key %u: %s\n",
			gettid(), key1, strerror(errno));
		return ret;
	}
	
	return ret;
}

int data_insert(ebpf_context_t *ctxt, uint64_t file_handle,
		uint64_t offset, uint64_t size, const char *data)
{
	uint64_t aligned_offset = offset & ~(uint64_t)(MAX_DATA_SIZE - 1);
	uint64_t end_offset = (offset + size + MAX_DATA_SIZE - 1) & ~(uint64_t)(MAX_DATA_SIZE - 1);
	uint64_t off;

    for (off = aligned_offset; off < end_offset; off += MAX_DATA_SIZE) {
        read_data_key_t key = {
            .file_handle = file_handle,
            .offset = off
        };

        read_data_value_t val = {0};
        val.size = MAX_DATA_SIZE;

        // 1. 尝试从 map 里读原来的数据
        int found = ebpf_data_lookup(ctxt, &key, sizeof(key), &val, sizeof(val), 2);

        // 2. 如果没有，从磁盘读
        if (found != 0) {
			ssize_t res = pread(file_handle, val.data, MAX_DATA_SIZE, off);
			if (res < 0) {
				perror("pread failed");
				continue;
			}
			if (res < MAX_DATA_SIZE) {
				memset(val.data + res, 0, MAX_DATA_SIZE - res);
				val.size = res;
			}
		}

        // 3. 决定要拷贝的区域
        uint64_t data_start = (off < offset) ? 0 : (off - offset);
        uint64_t block_start = (off > offset) ? 0 : (offset - off);
        uint64_t max_copy = (block_start < val.size) ? (val.size - block_start) : 0;
        uint64_t remain = size - data_start;
        uint64_t copy_size = (remain < max_copy) ? remain : max_copy;

        if (copy_size > 0) {
            memcpy(val.data + block_start, data + data_start, copy_size);
        }

        // 4. 更新回 map
        ebpf_data_update(ctxt, &key, sizeof(key), &val, sizeof(val), 2, 1);
    }

	return 0;
}
