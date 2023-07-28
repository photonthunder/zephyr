/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <zephyr/logging/log_backend.h>
#include <zephyr/logging/log_backend_std.h>
#include <zephyr/logging/log_core.h>
#include <zephyr/logging/log_output.h>
#include <assert.h>
#include <zephyr/fs/fcb.h>

#define MAX_PATH_LEN 256
#define MAX_FLASH_WRITE_SIZE 256

#define FCB_MAGIC 0xbaadbaad
#define FCB_VERSION 1
#define FCB_NUM_AREAS 16

static struct flash_sector logging_fcb_area[FCB_NUM_AREAS + 1];
static struct fcb config_init_logger_fcb;

//struct fcb log_fcb = {0};
struct fcb log_fcb_crc_disabled = { .f_flags = FCB_FLAGS_CRC_DISABLED };

#if DT_HAS_CHOSEN(zephyr_logger_partition)
#define LOGGER_PARTITION DT_FIXED_PARTITION_ID(DT_CHOSEN(zephyr_logger_partition))
#else
#error Need zephyr,logger-partition for FCB logging backend
#endif

static uint32_t log_format_current = CONFIG_LOG_BACKEND_FCB_OUTPUT_DEFAULT;

int write_log_to_fcb(uint8_t *data, size_t length, void *ctx)
{
	struct fcb_entry loc;
	int rc;
	while(1) {
		rc = fcb_append(&config_init_logger_fcb, length, &loc);
		if (rc == 0) {
			break;
		}
		else if (rc == -ENOSPC) {
			rc = fcb_rotate(&config_init_logger_fcb);
			if (rc != 0) {
				printk("fcb_rotate error %d\n", rc);
				return length;
			}
		}
		else {
			printk("fcb_append error %d\n", rc);
			return length;
		}
	}

	rc = flash_area_write(config_init_logger_fcb.fap, FCB_ENTRY_FA_DATA_OFF(loc), data, length);
	if (rc != 0) {
		printk("flash_area_write error %d\n", rc);
		return length;
	}
	
	rc = fcb_append_finish(&config_init_logger_fcb, &loc);
	if (rc != 0) {
		printk("fcb_append_finish error %d\n", rc);
		return length;
	}
	return length;
}

BUILD_ASSERT(!IS_ENABLED(CONFIG_LOG_MODE_IMMEDIATE),
	     "Immediate logging is not supported by LOG FCB backend.");

static uint8_t __aligned(4) buf[MAX_FLASH_WRITE_SIZE];
LOG_OUTPUT_DEFINE(log_output, write_log_to_fcb, buf, MAX_FLASH_WRITE_SIZE);

static void log_backend_fcb_init(const struct log_backend *const backend)
{
	config_init_logger_fcb.f_version = FCB_VERSION;
	config_init_logger_fcb.f_magic = FCB_MAGIC;
	config_init_logger_fcb.f_sectors = logging_fcb_area;
	uint32_t cnt = sizeof(logging_fcb_area) / sizeof(logging_fcb_area[0]);
	int rc;

	rc = flash_area_get_sectors(LOGGER_PARTITION, &cnt, logging_fcb_area);
	if (rc != 0 && rc != -ENOMEM) {
		printk("flash_area_get_sectors %d\n", rc);
		return;
	}

	config_init_logger_fcb.f_sector_cnt = cnt;

	rc = fcb_init(LOGGER_PARTITION, &config_init_logger_fcb);
	if (rc != 0 && rc != -ENOMSG) {
		printk("fcb_init error %d\n", rc);
		return;
	}

}

static void panic(struct log_backend const *const backend)
{
	/* In case of panic deinitialize backend. It is better to keep
	 * current data rather than log new and risk of failure.
	 */
	log_backend_deactivate(backend);
}

static void dropped(const struct log_backend *const backend, uint32_t cnt)
{
	ARG_UNUSED(backend);

	log_backend_std_dropped(&log_output, cnt);
}

static void process(const struct log_backend *const backend,
		union log_msg_generic *msg)
{
	uint32_t flags = log_backend_std_get_flags();

	log_format_func_t log_output_func = log_format_func_t_get(log_format_current);

	log_output_func(&log_output, &msg->log, flags);
}

static int format_set(const struct log_backend *const backend, uint32_t log_type)
{
	log_format_current = log_type;
	return 0;
}

static const struct log_backend_api log_backend_fcb_api = {
	.process = process,
	.panic = panic,
	.init = log_backend_fcb_init,
	.dropped = dropped,
	.format_set = format_set,
};

LOG_BACKEND_DEFINE(log_backend_fcb, log_backend_fcb_api,
		IS_ENABLED(CONFIG_LOG_BACKEND_FCB_AUTOSTART));