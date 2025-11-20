/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Goran Mekić
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/event.h>

#include <fcntl.h>

#include "oss.h"

int
main(int argc, char *argv[])
{
	int rc, bytes, kq;
	uint8_t *buf;
	count_info ci;
	oss_syncgroup sync_group = {0, 0, {0}};
	struct kevent event = {};
	struct config config_in = {
		.device = "/dev/dsp",
		.mode = O_RDONLY | O_EXCL | O_NONBLOCK,
		.format = AFMT_S32_NE,
		.sample_rate = 48000,
		.mmap = 1,
	};
	struct config config_out = {
		.device = "/dev/dsp",
		.mode = O_WRONLY | O_EXCL | O_NONBLOCK,
		.format = AFMT_S32_NE,
		.sample_rate = 48000,
		.mmap = 1,
	};

	oss_init(&config_in);
	oss_init(&config_out);

	/* Allocate and mmap buffers */
	bytes = config_in.buffer_info.bytes < config_out.buffer_info.bytes
		? config_in.buffer_info.bytes
		: config_out.buffer_info.bytes;
	buf = malloc(bytes);

	/* Initialize kqueue */
	kq = kqueue();
	if (kq == -1)
		err(1, "Failed to allocate kqueue");
	EV_SET(&event, config_in.fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, 0);
	event.udata = &config_in;
	if (kevent(kq, &event, 1, NULL, 0, NULL) < 0)
		err(1, "Failed to register kevent");
	EV_SET(&event, config_out.fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, 0);
	event.udata = &config_out;
	if (kevent(kq, &event, 1, NULL, 0, NULL) < 0)
		err(1, "Failed to register kevent");

	/* Configure and start sync group */
	sync_group.mode = PCM_ENABLE_INPUT;
	if (ioctl(config_in.fd, SNDCTL_DSP_SYNCGROUP, &sync_group) < 0)
		err(1, "Failed to add input to syncgroup");
	sync_group.mode = PCM_ENABLE_OUTPUT;
	if (ioctl(config_out.fd, SNDCTL_DSP_SYNCGROUP, &sync_group) < 0)
		err(1, "Failed to add output to syncgroup");
	if (ioctl(config_in.fd, SNDCTL_DSP_SYNCSTART, &sync_group.id) < 0)
		err(1, "Starting sync group failed");

	/* Main loop */
	for (;;) {
		rc = kevent(kq, NULL, 0, &event, 1, NULL);
		if (rc == -1 || event.data == 0) {
			warn("Event error");
			break;
		}
		if (event.flags & EV_ERROR) {
			warn("Event error: %s", strerror(event.data));
			break;
		}
		if (event.udata == &config_out) {
			ioctl(config_out.fd, SNDCTL_DSP_GETOPTR, &ci);
			memcpy(config_out.buf, buf, bytes);
			printf("Output");
		} else {
			ioctl(config_out.fd, SNDCTL_DSP_GETIPTR, &ci);
			memcpy(buf, config_in.buf, bytes);
			printf("Input");
		}
		printf(": %d\n", ci.ptr);
	}

	/* Cleanup */
	free(buf);
	if (munmap(config_in.buf, config_in.buffer_info.bytes) != 0)
		err(1, "Memory unmap failed");
	config_in.buf = NULL;
	if (munmap(config_out.buf, config_out.buffer_info.bytes) != 0)
		err(1, "Memory unmap failed");
	config_out.buf = NULL;
	EV_SET(&event, config_in.fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
	if (kevent(kq, &event, 1, NULL, 0, NULL) < 0)
		err(1, "Failed to unregister input kevent");
	EV_SET(&event, config_out.fd, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
	if (kevent(kq, &event, 1, NULL, 0, NULL) < 0)
		err(1, "Failed to unregister input kevent");
	close(kq);
	close(config_in.fd);
	close(config_out.fd);

	return (0);
}
