/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Goran Mekić
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

#include <err.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

#include "ossinit.h"
#include "ossmidi.h"

static int8_t *ibuf = NULL;
static int8_t *obuf = NULL;
static sample_t *channels = NULL;
static int algo = -1;
static int maxfd;
static int kq;
static struct kevent targetEvent;
static config_t config = {
	.device = "/dev/dsp",
	.channels = -1,
	.frag = -1,
	.sample_rate = 48000,
	.sample_size = sizeof(sample_t),
	.buffer_info.fragments = -1,
	.mmap = 0,
};
static midi_config_t midi_config = {
	.device = "/dev/umidi1.0",
};

void
handle_midi(midi_config_t *midi_config)
{
	midi_event_t event;
	uint8_t raw;
	int l = -1;

	if ((l = read(midi_config->fd, &raw, sizeof(raw))) != -1) {
		if (!(raw & 0x80)) {
			return;
		}
		event.type = raw & CMD_MASK;
		event.channel = raw & CHANNEL_MASK;
		switch (event.type) {
		case NOTE_ON:
		case NOTE_OFF:
		case CONTROLER_ON:
			if ((l = read(midi_config->fd, &(event.note),
				 sizeof(event.note))) == -1) {
				perror("Error reading MIDI note");
				exit(1);
			}
			if ((l = read(midi_config->fd, &(event.velocity),
				 sizeof(event.velocity))) == -1) {
				perror("Error reading MIDI velocity");
				exit(1);
			}
			break;
		}
		switch (event.type) {
		case NOTE_ON:
		case NOTE_OFF:
			printf("Channel %d, note %d, velocity %d\n",
			    event.channel, event.note, event.velocity);
			break;
		case CONTROLER_ON:
			printf("Channel %d, controller %d, value %d\n",
			    event.channel, event.controller, event.value);
			break;
		default:
			printf("Unknown event type %d\n", event.type);
		}
	}
}

void
handle_audio(config_t *config)
{
	int ret;
	int bytes = config->buffer_info.bytes;

	ret = read(config->fd, ibuf, bytes);
	if (ret < bytes) {
		fprintf(stderr, "Requested %d bytes, but read %d!\n", bytes,
		    ret);
		return;
	}
	oss_split(config, (sample_t *)ibuf, channels);
	/* All processing will happen here */
	printf("Audio processing\n");
	oss_merge(config, channels, (sample_t *)obuf);
	ret = write(config->fd, obuf, bytes);
	if (ret < bytes) {
		fprintf(stderr, "Requested %d bytes, but wrote %d!\n", bytes,
		    ret);
	}
}

void
work()
{
	int ret;
	if (algo == 0) {
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(config.fd, &fds);
		FD_SET(midi_config.fd, &fds);
		ret = select(maxfd + 1, &fds, NULL, NULL, NULL);
		if (FD_ISSET(config.fd, &fds)) {
			handle_audio(&config);
		} else if (FD_ISSET(midi_config.fd, &fds)) {
			handle_midi(&midi_config);
		}
	} else if (algo == 1) {
		// For simplicity of this example just use POLLIN.
		// For more complex examples one can split input and output
		// processing.
		struct pollfd pfds[2];

		pfds[0].fd = config.fd;
		pfds[0].events = POLLIN;
		pfds[1].fd = midi_config.fd;
		pfds[1].events = POLLIN;
		ret = poll(pfds, sizeof(pfds) / sizeof(struct pollfd), -1);
		if (pfds[0].revents != 0) {
			handle_audio(&config);
		} else if (pfds[1].revents != 0) {
			handle_midi(&midi_config);
		}
	} else if (algo == 2) {
		ret = kevent(kq, NULL, 0, &targetEvent, 1, NULL);
		if (ret == -1) {
			err(EXIT_FAILURE, "kevent wait");
		} else if (ret > 0) {
			if (targetEvent.flags & EV_ERROR) {
				errx(EXIT_FAILURE, "Event error: %s",
				    strerror(targetEvent.data));
				return;
			}
			if (targetEvent.ident == config.fd) {
				handle_audio(&config);
			} else if (targetEvent.ident == midi_config.fd) {
				handle_midi(&midi_config);
			}
		}
	}
}

int
main()
{
	int bytes;
	int ret;
	char ch;
	struct kevent events[2];

	config.format = format;
	oss_init(&config);
	oss_midi_init(&midi_config);

	/*
	 * Allocate input and output buffers so that their size match
	 * frag_size
	 */
	bytes = config.buffer_info.bytes;
	ibuf = malloc(bytes);
	obuf = malloc(bytes);
	channels = malloc(bytes);
	maxfd = config.fd > midi_config.fd ? midi_config.fd : midi_config.fd;

	for (;;) {
		printf(
		    "Choose waiting algorithm: (s)elect, (p)oll, (k)queue or (q)uit: ");
		ch = getchar();
		switch (ch) {
		case 'q':
			return 0;
		case 's':
			algo = 0;
			break;
		case 'p':
			algo = 1;
			break;
		case 'k': {
			algo = 2;
			kq = kqueue();
			if (kq == -1) {
				err(EXIT_FAILURE, "kqueue() failed");
			}

			EV_SET(events, config.fd, EVFILT_READ,
			    EV_ADD | EV_CLEAR, NOTE_READ, 0, NULL);
			EV_SET(events + 1, midi_config.fd, EVFILT_READ,
			    EV_ADD | EV_CLEAR, NOTE_READ, 0, NULL);
			ret = kevent(kq, events, 2, NULL, 0, NULL);
			if (ret == -1) {
				err(EXIT_FAILURE, "kevent register");
			}
			break;
		}
		default:
			algo = -1;
			while ((ch = getchar()) != '\n' && ch != EOF)
				;
			break;
		}
		if (algo >= 0) {
			break;
		}
	}
	for (;;) {
		work();
	}

	/* Cleanup */
	free(channels);
	free(obuf);
	free(ibuf);
	close(kq);
	close(midi_config.fd);
	close(config.fd);
	return (0);
}
