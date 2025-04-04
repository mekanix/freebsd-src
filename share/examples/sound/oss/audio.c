/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Goran Mekić
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * Portions of this software were developed by Christos Margiolis
 * <christos@FreeBSD.org> under sponsorship from the FreeBSD Foundation.
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

#include <sys/mman.h>
#include <sys/soundcard.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SAMPLE_SIZE
#define SAMPLE_SIZE 32
#endif

/* Format can be unsigned, in which case replace S with U */
#if SAMPLE_SIZE == 32
typedef int32_t sample_t;
int format = AFMT_S32_NE; /* Signed 32bit native endian format */
#elif SAMPLE_SIZE == 16
typedef int16_t sample_t;
int format = AFMT_S16_NE; /* Signed 16bit native endian format */
#elif SAMPLE_SIZE == 8
typedef int8_t sample_t;
int format = AFMT_S8_NE; /* Signed 8bit native endian format */
#else
#error Unsupported sample format!
typedef int32_t sample_t;
int format = AFMT_S32_NE; /* Not a real value, just silencing
			   * compiler errors */
#endif

/*
 * Minimal configuration for OSS
 * For real world applications, this structure will probably contain many
 * more fields
 */
typedef struct config {
	char *device;
	int channels;
	int fd;
	int format;
	int frag;
	int sample_count;
	int sample_rate;
	int sample_size;
	int chsamples;
	int mmap;
	oss_audioinfo audio_info;
	audio_buf_info buffer_info;
	caddr_t buf;
} config_t;

static int sinebuf[48] = { 0, 4276, 8480, 12539, 16383, 19947, 23169, 25995,
	28377, 30272, 31650, 32486, 32767, 32486, 31650, 30272, 28377, 25995,
	23169, 19947, 16383, 12539, 8480, 4276, 0, -4276, -8480, -12539, -16383,
	-19947, -23169, -25995, -28377, -30272, -31650, -32486, -32767, -32486,
	-31650, -30272, -28377, -25995, -23169, -19947, -16383, -12539, -8480,
	-4276 };
static int sinep = 0;

/*
 * Error state is indicated by value=-1 in which case application exits with
 * error
 */
static inline void
check_error(const int value, const char *message)
{
	if (value == -1)
		err(1, "OSS error: %s\n", message);
}

/* Calculate frag by giving it minimal size of buffer */
static inline int
size2frag(int x)
{
	int frag = 0;

	while ((1 << frag) < x)
		++frag;

	return (frag);
}

/*
 * Split input buffer into channels. Input buffer is in interleaved format
 * which means if we have 2 channels (L and R), this is what the buffer of 8
 * samples would contain: L,R,L,R,L,R,L,R. The result are two channels
 * containing: L,L,L,L and R,R,R,R.
 */
static void
oss_split(config_t *config, sample_t *input, sample_t *output)
{
	int channel, index, i;

	for (i = 0; i < config->sample_count; ++i) {
		channel = i % config->channels;
		index = i / config->channels;
		output[channel * index] = input[i];
	}
}

/*
 * Convert channels into interleaved format and place it in output
 * buffer
 */
static void
oss_merge(config_t *config, sample_t *input, sample_t *output)
{
	int channel, index;

	for (channel = 0; channel < config->channels; ++channel) {
		for (index = 0; index < config->chsamples; ++index) {
			output[index * config->channels + channel] =
			    input[channel * index];
		}
	}
}

static void
produce_output(short *buf, int samples, int channels)
{
	for (int i = 0; i < samples; ++i) {
		int v = sinebuf[sinep];
		sinep = (sinep + 1) % 48;
		for (int j = 0; j < channels; ++j) {
			*buf++ = v;
		}
	}
}

static void
oss_init(config_t *config)
{
	int error, tmp, min_frag;

	/* Open the device for read and write */
	if (config->mmap) {
		config->fd = open(config->device, O_WRONLY);
	} else {
		config->fd = open(config->device, O_RDWR);
	}
	check_error(config->fd, "open");

	/* Get device information */
	config->audio_info.dev = -1;
	error = ioctl(config->fd, SNDCTL_ENGINEINFO, &(config->audio_info));
	check_error(error, "SNDCTL_ENGINEINFO");
	printf("min_channels: %d\n", config->audio_info.min_channels);
	printf("max_channels: %d\n", config->audio_info.max_channels);
	printf("latency: %d\n", config->audio_info.latency);
	printf("handle: %s\n", config->audio_info.handle);
	if (config->audio_info.min_rate > config->sample_rate ||
	    config->sample_rate > config->audio_info.max_rate) {
		errx(1, "%s doesn't support chosen samplerate of %dHz!\n",
		    config->device, config->sample_rate);
	}
	if (config->channels < 1)
		config->channels = config->audio_info.max_channels;

	/*
	 * If device is going to be used in mmap mode, disable all format
	 * conversions. Official OSS documentation states error code should not
	 * be checked.
	 * http://manuals.opensound.com/developer/mmap_test.c.html#LOC10
	 */
	if (config->mmap) {
		tmp = 0;
		ioctl(config->fd, SNDCTL_DSP_COOKEDMODE, &tmp);
	}

	/*
	 * Set number of channels. If number of channels is chosen to the value
	 * near the one wanted, save it in config
	 */
	tmp = config->channels;
	error = ioctl(config->fd, SNDCTL_DSP_CHANNELS, &tmp);
	check_error(error, "SNDCTL_DSP_CHANNELS");
	/* Or check if tmp is close enough? */
	if (tmp != config->channels) {
		errx(1,
		    "%s doesn't support chosen channel count of %d set "
		    "to %d!\n",
		    config->device, config->channels, tmp);
	}
	config->channels = tmp;

	/* Set format, or bit size: 8, 16, 24 or 32 bit sample */
	tmp = config->format;
	error = ioctl(config->fd, SNDCTL_DSP_SETFMT, &tmp);
	check_error(error, "SNDCTL_DSP_SETFMT");
	if (tmp != config->format)
		errx(1, "%s doesn't support chosen sample format!\n", config->device);

	/* Most common values for samplerate (in kHz): 44.1, 48, 88.2, 96 */
	tmp = config->sample_rate;
	error = ioctl(config->fd, SNDCTL_DSP_SPEED, &tmp);
	check_error(error, "SNDCTL_DSP_SPEED");

	/* Get and check device capabilities */
	error = ioctl(config->fd, SNDCTL_DSP_GETCAPS, &(config->audio_info.caps));
	check_error(error, "SNDCTL_DSP_GETCAPS");

	if (config->mmap) {
		if (!(config->audio_info.caps & PCM_CAP_TRIGGER))
			errx(1, "Device doesn't support triggering!\n");
		if (!(config->audio_info.caps & PCM_CAP_MMAP))
			errx(1, "Device doesn't support mmap mode!\n");
	} else {
		if (!(config->audio_info.caps & PCM_CAP_DUPLEX))
			errx(1, "Device doesn't support full duplex!\n");
	}

	/*
	 * If desired frag is smaller than minimum, based on number of channels
	 * and format (size in bits: 8, 16, 24, 32), set that as frag. Buffer
	 * size is 2^frag, but the real size of the buffer will be read when
	 * the configuration of the device is successful
	 */
	min_frag = size2frag(config->sample_size * config->channels);

	if (config->frag < min_frag)
		config->frag = min_frag;

	/*
	 * Allocate buffer in fragments. Total buffer will be split in number
	 * of fragments (2 by default)
	 */
	if (config->buffer_info.fragments < 0)
		config->buffer_info.fragments = 2;
	tmp = ((config->buffer_info.fragments) << 16) | config->frag;
	error = ioctl(config->fd, SNDCTL_DSP_SETFRAGMENT, &tmp);
	check_error(error, "SNDCTL_DSP_SETFRAGMENT");

	/* When all is set and ready to go, get the size of buffer */
	error = ioctl(config->fd, SNDCTL_DSP_GETOSPACE, &(config->buffer_info));
	check_error(error, "SNDCTL_DSP_GETOSPACE");
	if (config->buffer_info.bytes < 1) {
		errx(1, "OSS buffer error: buffer size can not be %d\n", config->buffer_info.bytes);
	}
	config->sample_count = config->buffer_info.bytes / config->sample_size;
	config->chsamples = config->sample_count / config->channels;
	if (config->mmap) {
		if ((config->buf = mmap(NULL, config->buffer_info.bytes,
			 PROT_WRITE, MAP_FILE | MAP_SHARED, config->fd, 0)) ==
		    (caddr_t)-1) {
			errx(1, "mmap (write)");
		}
		printf("Buffer: %p - %p\n", config->buf, config->buf + config->buffer_info.bytes);
		tmp = 0;
		error = ioctl(config->fd, SNDCTL_DSP_SETTRIGGER, &tmp);
		check_error(error, "SNDCTL_DSP_SETTRIGGER");
		memset(config->buf, 0, config->buffer_info.bytes);
	}
}

int
main(int argc, char *argv[])
{
	int ret, tmp, error, num_samples;
	int8_t *ibuf, *obuf;
	count_info ci;
	config_t config = {
		.device = "/dev/dsp4",
		.channels = -1,
		.format = format,
		.frag = -1,
		.sample_rate = 48000,
		.sample_size = sizeof(sample_t),
		.buffer_info.fragments = -1,
		.mmap = 1,
		.buf = NULL,
	};

	/* Initialize device */
	oss_init(&config);

	/*
	 * Allocate input and output buffers so that their size match frag_size
	 */

	printf(
	    "bytes: %d, fragments: %d, fragsize: %d, fragstotal: %d, samples: %d\n",
	    config.buffer_info.bytes, config.buffer_info.fragments,
	    config.buffer_info.fragsize, config.buffer_info.fragstotal,
	    config.sample_count);

	if (config.mmap) {
		memset(config.buf, 0, config.buffer_info.bytes);
		int usec = 1000000 * config.chsamples / config.sample_rate;
		tmp = PCM_ENABLE_OUTPUT;
		error = ioctl(config.fd, SNDCTL_DSP_SETTRIGGER, &tmp);
		check_error(error, "SNDCTL_DSP_SETTRIGGER");
		for (;;) {
			error = ioctl(config.fd, SNDCTL_DSP_GETOPTR, &ci);
			while (ci.ptr != 0)
				error = ioctl(config.fd, SNDCTL_DSP_GETOPTR,
				    &ci);
			produce_output((short *)config.buf, config.chsamples,
			    config.channels);
			usleep(usec);
		}
	} else {
		ibuf = malloc(config.buffer_info.bytes);
		obuf = malloc(config.buffer_info.bytes);
		sample_t *channels = malloc(config.buffer_info.bytes);
		/* Minimal engine: read input and copy it to the output */
		for (;;) {
			ret = read(config.fd, ibuf, config.buffer_info.bytes);
			if (ret < config.buffer_info.bytes) {
				fprintf(stderr,
				    "Requested %d bytes, but read %d!\n",
				    config.buffer_info.bytes, ret);
				break;
			}
			oss_split(&config, (sample_t *)ibuf, channels);
			/* All processing will happen here */
			oss_merge(&config, channels, (sample_t *)obuf);
			ret = write(config.fd, obuf, config.buffer_info.bytes);
			if (ret < config.buffer_info.bytes) {
				fprintf(stderr,
				    "Requested %d bytes, but wrote %d!\n",
				    config.buffer_info.bytes, ret);
				break;
			}
		}
		free(channels);
		free(obuf);
		free(ibuf);
	}

	/* Cleanup */
	close(config.fd);

	return (0);
}
