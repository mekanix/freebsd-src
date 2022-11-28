/*	$NetBSD: blacklistctl.c,v 1.23 2018/05/24 19:21:01 christos Exp $	*/

/*-
 * Copyright (c) 2015 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/cdefs.h>
__RCSID("$NetBSD: blacklistctl.c,v 1.23 2018/05/24 19:21:01 christos Exp $");

#include <stdio.h>
#include <time.h>
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "conf.h"
#include "state.h"
#include "internal.h"
#include "support.h"

static __dead void
usage(int c)
{
	if (c == 0)
		warnx("Missing/unknown command");
	else if (c != '?')
		warnx("Unknown option `%c'", (char)c);
	fprintf(stderr, "Usage: %s dump [-abdnrw]\n", getprogname());
	fprintf(stderr, "       %s remove <ip address>\n", getprogname());
	exit(EXIT_FAILURE);
}

static const char *
star(char *buf, size_t len, int val)
{
	if (val == -1)
		return "*";
	snprintf(buf, len, "%d", val);
	return buf;
}

int
main(int argc, char *argv[])
{
	const char *dbname = _PATH_BLSTATE;
	DB *db;
	struct conf c;
	struct dbinfo dbi;
	unsigned int i;
	struct timespec ts;
	int all, blocked, remain, wide, noheader;
	int o;

	noheader = wide = blocked = all = remain = 0;
	lfun = dlog;

	if (argc == 1)
		usage(0);

	db = state_open(dbname, O_RDONLY, 0);
	if (db == NULL)
		err(EXIT_FAILURE, "Can't open `%s'", dbname);

	if (strcmp(argv[1], "dump") == 0) {
		argc--;
		argv++;

		while ((o = getopt(argc, argv, "abD:dnrw")) != -1)
			switch (o) {
			case 'a':
				all = 1;
				blocked = 0;
				break;
			case 'b':
				blocked = 1;
				break;
			case 'D':
				dbname = optarg;
				break;
			case 'd':
				debug++;
				break;
			case 'n':
				noheader = 1;
				break;
			case 'r':
				remain = 1;
				break;
			case 'w':
				wide = 1;
				break;
			default:
				usage(o);
			}


		clock_gettime(CLOCK_REALTIME, &ts);
		wide = wide ? 8 * 4 + 7 : 4 * 3 + 3;
		if (!noheader)
			printf("%*.*s/ma:port\tid\tnfail\t%s\n", wide, wide,
					"address", remain ? "remaining time" : "last access");
		for (i = 1; state_iterate(db, &c, &dbi, i) != 0; i = 0) {
			char buf[BUFSIZ];
			char mbuf[64], pbuf[64];
			if (!all) {
				if (blocked) {
					if (c.c_nfail == -1 || dbi.count < c.c_nfail)
						continue;
				} else {
					if (dbi.count >= c.c_nfail)
						continue;
				}
			}
			sockaddr_snprintf(buf, sizeof(buf), "%a", (void *)&c.c_ss);
			printf("%*.*s/%s:%s\t", wide, wide, buf,
					star(mbuf, sizeof(mbuf), c.c_lmask),
					star(pbuf, sizeof(pbuf), c.c_port));
			if (c.c_duration == -1) {
				strlcpy(buf, "never", sizeof(buf));
			} else {
				if (remain)
					fmtydhms(buf, sizeof(buf),
							c.c_duration - (ts.tv_sec - dbi.last));
				else
					fmttime(buf, sizeof(buf), dbi.last);
			}
			printf("%s\t%d/%s\t%-s\n", dbi.id, dbi.count,
					star(mbuf, sizeof(mbuf), c.c_nfail), buf);
		}
		state_close(db);
		return EXIT_SUCCESS;
	} else if (strcmp(argv[1], "remove") == 0) {
		struct sockaddr_storage sa;
		int rc = 0;

		argc--;
		argv++;

		if (argc < 2 || argc > 3)
			usage(0);

		// try to convert argv[1] to IPv4 address, then try IPv6
// #ifdef INET
		if (inet_pton(AF_INET, argv[1], &(((struct sockaddr_in *)&sa)->sin_addr)) != 0) {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;
			sa.ss_family = AF_INET;
			if (argc == 3) {
				sa4->sin_port = htons(atoi(argv[2]));
			} else {
				sa4->sin_port = 0;
			}
			rc = 1;
		}
// #endif
// #ifdef INET6
		if (inet_pton(AF_INET6, argv[1], &(((struct sockaddr_in6 *)&sa)->sin6_addr)) != 0) {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;
			sa.ss_family = AF_INET6;
			if (argc == 3) {
				sa6->sin6_port = htons(atoi(argv[2]));
			} else {
				sa6->sin6_port = 0;
			}
			rc = 1;
		}
// #endif
		if (rc == 0) {
			fprintf(stderr, "Could not convert %s to IP address\n", argv[1]);
			exit(EXIT_FAILURE);
		}

		for (i = 1; state_iterate(db, &c, &dbi, i) != 0; i = 0) {
			if (c.c_family == sa.ss_family) {
				if (c.c_family == AF_INET) {
					struct sockaddr_in *sa4 = (struct sockaddr_in *)&sa;
					struct sockaddr_in *dbsa = (struct sockaddr_in *)&(c.c_ss);
					if (sa4->sin_addr.s_addr == dbsa->sin_addr.s_addr) {
						if (sa4->sin_port == 0) {
							state_del(db, &c);
						} else if (sa4->sin_port == dbsa->sin_port) {
							state_del(db, &c);
						}
					}
				} else if (c.c_family == AF_INET6) {
					struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;
					struct sockaddr_in6 *dbsa = (struct sockaddr_in6 *)&(c.c_ss);
					if (sa6->sin6_addr.s6_addr == dbsa->sin6_addr.s6_addr) {
						if (sa6->sin6_port == 0) {
							state_del(db, &c);
						} else if (sa6->sin6_port == dbsa->sin6_port) {
							state_del(db, &c);
						}
					}
				}
			}
		}
		return EXIT_SUCCESS;
	}
	usage(0);
}
