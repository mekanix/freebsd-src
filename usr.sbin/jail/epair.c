#include <net/if.h>
#include <net/if_types.h>
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route_parsers.h>
#include <sys/socket.h>

#include <err.h>
#include <sysexits.h>
#include <unistd.h>

#include "epair.h"

struct args {
	char cloner[IFNAMSIZ];
	char clone[IFNAMSIZ];
};

struct clone_request {
	int              error;
	int              clone_error;
	int              cloner_error;

	// Up to the first variable sized TLV-record offsets are known at compile time.
	struct nlmsghdr  hdr;
	struct ifinfomsg ifinfo;
	struct nlattr    ifname_attr;
	char             ifname[IFNAMSIZ];

	// After the first variable sized TLV-record offsets have to be computed a runtime.
	struct nlattr    linkinfo_attr;
	struct nlattr    kind_attr;
	char             kind[IFNAMSIZ];
};

struct cookie_parsed {
	uint32_t  ifla_new_index;
	char      ifla_ifname[IFNAMSIZ];
};

#define OUT(_field) offsetof(struct cookie_parsed, _field)
static const struct snl_attr_parser cookie_parser[] = {
	{ .type = IFLA_IFNAME     , .off = OUT(ifla_ifname),    .cb = snl_attr_copy_string, .arg_u32 = IFNAMSIZ },
	{ .type = IFLA_NEW_IFINDEX, .off = OUT(ifla_new_index), .cb = snl_attr_get_uint32 , .arg     = 0        }
};
#undef OUT

static struct clone_request
new_clone_request(const char clone[IFNAMSIZ], const char cloner[IFNAMSIZ], uint32_t seq, uint32_t pid)
{
	// Perform input validation. The clone and cloner must be non-empty strings that each fit into IFNAMSIZ bytes.
	const size_t         clone_len    = clone  ? strlen(clone)  : 0;
	const size_t         cloner_len   = cloner ? strlen(cloner) : 0;
	const int            clone_error  = !clone  ? EFAULT : (!clone_len  ? ENOENT : (clone_len  >= IFNAMSIZ ? ENAMETOOLONG : 0));
	const int            cloner_error = !cloner ? EFAULT : (!cloner_len ? ENOENT : (cloner_len >= IFNAMSIZ ? ENAMETOOLONG : 0));
	const int            error        = clone_error ? clone_error : cloner_error;
	struct clone_request request      = { 0 };

	// Abort if the arguments are invalid.
	if (error) {
		request.error        = error;
		request.clone_error  = clone_error;
		request.cloner_error = cloner_error;
		return request;
	}

	// Compute the length length of the variable sized parts of the RTM_NEWLINK request
	const uint16_t ifname_len    = (uint16_t)(sizeof(struct nlattr) + clone_len + 1);
	const uint16_t kind_len      = (uint16_t)(sizeof(struct nlattr) + cloner_len + 1);
	const uint16_t linkinfo_len  = (uint16_t)(sizeof(struct nlattr) + NLA_ALIGN(kind_len));
	const uint32_t msg_len       = sizeof(struct nlmsghdr) + sizeof(struct ifinfomsg) + NLA_ALIGN(ifname_len) + linkinfo_len;

	// Compute pointers to all parts of the RTM_NEWLINK request.
	struct nlmsghdr  *const hdr           = &request.hdr;
	struct ifinfomsg *const ifinfo        = &request.ifinfo;
	struct nlattr    *const ifname_attr   = &request.ifname_attr;
	char             *const ifname        = request.ifname;
	struct nlattr    *const linkinfo_attr = (void *)&((char *)ifname_attr)[NLA_ALIGN(ifname_len)];
	struct nlattr    *const kind_attr     = &linkinfo_attr[1];
	char             *const kind          = (void *)(&kind_attr[1]);

	// Fill out the Netlink message header.
	*hdr = (struct nlmsghdr) {
		.nlmsg_len   = msg_len,
		.nlmsg_type  = RTM_NEWLINK,
		.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK | NLM_F_REQUEST,
		.nlmsg_seq   = seq,
		.nlmsg_pid   = pid,
	};

	// Fill out the interface info message (with zeroes).
	*ifinfo = (struct ifinfomsg) {
		.ifi_family = 0,
		.ifi_type   = 0,
		.ifi_index  = 0,
		.ifi_flags  = 0,
		.ifi_change = 0,
	};

	// Set the name of the interface to be cloned
	*ifname_attr = (struct nlattr) { .nla_len  = ifname_len, .nla_type = IFLA_IFNAME, };
	memcpy(ifname, clone, ifname_len - sizeof(struct nlattr));

	// The the name of the cloner the interface is to be cloned from.
	*linkinfo_attr = (struct nlattr) { .nla_len  = linkinfo_len, .nla_type = NLA_F_NESTED | IFLA_LINKINFO };
	*kind_attr     = (struct nlattr) { .nla_len  = kind_len    , .nla_type = IFLA_INFO_KIND               };
	memcpy(kind, cloner, kind_len - sizeof(struct nlattr));

	// Return the result Netlink message.
	return request;
}

static inline bool
parse_cookie(struct snl_state *state, struct snl_errmsg_data *parsed_err, struct cookie_parsed *parsed)
{

	struct nlattr *attrs = NLA_DATA(parsed_err->cookie);
	int            len   = NLA_DATA_LEN(parsed_err->cookie);

	return snl_parse_attrs_raw(state, attrs, len,
			cookie_parser, sizeof(cookie_parser)/sizeof(*cookie_parser), parsed);
}

char *
create_epair(void)
{
	struct snl_state  state[1];
	const uint32_t    pid = (uint32_t)getpid();

	const struct args args = {
		.clone = "epair",
		.cloner = "epair",
	};

	// Open a Netlink socket through snl(3).
	if (!snl_init(state, NETLINK_ROUTE)) {
		warnx("snl_init(NETLINK_ROUTE) failed");
		return (NULL);
	}

	// Enable the FreeBSD specific NETLINK_MSG_INFO option
	int optval = 1;
	if (setsockopt(state->fd, SOL_NETLINK, NETLINK_MSG_INFO, &optval, sizeof(optval))) {
		warnx("Failed to enable NETLINK_MSG_INFO option on Netlink socket.");
		return (NULL);
	}

	// Subscribe to link changes.
	const uint32_t group_id = RTMGRP_LINK;
	if (setsockopt(state->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, (void *)(uintptr_t)&group_id, sizeof(group_id))) {
		warnx("Failed to join RTMGRP_LINK Netlink multicast group.");
		return (NULL);
	}

	// Generate the request to clone a new interface.
	struct clone_request request = new_clone_request(args.clone, args.cloner, snl_get_seq(state), pid);
	if (request.error) {
		return (NULL);
	}

	// Send the request.
	warnx("Sending request to clone interface: len = %u, type = 0x%x, flags = 0x%x, seq = %u, pid = %u.",
			request.hdr.nlmsg_len, request.hdr.nlmsg_type, request.hdr.nlmsg_flags,
			request.hdr.nlmsg_seq, request.hdr.nlmsg_pid);
	if (!snl_send_message(state, &request.hdr)) {
		warnx("Failed to send netlink message.");
		return (NULL);
	}

	size_t ifname_len     = 0;
	char *ifname = malloc(IFNAMSIZ);
	int error = -1;

	// Process received Netlink messages.
	while (!ifname[0] || error < 0) {
		struct snl_errmsg_data err_msg = { 0 };
		struct snl_parsed_link link = { 0 };
		struct snl_msg_info attrs = { 0 };

		warnx("");
		warnx("Waiting for a Netlink message...");
		//struct nlmsghdr *msg = snl_read_message(state);
		struct nlmsghdr *msg = snl_read_message_dbg(state, &attrs);
		if (!msg) {
			warnx("Failed to receive a Netlink message.");
			return (NULL);
		}
		switch (msg->nlmsg_type) {
			case NLMSG_ERROR:
				if (!snl_parse_errmsg(state, msg, &err_msg)) {
					warnx("Failed to parse received Netlink error/acknowledgement message.");
					return (NULL);
				}

				if (!err_msg.cookie) {
					warnx("!!! NO COOKIE !!!");
				} else {
					struct cookie_parsed parsed = { 0 };
					if (!parse_cookie(state, &err_msg, &parsed)) {
						warn("Failed to parse err_msg cookie");
					}
					warnx("Created interface: NAME = %s, INDEX = %u", parsed.ifla_ifname, parsed.ifla_new_index);
					memcpy(ifname, parsed.ifla_ifname, IFNAMSIZ);
				}

				if (
					err_msg.orig_hdr->nlmsg_len   != request.hdr.nlmsg_len   ||
					err_msg.orig_hdr->nlmsg_type  != request.hdr.nlmsg_type  ||
					err_msg.orig_hdr->nlmsg_flags != request.hdr.nlmsg_flags ||
					err_msg.orig_hdr->nlmsg_seq   != request.hdr.nlmsg_seq   ||
					err_msg.orig_hdr->nlmsg_pid   != 0
				) {
					warnx("The received Netlink acknowledgement (len = %u, type = 0x%x, flags = 0x%x, seq = %u, pid=%u) "
							"does not match the sent clone request (len = %u, type = 0x%x, flags = 0x%x, seq = %u, pid=%u).",
							err_msg.orig_hdr->nlmsg_len, err_msg.orig_hdr->nlmsg_type, err_msg.orig_hdr->nlmsg_flags, err_msg.orig_hdr->nlmsg_seq, err_msg.orig_hdr->nlmsg_pid,
							request.hdr.nlmsg_len, request.hdr.nlmsg_type, request.hdr.nlmsg_flags, request.hdr.nlmsg_seq, request.hdr.nlmsg_pid);
					return (NULL);
				}

				error = err_msg.error;
				if (error == 0) {
					warnx("The clone request has been acknowledged.");
					return (ifname);
				} else if (error == EEXIST) {
					warnx("The interface already exists: %s.", request.ifname);
					memcpy(ifname, request.ifname, request.ifname_attr.nla_len - sizeof(struct nlattr));
				} else if (error == EPERM) {
					errno = error;
					warnx("Permission to clone the interface has been denied.");
					return (NULL);
				} else {
					warnx("Received unexpected error matching the clone request: error = %i, offset = %u, msg = %s",
							err_msg.error, err_msg.error_offs, err_msg.error_str);
					warnx("Original message: len = %u, type = 0x%x, flags = 0x%x, seq = %u, pid = %u",
							err_msg.orig_hdr->nlmsg_len, err_msg.orig_hdr->nlmsg_type, err_msg.orig_hdr->nlmsg_flags,
							err_msg.orig_hdr->nlmsg_seq, err_msg.orig_hdr->nlmsg_pid);
					errno = error;
					warnx("Encountered a fatal error");
					return (NULL);
				}

				break;

			case NL_RTM_NEWLINK:
				if (!snl_parse_nlmsg(state, msg, &snl_rtm_link_parser, &link)) {
					warnx("Failed to parse received RTM_NEWLINK message.");
					return (NULL);
				}
				if (!link.ifla_ifname) {
					warnx("The received RTM_NEWLINK message lacks the required IFLA_IFNAME attribute.");
					return (NULL);
				}
				ifname_len = strlen(link.ifla_ifname);
				if (ifname_len == 0) {
					warnx("The received RTM_NEWLINK message contains an empty IFLA_IFNAME attribute: %zu ∉ [1,%zu)", ifname_len, (size_t)IFNAMSIZ);
					return (NULL);
				} else if (ifname_len >= IFNAMSIZ) {
					warnx("The received RTM_NEWLINK message contains an oversized IFLA_IFNAME attribute: %zu ∉ [1,%zu)", ifname_len, (size_t)IFNAMSIZ);
					return (NULL);
				}

				warnx("Parsed received RTM_NEWLINK message: %s.", link.ifla_ifname);
				if (attrs.process_id != pid) {
					warnx("Ignoring received RTM_NEWLINK message on behalf of PID %u about the creation of an other interface: %s.",
							attrs.process_id, link.ifla_ifname);
					break;
				}

				memcpy(ifname, link.ifla_ifname, ifname_len + 1);
				warnx("The requested interface has been cloned: %s", ifname);
				break;

			default:
				warnx("Received an unknown Netlink message: len = %u, type = 0x%x, flags = 0x%x, seq = %u, pid = %u.",
						msg->nlmsg_len, msg->nlmsg_type, msg->nlmsg_flags, msg->nlmsg_seq, msg->nlmsg_pid);
				warnx("Out-of-band info about the unknown Netlink message: pid = %u, port = %u, seq %u.",
						attrs.process_id, attrs.port_id, attrs.seq_id);
				break;
		}
	}

	snl_free(state);
	return (NULL);
}
