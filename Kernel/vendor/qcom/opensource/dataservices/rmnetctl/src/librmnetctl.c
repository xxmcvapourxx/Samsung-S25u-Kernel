/******************************************************************************

			L I B R M N E T C T L . C

Copyright (c) 2013-2015, 2017-2019, 2021 The Linux Foundation.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
	* Redistributions of source code must retain the above copyright
	  notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above
	  copyright notice, this list of conditions and the following
	  disclaimer in the documentation and/or other materials provided
	  with the distribution.
	* Neither the name of The Linux Foundation nor the names of its
	  contributors may be used to endorse or promote products derived
	  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/

/*!
* @file    librmnetctl.c
* @brief   rmnet control API's implementation file
*/

/*===========================================================================
			INCLUDE FILES
===========================================================================*/

#include <sys/socket.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <linux/gen_stats.h>
#include <net/if.h>
#include <asm/types.h>
#include "librmnetctl_hndl.h"
#include "librmnetctl.h"

#ifdef USE_GLIB
#include <glib.h>
#define strlcpy g_strlcpy
#endif

#define RMNETCTL_SOCK_FLAG 0
#define ROOT_USER_ID 0
#define MIN_VALID_PROCESS_ID 0
#define MIN_VALID_SOCKET_FD 0
#define KERNEL_PROCESS_ID 0
#define UNICAST 0
#define MAX_BUF_SIZE sizeof(struct nlmsghdr) + sizeof(struct rmnet_nl_msg_s)
#define INGRESS_FLAGS_MASK   (RMNET_INGRESS_FIX_ETHERNET | \
			      RMNET_INGRESS_FORMAT_MAP | \
			      RMNET_INGRESS_FORMAT_DEAGGREGATION | \
			      RMNET_INGRESS_FORMAT_DEMUXING | \
			      RMNET_INGRESS_FORMAT_MAP_COMMANDS | \
			      RMNET_INGRESS_FORMAT_MAP_CKSUMV3 | \
			      RMNET_INGRESS_FORMAT_MAP_CKSUMV4)
#define EGRESS_FLAGS_MASK    (RMNET_EGRESS_FORMAT__RESERVED__ | \
			      RMNET_EGRESS_FORMAT_MAP | \
			      RMNET_EGRESS_FORMAT_AGGREGATION | \
			      RMNET_EGRESS_FORMAT_MUXING | \
			      RMNET_EGRESS_FORMAT_MAP_CKSUMV3 | \
			      RMNET_EGRESS_FORMAT_MAP_CKSUMV4)

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((char *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define NLMSG_DATA_SIZE  500

#define CHECK_MEMSCPY(x) ({if (x < 0 ){return RMNETCTL_LIB_ERR;}})

struct nlmsg {
	struct nlmsghdr nl_addr;
	struct ifinfomsg ifmsg;
	char data[NLMSG_DATA_SIZE];
};

/*!
* @brief Contains a list of error message from API
*/
// << RNDFIX :  multiple definition of 'rmnetctl_error_code_text'
char rmnetctl_error_code_text
[RMNETCTL_API_ERR_ENUM_LENGTH][RMNETCTL_ERR_MSG_SIZE] = {
	"ERROR: API succeeded\n",
	"ERROR: Unable to allocate the buffer to send message\n",
	"ERROR: Unable to allocate the buffer to receive message\n",
	"ERROR: Could not send the message to kernel\n",
	"ERROR: Unable to receive message from the kernel\n",
	"ERROR: Invalid process id\n",
	"ERROR: Invalid socket descriptor id\n",
	"ERROR: Could not bind to netlink socket\n",
	"ERROR: Only root can access this API\n",
	"ERROR: RmNet handle for the transaction was NULL\n",
	"ERROR: Request buffer for the transaction was NULL\n",
	"ERROR: Response buffer for the transaction was NULL\n",
	"ERROR: Request and response type do not match\n",
	"ERROR: Return type is invalid\n",
	"ERROR: String was truncated\n",
	/* Kernel errors */
	"ERROR: Kernel call succeeded\n",
	"ERROR: Invalid / Unsupported directive\n",
	"ERROR: Internal problem in the kernel module\n",
	"ERROR: The kernel is temporarily out of memory\n",
	"ERROR: Device already exists / Still in use\n",
	"ERROR: Invalid request / Unsupported scenario\n",
	"ERROR: Device doesn't exist\n",
	"ERROR: One or more of the arguments is invalid\n",
	"ERROR: Egress device is invalid\n",
	"ERROR: TC handle is full\n"
};
// RNDFIX >>
struct rmnetctl_uplink_params {
	uint16_t byte_count;
	uint8_t packet_count;
	uint8_t features;
	uint32_t time_limit;
};

/* Uplink Aggregation contexts for the RT RmNet driver */
enum {
	RMNETCTL_DEFAULT_UL_AGG_STATE,
	RMNETCTL_LL_UL_AGG_STATE,
	RMNETCTL_MAX_UL_AGG_STATE,
};

/* IFLA Attributes for the RT RmNet driver */
enum {
	RMNETCTL_IFLA_UNSPEC,
	RMNETCTL_IFLA_MUX_ID,
	RMNETCTL_IFLA_FLAGS,
	RMNETCTL_IFLA_DFC_QOS,
	RMNETCTL_IFLA_UPLINK_PARAMS,
	RMNETCTL_IFLA_UPLINK_STATE_ID,
	__RMNETCTL_IFLA_MAX,
};

/* Flow message types sent to DFC driver */
enum {
	/* Activate flow */
	RMNET_FLOW_MSG_ACTIVATE = 1,
	/* Delete flow */
	RMNET_FLOW_MSG_DEACTIVATE = 2,
	/* Legacy flow control */
	RMNET_FLOW_MSG_CONTROL = 3,
	/* Flow up */
	RMNET_FLOW_MSG_UP = 4,
	/* Flow down */
	RMNET_FLOW_MSG_DOWN = 5,
	/* Change ACK scaling */
	RMNET_FLOW_MSG_QMI_SCALE = 6,
	/* Change powersave workqueue polling freq */
	RMNET_FLOW_MSG_WDA_FREQ = 7,
	/* Change underlying transport channel */
	RMNET_FLOW_MSG_CHANNEL_SWITCH = 8,
};

/* 0 reserved, 1-15 for data, 16-30 for acks */
#define RMNETCTL_NUM_TX_QUEUES 31

/* This needs to be hardcoded here because some legacy linux systems
 * do not have this definition
 */
#define RMNET_IFLA_NUM_TX_QUEUES 31

/*===========================================================================
			LOCAL FUNCTION DEFINITIONS
===========================================================================*/
/* Helper functions
 * @brief helper function to implement a secure memcpy
 * @details take source and destination buffer size into
 *          considerations before copying
 * @param dst destination buffer
 * @param dst_size size of destination buffer
 * @param src source buffer
 * @param src_size size of source buffer
 * @return size of the smallest of two buffer
 */

static inline size_t memscpy(void *dst, size_t dst_size, const void *src,
			     size_t src_size) {
	size_t min_size = dst_size < src_size ? dst_size : src_size;
	memcpy(dst, src, min_size);
	return min_size;
}

/*
* @brief helper function to implement a secure memcpy
 * for a concatenating buffer where offset is kept
 * track of
 * @details take source and destination buffer size into
 *          considerations before copying
 * @param dst destination buffer
 * @param dst_size pointer used to decrement
 * @param src source buffer
 * @param src_size size of source buffer
 * @return size of the remaining buffer
 */


static inline int  memscpy_repeat(void* dst, size_t *dst_size,
	const void* src, size_t src_size)
{
	if( !dst_size || *dst_size <= src_size || !dst || !src)
		return RMNETCTL_LIB_ERR;
	else {
		*dst_size -= memscpy(dst, *dst_size, src, src_size);
	}
	return *dst_size;
}

/*!
* @brief Static function to check the dev name
* @details Checks if the name is not NULL and if the name is less than the
* RMNET_MAX_STR_LEN
* @param dev_name Name of the device
* @return RMNETCTL_SUCCESS if successful
* @return RMNETCTL_INVALID_ARG if invalid arguments were passed to the API
*/
static inline int _rmnetctl_check_dev_name(const char *dev_name) {
	int return_code = RMNETCTL_INVALID_ARG;
	do {
	if (!dev_name)
		break;
	if (strlen(dev_name) >= IFNAMSIZ)
		break;
	return_code = RMNETCTL_SUCCESS;
	} while(0);
	return return_code;
}

/*===========================================================================
				EXPOSED API
===========================================================================*/

/*
 *                       NEW DRIVER API
 */

 /* @brief Add a Routing Attribute to a Netlink message
  * @param *req The Netlink message we're adding to
  * @param *reqsize The remaining space within the Netlink message
  * @param type The type of the RTA to add
  * @param len The length of the RTA data to add
  * @param *data A pointer to the RTA data to add
  * @return RMNETCTL_LIB_ERR if there is not enough space to add the RTA
  * @return RMNETCTL_SUCCESS if we added the RTA successfully
  */
static int rta_put(struct nlmsg *req, size_t *reqsize, int type, int len,
		   void *data)
{
	struct rtattr *attr = NLMSG_TAIL(&req->nl_addr);

	attr->rta_type = type;
	attr->rta_len = RTA_LENGTH(len);
	CHECK_MEMSCPY(memscpy_repeat(RTA_DATA(attr), reqsize, data, len));
	req->nl_addr.nlmsg_len = NLMSG_ALIGN(req->nl_addr.nlmsg_len) +
				 RTA_ALIGN(attr->rta_len);

	return RMNETCTL_SUCCESS;
}

/* @brief Add an RTA to the Netlink message with a u8 data
 * @param *req The Netlink message
 * @param *reqsize The remainins space within the Netlink message
 * @param type The type of the RTA to add
 * @param data The data of the RTA
 * @rteturn RMNETCTL_LIB_ERR if there is not enough space to add the RTA
 * @return RMNETCTL_SUCCESS if we added the RTA successfully
 */
static int rta_put_u8(struct nlmsg *req, size_t *reqsize, int type,
		      uint8_t data)
{
	return rta_put(req, reqsize, type, sizeof(data), &data);
}

/* @brief Add an RTA to the Netlink message with a u16 data
 * @param *req The Netlink message
 * @param *reqsize The remainins space within the Netlink message
 * @param type The type of the RTA to add
 * @param data The data of the RTA
 * @rteturn RMNETCTL_LIB_ERR if there is not enough space to add the RTA
 * @return RMNETCTL_SUCCESS if we added the RTA successfully
 */
static int rta_put_u16(struct nlmsg *req, size_t *reqsize, int type,
		       uint16_t data)
{
	return rta_put(req, reqsize, type, sizeof(data), &data);
}

/* @brief Add an RTA to the Netlink message with a u32 data
 * @param *req The Netlink message
 * @param *reqsize The remainins space within the Netlink message
 * @param type The type of the RTA to add
 * @param data The data of the RTA
 * @rteturn RMNETCTL_LIB_ERR if there is not enough space to add the RTA
 * @return RMNETCTL_SUCCESS if we added the RTA successfully
 */
static int rta_put_u32(struct nlmsg *req, size_t *reqsize, int type,
		       uint32_t data)
{
	return rta_put(req, reqsize, type, sizeof(data), &data);
}

/* @brief Add an RTA to the Netlink message with string data
 * @param *req The Netlink message
 * @param *reqsize The remainins space within the Netlink message
 * @param type The type of the RTA to add
 * @param *data The data of the RTA
 * @rteturn RMNETCTL_LIB_ERR if there is not enough space to add the RTA
 * @return RMNETCTL_SUCCESS if we added the RTA successfully
 */
static int rta_put_string(struct nlmsg *req, size_t *reqsize, int type,
			  char *data)
{
	return rta_put(req, reqsize, type, strlen(data) + 1, data);
}

/* @brief Start a nested RTA within the Netlink message
 * @param *req The Netlink message
 * @param *reqsize The remainins space within the Netlink message
 * @param type The type of the RTA to add
 * @param **start A pointer where we store the start of the ensted attribute
 * @rteturn RMNETCTL_LIB_ERR if there is not enough space to add the RTA
 * @return RMNETCTL_SUCCESS if we added the RTA successfully
 */
static int rta_nested_start(struct nlmsg *req, size_t *reqsize, int type,
			    struct rtattr **start)
{
	*start = NLMSG_TAIL(&req->nl_addr);
	return rta_put(req, reqsize, type, 0, NULL);
}

/* @brief End a nested RTA previously started with rta_nested_start
 * @param *req The Netlink message
 * @param *start The start of the nested RTA, as provided by rta_nested_start
 */
static void rta_nested_end(struct nlmsg *req, struct rtattr *start)
{
	start->rta_len = (char *)NLMSG_TAIL(&req->nl_addr) - (char *)start;
}

static void rta_parse(struct rtattr **tb, int maxtype, struct rtattr *head,
		      int len)
{
	struct rtattr *rta;

	memset(tb, 0, sizeof(struct rtattr *) * maxtype);
	for (rta = head; RTA_OK(rta, len);
	     rta = RTA_NEXT(rta, len)) {
		__u16 type = rta->rta_type & NLA_TYPE_MASK;

		if (type > 0 && type < maxtype)
			tb[type] = rta;
	}
}

static struct rtattr *rta_find(struct rtattr *rta, int attrlen, uint16_t type)
{
	for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
		if (rta->rta_type == (type & NLA_TYPE_MASK))
			return rta;
	}

	return NULL;
}

/* @brief Fill a Netlink messages with the necessary common RTAs for creating a
 * RTM_NEWLINK message for creating or changing rmnet devices.
 * @param *req The netlink message
 * @param *reqsize The remaining space within the Netlink message
 * @param devindex The ifindex of the physical device
 * @param *vndname The name of the rmnet device
 * @param index The MUX ID of the rmnet device
 * @param flagconfig The dataformat flags for the rmnet device
 * @return RMNETCTL_LIB_ERR if there is not enough space to add all RTAs
 * @return RMNETCTL_SUCCESS if everything was added successfully
 */
static int rmnet_fill_newlink_msg(struct nlmsg *req, size_t *reqsize,
				  unsigned int devindex, char *vndname,
				  uint8_t index, uint32_t flagconfig)
{
	struct rtattr *linkinfo, *datainfo;
	struct ifla_vlan_flags flags;
	int rc;

	/* Set up link attr with devindex as data */
	rc = rta_put_u32(req, reqsize, IFLA_LINK, devindex);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_put_string(req, reqsize, IFLA_IFNAME, vndname);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	/* Set up info kind RMNET that has linkinfo and type */
	rc = rta_nested_start(req, reqsize, IFLA_LINKINFO, &linkinfo);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_put_string(req, reqsize, IFLA_INFO_KIND, "rmnet");
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_nested_start(req, reqsize, IFLA_INFO_DATA, &datainfo);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_put_u16(req, reqsize, RMNETCTL_IFLA_MUX_ID, index);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	if (flagconfig != 0) {
		flags.mask = flagconfig;
		flags.flags = flagconfig;

		rc = rta_put(req, reqsize, RMNETCTL_IFLA_FLAGS, sizeof(flags),
			     &flags);
		if (rc != RMNETCTL_SUCCESS)
			return rc;
	}

	rta_nested_end(req, datainfo);
	rta_nested_end(req, linkinfo);

	return RMNETCTL_SUCCESS;
}

/* @brief Fill a Netlink messages with the necessary common RTAs for creating a
 * RTM_NEWLINK message that configures the uplink aggregation parameters
 * @param *req The netlink message
 * @param *reqsize The remaining space within the Netlink message
 * @param devindex The ifindex of the physical device
 * @param *vndname The name of the rmnet device
 * @param packet_count The max packet count
 * @param byte_count The max byte count
 * @param time_limit The max time limit
 * @param features The enabled aggregatin features
 * @param state_id The aggregation state to configure
 * @param flagconfig The dataformat flags for the rmnet device
 * @return RMNETCTL_LIB_ERR if there is not enough space to add all RTAs
 * @return RMNETCTL_SUCCESS if everything was added successfully
 */
static int rmnet_fill_ul_agg_msg(struct nlmsg *req, size_t *reqsize,
				 unsigned int devindex, char *vndname,
				 uint8_t packet_count, uint16_t byte_count,
				 uint32_t time_limit, uint8_t features,
				 uint8_t state_id)
{
	struct rmnetctl_uplink_params uplink_params;
	struct rtattr *linkinfo, *datainfo;
	int rc;

	memset(&uplink_params, 0, sizeof(uplink_params));

	/* Set up link attr with devindex as data */
	rc = rta_put_u32(req, reqsize, IFLA_LINK, devindex);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_put_string(req, reqsize, IFLA_IFNAME, vndname);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	/* Set up IFLA info kind RMNET that has linkinfo and type */
	rc = rta_nested_start(req, reqsize, IFLA_LINKINFO, &linkinfo);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_put_string(req, reqsize, IFLA_INFO_KIND, "rmnet");
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_nested_start(req, reqsize, IFLA_INFO_DATA, &datainfo);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	uplink_params.byte_count = byte_count;
	uplink_params.packet_count = packet_count;
	uplink_params.features = features;
	uplink_params.time_limit = time_limit;
	rc = rta_put(req, reqsize, RMNETCTL_IFLA_UPLINK_PARAMS,
		     sizeof(uplink_params), &uplink_params);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	if (state_id != RMNETCTL_DEFAULT_UL_AGG_STATE) {
		rc = rta_put_u8(req, reqsize, RMNETCTL_IFLA_UPLINK_STATE_ID,
				state_id);
		if (rc != RMNETCTL_SUCCESS)
			return rc;
	}

	rta_nested_end(req, datainfo);
	rta_nested_end(req, linkinfo);

	return RMNETCTL_SUCCESS;
}

/* @brief Add all necessary RTA elements to a Netlink message suitable for
 * sending to the DFC driver
 * @param *req The Netlink message
 * @param *reqsize The remaining space in the Netlink message
 * @param devindex The ifindex of the real physical device
 * @param *vndname The name of the VND we're modifying
 * @param *flowinfo The parameters sent to the DFC driver
 * @param flowlen The length of the flowinfo parameter in bytes
 * @return RMENTCTL_LIB_ERR if there is not enough space to add the RTAs
 * @return RMNETCTL_SUCCESS if everything was added successfully
 */
static int rmnet_fill_flow_msg(struct nlmsg *req, size_t *reqsize,
			       unsigned int devindex, char *vndname,
			       char *flowinfo, size_t flowlen)
{
	struct rtattr *linkinfo, *datainfo;
	int rc;

	/* Set up link attr with devindex as data */
	rc = rta_put_u32(req, reqsize, IFLA_LINK, devindex);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_put_string(req, reqsize, IFLA_IFNAME, vndname);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	/* Set up IFLA info kind RMNET that has linkinfo and type */
	rc = rta_nested_start(req, reqsize, IFLA_LINKINFO, &linkinfo);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_put_string(req, reqsize, IFLA_INFO_KIND, "rmnet");
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_nested_start(req, reqsize, IFLA_INFO_DATA, &datainfo);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rta_put(req, reqsize, RMNETCTL_IFLA_DFC_QOS, flowlen,
		     flowinfo);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rta_nested_end(req, datainfo);
	rta_nested_end(req, linkinfo);

	return RMNETCTL_SUCCESS;
}

/* @brief Synchronous method to receive messages to and from the kernel
 * using netlink sockets
 * @details Receives the ack response from the kernel.
 * @param *hndl RmNet handle for this transaction
 * @param *error_code Error code if transaction fails
 * @return RMNETCTL_API_SUCCESS if successfully able to send and receive message
 * from the kernel
 * @return RMNETCTL_API_ERR_HNDL_INVALID if RmNet handle for the transaction was
 * NULL
 * @return RMNETCTL_API_ERR_MESSAGE_RECEIVE if could not receive message from
 * the kernel
 * @return RMNETCTL_API_ERR_MESSAGE_TYPE if the response type does not
 * match
 */
static int rmnet_get_ack(rmnetctl_hndl_t *hndl, uint16_t *error_code)
{
	struct nlack {
		struct nlmsghdr ackheader;
		struct nlmsgerr ackdata;
		char   data[256];

	} ack;
	int i;

	if (!hndl || !error_code)
		return RMNETCTL_INVALID_ARG;

	if ((i = recv(hndl->netlink_fd, &ack, sizeof(ack), 0)) < 0) {
		*error_code = errno;
		return RMNETCTL_API_ERR_MESSAGE_RECEIVE;
	}

	/*Ack should always be NLMSG_ERROR type*/
	if (ack.ackheader.nlmsg_type == NLMSG_ERROR) {
		if (ack.ackdata.error == 0) {
			*error_code = RMNETCTL_API_SUCCESS;
			return RMNETCTL_SUCCESS;
		} else {
			*error_code = -ack.ackdata.error;
			return RMNETCTL_KERNEL_ERR;
		}
	}

	*error_code = RMNETCTL_API_ERR_RETURN_TYPE;
	return RMNETCTL_API_FIRST_ERR;
}

/*
 *                       EXPOSED NEW DRIVER API
 */
int rtrmnet_ctl_init(rmnetctl_hndl_t **hndl, uint16_t *error_code)
{
	struct sockaddr_nl __attribute__((__may_alias__)) *saddr_ptr;
	int netlink_fd = -1;
	socklen_t addr_len = sizeof(struct sockaddr_nl);

	if (!hndl || !error_code)
		return RMNETCTL_INVALID_ARG;

	*hndl = (rmnetctl_hndl_t *)malloc(sizeof(rmnetctl_hndl_t));
	if (!*hndl) {
		*error_code = RMNETCTL_API_ERR_HNDL_INVALID;
		return RMNETCTL_LIB_ERR;
	}

	memset(*hndl, 0, sizeof(rmnetctl_hndl_t));

	netlink_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (netlink_fd < MIN_VALID_SOCKET_FD) {
		free(*hndl);
		*error_code = RMNETCTL_INIT_ERR_NETLINK_FD;
		return RMNETCTL_LIB_ERR;
	}

	(*hndl)->netlink_fd = netlink_fd;

	(*hndl)->src_addr.nl_family = AF_NETLINK;
	(*hndl)->src_addr.nl_pid = 0; /* auto assign */

	saddr_ptr = &(*hndl)->src_addr;
	if (bind((*hndl)->netlink_fd,
		(struct sockaddr *)saddr_ptr,
		sizeof(struct sockaddr_nl)) < 0) {
		close((*hndl)->netlink_fd);
		free(*hndl);
		*error_code = RMNETCTL_INIT_ERR_BIND;
		return RMNETCTL_LIB_ERR;
	}

	/* Get assigned port_id */
	if (!getsockname(netlink_fd, (struct sockaddr *)saddr_ptr, &addr_len))
		(*hndl)->pid = (*hndl)->src_addr.nl_pid;

	(*hndl)->dest_addr.nl_family = AF_NETLINK;
	(*hndl)->dest_addr.nl_pid = KERNEL_PROCESS_ID;
	(*hndl)->dest_addr.nl_groups = UNICAST;

	return RMNETCTL_SUCCESS;
}

int rtrmnet_ctl_deinit(rmnetctl_hndl_t *hndl)
{
	if (!hndl)
		return RMNETCTL_SUCCESS;

	if (hndl->llc_hndl)
		rtrmnet_ctl_deinit(hndl->llc_hndl);

	close(hndl->netlink_fd);
	free(hndl);

	return RMNETCTL_SUCCESS;
}

int rtrmnet_ctl_newvnd(rmnetctl_hndl_t *hndl, char *devname, char *vndname,
		       uint16_t *error_code, uint8_t  index,
		       uint32_t flagconfig)
{
	unsigned int devindex = 0;
	struct nlmsg req;
	size_t reqsize;
	int rc;

	if (!hndl || !devname || !vndname || !error_code ||
	   _rmnetctl_check_dev_name(vndname) || _rmnetctl_check_dev_name(devname))
		return RMNETCTL_INVALID_ARG;

	memset(&req, 0, sizeof(req));
	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL |
				  NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
	rc = rta_put_u32(&req, &reqsize, RMNET_IFLA_NUM_TX_QUEUES,
			 RMNETCTL_NUM_TX_QUEUES);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	rc = rmnet_fill_newlink_msg(&req, &reqsize, devindex, vndname, index,
				    flagconfig);
	if (rc != RMNETCTL_SUCCESS)
		return rc;

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}

int rtrmnet_ctl_delvnd(rmnetctl_hndl_t *hndl, char *vndname,
		       uint16_t *error_code)
{
	unsigned int devindex = 0;
	struct nlmsg req;

	if (!hndl || !vndname || !error_code)
		return RMNETCTL_INVALID_ARG;

	memset(&req, 0, sizeof(req));
	req.nl_addr.nlmsg_type = RTM_DELLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of vndname*/
	devindex = if_nametoindex(vndname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	/* Setup index attribute */
	req.ifmsg.ifi_index = devindex;
	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}


int rtrmnet_ctl_changevnd(rmnetctl_hndl_t *hndl, char *devname, char *vndname,
			  uint16_t *error_code, uint8_t  index,
			  uint32_t flagconfig)
{
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));

	if (!hndl || !devname || !vndname || !error_code ||
	    _rmnetctl_check_dev_name(vndname) || _rmnetctl_check_dev_name(devname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	rc = rmnet_fill_newlink_msg(&req, &reqsize, devindex, vndname, index,
				    flagconfig);
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}

int rtrmnet_ctl_getvnd(rmnetctl_hndl_t *hndl, char *vndname,
		       uint16_t *error_code, uint16_t *mux_id,
		       uint32_t *flagconfig, uint8_t *agg_count,
		       uint16_t *agg_size, uint32_t *agg_time,
		       uint8_t *features)
{
	struct nlmsg req;
	struct nlmsghdr *resp;
	struct rtattr *attrs, *linkinfo, *datainfo;
	struct rtattr *tb[__RMNETCTL_IFLA_MAX];
	unsigned int devindex = 0;
	int resp_len;

	memset(&req, 0, sizeof(req));

	if (!hndl || !vndname || !error_code || !(mux_id || flagconfig) ||
	    _rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	req.nl_addr.nlmsg_type = RTM_GETLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of vndname */
	devindex = if_nametoindex(vndname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	req.ifmsg.ifi_index = devindex;
	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	resp_len = recv(hndl->netlink_fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
	if (resp_len < 0) {
		*error_code = errno;
		return RMNETCTL_API_ERR_MESSAGE_RECEIVE;
	}

	resp = malloc((size_t)resp_len);
	if (!resp) {
		*error_code = errno;
		return RMNETCTL_LIB_ERR;
	}

	resp_len = recv(hndl->netlink_fd, (char *)resp, (size_t)resp_len, 0);
	if (resp_len < 0) {
		*error_code = errno;
		free(resp);
		return RMNETCTL_API_ERR_MESSAGE_RECEIVE;
	}

	/* Parse out the RT attributes */
	attrs = (struct rtattr *)((char *)NLMSG_DATA(resp) +
				  NLMSG_ALIGN(sizeof(req.ifmsg)));
	linkinfo = rta_find(attrs, NLMSG_PAYLOAD(resp, sizeof(req.ifmsg)),
			    IFLA_LINKINFO);
	if (!linkinfo) {
		free(resp);
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return RMNETCTL_KERNEL_ERR;
	}

	datainfo = rta_find(RTA_DATA(linkinfo), RTA_PAYLOAD(linkinfo),
			    IFLA_INFO_DATA);
	if (!datainfo) {
		free(resp);
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return RMNETCTL_KERNEL_ERR;
	}

	/* Parse all the rmnet-specific information from the kernel */
	rta_parse(tb, __RMNETCTL_IFLA_MAX, RTA_DATA(datainfo),
		  RTA_PAYLOAD(datainfo));
	if (tb[RMNETCTL_IFLA_MUX_ID] && mux_id)
		*mux_id = *((uint16_t *)RTA_DATA(tb[RMNETCTL_IFLA_MUX_ID]));
	if (tb[RMNETCTL_IFLA_FLAGS] && flagconfig) {
		struct ifla_vlan_flags *flags;

		flags = (struct ifla_vlan_flags *)
			 RTA_DATA(tb[RMNETCTL_IFLA_FLAGS]);
		*flagconfig = flags->flags;
	}
	if (tb[RMNETCTL_IFLA_UPLINK_PARAMS]) {
		struct rmnetctl_uplink_params *ul_agg;

		ul_agg = (struct rmnetctl_uplink_params *)
			 RTA_DATA(tb[RMNETCTL_IFLA_UPLINK_PARAMS]);

		if (agg_size)
			*agg_size = ul_agg->byte_count;

		if (agg_count)
			*agg_count = ul_agg->packet_count;

		if (features)
			*features = ul_agg->features;

		if (agg_time)
			*agg_time = ul_agg->time_limit;
	}

	free(resp);
	return RMNETCTL_API_SUCCESS;
}

int rtrmnet_ctl_bridgevnd(rmnetctl_hndl_t *hndl, char *devname, char *vndname,
			  uint16_t *error_code)
{
	unsigned int devindex = 0, vndindex = 0;
	struct nlmsg req;
	size_t reqsize;
	int rc;

	if (!hndl || !vndname || !devname || !error_code || _rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	memset(&req, 0, sizeof(req));
	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of vndname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	vndindex = if_nametoindex(vndname);
	if (vndindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	/* Setup index attribute */
	req.ifmsg.ifi_index = devindex;
	rc = rta_put_u32(&req, &reqsize, IFLA_MASTER, vndindex);
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}

int rtrmnet_set_uplink_aggregation_params(rmnetctl_hndl_t *hndl,
					  char *devname,
					  char *vndname,
					  uint8_t packet_count,
					  uint16_t byte_count,
					  uint32_t time_limit,
					  uint8_t features,
					  uint16_t *error_code)
{
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));

	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	rc = rmnet_fill_ul_agg_msg(&req, &reqsize, devindex, vndname,
				   packet_count, byte_count, time_limit,
				   features, RMNETCTL_DEFAULT_UL_AGG_STATE);
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);

}

int rtrmnet_set_ll_uplink_aggregation_params(rmnetctl_hndl_t *hndl,
					     char *devname,
					     char *vndname,
					     uint8_t packet_count,
					     uint16_t byte_count,
					     uint32_t time_limit,
					     uint8_t features,
					     uint16_t *error_code)
{
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));

	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	rc = rmnet_fill_ul_agg_msg(&req, &reqsize, devindex, vndname,
				   packet_count, byte_count, time_limit,
				   features, RMNETCTL_LL_UL_AGG_STATE);
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);

}

int rtrmnet_activate_flow(rmnetctl_hndl_t *hndl,
			  char *devname,
			  char *vndname,
			  uint8_t bearer_id,
			  uint32_t flow_id,
			  int ip_type,
			  uint32_t tcm_handle,
			  uint16_t *error_code)
{
	struct tcmsg  flowinfo;
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize =0;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&flowinfo, 0, sizeof(flowinfo));


	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	flowinfo.tcm_handle = tcm_handle;
	flowinfo.tcm_family = RMNET_FLOW_MSG_ACTIVATE;
	flowinfo.tcm__pad1 = bearer_id;
	flowinfo.tcm_ifindex = ip_type;
	flowinfo.tcm_parent = flow_id;

	rc = rmnet_fill_flow_msg(&req, &reqsize, devindex, vndname,
				 (char *)&flowinfo, sizeof(flowinfo));
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}


int rtrmnet_delete_flow(rmnetctl_hndl_t *hndl,
			  char *devname,
			  char *vndname,
			  uint8_t bearer_id,
			  uint32_t flow_id,
			  int ip_type,
			  uint16_t *error_code)
{
	struct tcmsg  flowinfo;
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&flowinfo, 0, sizeof(flowinfo));

	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	flowinfo.tcm_family = RMNET_FLOW_MSG_DEACTIVATE;
	flowinfo.tcm_ifindex = ip_type;
	flowinfo.tcm__pad1 = bearer_id;
	flowinfo.tcm_parent = flow_id;

	rc = rmnet_fill_flow_msg(&req, &reqsize, devindex, vndname,
				 (char *)&flowinfo,sizeof(flowinfo));
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}

int rtrmnet_control_flow(rmnetctl_hndl_t *hndl,
			  char *devname,
			  char *vndname,
			  uint8_t bearer_id,
			  uint16_t sequence,
			  uint32_t grantsize,
			  uint8_t ack,
			  uint16_t *error_code)
{
	struct tcmsg  flowinfo;
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&flowinfo, 0, sizeof(flowinfo));

	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	flowinfo.tcm_family = RMNET_FLOW_MSG_CONTROL;
	flowinfo.tcm__pad1 = bearer_id;
	flowinfo.tcm__pad2 = sequence;
	flowinfo.tcm_parent = ack;
	flowinfo.tcm_info = grantsize;

	rc = rmnet_fill_flow_msg(&req, &reqsize, devindex, vndname,
				 (char *)&flowinfo, sizeof(flowinfo));
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}


int rtrmnet_flow_state_up(rmnetctl_hndl_t *hndl,
			  char *devname,
			  char *vndname,
			  uint32_t instance,
			  uint32_t ep_type,
			  uint32_t ifaceid,
			  int flags,
			  uint16_t *error_code)
{
	struct tcmsg  flowinfo;
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&flowinfo, 0, sizeof(flowinfo));

	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	flowinfo.tcm_handle = instance;
	flowinfo.tcm_family = RMNET_FLOW_MSG_UP;
	flowinfo.tcm_ifindex = flags;
	flowinfo.tcm_parent = ifaceid;
	flowinfo.tcm_info = ep_type;

	rc = rmnet_fill_flow_msg(&req, &reqsize, devindex, vndname,
				 (char *)&flowinfo, sizeof(flowinfo));
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}


int rtrmnet_flow_state_down(rmnetctl_hndl_t *hndl,
			  char *devname,
			  char *vndname,
			  uint32_t instance,
			  uint16_t *error_code)
{
	struct tcmsg  flowinfo;
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&flowinfo, 0, sizeof(flowinfo));

	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	flowinfo.tcm_handle = instance;
	flowinfo.tcm_family = RMNET_FLOW_MSG_DOWN;

	rc = rmnet_fill_flow_msg(&req, &reqsize, devindex, vndname,
				 (char *)&flowinfo, sizeof(flowinfo));
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}

int rtrmnet_set_qmi_scale(rmnetctl_hndl_t *hndl,
			  char *devname,
			  char *vndname,
			  uint32_t scale,
			  uint16_t *error_code)
{
	struct tcmsg  flowinfo;
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&flowinfo, 0, sizeof(flowinfo));

	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname) || !scale)
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	flowinfo.tcm_ifindex = scale;
	flowinfo.tcm_family = RMNET_FLOW_MSG_QMI_SCALE;

	rc = rmnet_fill_flow_msg(&req, &reqsize, devindex, vndname,
				 (char *)&flowinfo, sizeof(flowinfo));
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}

int rtrmnet_set_wda_freq(rmnetctl_hndl_t *hndl,
			 char *devname,
			 char *vndname,
			 uint32_t freq,
			 uint16_t *error_code)
{
	struct tcmsg  flowinfo;
	struct nlmsg req;
	unsigned int devindex = 0;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&flowinfo, 0, sizeof(flowinfo));

	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname))
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	flowinfo.tcm_ifindex = freq;
	flowinfo.tcm_family = RMNET_FLOW_MSG_WDA_FREQ;

	rc = rmnet_fill_flow_msg(&req, &reqsize, devindex, vndname,
				 (char *)&flowinfo, sizeof(flowinfo));
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	return rmnet_get_ack(hndl, error_code);
}

int rtrmnet_change_bearer_channel(rmnetctl_hndl_t *hndl,
				  char *devname,
				  char *vndname,
				  uint8_t switch_type,
				  uint32_t flags,
				  uint8_t num_bearers,
				  uint8_t *bearers,
				  uint16_t *error_code)
{
	struct nlmsg req;
	struct {
		struct tcmsg tcm;
		uint8_t data[16]; /* Max number of bearers */
	} flowinfo;
	unsigned int devindex;
	size_t reqsize;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&flowinfo, 0, sizeof(flowinfo));
	if (!hndl || !devname || !error_code ||_rmnetctl_check_dev_name(devname) ||
		_rmnetctl_check_dev_name(vndname) || num_bearers > 16 || !bearers)
		return RMNETCTL_INVALID_ARG;

	reqsize = NLMSG_DATA_SIZE - sizeof(struct rtattr);
	req.nl_addr.nlmsg_type = RTM_NEWLINK;
	req.nl_addr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl_addr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl_addr.nlmsg_seq = hndl->transaction_id;
	hndl->transaction_id++;

	/* Get index of devname*/
	devindex = if_nametoindex(devname);
	if (devindex == 0) {
		*error_code = errno;
		return RMNETCTL_KERNEL_ERR;
	}

	/* Create 2nd hndl to receive LLC status */
	if ((flags & RMNETCTL_LL_MASK_ACK) && !hndl->llc_hndl) {
		rc = rtrmnet_ctl_init(&hndl->llc_hndl, error_code);
		if (rc != RMNETCTL_SUCCESS) {
			hndl->llc_hndl = NULL;
			return rc;
		}
	}

	/* Fill the flow information */
	flowinfo.tcm.tcm_family = RMNET_FLOW_MSG_CHANNEL_SWITCH;
	flowinfo.tcm.tcm__pad1 = switch_type;
	flowinfo.tcm.tcm__pad2 = num_bearers;
	flowinfo.tcm.tcm_info = flags;
	memscpy(flowinfo.data, 16, bearers, num_bearers);
	/* DFC needs this to send the ACK back to LLC socket specifically */
	if (hndl->llc_hndl) {
		flowinfo.tcm.tcm_ifindex = hndl->llc_hndl->netlink_fd;
		flowinfo.tcm.tcm_handle = hndl->llc_hndl->pid;
		flowinfo.tcm.tcm_parent = hndl->transaction_id--;
	}

	rc = rmnet_fill_flow_msg(&req, &reqsize, devindex, vndname,
				 (char *)&flowinfo, sizeof(flowinfo));
	if (rc != RMNETCTL_SUCCESS) {
		*error_code = RMNETCTL_API_ERR_RTA_FAILURE;
		return rc;
	}

	/* Fire away */
	if (send(hndl->netlink_fd, &req, req.nl_addr.nlmsg_len, 0) < 0) {
		*error_code = RMNETCTL_API_ERR_MESSAGE_SEND;
		return RMNETCTL_LIB_ERR;
	}

	/* Initial ACK: The kernel got the message */
	return rmnet_get_ack(hndl, error_code);
}

int rtrmnet_get_ll_ack(rmnetctl_hndl_t *hndl,
		       struct rmnetctl_ll_ack *ll_ack,
		       uint16_t *error_code)
{
	struct nlack {
		struct nlmsghdr ackheader;
		struct nlmsgerr ackdata;

	} ack;
	int i;

	if (!hndl || !hndl->llc_hndl || !ll_ack || !error_code)
		return RMNETCTL_INVALID_ARG;

	if ((i = recv(hndl->llc_hndl->netlink_fd, &ack, sizeof(ack), 0)) < 0) {
		*error_code = errno;
		return RMNETCTL_API_ERR_MESSAGE_RECEIVE;
	}

	/*Ack should always be NLMSG_ERROR type*/
	if (ack.ackheader.nlmsg_type == NLMSG_ERROR) {
		if (ack.ackdata.error == 0) {
			ll_ack->bearer_id =
				(uint8_t)ack.ackdata.msg.nlmsg_type;
			ll_ack->status_code =
				(uint8_t)ack.ackdata.msg.nlmsg_flags;
			ll_ack->current_ch =
				(uint8_t)ack.ackdata.msg.nlmsg_seq;
			*error_code = RMNETCTL_API_SUCCESS;
			return RMNETCTL_SUCCESS;
		} else {
			*error_code = -ack.ackdata.error;
			return RMNETCTL_KERNEL_ERR;
		}
	}

	*error_code = RMNETCTL_API_ERR_RETURN_TYPE;
	return RMNETCTL_API_FIRST_ERR;
}

static const char *rmnetctl_ll_status_text[] = {
        "Error",
        "Success",
        "Switched to Default",
        "Switched to LL",
        "Temporary Failure",
        "Permanent Failure"
};

const char *rtrmnet_ll_status_to_text(uint8_t status)
{
	if (status == LL_STATUS_TIMEOUT)
		return "Time out";

	if (status == LL_STATUS_NO_EFFECT)
		return "No Effect";

	if (status < sizeof(rmnetctl_ll_status_text) /
		     sizeof(rmnetctl_ll_status_text[0]))
		return rmnetctl_ll_status_text[status];

	return "Unknown";
}
