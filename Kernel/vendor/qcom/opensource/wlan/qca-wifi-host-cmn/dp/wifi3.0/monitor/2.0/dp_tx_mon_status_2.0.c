/*
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "dp_types.h"
#include "qdf_nbuf.h"
#include "dp_internal.h"
#include "qdf_mem.h"   /* qdf_mem_malloc,free */
#include <dp_be.h>
#include <qdf_nbuf_frag.h>
#include <hal_be_api_mon.h>
#include <dp_mon.h>
#include <dp_tx_mon_2.0.h>
#include <dp_mon_2.0.h>
#ifdef QCA_SUPPORT_LITE_MONITOR
#include <dp_lite_mon.h>
#endif

#define MAX_PPDU_INFO_LIST_DEPTH 64

#if defined(WLAN_TX_PKT_CAPTURE_ENH_BE) || defined(WLAN_PKT_CAPTURE_TX_2_0) ||\
	defined(WLAN_TX_MON_CORE_DEBUG)
void
dp_tx_mon_status_free_packet_buf(struct dp_pdev *pdev,
				 qdf_frag_t status_frag, uint32_t end_offset,
				 struct dp_tx_mon_desc_list *mon_desc_list_ref,
				 uint8_t mac_id)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_mon_packet_info packet_info = {0};
	uint8_t *tx_tlv;
	uint8_t *mon_buf_tx_tlv;
	uint8_t *tx_tlv_start;

	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	tx_tlv = status_frag;
	tx_tlv_start = tx_tlv;
	/*
	 * parse each status buffer and find packet buffer in it
	 */
	do {
		if (hal_txmon_is_mon_buf_addr_tlv(pdev->soc->hal_soc, tx_tlv)) {
			struct dp_mon_desc *mon_desc = NULL;
			qdf_frag_t packet_buffer = NULL;
			uint32_t cookie_2;

			mon_buf_tx_tlv = ((uint8_t *)tx_tlv +
					  HAL_RX_TLV_HDR_SIZE);
			hal_txmon_populate_packet_info(pdev->soc->hal_soc,
						       mon_buf_tx_tlv,
						       &packet_info);

			mon_desc = dp_mon_get_desc_addr(packet_info.sw_cookie);
			cookie_2 = DP_MON_GET_COOKIE(packet_info.sw_cookie);

			qdf_assert_always(mon_desc);

			if (mon_desc->cookie_2 != cookie_2) {
				qdf_err("duplicate cookie found mon_desc:%pK", mon_desc);
				qdf_assert_always(0);
			}

			if (mon_desc->magic != DP_MON_DESC_MAGIC)
				qdf_assert_always(0);

			if (!mon_desc->unmapped) {
				qdf_mem_unmap_page(pdev->soc->osdev,
						   (qdf_dma_addr_t)mon_desc->paddr,
						   DP_MON_DATA_BUFFER_SIZE,
						   QDF_DMA_FROM_DEVICE);
				mon_desc->unmapped = 1;
			}

			packet_buffer = (qdf_frag_t)(mon_desc->buf_addr);
			mon_desc->buf_addr = NULL;

			qdf_assert_always(packet_buffer);
			/* increment reap count */
			mon_desc_list_ref->tx_mon_reap_cnt++;

			/* add the mon_desc to free list */
			dp_mon_add_to_free_desc_list(&mon_desc_list_ref->desc_list,
						     &mon_desc_list_ref->tail,
						     mon_desc);

			tx_mon_be->stats.pkt_buf_recv++;
			tx_mon_be->stats.pkt_buf_free++;

			/* free buffer, mapped to descriptor */
			qdf_frag_free(packet_buffer);
		}

		/* need api definition for hal_tx_status_get_next_tlv */
		tx_tlv = hal_tx_status_get_next_tlv(tx_tlv,
						   mon_pdev->is_tlv_hdr_64_bit);
	} while ((tx_tlv - tx_tlv_start) < end_offset);
}
#endif

#if defined(WLAN_TX_PKT_CAPTURE_ENH_BE) && defined(WLAN_PKT_CAPTURE_TX_2_0)
/**
 * dp_tx_mon_status_queue_free() - API to free status buffer
 * @pdev: pdev Handle
 * @tx_mon_be: pointer to tx_monitor_be
 * @mon_desc_list_ref: tx monitor descriptor list reference
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_status_queue_free(struct dp_pdev *pdev,
			    struct dp_pdev_tx_monitor_be *tx_mon_be,
			    struct dp_tx_mon_desc_list *mon_desc_list_ref,
			    uint8_t mac_id)
{
	uint8_t last_frag_q_idx = tx_mon_be->last_frag_q_idx;
	qdf_frag_t status_frag = NULL;
	uint8_t i = tx_mon_be->cur_frag_q_idx;
	uint32_t end_offset = 0;

	if (last_frag_q_idx > MAX_STATUS_BUFFER_IN_PPDU)
		last_frag_q_idx = MAX_STATUS_BUFFER_IN_PPDU;

	for (; i < last_frag_q_idx; i++) {
		status_frag = tx_mon_be->frag_q_vec[i].frag_buf;

		if (qdf_unlikely(!status_frag))
			continue;

		end_offset = tx_mon_be->frag_q_vec[i].end_offset;
		dp_tx_mon_status_free_packet_buf(pdev, status_frag, end_offset,
						 mon_desc_list_ref, mac_id);
		tx_mon_be->stats.status_buf_free++;
		qdf_frag_free(status_frag);
		tx_mon_be->frag_q_vec[i].frag_buf = NULL;
		tx_mon_be->frag_q_vec[i].end_offset = 0;
	}
	tx_mon_be->last_frag_q_idx = 0;
	tx_mon_be->cur_frag_q_idx = 0;
}

/**
 * dp_tx_mon_enqueue_mpdu_nbuf() - API to enqueue nbuf from per user mpdu queue
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @user_id: user index
 * @mpdu_nbuf: nbuf to be enqueue
 *
 * Return: void
 */
static void
dp_tx_mon_enqueue_mpdu_nbuf(struct dp_pdev *pdev,
			    struct dp_tx_ppdu_info *tx_ppdu_info,
			    uint8_t user_id, qdf_nbuf_t mpdu_nbuf)
{
	qdf_nbuf_t radiotap = NULL;
	/* enqueue mpdu_nbuf to the per user mpdu_q */
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;

	if (!TXMON_PPDU_HAL(tx_ppdu_info, num_users))
		QDF_BUG(0);

	usr_mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, user_id, mpdu_q);

	radiotap = qdf_nbuf_alloc(pdev->soc->osdev, MAX_MONITOR_HEADER,
				  MAX_MONITOR_HEADER,
				  4, FALSE);
	if (qdf_unlikely(!radiotap)) {
		qdf_err("Unable to allocate radiotap buffer\n");
		qdf_nbuf_free(mpdu_nbuf);
		return;
	}

	/* append ext list */
	qdf_nbuf_append_ext_list(radiotap, mpdu_nbuf, qdf_nbuf_len(mpdu_nbuf));
	qdf_nbuf_queue_add(usr_mpdu_q, radiotap);
}

/*
 * TX MONITOR
 *
 * frame format
 * -------------------------------------------------------------------------
 *  FUNC   | ToDS | FromDS | ADDRESS 1 | ADDRESS 2 | ADDRESS 3 | ADDRESS 4 |
 *  ------------------------------------------------------------------------
 *  IBSS   |  0   |    0   | DA        | SA        | BSSID     | NOT USED  |
 *  TO AP  |  1   |    0   | BSSID     | SA        | DA        | NOT USED  |
 *  From AP|  0   |    1   | DA        | BSSID     | SA        | NOT USED  |
 *  WDS    |  1   |    1   | RA        | TA        | DA        | SA        |
 *  ------------------------------------------------------------------------
 *
 *  HOST GENERATED FRAME:
 *  =====================
 *     1. RTS
 *     2. CTS
 *     3. ACK
 *     4. BA
 *     5. Multi STA BA
 *
 *  control frame
 *  ------------------------------------------------------------
 *  | protocol 2b | Type 2b | subtype 4b | ToDS 1b | FromDS 1b |
 *                | Morefrag 1b | Retry 1b | pwr_mgmt 1b | More data 1b |
 *                              | protected frm 1b | order 1b |
 *  -----------------------------------------------------------
 *  control frame originated from wireless station so ToDS = FromDS = 0,
 *
 *  RTS
 *  ---------------------------------------------------------------------------
 *  | FrameCtl 2 | Duration 2 | Receiver Address 6 | Transmit address 6 | FCS |
 *  ---------------------------------------------------------------------------
 *  subtype in FC is RTS - 1101
 *  type in FC is control frame - 10
 *
 *  CTS
 *  --------------------------------------------------------
 *  | FrameCtl 2 | Duration 2 | Receiver Address 6 | FCS 4 |
 *  --------------------------------------------------------
 *  subtype in FC is CTS - 0011
 *  type in FC is control frame - 10
 *
 *  ACK
 *  --------------------------------------------------------
 *  | FrameCtl 2 | Duration 2 | Receiver Address 6 | FCS 4 |
 *  --------------------------------------------------------
 *  subtype in FC is ACK - 1011
 *  type in FC is control frame - 10
 *
 *  Block ACK
 *  --------------------------------------------------------------------------
 *  | FC 2 | Dur 2 | RA 6 | TA 6 | BA CTRL 2 | BA Information variable | FCS |
 *  --------------------------------------------------------------------------
 *
 *	Block Ack control
 *	---------------------------------------------------------------
 *	| BA ACK POLICY B0 | BA TYPE B1-B4 | Rsv B5-B11 | TID B12-B15 |
 *	---------------------------------------------------------------
 *
 *	BA ack policy
 *	0 - Normal Ack
 *	1 - No Ack
 *
 *	Block Ack Type
 *	0     - Reserved
 *	1     - extended compressed
 *	2     - compressed
 *	3     - Multi TID
 *	4-5   - Reserved
 *	6     - GCR
 *	7-9   - Reserved
 *	10    - GLK-GCR
 *	11    - Multi-STA
 *	12-15 - Reserved
 *
 *	Block Ack information
 *	----------------------------------------------------------
 *	| Block ack start seq ctrl 2 | Block ack bitmap variable |
 *	----------------------------------------------------------
 *
 *	Multi STA Block Ack Information
 *	-----------------------------------------------------------------
 *	| Per STA TID info 2 | BA start seq ctrl 2 | BA bitmap variable |
 *	-----------------------------------------------------------------
 *
 *		Per STA TID info
 *		------------------------------------
 *		| AID11 11b | Ack Type 1b | TID 4b |
 *		------------------------------------
 *		AID11 - 2045 means unassociated STA, then ACK Type and TID 0, 15
 *
 *		Mgmt/PS-POLL frame ack
 *		Ack type - 1 and TID - 15, BA_seq_ctrl & BA_bitmap - not present
 *
 *		All ack context - with no bitmap (all AMPDU success)
 *		Ack type - 1 and TID - 14, BA_seq_ctrl & BA_bitmap - not present
 *
 *		Block ack context
 *		Ack type - 0 and  TID - 0~7 BA_seq_ctrl & BA_bitmap - present
 *
 *		Ack context
 *		Ack type - 1 and TID - 0~7 BA_seq_ctrl & BA_bitmap - not present
 *
 *
 */

/**
 * dp_tx_mon_generate_cts2self_frm() - API to generate cts2self frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @window_flag: frame generated window
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_cts2self_frm(struct dp_pdev *pdev,
				struct dp_tx_ppdu_info *tx_ppdu_info,
				uint8_t window_flag,
				uint8_t mac_id)
{
	/* allocate and populate CTS/ CTS2SELF frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	uint16_t duration_le = 0;
	struct ieee80211_frame_min_one *wh_min = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint8_t frm_ctl;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);

	if (window_flag == INITIATOR_WINDOW)
		tx_status_info = &tx_mon_be->prot_status_info;
	else
		tx_status_info = &tx_mon_be->data_status_info;

	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_min = (struct ieee80211_frame_min_one *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_min, MAX_DUMMY_FRM_BODY);

	frm_ctl = (QDF_IEEE80211_FC0_VERSION_0 | QDF_IEEE80211_FC0_TYPE_CTL |
		   QDF_IEEE80211_FC0_SUBTYPE_CTS);
	TXMON_PPDU_COM(tx_ppdu_info, frame_control) = frm_ctl;
	TXMON_PPDU_COM(tx_ppdu_info, frame_control_info_valid) = 1;
	wh_min->i_fc[1] = 0;
	wh_min->i_fc[0] = frm_ctl;

	duration_le = qdf_cpu_to_le16(TXMON_PPDU_COM(tx_ppdu_info, duration));
	wh_min->i_dur[1] = (duration_le & 0xFF00) >> 8;
	wh_min->i_dur[0] = (duration_le & 0xFF);

	qdf_mem_copy(wh_min->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr2),
		     QDF_MAC_ADDR_SIZE);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_min));
	dp_tx_mon_enqueue_mpdu_nbuf(pdev, tx_ppdu_info, 0, mpdu_nbuf);
	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 1;
}

/**
 * dp_tx_mon_generate_rts_frm() - API to generate rts frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @window_flag: frame generated window
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_rts_frm(struct dp_pdev *pdev,
			   struct dp_tx_ppdu_info *tx_ppdu_info,
			   uint8_t window_flag,
			   uint8_t mac_id)
{
	/* allocate and populate RTS frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	uint16_t duration_le = 0;
	struct ieee80211_ctlframe_addr2 *wh_min = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint8_t frm_ctl;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	tx_status_info = &tx_mon_be->prot_status_info;
	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_min = (struct ieee80211_ctlframe_addr2 *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_min, MAX_DUMMY_FRM_BODY);

	frm_ctl = (QDF_IEEE80211_FC0_VERSION_0 | QDF_IEEE80211_FC0_TYPE_CTL |
		   QDF_IEEE80211_FC0_SUBTYPE_RTS);
	TXMON_PPDU_COM(tx_ppdu_info, frame_control) = frm_ctl;
	TXMON_PPDU_COM(tx_ppdu_info, frame_control_info_valid) = 1;
	wh_min->i_fc[1] = 0;
	wh_min->i_fc[0] = frm_ctl;

	duration_le = qdf_cpu_to_le16(TXMON_PPDU_COM(tx_ppdu_info, duration));
	wh_min->i_aidordur[1] = (duration_le & 0xFF00) >> 8;
	wh_min->i_aidordur[0] = (duration_le & 0xFF);

	if (!tx_status_info->protection_addr)
		tx_status_info = &tx_mon_be->data_status_info;

	if (window_flag == INITIATOR_WINDOW) {
		qdf_mem_copy(wh_min->i_addr1,
			     TXMON_STATUS_INFO(tx_status_info, addr1),
			     QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(wh_min->i_addr2,
			     TXMON_STATUS_INFO(tx_status_info, addr2),
			     QDF_MAC_ADDR_SIZE);
	} else {
		qdf_mem_copy(wh_min->i_addr1,
			     TXMON_STATUS_INFO(tx_status_info, addr2),
			     QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(wh_min->i_addr2,
			     TXMON_STATUS_INFO(tx_status_info, addr1),
			     QDF_MAC_ADDR_SIZE);
	}

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_min));
	dp_tx_mon_enqueue_mpdu_nbuf(pdev, tx_ppdu_info, 0, mpdu_nbuf);
	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 1;
}

/**
 * dp_tx_mon_generate_ack_frm() - API to generate ack frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_ack_frm(struct dp_pdev *pdev,
			   struct dp_tx_ppdu_info *tx_ppdu_info,
			   uint8_t mac_id)
{
	/* allocate and populate ACK frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_frame_min_one *wh_addr1 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint8_t user_id = TXMON_PPDU_HAL(tx_ppdu_info, cur_usr_idx);
	uint8_t frm_ctl;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	tx_status_info = &tx_mon_be->data_status_info;
	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_addr1 = (struct ieee80211_frame_min_one *)qdf_nbuf_data(mpdu_nbuf);

	frm_ctl = (QDF_IEEE80211_FC0_VERSION_0 | QDF_IEEE80211_FC0_TYPE_CTL |
		   QDF_IEEE80211_FC0_SUBTYPE_ACK);
	TXMON_PPDU_COM(tx_ppdu_info, frame_control) = frm_ctl;
	TXMON_PPDU_COM(tx_ppdu_info, frame_control_info_valid) = 1;
	wh_addr1->i_fc[1] = 0;
	wh_addr1->i_fc[0] = frm_ctl;

	qdf_mem_copy(wh_addr1->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);

	/* set duration zero for ack frame */
	*(u_int16_t *)(&wh_addr1->i_dur) = qdf_cpu_to_le16(0x0000);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_addr1));

	dp_tx_mon_enqueue_mpdu_nbuf(pdev, tx_ppdu_info, user_id, mpdu_nbuf);
	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 1;
}

/**
 * dp_tx_mon_generate_3addr_qos_null_frm() - API to generate
 * 3 address qosnull frame
 *
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_3addr_qos_null_frm(struct dp_pdev *pdev,
				      struct dp_tx_ppdu_info *tx_ppdu_info,
				      uint8_t mac_id)
{
	/* allocate and populate 3 address qos null frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_qosframe *wh_addr3 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint16_t duration_le = 0;
	uint8_t num_users = 0;
	uint8_t frm_ctl;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	tx_status_info = &tx_mon_be->data_status_info;
	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_addr3 = (struct ieee80211_qosframe *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_addr3, sizeof(struct ieee80211_qosframe));

	frm_ctl = (QDF_IEEE80211_FC0_VERSION_0 | QDF_IEEE80211_FC0_TYPE_DATA |
		   QDF_IEEE80211_FC0_SUBTYPE_QOS_NULL);
	TXMON_PPDU_COM(tx_ppdu_info, frame_control) = frm_ctl;
	TXMON_PPDU_COM(tx_ppdu_info, frame_control_info_valid) = 1;
	wh_addr3->i_fc[1] = 0;
	wh_addr3->i_fc[0] = frm_ctl;

	duration_le = qdf_cpu_to_le16(TXMON_PPDU_COM(tx_ppdu_info, duration));
	wh_addr3->i_dur[1] = (duration_le & 0xFF00) >> 8;
	wh_addr3->i_dur[0] = (duration_le & 0xFF);

	qdf_mem_copy(wh_addr3->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr3->i_addr2,
		     TXMON_STATUS_INFO(tx_status_info, addr2),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr3->i_addr3,
		     TXMON_STATUS_INFO(tx_status_info, addr3),
		     QDF_MAC_ADDR_SIZE);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_addr3));
	dp_tx_mon_enqueue_mpdu_nbuf(pdev, tx_ppdu_info, num_users, mpdu_nbuf);
	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 1;
}

/**
 * dp_tx_mon_generate_4addr_qos_null_frm() - API to generate
 * 4 address qos null frame
 *
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_4addr_qos_null_frm(struct dp_pdev *pdev,
				      struct dp_tx_ppdu_info *tx_ppdu_info,
				      uint8_t mac_id)
{
	/* allocate and populate 4 address qos null frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_qosframe_addr4 *wh_addr4 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint16_t duration_le = 0;
	uint8_t num_users = 0;
	uint8_t frm_ctl;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	tx_status_info = &tx_mon_be->data_status_info;
	/*
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!mpdu_nbuf)
		return;

	wh_addr4 = (struct ieee80211_qosframe_addr4 *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_addr4, sizeof(struct ieee80211_qosframe_addr4));

	frm_ctl = (QDF_IEEE80211_FC0_VERSION_0 | QDF_IEEE80211_FC0_TYPE_DATA |
		   QDF_IEEE80211_FC0_SUBTYPE_QOS_NULL);
	TXMON_PPDU_COM(tx_ppdu_info, frame_control) = frm_ctl;
	TXMON_PPDU_COM(tx_ppdu_info, frame_control_info_valid) = 1;
	wh_addr4->i_fc[1] = 0;
	wh_addr4->i_fc[0] = frm_ctl;

	duration_le = qdf_cpu_to_le16(TXMON_PPDU_COM(tx_ppdu_info, duration));
	wh_addr4->i_dur[1] = (duration_le & 0xFF00) >> 8;
	wh_addr4->i_dur[0] = (duration_le & 0xFF);

	qdf_mem_copy(wh_addr4->i_addr1,
		     TXMON_STATUS_INFO(tx_status_info, addr1),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr4->i_addr2,
		     TXMON_STATUS_INFO(tx_status_info, addr2),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr4->i_addr3,
		     TXMON_STATUS_INFO(tx_status_info, addr3),
		     QDF_MAC_ADDR_SIZE);
	qdf_mem_copy(wh_addr4->i_addr4,
		     TXMON_STATUS_INFO(tx_status_info, addr4),
		     QDF_MAC_ADDR_SIZE);

	qdf_nbuf_set_pktlen(mpdu_nbuf, sizeof(*wh_addr4));
	dp_tx_mon_enqueue_mpdu_nbuf(pdev, tx_ppdu_info, num_users, mpdu_nbuf);
	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 1;
}

#define TXMON_BA_PER_STA_TID_INF_SZ	2
#define TXMON_BA_START_SQ_CTRL_SZ	2
#define TXMON_BA_CTRL_SZ		2
#define TXMON_BA_INFO_SZ(bitmap_sz)	\
		((TXMON_BA_START_SQ_CTRL_SZ) + (4 << (bitmap_sz)))
#define TXMON_MU_BA_INFO_SZ(bitmap_sz)	\
		((TXMON_BA_START_SQ_CTRL_SZ) + (TXMON_BA_PER_STA_TID_INF_SZ) +\
		 (4 << (bitmap_sz)))
#define TXMON_MU_BA_ACK_FRAME_SZ(bitmap_sz)		\
		(sizeof(struct ieee80211_ctlframe_addr2) +\
		 TXMON_BA_CTRL_SZ + (bitmap_sz))

#define TXMON_BA_ACK_FRAME_SZ(bitmap_sz)		\
		(sizeof(struct ieee80211_ctlframe_addr2) +\
		 TXMON_BA_CTRL_SZ + TXMON_BA_INFO_SZ(bitmap_sz))

static uint8_t *
dp_init_mu_ba_per_tid_info(struct dp_tx_ppdu_info *tx_ppdu_info, uint8_t *frm,
			   uint8_t user_id)
{
	*((uint16_t *)frm) =
		qdf_cpu_to_le16((TXMON_PPDU_USR(tx_ppdu_info, user_id, tid) <<
				 DP_IEEE80211_BAR_CTL_TID_S) |
				(TXMON_PPDU_USR(tx_ppdu_info, user_id,
						aid) & 0x7FF));
	frm += 2;
	*((uint16_t *)frm) = qdf_cpu_to_le16(
			TXMON_PPDU_USR(tx_ppdu_info, user_id, start_seq));
	frm += 2;
	qdf_mem_copy(frm,
		     TXMON_PPDU_USR(tx_ppdu_info, user_id, ba_bitmap),
				    4 <<
				    TXMON_PPDU_USR(tx_ppdu_info,
						   user_id, ba_bitmap_sz));
	frm += 4 << TXMON_PPDU_USR(tx_ppdu_info, user_id, ba_bitmap_sz);

	return frm;
}

static uint8_t *
dp_skip_ba_tail_to_per_user_info(struct dp_tx_ppdu_info *tx_ppdu_info,
				 qdf_nbuf_t mpdu_nbuf, uint8_t user_id)
{
	struct ieee80211_ctlframe_addr2 *wh_addr2 = NULL;
	uint8_t *frm = NULL;
	uint8_t i;

	wh_addr2 = (struct ieee80211_ctlframe_addr2 *)qdf_nbuf_data(mpdu_nbuf);
	frm = (uint8_t *)&wh_addr2[1];

	/* skip BA control */
	frm += 2;

	for (i = 0; i < user_id; i++) {
		frm += 2; // skip TID info
		frm += 2; // skip BA SSC

		/* skip BA bitmap */
		frm += 4 << TXMON_PPDU_USR(tx_ppdu_info, i, ba_bitmap_sz);
	}

	return frm;
}

static void
dp_set_common_ba_section(struct dp_tx_ppdu_info *tx_ppdu_info,
			 struct dp_mon_pdev_be *mon_pdev_be,
			 qdf_nbuf_t mpdu_nbuf, uint8_t window_flag,
			 uint8_t mac_id)
{
	struct ieee80211_ctlframe_addr2 *wh_addr2 = NULL;
	uint8_t frm_ctl;
	struct hal_tx_status_info *tx_status_info;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	uint8_t num_users = TXMON_PPDU_HAL(tx_ppdu_info, num_users);
	uint8_t *frm = NULL;
	uint16_t ba_control = 0;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	tx_status_info = &tx_mon_be->data_status_info;

	wh_addr2 = (struct ieee80211_ctlframe_addr2 *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_addr2, DP_BA_ACK_FRAME_SIZE);

	frm_ctl = (QDF_IEEE80211_FC0_VERSION_0 | QDF_IEEE80211_FC0_TYPE_CTL |
		   QDF_IEEE80211_FC0_SUBTYPE_BA);
	TXMON_PPDU_COM(tx_ppdu_info, frame_control) = frm_ctl;
	TXMON_PPDU_COM(tx_ppdu_info, frame_control_info_valid) = 1;
	wh_addr2->i_fc[1] = 0;
	wh_addr2->i_fc[0] = frm_ctl;

	*(u_int16_t *)(&wh_addr2->i_aidordur) = qdf_cpu_to_le16(0x0000);

	if (window_flag == RESPONSE_WINDOW) {
		qdf_mem_copy(wh_addr2->i_addr2,
			     TXMON_STATUS_INFO(tx_status_info, addr2),
			     QDF_MAC_ADDR_SIZE);
		if (num_users > 1)
			qdf_mem_set(wh_addr2->i_addr1, QDF_MAC_ADDR_SIZE, 0xFF);
		else
			qdf_mem_copy(wh_addr2->i_addr1,
				     TXMON_STATUS_INFO(tx_status_info, addr1),
				     QDF_MAC_ADDR_SIZE);
	} else {
		qdf_mem_copy(wh_addr2->i_addr2,
			     TXMON_STATUS_INFO(tx_status_info, addr1),
			     QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(wh_addr2->i_addr1,
			     TXMON_STATUS_INFO(tx_status_info, addr2),
			     QDF_MAC_ADDR_SIZE);
	}

	frm = (uint8_t *)&wh_addr2[1];

	/* BA control */
	ba_control = 0x0016;
	*((uint16_t *)frm) = qdf_cpu_to_le16(ba_control);
}

/**
 * dp_tx_mon_generate_mu_block_ack_frm() - API to generate MU block ack frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @window_flag: frame generated window
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_mu_block_ack_frm(struct dp_pdev *pdev,
				    struct dp_tx_ppdu_info *tx_ppdu_info,
				    uint8_t window_flag,
				    uint8_t mac_id)
{
	/* allocate and populate MU block ack frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint32_t ba_sz = 0;
	uint8_t num_users = TXMON_PPDU_HAL(tx_ppdu_info, num_users);
	uint8_t i = 0;
	uint8_t user_id = 0;
	uint8_t *per_usr_start = NULL;
	uint8_t *frm = NULL;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	/* Only the last user should proceed with the rest of this function */
	user_id = TXMON_PPDU_HAL(tx_ppdu_info, cur_usr_idx);
	if (user_id != num_users - 1)
		return;

	for (i = 0; i < num_users; i++)
		ba_sz += TXMON_MU_BA_INFO_SZ(TXMON_PPDU_USR(tx_ppdu_info, i,
							    ba_bitmap_sz));

	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   TXMON_MU_BA_ACK_FRAME_SZ(ba_sz),
				   0, 4, FALSE);
	if (!mpdu_nbuf) {
		/* TODO: update status and break */
		return;
	}
	dp_set_common_ba_section(tx_ppdu_info, mon_pdev_be, mpdu_nbuf,
				 window_flag, mac_id);

	per_usr_start = dp_skip_ba_tail_to_per_user_info(tx_ppdu_info,
							 mpdu_nbuf, 0);
	frm = per_usr_start;
	frm += ba_sz;
	qdf_nbuf_set_pktlen(mpdu_nbuf, (frm -
					(uint8_t *)qdf_nbuf_data(mpdu_nbuf)));

	for (i = 0; i < num_users; i++)
		per_usr_start = dp_init_mu_ba_per_tid_info(tx_ppdu_info,
							   per_usr_start, i);

	/* always enqueue to first active user */
	dp_tx_mon_enqueue_mpdu_nbuf(pdev, tx_ppdu_info, 0, mpdu_nbuf);
	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 1;
	/* HE MU fields not required for Multi Sta Block ack frame */
	TXMON_PPDU_COM(tx_ppdu_info, he_mu_flags) = 0;
}

/**
 * dp_tx_mon_generate_block_ack_frm() - API to generate block ack frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @window_flag: frame generated window
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_block_ack_frm(struct dp_pdev *pdev,
				 struct dp_tx_ppdu_info *tx_ppdu_info,
				 uint8_t window_flag,
				 uint8_t mac_id)
{
	/* allocate and populate block ack frame */
	/* enqueue 802.11 payload to per user mpdu_q */
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	struct ieee80211_ctlframe_addr2 *wh_addr2 = NULL;
	qdf_nbuf_t mpdu_nbuf = NULL;
	uint8_t *frm = NULL;
	uint8_t user_id = TXMON_PPDU_HAL(tx_ppdu_info, cur_usr_idx);
	uint32_t ba_bitmap_sz = TXMON_PPDU_USR(tx_ppdu_info,
					       user_id, ba_bitmap_sz);
	uint8_t frm_ctl;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	tx_status_info = &tx_mon_be->data_status_info;
	/*
	 * for multi sta block ack, do we need to increase the size
	 * or copy info on subsequent frame offset
	 *
	 * for radiotap we allocate new skb,
	 * so we don't need reserver skb header
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   TXMON_BA_ACK_FRAME_SZ(ba_bitmap_sz),
				   0, 4, FALSE);
	if (!mpdu_nbuf) {
		/* TODO: update status and break */
		return;
	}

	/*
	 * BA CONTROL
	 * fields required to construct block ack information
	 * B0 - BA ACK POLICY
	 *	0 - Normal ACK
	 *	1 - No ACK
	 * B1 - MULTI TID
	 * B2 - COMPRESSED BITMAP
	 *	B12
	 *	00 - Basic block ack
	 *	01 - Compressed block ack
	 *	10 - Reserved
	 *	11 - Multi tid block ack
	 * B3-B11 - Reserved
	 * B12-B15 - TID info
	 *
	 * BA INFORMATION
	 * Per sta tid info
	 *	AID: 11 bits
	 *	ACK type: 1 bit
	 *	TID: 4 bits
	 *
	 * BA SEQ CTRL
	 *
	 * BA bitmap
	 *
	 */

	wh_addr2 = (struct ieee80211_ctlframe_addr2 *)qdf_nbuf_data(mpdu_nbuf);
	qdf_mem_zero(wh_addr2, DP_BA_ACK_FRAME_SIZE);

	frm_ctl = (QDF_IEEE80211_FC0_VERSION_0 | QDF_IEEE80211_FC0_TYPE_CTL |
		   QDF_IEEE80211_FC0_SUBTYPE_BA);
	TXMON_PPDU_COM(tx_ppdu_info, frame_control) = frm_ctl;
	TXMON_PPDU_COM(tx_ppdu_info, frame_control_info_valid) = 1;
	wh_addr2->i_fc[1] = 0;
	wh_addr2->i_fc[0] = frm_ctl;

	/* duration */
	*(u_int16_t *)(&wh_addr2->i_aidordur) = qdf_cpu_to_le16(0x0020);

	if (window_flag) {
		qdf_mem_copy(wh_addr2->i_addr2,
			     TXMON_STATUS_INFO(tx_status_info, addr2),
			     QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(wh_addr2->i_addr1,
			     TXMON_STATUS_INFO(tx_status_info, addr1),
			     QDF_MAC_ADDR_SIZE);
	} else {
		qdf_mem_copy(wh_addr2->i_addr2,
			     TXMON_STATUS_INFO(tx_status_info, addr1),
			     QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(wh_addr2->i_addr1,
			     TXMON_STATUS_INFO(tx_status_info, addr2),
			     QDF_MAC_ADDR_SIZE);
	}

	frm = (uint8_t *)&wh_addr2[1];
	/* BA control */
	*((uint16_t *)frm) = qdf_cpu_to_le16(TXMON_PPDU_USR(tx_ppdu_info,
							    user_id,
							    ba_control));
	frm += 2;
	*((uint16_t *)frm) = qdf_cpu_to_le16(TXMON_PPDU_USR(tx_ppdu_info,
							    user_id,
							    start_seq));
	frm += 2;
	qdf_mem_copy(frm,
		     TXMON_PPDU_USR(tx_ppdu_info, user_id, ba_bitmap),
		     4 << TXMON_PPDU_USR(tx_ppdu_info, user_id, ba_bitmap_sz));
	frm += (4 << TXMON_PPDU_USR(tx_ppdu_info, user_id, ba_bitmap_sz));

	qdf_nbuf_set_pktlen(mpdu_nbuf,
			    (frm - (uint8_t *)qdf_nbuf_data(mpdu_nbuf)));

	dp_tx_mon_enqueue_mpdu_nbuf(pdev, tx_ppdu_info, 0, mpdu_nbuf);

	TXMON_PPDU_HAL(tx_ppdu_info, is_used) = 1;
}

/**
 * dp_tx_mon_alloc_mpdu() - API to allocate mpdu and add that current
 * user index
 *
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 *
 * Return: void
 */
static void
dp_tx_mon_alloc_mpdu(struct dp_pdev *pdev, struct dp_tx_ppdu_info *tx_ppdu_info)
{
	qdf_nbuf_t mpdu_nbuf = NULL;
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;
	uint32_t usr_idx = 0;

	/*
	 * payload will be added as a frag to buffer
	 * and we allocate new skb for radiotap header
	 * we allocate a dummy buffer size
	 */
	mpdu_nbuf = qdf_nbuf_alloc(pdev->soc->osdev,
				   MAX_MONITOR_HEADER, MAX_MONITOR_HEADER,
				   4, FALSE);
	if (!mpdu_nbuf) {
		qdf_err("%s: %d No memory to allocate mpdu_nbuf!!!!!\n",
			__func__, __LINE__);
		return;
	}

	usr_idx = TXMON_PPDU_HAL(tx_ppdu_info, cur_usr_idx);
	usr_mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, usr_idx, mpdu_q);

	qdf_nbuf_queue_add(usr_mpdu_q, mpdu_nbuf);
}

/**
 * dp_tx_mon_generate_data_frm() - API to generate data frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @take_ref:
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_data_frm(struct dp_pdev *pdev,
			    struct dp_tx_ppdu_info *tx_ppdu_info,
			    bool take_ref,
			    uint8_t mac_id)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	qdf_nbuf_t mpdu_nbuf = NULL;
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;
	uint32_t usr_idx = 0;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);

	tx_status_info = &tx_mon_be->data_status_info;
	usr_idx = TXMON_PPDU_HAL(tx_ppdu_info, cur_usr_idx);
	usr_mpdu_q = &TXMON_PPDU_USR(tx_ppdu_info, usr_idx, mpdu_q);
	mpdu_nbuf = qdf_nbuf_queue_last(usr_mpdu_q);

	if (!mpdu_nbuf)
		QDF_BUG(0);

	tx_mon_be->stats.pkt_buf_processed++;

	/* add function to either copy or add frag to frag_list */
	qdf_nbuf_add_frag(pdev->soc->osdev,
			  TXMON_STATUS_INFO(tx_status_info, buffer),
			  mpdu_nbuf,
			  TXMON_STATUS_INFO(tx_status_info, offset),
			  TXMON_STATUS_INFO(tx_status_info, length),
			  DP_MON_DATA_BUFFER_SIZE,
			  take_ref, TXMON_NO_BUFFER_SZ);
}

/**
 * dp_tx_mon_generate_prot_frm() - API to generate protection frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @mac_id: LMAC ID
 *
 * Return: void
 */
static void
dp_tx_mon_generate_prot_frm(struct dp_pdev *pdev,
			    struct dp_tx_ppdu_info *tx_ppdu_info,
			    uint8_t mac_id)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	tx_status_info = &tx_mon_be->prot_status_info;

	/* update medium prot type from data */
	TXMON_STATUS_INFO(tx_status_info, medium_prot_type) =
		tx_mon_be->data_status_info.medium_prot_type;

	switch (TXMON_STATUS_INFO(tx_status_info, medium_prot_type)) {
	case TXMON_MEDIUM_NO_PROTECTION:
	{
		/* no protection frame - do nothing */
		break;
	}
	case TXMON_MEDIUM_RTS_LEGACY:
	case TXMON_MEDIUM_RTS_11AC_STATIC_BW:
	case TXMON_MEDIUM_RTS_11AC_DYNAMIC_BW:
	{
		dp_tx_mon_generate_rts_frm(pdev, tx_ppdu_info,
					   INITIATOR_WINDOW, mac_id);
		break;
	}
	case TXMON_MEDIUM_CTS2SELF:
	{
		dp_tx_mon_generate_cts2self_frm(pdev, tx_ppdu_info,
						INITIATOR_WINDOW, mac_id);
		break;
	}
	case TXMON_MEDIUM_QOS_NULL_NO_ACK_3ADDR:
	{
		dp_tx_mon_generate_3addr_qos_null_frm(pdev, tx_ppdu_info,
						      mac_id);
		break;
	}
	case TXMON_MEDIUM_QOS_NULL_NO_ACK_4ADDR:
	{
		dp_tx_mon_generate_4addr_qos_null_frm(pdev, tx_ppdu_info,
						      mac_id);
		break;
	}
	}
}

/**
 * dp_tx_mon_generated_response_frm() - API to handle generated response frame
 * @pdev: pdev Handle
 * @tx_ppdu_info: pointer to tx ppdu info structure
 * @mac_id: LMAC ID
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
dp_tx_mon_generated_response_frm(struct dp_pdev *pdev,
				 struct dp_tx_ppdu_info *tx_ppdu_info,
				 uint8_t mac_id)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint8_t gen_response = 0;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return QDF_STATUS_E_NOMEM;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);

	tx_status_info = &tx_mon_be->data_status_info;
	gen_response = TXMON_STATUS_INFO(tx_status_info, generated_response);

	switch (gen_response) {
	case TXMON_GEN_RESP_SELFGEN_ACK:
	{
		dp_tx_mon_generate_ack_frm(pdev, tx_ppdu_info, mac_id);
		break;
	}
	case TXMON_GEN_RESP_SELFGEN_CTS:
	{
		dp_tx_mon_generate_cts2self_frm(pdev, tx_ppdu_info,
						RESPONSE_WINDOW, mac_id);
		break;
	}
	case TXMON_GEN_RESP_SELFGEN_BA:
	{
		dp_tx_mon_generate_block_ack_frm(pdev, tx_ppdu_info,
						 RESPONSE_WINDOW, mac_id);
		break;
	}
	case TXMON_GEN_RESP_SELFGEN_MBA:
	{
		dp_tx_mon_generate_mu_block_ack_frm(pdev, tx_ppdu_info,
						    RESPONSE_WINDOW, mac_id);
		break;
	}
	case TXMON_GEN_RESP_SELFGEN_CBF:
	{
		break;
	}
	case TXMON_GEN_RESP_SELFGEN_TRIG:
	{
		break;
	}
	case TXMON_GEN_RESP_SELFGEN_NDP_LMR:
	{
		break;
	}
	};

	return status;
}

static inline
void dp_tx_mon_free_last_mpdu_q(struct dp_pdev_tx_monitor_be *tx_mon_be,
				struct dp_tx_ppdu_info *tx_data_ppdu_info,
				uint32_t usr_idx)
{
	qdf_nbuf_t mpdu_nbuf = NULL;
	qdf_nbuf_queue_t *usr_mpdu_q = NULL;
	uint32_t num_frag = 0;

	usr_mpdu_q = &TXMON_PPDU_USR(tx_data_ppdu_info, usr_idx, mpdu_q);
	mpdu_nbuf = qdf_nbuf_queue_remove_last(usr_mpdu_q);

	num_frag = qdf_nbuf_get_nr_frags_in_fraglist(mpdu_nbuf);
	tx_mon_be->stats.pkt_buf_drop += num_frag;

	qdf_nbuf_free(mpdu_nbuf);
}

/**
 * dp_tx_mon_update_ppdu_info_status() - API to update frame as information
 * is stored only for that processing
 *
 * @pdev: pdev Handle
 * @tx_data_ppdu_info: pointer to data tx ppdu info
 * @tx_prot_ppdu_info: pointer to protection tx ppdu info
 * @tx_tlv_hdr: pointer to tx_tlv_hdr
 * @status_frag: pointer to fragment
 * @tlv_status: tlv status return from hal api
 * @mon_desc_list_ref: tx monitor descriptor list reference
 * @mac_id: LMAC_ID
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS
dp_tx_mon_update_ppdu_info_status(struct dp_pdev *pdev,
				  struct dp_tx_ppdu_info *tx_data_ppdu_info,
				  struct dp_tx_ppdu_info *tx_prot_ppdu_info,
				  void *tx_tlv_hdr,
				  qdf_frag_t status_frag,
				  uint32_t tlv_status,
				  struct dp_tx_mon_desc_list *mon_desc_list_ref,
				  uint8_t mac_id)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct hal_tx_status_info *tx_status_info;
	struct dp_mon_mac *mon_mac;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint32_t usr_idx = TXMON_PPDU_HAL(tx_data_ppdu_info, cur_usr_idx);

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return QDF_STATUS_E_NOMEM;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	mon_mac = dp_get_mon_mac(pdev, mac_id);

	switch (tlv_status) {
	case HAL_MON_TX_FES_SETUP:
	{
		/*
		 * start of initiator window
		 *
		 * got number of user count from  fes setup tlv
		 */
		break;
	}
	case HAL_MON_RX_RESPONSE_REQUIRED_INFO:
	{
		break;
	}
	case HAL_MON_TX_FES_STATUS_START_PROT:
	{
		/* update tsft to local */
		break;
	}
	case HAL_MON_TX_FES_STATUS_START_PPDU:
	{
		/* update tsft to local */
		break;
	}
	case HAL_MON_TX_FES_STATUS_PROT:
	{
		TXMON_PPDU_COM(tx_prot_ppdu_info, ppdu_timestamp) =
			TXMON_PPDU_COM(tx_prot_ppdu_info, ppdu_timestamp) << 1;

		/* based on medium protection type we need to generate frame */
		dp_tx_mon_generate_prot_frm(pdev, tx_prot_ppdu_info, mac_id);
		break;
	}
	case HAL_MON_RX_FRAME_BITMAP_ACK:
	{
		break;
	}
	case HAL_MON_RX_FRAME_BITMAP_BLOCK_ACK_256:
	case HAL_MON_RX_FRAME_BITMAP_BLOCK_ACK_1K:
	{
		/*
		 * this comes for each user
		 * BlockAck is not same as ACK, single frame can hold
		 * multiple BlockAck info
		 */
		tx_status_info = &tx_mon_be->data_status_info;

		if (TXMON_PPDU_HAL(tx_data_ppdu_info, num_users) == 1)
			dp_tx_mon_generate_block_ack_frm(pdev,
							 tx_data_ppdu_info,
							 INITIATOR_WINDOW,
							 mac_id);
		else
			dp_tx_mon_generate_mu_block_ack_frm(pdev,
							    tx_data_ppdu_info,
							    INITIATOR_WINDOW,
							    mac_id);

		break;
	}
	case HAL_MON_TX_MPDU_START:
	{
		if (qdf_unlikely(TXMON_PPDU_USR(tx_data_ppdu_info, usr_idx,
						is_mpdu_incomplete)))
			dp_tx_mon_free_last_mpdu_q(tx_mon_be,
						   tx_data_ppdu_info, usr_idx);

		dp_tx_mon_alloc_mpdu(pdev, tx_data_ppdu_info);
		TXMON_PPDU_USR(tx_data_ppdu_info, usr_idx,
			       is_mpdu_incomplete) = 1;
		break;
	}
	case HAL_MON_TX_MPDU_END:
	{
		TXMON_PPDU_USR(tx_data_ppdu_info, usr_idx,
			       is_mpdu_incomplete) = 0;
		break;
	}
	case HAL_MON_TX_MSDU_START:
	{
		break;
	}
	case HAL_MON_TX_DATA:
	{
		TXMON_PPDU_HAL(tx_data_ppdu_info, is_used) = 1;
		dp_tx_mon_generate_data_frm(pdev, tx_data_ppdu_info,
					    true, mac_id);
		break;
	}
	case HAL_MON_TX_BUFFER_ADDR:
	{
		struct hal_mon_packet_info *packet_info = NULL;
		struct dp_mon_desc *mon_desc = NULL;
		qdf_frag_t packet_buffer = NULL;
		uint32_t end_offset = 0;
		uint32_t cookie_2;

		tx_status_info = &tx_mon_be->data_status_info;
		/* update buffer from packet info */
		packet_info = &TXMON_PPDU_HAL(tx_data_ppdu_info, packet_info);
		mon_desc = (struct dp_mon_desc *)(uintptr_t)packet_info->sw_cookie;
		mon_desc = dp_mon_get_desc_addr(packet_info->sw_cookie);
		cookie_2 = DP_MON_GET_COOKIE(packet_info->sw_cookie);

		qdf_assert_always(mon_desc);

		if (mon_desc->magic != DP_MON_DESC_MAGIC)
			qdf_assert_always(0);

		qdf_assert_always(mon_desc->buf_addr);
		tx_mon_be->stats.pkt_buf_recv++;

		if (mon_desc->cookie_2 != cookie_2) {
			mon_mac->rx_mon_stats.dup_mon_sw_desc++;
			qdf_assert_always(0);
		}
		if (!mon_desc->unmapped) {
			qdf_mem_unmap_page(pdev->soc->osdev,
					   (qdf_dma_addr_t)mon_desc->paddr,
					   DP_MON_DATA_BUFFER_SIZE,
					   QDF_DMA_FROM_DEVICE);
			mon_desc->unmapped = 1;
		}

		packet_buffer = mon_desc->buf_addr;
		mon_desc->buf_addr = NULL;

		/* increment reap count */
		mon_desc_list_ref->tx_mon_reap_cnt++;

		/* add the mon_desc to free list */
		dp_mon_add_to_free_desc_list(&mon_desc_list_ref->desc_list,
					     &mon_desc_list_ref->tail,
					     mon_desc);

		TXMON_STATUS_INFO(tx_status_info, buffer) = packet_buffer;
		TXMON_STATUS_INFO(tx_status_info, offset) = end_offset;
		TXMON_STATUS_INFO(tx_status_info,
				  length) = packet_info->dma_length;

		TXMON_PPDU_HAL(tx_data_ppdu_info, is_used) = 1;
		dp_tx_mon_generate_data_frm(pdev, tx_data_ppdu_info,
					    false, mac_id);
		break;
	}
	case HAL_MON_TX_FES_STATUS_END:
	{
		uint32_t num_users = TXMON_PPDU_HAL(tx_data_ppdu_info,
						    num_users);
		uint32_t i = 0;

		for (i = 0; i < num_users; i++) {
			if (qdf_unlikely(TXMON_PPDU_USR(tx_data_ppdu_info, i,
							is_mpdu_incomplete))) {
				dp_tx_mon_free_last_mpdu_q(tx_mon_be,
							   tx_data_ppdu_info,
							   i);
				TXMON_PPDU_USR(tx_data_ppdu_info, i,
					       is_mpdu_incomplete) = 0;
			}
		}
		break;
	}
	case HAL_MON_RESPONSE_END_STATUS_INFO:
	{
		dp_tx_mon_generated_response_frm(pdev, tx_data_ppdu_info,
						 mac_id);
		break;
	}
	case HAL_MON_TX_FES_STATUS_START:
	{
		/* update the medium protection type */
		break;
	}
	case HAL_MON_TX_QUEUE_EXTENSION:
	{
		/* No action for Queue Extension TLV */
		break;
	}
	case HAL_MON_TX_FW2SW:
	{
		/* update the frequency */
		tx_status_info = &tx_mon_be->data_status_info;

		TXMON_PPDU_COM(tx_data_ppdu_info,
			       chan_freq) = TXMON_STATUS_INFO(tx_status_info,
							      freq);
		TXMON_PPDU_COM(tx_prot_ppdu_info,
			       chan_freq) = TXMON_STATUS_INFO(tx_status_info,
							      freq);
		break;
	}
	case HAL_MON_TX_FES_STATUS_ACK_BA:
	{
		/* No action for FES Status ACK BA */
		break;
	}
	default:
	{
		/* return or break in default case */
		break;
	}
	};

	return status;
}

#ifdef WLAN_SUPPORT_TX_PKT_CAP_CUSTOM_CLASSIFY
/**
 * dp_pdev_update_tx_pkt_cap_stats() - API to aggregate Tx pkt cap
 * stats from ppdu counter to pdev level counter
 *
 * @mon_pdev_be: monitor pdev Handle
 *
 * Return: void
 */
static inline
void dp_pdev_update_tx_pkt_cap_stats(struct dp_mon_pdev_be *mon_pdev_be)
{
	uint8_t i;

	for (i = 0; i < CDP_TX_PKT_TYPE_MAX; i++) {
		mon_pdev_be->tx_monitor_be.dp_tx_pkt_cap_stats[i] +=
		mon_pdev_be->tx_monitor_be.data_status_info.dp_tx_pkt_cap_cookie[i];
	}
}
#else
static inline
void dp_pdev_update_tx_pkt_cap_stats(struct dp_mon_pdev_be *mon_pdev_be)
{
}
#endif /* WLAN_SUPPORT_TX_PKT_CAP_CUSTOM_CLASSIFY */

#ifdef MONITOR_TLV_RECORDING_ENABLE
/**
 * dp_tx_mon_record_index_update() - update the indexes of dp_mon_tlv_logger
 *					to store next Tx TLV
 *
 * @mon_pdev_be: pointer to dp_mon_pdev_be
 *
 * Return: void
 */
void dp_tx_mon_record_index_update(struct dp_mon_pdev_be *mon_pdev_be)
{
	struct dp_mon_tlv_logger *tlv_log = NULL;
	struct dp_tx_mon_tlv_info *tlv_info = NULL;

	tlv_log = mon_pdev_be->tx_tlv_log;
	tlv_info = (struct dp_tx_mon_tlv_info *)tlv_log->buff;

	(tlv_log->curr_ppdu_pos + 1 == MAX_NUM_PPDU_RECORD) ?
		tlv_log->curr_ppdu_pos = 0 :
			tlv_log->curr_ppdu_pos++;

	tlv_log->wrap_flag = 0;
	tlv_log->ppdu_start_idx = tlv_log->curr_ppdu_pos *
		MAX_TLVS_PER_PPDU;
	tlv_log->mpdu_idx = tlv_log->ppdu_start_idx +
		MAX_PPDU_START_TLV_NUM;
	tlv_log->ppdu_end_idx = tlv_log->mpdu_idx + MAX_MPDU_TLV_NUM;
	tlv_log->max_ppdu_start_idx = tlv_log->ppdu_start_idx +
		MAX_PPDU_START_TLV_NUM - 1;
	tlv_log->max_mpdu_idx = tlv_log->mpdu_idx +
		MAX_MPDU_TLV_NUM - 1;
	tlv_log->max_ppdu_end_idx = tlv_log->ppdu_end_idx +
		MAX_PPDU_END_TLV_NUM - 1;
}

/**
 * dp_tx_mon_record_tlv() - Store the contents of the tlv in buffer
 *
 * @mon_pdev_be: pointer to dp_mon_pdev_be
 * @data_ppdu_info: pointer to HAL Tx data ppdu info
 * @proto_ppdu_info: pointer to HAL Tx proto ppdu info
 *
 * Return: void
 */
void dp_tx_mon_record_tlv(struct dp_mon_pdev_be *mon_pdev_be,
			  struct hal_tx_ppdu_info *data_ppdu_info,
			  struct hal_tx_ppdu_info *proto_ppdu_info)
{
	struct hal_tx_ppdu_info *ppdu_info = NULL;
	struct dp_tx_mon_tlv_info *tlv_info = NULL;
	struct dp_mon_tlv_logger *tlv_log = NULL;
	uint16_t *ppdu_start_idx = NULL;
	uint16_t *mpdu_idx = NULL;
	uint16_t *ppdu_end_idx = NULL;
	uint32_t tlv_tag;

	if (!mon_pdev_be || !(mon_pdev_be->tx_tlv_log))
		return;

	tlv_log = mon_pdev_be->tx_tlv_log;
	if (!tlv_log->tlv_logging_enable || !(tlv_log->buff))
		return;

	tlv_info = (struct dp_tx_mon_tlv_info *)tlv_log->buff;
	ppdu_start_idx = &tlv_log->ppdu_start_idx;
	mpdu_idx = &tlv_log->mpdu_idx;
	ppdu_end_idx = &tlv_log->ppdu_end_idx;

	ppdu_info = (data_ppdu_info->tx_tlv_info.is_data_ppdu_info) ?
			data_ppdu_info : proto_ppdu_info;
	tlv_tag = ppdu_info->tx_tlv_info.tlv_tag;

	if (ppdu_info->tx_tlv_info.tlv_category == CATEGORY_PPDU_START) {
		tlv_info[*ppdu_start_idx].tlv_tag = tlv_tag;
		switch (tlv_tag) {
		case WIFITX_FES_SETUP_E:
		case WIFITXPCU_BUFFER_STATUS_E:
		case WIFIPCU_PPDU_SETUP_INIT_E:
		case WIFISCH_CRITICAL_TLV_REFERENCE_E:
		case WIFITX_PEER_ENTRY_E:
		case WIFITX_RAW_OR_NATIVE_FRAME_SETUP_E:
		case WIFITX_QUEUE_EXTENSION_E:
		case WIFITX_FES_SETUP_COMPLETE_E:
		case WIFIFW2SW_MON_E:
		case WIFISCHEDULER_END_E:
		case WIFITQM_MPDU_GLOBAL_START_E:
			;
		}
		if (*ppdu_start_idx < tlv_log->max_ppdu_start_idx)
			(*ppdu_start_idx)++;
	} else if (ppdu_info->tx_tlv_info.tlv_category == CATEGORY_MPDU) {
		tlv_info[*mpdu_idx].tlv_tag = tlv_tag;
		switch (tlv_tag) {
		case WIFITX_MPDU_START_E:
		case WIFITX_MSDU_START_E:
		case WIFITX_DATA_E:
		case WIFITX_MSDU_END_E:
		case WIFITX_MPDU_END_E:
			;
		}
		if (*mpdu_idx < tlv_log->max_mpdu_idx) {
			(*mpdu_idx)++;
		} else {
			*mpdu_idx = *mpdu_idx - MAX_MPDU_TLV_NUM + 1;
			tlv_log->wrap_flag ^= 1;
		}
	} else if (ppdu_info->tx_tlv_info.tlv_category == CATEGORY_PPDU_END) {
		tlv_info[*ppdu_end_idx].tlv_tag = tlv_tag;
		switch (tlv_tag) {
		case WIFITX_LAST_MPDU_FETCHED_E:
		case WIFITX_LAST_MPDU_END_E:
		case WIFIPDG_TX_REQ_E:
		case WIFITX_FES_STATUS_START_PPDU_E:
		case WIFIPHYTX_PPDU_HEADER_INFO_REQUEST_E:
		case WIFIMACTX_L_SIG_A_E:
		case WIFITXPCU_PREAMBLE_DONE_E:
		case WIFIMACTX_USER_DESC_COMMON_E:
		case WIFIMACTX_SERVICE_E:
		case WIFITXDMA_STOP_REQUEST_E:
		case WIFITXPCU_USER_BUFFER_STATUS_E:
		case WIFITX_FES_STATUS_USER_PPDU_E:
		case WIFITX_MPDU_COUNT_TRANSFER_END_E:
		case WIFIRX_START_PARAM_E:
		case WIFITX_FES_STATUS_ACK_OR_BA_E:
		case WIFITX_FES_STATUS_USER_RESPONSE_E:
		case WIFITX_FES_STATUS_END_E:
		case WIFITX_FES_STATUS_PROT_E:
		case WIFIMACTX_PHY_DESC_E:
		case WIFIMACTX_HE_SIG_A_SU_E:
			;
		}
		if (*ppdu_end_idx < tlv_log->max_ppdu_end_idx)
			(*ppdu_end_idx)++;
	}
}

/**
 * dp_tx_mon_record_clear_buffer() - Clear the buffer to record next PPDU
 *
 * @mon_pdev_be : pointer to dp_mon_pdev_be
 *
 * Return
 */
void dp_tx_mon_record_clear_buffer(struct dp_mon_pdev_be *mon_pdev_be)
{
	struct dp_mon_tlv_logger *tlv_log = NULL;
	struct dp_tx_mon_tlv_info *tlv_info = NULL;

	tlv_log = mon_pdev_be->tx_tlv_log;
	tlv_info = (struct dp_tx_mon_tlv_info *)tlv_log->buff;
	qdf_mem_zero(&tlv_info[tlv_log->ppdu_start_idx],
		     MAX_TLVS_PER_PPDU *
		     sizeof(struct dp_tx_mon_tlv_info));
}
#else

static
void dp_tx_mon_record_index_update(struct dp_mon_pdev_be *mon_pdev_be)
{
}

static
void dp_tx_mon_record_tlv(struct dp_mon_pdev_be *mon_pdev_be,
			  struct hal_tx_ppdu_info *data_ppdu_info,
			  struct hal_tx_ppdu_info *proto_ppdu_info)
{
}

static
void dp_tx_mon_record_clear_buffer(struct dp_mon_pdev_be *mon_pdev_be)
{
}
#endif

#define SW_FILTER_CHECK_PASSED		(1U)
#define SW_FILTER_CHECK_AGAIN		(2U)
#define SW_FILTER_CHECK_FAILED		(3U)

#ifdef QCA_SUPPORT_LITE_MONITOR

/**
 * dp_tx_mon_get_sw_filter_en() - flag to indicate sw filter enable
 *
 * @mon_pdev_be: pointer to dp_mon_pdev_be
 * @initiator: flag to indicate initiator window
 * @num_users: number of users
 *
 * Return: bool
 */
static inline bool
dp_tx_mon_get_sw_filter_en(struct dp_mon_pdev_be *mon_pdev_be,
			   bool initiator, uint8_t num_users)
{
	struct dp_lite_mon_tx_config *config;

	config = mon_pdev_be->lite_mon_tx_config;
	return (initiator && config->disable_hw_filter &&
		(1 == num_users)) ? true : false;
}

/**
 * dp_tx_mon_sw_filter() - Filter packet based on config set by user
 *
 * @mon_pdev_be: pointer to dp_mon_pdev_be
 * @tlv_status: tlv status received after parsing in hal.
 * @tx_data_ppdu_info: pointer to Tx data ppdu info
 * @tx_status_data: pointer to Tx status data
 *
 * Return: uint32_t
 */
static inline uint32_t
dp_tx_mon_sw_filter(struct dp_mon_pdev_be *mon_pdev_be,
		    uint32_t tlv_status,
		    struct dp_tx_ppdu_info *tx_data_ppdu_info,
		    struct hal_tx_status_info *tx_status_data)
{
	struct dp_lite_mon_tx_config *config = mon_pdev_be->lite_mon_tx_config;
	uint16_t mgmt, ctrl, data;
	uint16_t frame_ctrl;
	uint16_t type;

	/*
	 * function will be called with two option:
	 * 1. HAL_MON_TX_PEER_ENTRY
	 * 2. HAL_MON_TX_QUEUE_EXTENSION
	 */
	if (HAL_MON_TX_PEER_ENTRY == tlv_status) {
		struct dp_lite_mon_peer *peer;

		/*
		 * In tx peer entry, address 1 is addr_a and address 2 is addr b
		 */
		if (!config->tx_config.peer_count)
			return SW_FILTER_CHECK_AGAIN;

		qdf_spin_lock_bh(&config->lite_mon_tx_lock);
		TAILQ_FOREACH(peer, &config->tx_config.peer_list,
			      peer_list_elem) {
			if (!qdf_mem_cmp(&peer->peer_mac.raw[0],
					 tx_status_data->addr2,
					 QDF_MAC_ADDR_SIZE)) {
				qdf_spin_unlock_bh(&config->lite_mon_tx_lock);
				/* set is sw_filter done flag set */
				TXMON_PPDU_USR(tx_data_ppdu_info, 0,
					       is_sw_filter_done) = 1;
				return SW_FILTER_CHECK_PASSED;
			}
		}
		qdf_spin_unlock_bh(&config->lite_mon_tx_lock);

		return SW_FILTER_CHECK_AGAIN;
	}

	mgmt = config->tx_config.mgmt_filter[DP_MON_FRM_FILTER_MODE_FP];
	ctrl = config->tx_config.ctrl_filter[DP_MON_FRM_FILTER_MODE_FP];
	data = config->tx_config.data_filter[DP_MON_FRM_FILTER_MODE_FP];

	frame_ctrl = TXMON_PPDU_COM(tx_data_ppdu_info, frame_control);

	type = frame_ctrl & IEEE80211_FC0_TYPE_MASK;

	if ((mgmt && QDF_IEEE80211_FC0_TYPE_MGT == type) ||
	    (ctrl && QDF_IEEE80211_FC0_TYPE_CTL == type) ||
	    (data && QDF_IEEE80211_FC0_TYPE_DATA == type)) {
		TXMON_PPDU_USR(tx_data_ppdu_info, 0, is_sw_filter_done) = 1;
		return SW_FILTER_CHECK_PASSED;
	}

	return SW_FILTER_CHECK_FAILED;
}
#else
/**
 * dp_tx_mon_get_sw_filter_en() - flag to indicate sw filter enable
 *
 * @mon_pdev_be: pointer to dp_mon_pdev_be
 * @initiator: flag to indicate initiator window
 * @num_users: number of users
 *
 * Return: bool
 */
static inline bool
dp_tx_mon_get_sw_filter_en(struct dp_mon_pdev_be *mon_pdev_be,
			   bool initiator, uint8_t num_users)
{
	return false;
}

/**
 * dp_tx_mon_sw_filter() - Filter packet based on config set by user
 *
 * @mon_pdev_be: pointer to dp_mon_pdev_be
 * @tlv_status: tlv status received after parsing in hal.
 * @tx_data_ppdu_info: pointer to Tx data ppdu info
 * @tx_status_data: pointer to Tx status data
 *
 * Return: uint32_t
 */
static inline uint32_t
dp_tx_mon_sw_filter(struct dp_mon_pdev_be *mon_pdev_be,
		    uint32_t tlv_status,
		    struct dp_tx_ppdu_info *tx_data_ppdu_info,
		    struct hal_tx_status_info *tx_status_data)
{
	return SW_FILTER_CHECK_PASSED;
}
#endif

/**
 * dp_tx_mon_reset_ppdu_info() - reset ppdu_info
 *
 * @tx_data_ppdu_info: pointer to Tx data ppdu info
 * @tx_prot_ppdu_info: pointer to Tx prot ppdu info
 *
 * Return: void
 */
static inline
void dp_tx_mon_reset_ppdu_info(struct dp_tx_ppdu_info *tx_data_ppdu_info,
			       struct dp_tx_ppdu_info *tx_prot_ppdu_info)
{
	/*
	 * set is_used and num_users as 0
	 * during structure free, buffer will be freed
	 */
	TXMON_PPDU_HAL(tx_data_ppdu_info, is_used) = 0;
	TXMON_PPDU_HAL(tx_data_ppdu_info, num_users) = 0;

	TXMON_PPDU_HAL(tx_prot_ppdu_info, is_used) = 0;
	TXMON_PPDU_HAL(tx_prot_ppdu_info, num_users) = 0;
}

/**
 * dp_tx_mon_process_tlv_2_0() - API to parse PPDU worth information
 * @pdev: DP_PDEV handle
 * @initiator: flag to identify initiator
 * @mon_desc_list_ref: tx monitor descriptor list reference
 * @mac_id: LMAC ID
 *
 * Return: status
 */
static QDF_STATUS
dp_tx_mon_process_tlv_2_0(struct dp_pdev *pdev,
			  bool initiator,
			  struct dp_tx_mon_desc_list *mon_desc_list_ref,
			  uint8_t mac_id)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;
	struct dp_tx_ppdu_info *tx_prot_ppdu_info = NULL;
	struct dp_tx_ppdu_info *tx_data_ppdu_info = NULL;
	struct hal_tx_status_info *tx_status_prot;
	struct hal_tx_status_info *tx_status_data;
	qdf_frag_t status_frag = NULL;
	uint32_t end_offset = 0;
	uint32_t tlv_status;
	uint32_t status = QDF_STATUS_SUCCESS;
	uint8_t *tx_tlv;
	uint8_t *tx_tlv_start;
	uint8_t num_users = 0;
	uint8_t cur_frag_q_idx;
	bool schedule_wrq = false;
	struct dp_mon_mac *mon_mac;
	bool sw_filter_en = false;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return QDF_STATUS_E_NOMEM;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return QDF_STATUS_E_NOMEM;

	mon_mac = dp_get_mon_mac(pdev, mac_id);
	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);
	cur_frag_q_idx = tx_mon_be->cur_frag_q_idx;

	tx_status_prot = &tx_mon_be->prot_status_info;
	tx_status_data = &tx_mon_be->data_status_info;

	tx_prot_ppdu_info = dp_tx_mon_get_ppdu_info(pdev, TX_PROT_PPDU_INFO,
						    1, tx_mon_be->be_ppdu_id,
						    mac_id);

	if (!tx_prot_ppdu_info) {
		dp_mon_info("tx prot ppdu info alloc got failed!!");
		return QDF_STATUS_E_NOMEM;
	}

	status_frag = tx_mon_be->frag_q_vec[cur_frag_q_idx].frag_buf;
	end_offset = tx_mon_be->frag_q_vec[cur_frag_q_idx].end_offset;
	tx_tlv = status_frag;
	dp_mon_debug("last_frag_q_idx: %d status_frag:%pK",
		     tx_mon_be->last_frag_q_idx, status_frag);

	/* get number of user from tlv window */
	tlv_status = hal_txmon_status_get_num_users(pdev->soc->hal_soc,
						    tx_tlv, &num_users);
	if (tlv_status == HAL_MON_TX_STATUS_PPDU_NOT_DONE || !num_users) {
		dp_tx_mon_free_ppdu_info(tx_prot_ppdu_info, tx_mon_be);
		tx_mon_be->tx_prot_ppdu_info = NULL;
		dp_mon_err("window open with tlv_tag[0x%x] num_users[%d]!\n",
			   hal_tx_status_get_tlv_tag(tx_tlv), num_users);
		return QDF_STATUS_E_INVAL;
	}

	/* allocate tx_data_ppdu_info based on num_users */
	tx_data_ppdu_info = dp_tx_mon_get_ppdu_info(pdev, TX_DATA_PPDU_INFO,
						    num_users,
						    tx_mon_be->be_ppdu_id,
						    mac_id);
	if (!tx_data_ppdu_info) {
		dp_tx_mon_free_ppdu_info(tx_prot_ppdu_info, tx_mon_be);
		tx_mon_be->tx_prot_ppdu_info = NULL;
		dp_mon_info("tx prot ppdu info alloc got failed!!");
		return QDF_STATUS_E_NOMEM;
	}

	/*
	 * sw_filter_en flag will be set if the window is initiator and
	 * disable hw filter configuration is enabled through ini.
	 */
	sw_filter_en = dp_tx_mon_get_sw_filter_en(mon_pdev_be,
						  initiator, num_users);

	/* iterate status buffer queue */
	while (tx_mon_be->cur_frag_q_idx < tx_mon_be->last_frag_q_idx) {
		/* get status buffer from frag_q_vec */
		status_frag = tx_mon_be->frag_q_vec[cur_frag_q_idx].frag_buf;
		end_offset = tx_mon_be->frag_q_vec[cur_frag_q_idx].end_offset;
		if (qdf_unlikely(!status_frag)) {
			dp_mon_err("status frag is NULL\n");
			QDF_BUG(0);
		}

		tx_tlv = status_frag;
		tx_tlv_start = tx_tlv;

		dp_tx_mon_record_clear_buffer(mon_pdev_be);
		/*
		 * parse each status buffer and populate the information to
		 * dp_tx_ppdu_info
		 */
		do {
			tlv_status = hal_txmon_status_parse_tlv(
					pdev->soc->hal_soc,
					&tx_data_ppdu_info->hal_txmon,
					&tx_prot_ppdu_info->hal_txmon,
					tx_status_data,
					tx_status_prot,
					tx_tlv, status_frag);

			/* sw filter to drop packet here */
			if (sw_filter_en &&
			    ((HAL_MON_TX_QUEUE_EXTENSION == tlv_status) ||
			     (HAL_MON_TX_PEER_ENTRY == tlv_status))) {
				uint32_t state;

				state = dp_tx_mon_sw_filter(mon_pdev_be,
							    tlv_status,
							    tx_data_ppdu_info,
							    tx_status_data);

				switch (state) {
				case SW_FILTER_CHECK_PASSED:
				{
					sw_filter_en = false;
					break;
				}
				case SW_FILTER_CHECK_AGAIN:
				{
					/*
					 * mac address type failed, but there is
					 * a chance that it can matched with the
					 * type. So we need to do filter check
					 * again.
					 */
					break;
				}
				case SW_FILTER_CHECK_FAILED:
				{
					dp_tx_mon_reset_ppdu_info(
							tx_data_ppdu_info,
							tx_prot_ppdu_info);
					tx_mon_be->stats.ppdu_drop_sw_filter++;
					goto drop_packet_without_processing;
					/* no point in putting break here */
					break;
				}
				}
			}

			dp_tx_mon_record_tlv(mon_pdev_be,
					     &tx_data_ppdu_info->hal_txmon,
					     &tx_prot_ppdu_info->hal_txmon);

			status =
				dp_tx_mon_update_ppdu_info_status(
							pdev,
							tx_data_ppdu_info,
							tx_prot_ppdu_info,
							tx_tlv,
							status_frag,
							tlv_status,
							mon_desc_list_ref,
							mac_id);

			/* need api definition for hal_tx_status_get_next_tlv */
			tx_tlv = hal_tx_status_get_next_tlv(tx_tlv,
						mon_pdev->is_tlv_hdr_64_bit);
			if ((tx_tlv - tx_tlv_start) >= end_offset)
				break;
		} while ((tx_tlv - tx_tlv_start) < end_offset);

		/*
		 * free status buffer after parsing
		 * is status_frag mapped to mpdu if so make sure
		 */
		tx_mon_be->stats.status_buf_free++;
		qdf_frag_free(status_frag);
		tx_mon_be->frag_q_vec[cur_frag_q_idx].frag_buf = NULL;
		tx_mon_be->frag_q_vec[cur_frag_q_idx].end_offset = 0;
		cur_frag_q_idx = ++tx_mon_be->cur_frag_q_idx;

		dp_tx_mon_record_index_update(mon_pdev_be);
	}

	/* Accumulate tx pkt cap stats in mon pdev */
	dp_pdev_update_tx_pkt_cap_stats(mon_pdev_be);
drop_packet_without_processing:
	/* clear the unreleased frag array */
	dp_tx_mon_status_queue_free(pdev, tx_mon_be, mon_desc_list_ref,
				    mac_id);

	if (TXMON_PPDU_HAL(tx_prot_ppdu_info, is_used)) {
		if (qdf_unlikely(!TXMON_PPDU_COM(tx_prot_ppdu_info,
						 chan_num))) {
			/* update channel number, if not fetched properly */
			TXMON_PPDU_COM(tx_prot_ppdu_info,
				       chan_num) = mon_mac->mon_chan_num;
		}

		if (qdf_unlikely(!TXMON_PPDU_COM(tx_prot_ppdu_info,
						 chan_freq))) {
			/* update channel frequency, if not fetched properly */
			TXMON_PPDU_COM(tx_prot_ppdu_info,
				       chan_freq) = mon_mac->mon_chan_freq;
		}

		/*
		 * add dp_tx_ppdu_info to pdev queue
		 * for post processing
		 *
		 * TODO: add a threshold check and drop the ppdu info
		 */
		qdf_spin_lock_bh(&tx_mon_be->tx_mon_list_lock);
		tx_mon_be->last_prot_ppdu_info =
					tx_mon_be->tx_prot_ppdu_info;
		STAILQ_INSERT_TAIL(&tx_mon_be->tx_ppdu_info_queue,
				   tx_prot_ppdu_info,
				   tx_ppdu_info_queue_elem);
		tx_mon_be->tx_ppdu_info_list_depth++;

		tx_mon_be->tx_prot_ppdu_info = NULL;
		qdf_spin_unlock_bh(&tx_mon_be->tx_mon_list_lock);
		schedule_wrq = true;
	} else {
		dp_tx_mon_free_ppdu_info(tx_prot_ppdu_info, tx_mon_be);
		tx_mon_be->tx_prot_ppdu_info = NULL;
		tx_prot_ppdu_info = NULL;
	}

	if (TXMON_PPDU_HAL(tx_data_ppdu_info, is_used)) {
		if (qdf_unlikely(!TXMON_PPDU_COM(tx_data_ppdu_info,
						 chan_num))) {
			/* update channel number, if not fetched properly */
			TXMON_PPDU_COM(tx_data_ppdu_info,
				       chan_num) = mon_mac->mon_chan_num;
		}

		if (qdf_unlikely(!TXMON_PPDU_COM(tx_data_ppdu_info,
						 chan_freq))) {
			/* update channel frequency, if not fetched properly */
			TXMON_PPDU_COM(tx_data_ppdu_info,
				       chan_freq) = mon_mac->mon_chan_freq;
		}

		/*
		 * add dp_tx_ppdu_info to pdev queue
		 * for post processing
		 *
		 * TODO: add a threshold check and drop the ppdu info
		 */
		qdf_spin_lock_bh(&tx_mon_be->tx_mon_list_lock);
		tx_mon_be->last_data_ppdu_info =
					tx_mon_be->tx_data_ppdu_info;
		STAILQ_INSERT_TAIL(&tx_mon_be->tx_ppdu_info_queue,
				   tx_data_ppdu_info,
				   tx_ppdu_info_queue_elem);
		tx_mon_be->tx_ppdu_info_list_depth++;

		tx_mon_be->tx_data_ppdu_info = NULL;
		qdf_spin_unlock_bh(&tx_mon_be->tx_mon_list_lock);
		schedule_wrq = true;
	} else {
		dp_tx_mon_free_ppdu_info(tx_data_ppdu_info, tx_mon_be);
		tx_mon_be->tx_data_ppdu_info = NULL;
		tx_data_ppdu_info = NULL;
	}

	if (schedule_wrq)
		qdf_queue_work(NULL, tx_mon_be->post_ppdu_workqueue,
			       &tx_mon_be->post_ppdu_work);

	return QDF_STATUS_SUCCESS;
}

void dp_tx_mon_update_end_reason(struct dp_mon_pdev *mon_pdev,
				 int ppdu_id, int end_reason,
				 uint8_t mac_id)
{
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);

	tx_mon_be->be_end_reason_bitmap |= (1 << end_reason);
}

QDF_STATUS
dp_tx_mon_process_status_tlv(struct dp_soc *soc,
			     struct dp_pdev *pdev,
			     struct hal_mon_desc *mon_ring_desc,
			     qdf_frag_t status_frag,
			     uint32_t end_offset,
			     struct dp_tx_mon_desc_list *mon_desc_list_ref,
			     uint8_t mac_id)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be = NULL;
	uint8_t last_frag_q_idx = 0;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		goto free_status_buffer;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		goto free_status_buffer;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		goto free_status_buffer;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);

	if (qdf_unlikely(tx_mon_be->last_frag_q_idx >
			 MAX_STATUS_BUFFER_IN_PPDU)) {
		dp_mon_err("status frag queue for a ppdu[%d] exceed %d\n",
			   tx_mon_be->be_ppdu_id,
			   MAX_STATUS_BUFFER_IN_PPDU);
		dp_tx_mon_status_queue_free(pdev, tx_mon_be, mon_desc_list_ref,
					    mac_id);
		goto free_status_buffer;
	}

	if (tx_mon_be->mode == TX_MON_BE_DISABLE &&
	    !dp_lite_mon_is_tx_enabled(mon_pdev)) {
		dp_tx_mon_status_queue_free(pdev, tx_mon_be,
					    mon_desc_list_ref, mac_id);
		goto free_status_buffer;
	}

	if (tx_mon_be->be_ppdu_id != mon_ring_desc->ppdu_id &&
	    tx_mon_be->last_frag_q_idx) {
		if (tx_mon_be->be_end_reason_bitmap &
		    (1 << HAL_MON_FLUSH_DETECTED)) {
			tx_mon_be->stats.ppdu_info_drop_flush++;
			dp_tx_mon_status_queue_free(pdev, tx_mon_be,
						    mon_desc_list_ref,
						    mac_id);
		} else if (tx_mon_be->be_end_reason_bitmap &
			   (1 << HAL_MON_PPDU_TRUNCATED)) {
			tx_mon_be->stats.ppdu_info_drop_trunc++;
			dp_tx_mon_status_queue_free(pdev, tx_mon_be,
						    mon_desc_list_ref,
						    mac_id);
		} else {
			dp_mon_err("End of ppdu not seen PID:%d cur_pid:%d idx:%d",
				   tx_mon_be->be_ppdu_id,
				   mon_ring_desc->ppdu_id,
				   tx_mon_be->last_frag_q_idx);
			/* schedule ppdu worth information */
			dp_tx_mon_status_queue_free(pdev, tx_mon_be,
						    mon_desc_list_ref,
						    mac_id);
		}

		/* reset end reason bitmap */
		tx_mon_be->be_end_reason_bitmap = 0;
		tx_mon_be->last_frag_q_idx = 0;
		tx_mon_be->cur_frag_q_idx = 0;
	}

	tx_mon_be->be_ppdu_id = mon_ring_desc->ppdu_id;
	tx_mon_be->be_end_reason_bitmap |= (1 << mon_ring_desc->end_reason);

	last_frag_q_idx = tx_mon_be->last_frag_q_idx;

	tx_mon_be->frag_q_vec[last_frag_q_idx].frag_buf = status_frag;
	tx_mon_be->frag_q_vec[last_frag_q_idx].end_offset = end_offset;
	tx_mon_be->last_frag_q_idx++;

	if (mon_ring_desc->end_reason == HAL_MON_END_OF_PPDU) {
		/* drop processing of tlv, if ppdu info list exceed threshold */
		if ((tx_mon_be->defer_ppdu_info_list_depth +
		     tx_mon_be->tx_ppdu_info_list_depth) >
		    MAX_PPDU_INFO_LIST_DEPTH) {
			tx_mon_be->stats.ppdu_info_drop_th++;
			dp_tx_mon_status_queue_free(pdev, tx_mon_be,
						    mon_desc_list_ref,
						    mac_id);
			return QDF_STATUS_E_PENDING;
		}

		if (dp_tx_mon_process_tlv_2_0(pdev,
					      mon_ring_desc->initiator,
					      mon_desc_list_ref, mac_id) !=
		    QDF_STATUS_SUCCESS)
			dp_tx_mon_status_queue_free(pdev, tx_mon_be,
						    mon_desc_list_ref,
						    mac_id);
	}

	return QDF_STATUS_SUCCESS;

free_status_buffer:
	dp_tx_mon_status_free_packet_buf(pdev, status_frag, end_offset,
					 mon_desc_list_ref, mac_id);
	if (qdf_likely(tx_mon_be))
		tx_mon_be->stats.status_buf_free++;

	qdf_frag_free(status_frag);

	return QDF_STATUS_E_NOMEM;
}

#endif

#ifdef WLAN_TX_MON_CORE_DEBUG
QDF_STATUS
dp_tx_mon_process_status_tlv(struct dp_soc *soc,
			     struct dp_pdev *pdev,
			     struct hal_mon_desc *mon_ring_desc,
			     qdf_frag_t status_frag,
			     uint32_t end_offset,
			     struct dp_tx_mon_desc_list *mon_desc_list_ref,
			     uint8_t mac_id)
{
	struct dp_mon_pdev *mon_pdev;
	struct dp_mon_pdev_be *mon_pdev_be;
	struct dp_pdev_tx_monitor_be *tx_mon_be;

	/* sanity check */
	if (qdf_unlikely(!pdev))
		return QDF_STATUS_E_INVAL;

	mon_pdev = pdev->monitor_pdev;
	if (qdf_unlikely(!mon_pdev))
		return QDF_STATUS_E_INVAL;

	mon_pdev_be = dp_get_be_mon_pdev_from_dp_mon_pdev(mon_pdev);
	if (qdf_unlikely(!mon_pdev_be))
		return QDF_STATUS_E_INVAL;

	tx_mon_be = dp_mon_pdev_get_tx_mon(mon_pdev_be, mac_id);

	dp_tx_mon_status_free_packet_buf(pdev, status_frag, end_offset,
					 mon_desc_list_ref, mac_id);
	tx_mon_be->stats.status_buf_free++;
	qdf_frag_free(status_frag);

	return QDF_STATUS_E_INVAL;
}

void dp_tx_mon_update_end_reason(struct dp_mon_pdev *mon_pdev,
				 int ppdu_id, int end_reason)
{
}
#endif

#if defined(WLAN_TX_PKT_CAPTURE_ENH_BE) && defined(WLAN_PKT_CAPTURE_TX_2_0) && \
	defined(BE_PKTLOG_SUPPORT)
QDF_STATUS
dp_tx_process_pktlog_be(struct dp_soc *soc, struct dp_pdev *pdev,
			qdf_frag_t status_frag, uint32_t end_offset)
{
	struct dp_mon_pdev *mon_pdev = pdev->monitor_pdev;
	qdf_nbuf_t nbuf = NULL;
	enum WDI_EVENT pktlog_mode = WDI_NO_VAL;
	int frag_bytes;

	if (!mon_pdev->pktlog_hybrid_mode)
		return QDF_STATUS_E_INVAL;

	nbuf = qdf_nbuf_alloc(soc->osdev, MAX_DUMMY_FRM_BODY, 0, 4, FALSE);
	if (!nbuf)
		return QDF_STATUS_E_NOMEM;

	qdf_nbuf_add_rx_frag(status_frag, nbuf, 0,
			     (end_offset + 1),
			     0, true);

	if (mon_pdev->pktlog_hybrid_mode)
		pktlog_mode = WDI_EVENT_HYBRID_TX;

	frag_bytes = qdf_nbuf_get_frag_len(nbuf, 0);
	if (pktlog_mode != WDI_NO_VAL) {
		dp_wdi_event_handler(pktlog_mode, soc,
				     nbuf, HTT_INVALID_PEER,
				     WDI_NO_VAL, pdev->pdev_id);
	}
	qdf_nbuf_free(nbuf);

	return QDF_STATUS_SUCCESS;
}
#endif
