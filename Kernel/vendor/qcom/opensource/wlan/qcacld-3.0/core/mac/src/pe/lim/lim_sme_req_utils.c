/*
 * Copyright (c) 2011-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 *
 * This file lim_sme_req_utils.cc contains the utility functions
 * for processing SME request messages.
 * Author:        Chandra Modumudi
 * Date:          02/11/02
 * History:-
 * Date           Modified by    Modification Information
 * --------------------------------------------------------------------
 * 05/26/10       js             WPA handling in (Re)Assoc frames
 *
 */

#include "wni_api.h"
#include "wni_cfg.h"
#include "sir_api.h"
#include "sch_api.h"
#include "utils_api.h"
#include "lim_types.h"
#include "lim_utils.h"
#include "lim_assoc_utils.h"
#include "lim_security_utils.h"
#include "lim_ser_des_utils.h"
#include "lim_sme_req_utils.h"

/**
 * lim_is_rsn_ie_valid_in_sme_req_message()
 *
 * @mac_ctx   Pointer to Global MAC structure
 * @rsn_ie    Pointer to received RSN IE
 *
 * This function is called to verify if the RSN IE received in various SME_REQ
 * messages is valid or not
 *
 * Return: true when RSN IE is valid, false otherwise
 *
 */
static uint8_t
lim_is_rsn_ie_valid_in_sme_req_message(struct mac_context *mac_ctx,
				       tpSirRSNie rsn_ie)
{
	uint8_t start = 0;
	uint32_t val;
	int len;

	val = mac_ctx->mlme_cfg->feature_flags.enable_rsn;
	if (rsn_ie->length && !val) {
		/* Privacy & RSN not enabled in CFG.
		 * In order to allow mixed mode for Guest access
		 * allow BSS creation/join with no Privacy capability
		 * yet advertising WPA IE
		 */
		pe_debug("RSN ie len: %d RSN: %d",
			       rsn_ie->length, val);
	}

	if (!rsn_ie->length) {
		pe_debug("RSN IE length is 0");
		return true;
	}

	if ((rsn_ie->rsnIEdata[0] != DOT11F_EID_RSN)
#ifdef FEATURE_WLAN_WAPI
	    && (rsn_ie->rsnIEdata[0] != DOT11F_EID_WAPI)
#endif
	    && (rsn_ie->rsnIEdata[0] != DOT11F_EID_WPA)) {
		pe_err("RSN/WPA/WAPI EID: %d not [%d || %d]",
			rsn_ie->rsnIEdata[0], DOT11F_EID_RSN,
			DOT11F_EID_WPA);
		return false;
	}

	len = rsn_ie->length;
	start = 0;
	while (len > 0) {
		switch (rsn_ie->rsnIEdata[start]) {
		case DOT11F_EID_RSN:
		/* Check validity of RSN IE */
			if ((rsn_ie->rsnIEdata[start + 1] >
			    DOT11F_IE_RSN_MAX_LEN)
			    || (rsn_ie->rsnIEdata[start + 1] <
				DOT11F_IE_RSN_MIN_LEN)) {
				pe_err("RSN IE len: %d not [%d,%d]",
					rsn_ie->rsnIEdata[start + 1],
					DOT11F_IE_RSN_MIN_LEN,
					DOT11F_IE_RSN_MAX_LEN);
				return false;
			}
			break;
		case DOT11F_EID_WPA:
			/* Check validity of WPA IE */
			if (WLAN_MAX_IE_LEN <= start)
				break;

			if (start <= (WLAN_MAX_IE_LEN - sizeof(uint32_t)))
				val = sir_read_u32((uint8_t *) &
					rsn_ie->rsnIEdata[start + 2]);

			if ((rsn_ie->rsnIEdata[start + 1] <
			     DOT11F_IE_WPA_MIN_LEN)
			    || (rsn_ie->rsnIEdata[start + 1] >
				DOT11F_IE_WPA_MAX_LEN)
			    || (SIR_MAC_WPA_OUI != val)) {
				pe_err("WPA IE len: %d not [%d,%d] OR data 0x%x not 0x%x",
					rsn_ie->rsnIEdata[start + 1],
					DOT11F_IE_WPA_MIN_LEN,
					DOT11F_IE_WPA_MAX_LEN,
					val, SIR_MAC_WPA_OUI);
				return false;
			}
			break;
#ifdef FEATURE_WLAN_WAPI
		case DOT11F_EID_WAPI:
			if ((rsn_ie->rsnIEdata[start + 1] >
			    DOT11F_IE_WAPI_MAX_LEN)
			    || (rsn_ie->rsnIEdata[start + 1] <
				DOT11F_IE_WAPI_MIN_LEN)) {
				pe_err("WAPI IE len: %d not [%d,%d]",
					rsn_ie->rsnIEdata[start + 1],
					DOT11F_IE_WAPI_MIN_LEN,
					DOT11F_IE_WAPI_MAX_LEN);
				return false;
			}
			break;
#endif
		default:
			/* we will never be here, simply for completeness */
			return false;
		} /* end of switch */
		/* EID + length field + length */
		start += 2 + rsn_ie->rsnIEdata[start + 1];
		len -= start;
	} /* end while loop */
	return true;
} /*** end lim_is_rs_nie_valid_in_sme_req_message() ***/

/**
 * lim_set_rs_nie_wp_aiefrom_sme_start_bss_req_message() - to set rsnie/wpaie
 *
 * @mac_ctx : Pointer to Global MAC structure
 * @rsn_ie  : Pointer to received RSN IE
 * @session : Pointer to pe session
 *
 * This function is called to verify if the RSN IE received in various
 * SME_REQ messages is valid or not. RSN IE validity checks are performed in
 * this function
 *
 * Return: true when RSN IE is valid, false otherwise
 */
uint8_t
lim_set_rs_nie_wp_aiefrom_sme_start_bss_req_message(struct mac_context *mac_ctx,
						    tpSirRSNie rsn_ie,
						    struct pe_session *session)
{
	uint32_t ret;
	uint8_t wpa_idx = 0;
	uint32_t val;
	bool privacy;

	privacy = mac_ctx->mlme_cfg->wep_params.is_privacy_enabled;

	val = mac_ctx->mlme_cfg->feature_flags.enable_rsn;
	if (rsn_ie->length && (!privacy || !val)) {
		/*
		 * Privacy & RSN not enabled in CFG.
		 * In order to allow mixed mode for Guest access
		 * allow BSS creation/join with no Privacy capability
		 * yet advertising WPA IE
		 */
		pe_debug("RSN ie len: %d but PRIVACY: %d RSN: %d",
			rsn_ie->length, privacy, val);
	}

	if (!rsn_ie->length)
		return true;

	if ((rsn_ie->rsnIEdata[0] != WLAN_ELEMID_RSN) &&
	    (rsn_ie->rsnIEdata[0] != SIR_MAC_WPA_EID)) {
		pe_err("RSN/WPA EID: %d not [%d || %d]",
			rsn_ie->rsnIEdata[0], WLAN_ELEMID_RSN,
			SIR_MAC_WPA_EID);
		return false;
	}
	/* Check validity of RSN IE */
	if ((rsn_ie->rsnIEdata[0] == WLAN_ELEMID_RSN) &&
	    (rsn_ie->rsnIEdata[1] < SIR_MAC_RSN_IE_MIN_LENGTH)) {
		pe_err("RSN IE len: %d not [%d,%d]",
			rsn_ie->rsnIEdata[1], SIR_MAC_RSN_IE_MIN_LENGTH,
			WLAN_MAX_IE_LEN);
		return false;
	}

	if (rsn_ie->length > rsn_ie->rsnIEdata[1] + 2) {
		if (rsn_ie->rsnIEdata[0] != WLAN_ELEMID_RSN) {
			pe_err("First byte: %d in rsnIEdata isn't RSN_EID",
				rsn_ie->rsnIEdata[1]);
			return false;
		}
		pe_debug("WPA IE is present along with WPA2 IE");
		wpa_idx = 2 + rsn_ie->rsnIEdata[1];
	} else if ((rsn_ie->length == rsn_ie->rsnIEdata[1] + 2) &&
		   (rsn_ie->rsnIEdata[0] == WLAN_ELEMID_RSN)) {
		pe_debug("Only RSN IE is present");
		ret = dot11f_unpack_ie_rsn(mac_ctx, &rsn_ie->rsnIEdata[2],
					   rsn_ie->rsnIEdata[1],
					   &session->gStartBssRSNIe, false);
		if (!DOT11F_SUCCEEDED(ret)) {
			pe_err("unpack failed, ret: %d", ret);
			return false;
		}
		return true;
	} else if ((rsn_ie->length == rsn_ie->rsnIEdata[1] + 2)
		   && (rsn_ie->rsnIEdata[0] == SIR_MAC_WPA_EID)) {
		pe_debug("Only WPA IE is present");
		ret = dot11f_unpack_ie_wpa(mac_ctx, &rsn_ie->rsnIEdata[6],
					   rsn_ie->rsnIEdata[1] - 4,
					   &session->gStartBssWPAIe, false);
		if (!DOT11F_SUCCEEDED(ret)) {
			pe_err("unpack failed, ret: %d", ret);
			return false;
		}
		return true;
	}
	/* Check validity of WPA IE */
	if (wpa_idx + 6 >= WLAN_MAX_IE_LEN)
		return false;

	val = sir_read_u32((uint8_t *)&rsn_ie->rsnIEdata[wpa_idx + 2]);
	if ((rsn_ie->rsnIEdata[wpa_idx] == SIR_MAC_WPA_EID)
	    && ((rsn_ie->rsnIEdata[wpa_idx + 1] < SIR_MAC_WPA_IE_MIN_LENGTH)
	     || (SIR_MAC_WPA_OUI != val))) {
		pe_err("WPA IE len: %d not [%d,%d] OR data 0x%x not 0x%x",
			rsn_ie->rsnIEdata[1],
			SIR_MAC_RSN_IE_MIN_LENGTH,
			WLAN_MAX_IE_LEN, val,
			SIR_MAC_WPA_OUI);
		return false;
	} else {
		/* Both RSN and WPA IEs are present */
		ret = dot11f_unpack_ie_rsn(mac_ctx, &rsn_ie->rsnIEdata[2],
					   rsn_ie->rsnIEdata[1],
					   &session->gStartBssRSNIe, false);
		if (!DOT11F_SUCCEEDED(ret)) {
			pe_err("unpack failed, ret: %d", ret);
			return false;
		}
		ret = dot11f_unpack_ie_wpa(mac_ctx,
					   &rsn_ie->rsnIEdata[wpa_idx + 6],
					   rsn_ie->rsnIEdata[wpa_idx + 1] - 4,
					   &session->gStartBssWPAIe, false);
		if (!DOT11F_SUCCEEDED(ret)) {
			pe_err("unpack failed, ret: %d", ret);
			return false;
		}
	}
	return true;
}

#ifdef WLAN_FEATURE_11BE_MLO
uint32_t lim_populate_rnr_entry(struct mac_context *mac_ctx,
				struct pe_session *session_entry,
				uint8_t *ie)
{
	uint32_t rnr_ie_len;
	uint16_t tbtt_count, tbtt_length, i = 0, fieldtype;
	uint8_t *data;
	uint32_t ret = DOT11F_UNKNOWN_IES;
	struct neighbor_ap_info_field *neighbor_ap_info;

	qdf_mem_zero(&session_entry->start_bss_rnr_ie[0],
		     (sizeof(tDot11fIEreduced_neighbor_report) *
		      MAX_NUM_RNR_ENTRY));

	if (!ie) {
		pe_debug("remove rnrie");
		return 0;
	}
	rnr_ie_len = ie[TAG_LEN_POS];
	data = ie + MIN_IE_LEN;

	while ((data < (ie + rnr_ie_len + MIN_IE_LEN)) &&
	       i < MAX_NUM_RNR_ENTRY) {
		neighbor_ap_info = (struct neighbor_ap_info_field *)data;

		tbtt_count = neighbor_ap_info->tbtt_header.tbtt_info_count;
		tbtt_length = neighbor_ap_info->tbtt_header.tbtt_info_length;
		fieldtype = neighbor_ap_info->tbtt_header.tbbt_info_fieldtype;

		pe_debug("chan %d, opclass %d tbtt_cnt %d, tbtt_len %d, fieldtype %d",
			 neighbor_ap_info->channel_number,
			 neighbor_ap_info->operting_class,
			 tbtt_count, tbtt_length, fieldtype);

		if (tbtt_count) {
			pe_debug("Not support MBSSID case or rnr content wrong");
			ret = DOT11F_UNKNOWN_IES;
			return ret;
		}

		ret = dot11f_unpack_ie_reduced_neighbor_report(mac_ctx,
							       data,
							       (sizeof(struct neighbor_ap_info_field) +
								tbtt_length),
							       &session_entry->start_bss_rnr_ie[i],
							       false);
		if (!DOT11F_SUCCEEDED(ret)) {
			pe_err("unpack failed, ret: %d", ret);
			return ret;
		}
		data += sizeof(struct neighbor_ap_info_field) + tbtt_length;
		i++;
	}
	return ret;
}

bool
lim_set_rnr_ie_from_start_bss_req(struct mac_context *mac_ctx,
				  struct ssirrnrie *rnr_ie,
				  struct pe_session *session)
{
	uint32_t ret;

	if (!rnr_ie->length)
		return true;

	if (rnr_ie->rnriedata[ID_POS] !=
	    WLAN_ELEMID_REDUCED_NEIGHBOR_REPORT) {
		pe_debug("EID: %d is not rnr", rnr_ie->rnriedata[ID_POS]);
		return false;
	}
	/* Check validity of RNR IE */
	if (rnr_ie->rnriedata[TAG_LEN_POS] < SIR_MAC_RSN_IE_MIN_LENGTH) {
		pe_debug("invalid RNR IE len: %d",
			 rnr_ie->rnriedata[TAG_LEN_POS]);
		return false;
	}

	ret = lim_populate_rnr_entry(mac_ctx, session,
				     &rnr_ie->rnriedata[ID_POS]);
	if (!DOT11F_SUCCEEDED(ret))
		return false;

	return true;
}

#else
bool
lim_set_rnr_ie_from_start_bss_req(struct mac_context *mac_ctx,
				  struct ssirrnrie *rnr_ie,
				  struct pe_session *session)
{
	return false;
}
#endif

bool lim_is_sme_start_bss_req_valid(struct mac_context *mac_ctx,
				    struct start_bss_config *start_bss_req,
				    enum bss_type bss_type)
{
	uint8_t i = 0;
	tSirMacRateSet *opr_rates = &start_bss_req->operationalRateSet;

	switch (bss_type) {
	case eSIR_INFRASTRUCTURE_MODE:
		/**
		 * Should not have received start BSS req with bssType
		 * Infrastructure on STA.
		 */
		pe_warn("Invalid bss type: %d in eWNI_SME_START_BSS_REQ",
			bss_type);
		return false;
		break;
	case eSIR_INFRA_AP_MODE:
		break;
	case eSIR_NDI_MODE:
		break;
	default:
		/**
		 * Should not have received start BSS req with bssType
		 * other than Infrastructure/IBSS.
		 */
		pe_warn("Invalid bss type: %d in eWNI_SME_START_BSS_REQ",
			bss_type);
		return false;
	}

	if (!lim_is_rsn_ie_valid_in_sme_req_message(mac_ctx,
						    &start_bss_req->rsnIE))
		return false;

	if (start_bss_req->nwType != eSIR_11A_NW_TYPE
	    && start_bss_req->nwType != eSIR_11B_NW_TYPE
	    && start_bss_req->nwType != eSIR_11G_NW_TYPE)
		return false;

	if (start_bss_req->nwType == eSIR_11A_NW_TYPE) {
		for (i = 0; i < opr_rates->numRates; i++) {
			if (sirIsArate(opr_rates->rate[i] & 0x7F))
				continue;

			pe_warn("Invalid operational 11A rates");
			QDF_TRACE_HEX_DUMP(QDF_MODULE_ID_PE,
					   QDF_TRACE_LEVEL_WARN,
					   opr_rates->rate,
					   opr_rates->numRates);
			return false;
		}
		return true;
	}
	/* check if all the rates in the opr rate set are legal 11G rates */
	if (start_bss_req->nwType == eSIR_11G_NW_TYPE) {
		for (i = 0; i < opr_rates->numRates; i++) {
			if (sirIsGrate(opr_rates->rate[i] & 0x7F))
				continue;

			pe_warn("Invalid operational 11G rates");
			QDF_TRACE_HEX_DUMP(QDF_MODULE_ID_PE,
					   QDF_TRACE_LEVEL_WARN,
					   opr_rates->rate,
					   opr_rates->numRates);
			return false;
		}
		return true;
	}

	for (i = 0; i < opr_rates->numRates; i++) {
		if (sirIsBrate(opr_rates->rate[i] & 0x7F))
			continue;

		pe_warn("Invalid operational 11B rates");
		QDF_TRACE_HEX_DUMP(QDF_MODULE_ID_PE,
				   QDF_TRACE_LEVEL_WARN,
				   opr_rates->rate,
				   opr_rates->numRates);
		return false;
	}
	return true;
}

bool lim_is_sme_disassoc_req_valid(struct mac_context *mac,
				   struct disassoc_req *disassoc_req,
				   struct pe_session *pe_session)
{
	if (qdf_is_macaddr_group(&disassoc_req->peer_macaddr) &&
	    !qdf_is_macaddr_broadcast(&disassoc_req->peer_macaddr))
		return false;

	return true;
} /*** end lim_is_sme_disassoc_req_valid() ***/

bool lim_is_sme_disassoc_cnf_valid(struct mac_context *mac,
				   struct disassoc_cnf *disassoc_cnf,
				   struct pe_session *pe_session)
{
	if (qdf_is_macaddr_group(&disassoc_cnf->peer_macaddr))
		return false;

	return true;
} /*** end lim_is_sme_disassoc_cnf_valid() ***/

bool lim_is_sme_deauth_req_valid(struct mac_context *mac,
				 struct deauth_req *deauth_req,
				 struct pe_session *pe_session)
{
	if (qdf_is_macaddr_group(&deauth_req->peer_macaddr) &&
	    !qdf_is_macaddr_broadcast(&deauth_req->peer_macaddr))
		return false;

	return true;
} /*** end lim_is_sme_deauth_req_valid() ***/
