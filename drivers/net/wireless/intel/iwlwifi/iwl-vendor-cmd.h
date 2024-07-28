/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2012-2014, 2018-2024 Intel Corporation
 * Copyright (C) 2013-2015 Intel Mobile Communications GmbH
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 */
#ifndef __VENDOR_CMD_H__
#define __VENDOR_CMD_H__

#define INTEL_OUI	0x001735

/**
 * enum iwl_mvm_vendor_cmd - supported vendor commands
 * @IWL_MVM_VENDOR_CMD_SET_LOW_LATENCY: set low-latency mode for the given
 *	virtual interface
 * @IWL_MVM_VENDOR_CMD_GET_LOW_LATENCY: query low-latency mode
 * @IWL_MVM_VENDOR_CMD_LTE_STATE: inform the LTE modem state
 * @IWL_MVM_VENDOR_CMD_LTE_COEX_CONFIG_INFO: configure LTE-Coex static
 *	parameters
 * @IWL_MVM_VENDOR_CMD_LTE_COEX_DYNAMIC_INFO: configure LTE dynamic parameters
 * @IWL_MVM_VENDOR_CMD_LTE_COEX_SPS_INFO: configure semi oersistent info
 * @IWL_MVM_VENDOR_CMD_LTE_COEX_WIFI_RPRTD_CHAN: Wifi reported channel as
 *	calculated by the coex-manager
 * @IWL_MVM_VENDOR_CMD_SET_COUNTRY: set a new mcc regulatory information
 * @IWL_MVM_VENDOR_CMD_PROXY_FRAME_FILTERING: filter GTK, gratuitous
 *	ARP & unsolicited NA
 * @IWL_MVM_VENDOR_CMD_SET_NIC_TXPOWER_LIMIT: set the NIC's (SAR) TX power limit
 * @IWL_MVM_VENDOR_CMD_GSCAN_GET_CAPABILITIES: get driver gscan capabilities as
 *	specified in %IWL_MVM_VENDOR_ATTR_GSCAN_*
 * @IWL_MVM_VENDOR_CMD_GSCAN_START: set gscan parameters and start gscan
 * @IWL_MVM_VENDOR_CMD_GSCAN_STOP: stop a previously started gscan
 * @IWL_MVM_VENDOR_CMD_GSCAN_RESULTS_EVENT: event that reports scan results
 *	from gscan. This event is sent when the scan results buffer has reached
 *	the report threshold, or when scanning a bucket with report mode
 *	%IWL_MVM_VENDOR_GSCAN_REPORT_BUFFER_COMPLETE was completed.
 * @IWL_MVM_VENDOR_CMD_GSCAN_SET_BSSID_HOTLIST: set a list of AP's to track
 *	changes in their RSSI and report scan results history when RSSI goes
 *	above/below threshold. Sending this command with an empty list of AP's
 *	will cancel previous set_bssid_hotlist request.
 * @IWL_MVM_VENDOR_CMD_GSCAN_SET_SIGNIFICANT_CHANGE: set a list of APs to track
 *	significant changes in their RSSI. Sending this command with an empty
 *	list of AP's will cancel previous set_significant_change request.
 * @IWL_MVM_VENDOR_CMD_GSCAN_HOTLIST_CHANGE_EVENT: event that indicates that an
 *	AP from the BSSID hotlist was lost or found.
 * @IWL_MVM_VENDOR_CMD_GSCAN_SIGNIFICANT_CHANGE_EVENT: event that indicates a
 *	significant change in the RSSI level of beacons received from a certain
 *	AP.
 * @IWL_MVM_VENDOR_CMD_RXFILTER: Set/clear rx filter.
 * @IWL_MVM_VENDOR_CMD_GSCAN_BEACON_EVENT: event that reports a
 *	beacon/probe response was received, and contains information from the
 *	beacon/probe response. This event is sent for buckets with report mode
 *	set to %IWL_MVM_VENDOR_GSCAN_REPORT_BUFFER_COMPLETE_RESULTS.
 * @IWL_MVM_VENDOR_CMD_DBG_COLLECT: collect debug data
 * @IWL_MVM_VENDOR_CMD_NAN_FAW_CONF: Configure post NAN further availability.
 * @IWL_MVM_VENDOR_CMD_SET_SAR_PROFILE: set the NIC's tx power limits
 *	according to the specified tx power profiles. In this command
 *	%IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE and
 *	%IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE must be passed.
 * @IWL_MVM_VENDOR_CMD_GET_SAR_PROFILE_INFO: get sar profile information.
 *	This command provides the user with the following information:
 *	Number of enabled SAR profiles, current used SAR profile per chain.
 * @IWL_MVM_VENDOR_CMD_NEIGHBOR_REPORT_REQUEST: Send a neighbor report request
 *	to the AP we are currently connected to. The request parameters are
 *	specified with %IWL_MVM_VENDOR_ATTR_NR_*.
 * @IWL_MVM_VENDOR_CMD_NEIGHBOR_REPORT_RESPONSE: An event that reports a list of
 *	neighbor APs received in a neighbor report response frame. The report is
 *	a nested list of &enum iwl_mvm_vendor_neighbor_report.
 * @IWL_MVM_VENDOR_CMD_GET_SAR_GEO_PROFILE: get sar geographic profile
 *	information. This command provides the user with the following
 *	information: Per band tx power offset for chain A and chain B as well as
 *	maximum allowed tx power on this band.
 * @IWL_MVM_VENDOR_CMD_TEST_FIPS: request the output of a certain function for
 *	the specified test vector. The test vector is specified with one of:
 *	&IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_SHA,
 *	&IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HMAC, or
 *	&IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_KDF. Only one test vector shall be
 *	specified per test command.
 *	The result output is sent back in &IWL_MVM_VENDOR_ATTR_FIPS_TEST_RESULT
 *	attribute. In case the function failed to produce an output for the
 *	requested test vector, &IWL_MVM_VENDOR_ATTR_FIPS_TEST_RESULT is not set.
 * @IWL_MVM_VENDOR_CMD_CSI_EVENT: CSI event, use as a command to enable unicast
 *	reporting to the calling socket
 * @IWL_MVM_VENDOR_CMD_ADD_PASN_STA: add a PASN station for and initiator or
 *	responder based on the interface type. &IWL_MVM_VENDOR_ATTR_ADDR
 *	specifies the station's mac address. &IWL_MVM_VENDOR_ATTR_STA_TK and
 *	&IWL_MVM_VENDOR_ATTR_STA_CIPHER specify the cipher suite and key to use
 *	for PMF for this station. &IWL_MVM_VENDOR_ATTR_STA_HLTK specifies the
 *	HLTK for secure LTF bits generation.
 * @IWL_MVM_VENDOR_CMD_REMOVE_PASN_STA: remove the PASN station with the mac
 *	address specified with &IWL_MVM_VENDOR_ATTR_ADDR.
 * @IWL_MVM_VENDOR_CMD_GET_CSME_CONN_INFO: reports CSME connection info.
 * @IWL_MVM_VENDOR_CMD_HOST_GET_OWNERSHIP: host ask for ownership on the device.
 * @IWL_MVM_VENDOR_CMD_ROAMING_FORBIDDEN_EVENT: notifies if roaming is allowed.
 *	contains a &IWL_MVM_VENDOR_ATTR_ROAMING_FORBIDDEN and a
 *	&IWL_MVM_VENDOR_ATTR_VIF_ADDR attribute.
 * @IWL_MVM_VENDOR_CMD_PPAG_GET_TABLE: retrieves the PPAG table.
 *	Contains a &IWL_MVM_VENDOR_ATTR_PPAG_TABLE and a
 *	&IWL_MVM_VENDOR_ATTR_PPAG_NUM_SUB_BANDS attribute.
 * @IWL_MVM_VENDOR_CMD_SAR_GET_TABLE: retrieves the full SAR table.
 *	Contains a &IWL_MVM_VENDOR_ATTR_SAR_TABLE and a
 *	&IWL_MVM_VENDOR_ATTR_SAR_VER attributes.
 * @IWL_MVM_VENDOR_CMD_GEO_SAR_GET_TABLE: retrieves the full GEO SAR table.
 *	Contains a &IWL_MVM_VENDOR_ATTR_SAR_TABLE and a
 *	&IWL_MVM_VENDOR_ATTR_GEO_SAR_VER attributes.
 * @IWL_MVM_VENDOR_CMD_SGOM_GET_TABLE: retrieves the full SGOM table.
 *	Contains a &IWL_MVM_VENDOR_ATTR_SGOM_TABLE attributes.
 * @IWL_MVM_VENDOR_CMD_RFIM_SET_TABLE: Set the RFIM (RF interference mitigation)
 *	table
 * @IWL_MVM_VENDOR_CMD_RFIM_GET_TABLE: Retrieve the RFIM table
 * @IWL_MVM_VENDOR_CMD_RFIM_GET_CAPA: Retrieve RFIM capabilities
 * @IWL_MVM_VENDOR_CMD_RFIM_SET_CNVI_MASTER: Set CNVI is master or not
 * @IWL_MVM_VENDOR_CMD_GET_LINK_INFO: Get link information.
 *	This is needed for RFIm user app
 * @IWL_MVM_VENDOR_CMD_LINK_INFO_CHANGED_EVENT: Link information is changed
 */

enum iwl_mvm_vendor_cmd {
	IWL_MVM_VENDOR_CMD_SET_LOW_LATENCY			= 0x00,
	IWL_MVM_VENDOR_CMD_GET_LOW_LATENCY			= 0x01,
	/* 0x2 is deprecated */
	IWL_MVM_VENDOR_CMD_LTE_STATE				= 0x03,
	IWL_MVM_VENDOR_CMD_LTE_COEX_CONFIG_INFO			= 0x04,
	IWL_MVM_VENDOR_CMD_LTE_COEX_DYNAMIC_INFO		= 0x05,
	IWL_MVM_VENDOR_CMD_LTE_COEX_SPS_INFO			= 0x06,
	IWL_MVM_VENDOR_CMD_LTE_COEX_WIFI_RPRTD_CHAN		= 0x07,
	IWL_MVM_VENDOR_CMD_SET_COUNTRY				= 0x08,
	IWL_MVM_VENDOR_CMD_PROXY_FRAME_FILTERING		= 0x09,
	/* 0x0a is deprecated */
	/* 0x0b is deprecated */
	/* 0x0c is deprecated */
	IWL_MVM_VENDOR_CMD_SET_NIC_TXPOWER_LIMIT		= 0x0d,
	/* 0x0e is deprecated */
	IWL_MVM_VENDOR_CMD_GSCAN_GET_CAPABILITIES		= 0x0f,
	IWL_MVM_VENDOR_CMD_GSCAN_START				= 0x10,
	IWL_MVM_VENDOR_CMD_GSCAN_STOP				= 0x11,
	IWL_MVM_VENDOR_CMD_GSCAN_RESULTS_EVENT			= 0x12,
	IWL_MVM_VENDOR_CMD_GSCAN_SET_BSSID_HOTLIST		= 0x13,
	IWL_MVM_VENDOR_CMD_GSCAN_SET_SIGNIFICANT_CHANGE		= 0x14,
	IWL_MVM_VENDOR_CMD_GSCAN_HOTLIST_CHANGE_EVENT		= 0x15,
	IWL_MVM_VENDOR_CMD_GSCAN_SIGNIFICANT_CHANGE_EVENT	= 0x16,
	IWL_MVM_VENDOR_CMD_RXFILTER				= 0x17,
	IWL_MVM_VENDOR_CMD_GSCAN_BEACON_EVENT			= 0x18,
	IWL_MVM_VENDOR_CMD_DBG_COLLECT				= 0x19,
	IWL_MVM_VENDOR_CMD_NAN_FAW_CONF				= 0x1a,
	/* 0x1b is deprecated */
	IWL_MVM_VENDOR_CMD_SET_SAR_PROFILE			= 0x1c,
	IWL_MVM_VENDOR_CMD_GET_SAR_PROFILE_INFO			= 0x1d,
	IWL_MVM_VENDOR_CMD_NEIGHBOR_REPORT_REQUEST		= 0x1e,
	IWL_MVM_VENDOR_CMD_NEIGHBOR_REPORT_RESPONSE		= 0x1f,
	IWL_MVM_VENDOR_CMD_GET_SAR_GEO_PROFILE			= 0x20,
	IWL_MVM_VENDOR_CMD_TEST_FIPS				= 0x21,
	/* 0x22 is reserved */
	/* 0x23 is reserved */
	IWL_MVM_VENDOR_CMD_CSI_EVENT				= 0x24,
	IWL_MVM_VENDOR_CMD_ADD_PASN_STA				= 0x25,
	IWL_MVM_VENDOR_CMD_REMOVE_PASN_STA			= 0x26,
	IWL_MVM_VENDOR_CMD_RFIM_SET_TABLE			= 0x27,
	IWL_MVM_VENDOR_CMD_RFIM_GET_TABLE			= 0x28,
	IWL_MVM_VENDOR_CMD_RFIM_GET_CAPA			= 0x29,
	/* 0x2a is deprecated */
	/* 0x2b is deprecated */
	/* 0x2c is deprecated */
	IWL_MVM_VENDOR_CMD_GET_CSME_CONN_INFO			= 0x2d,
	IWL_MVM_VENDOR_CMD_HOST_GET_OWNERSHIP			= 0x30,
	IWL_MVM_VENDOR_CMD_ROAMING_FORBIDDEN_EVENT		= 0x32,
	IWL_MVM_VENDOR_CMD_PPAG_GET_TABLE                       = 0x33,
	IWL_MVM_VENDOR_CMD_SAR_GET_TABLE                        = 0x34,
	IWL_MVM_VENDOR_CMD_GEO_SAR_GET_TABLE                    = 0x35,
	IWL_MVM_VENDOR_CMD_SGOM_GET_TABLE			= 0x36,
	IWL_MVM_VENDOR_CMD_RFIM_SET_CNVI_MASTER			= 0x37,
	IWL_MVM_VENDOR_CMD_GET_LINK_INFO			= 0x38,
	IWL_MVM_VENDOR_CMD_LINK_INFO_CHANGED_EVENT		= 0x39,
};

/**
 * enum iwl_mvm_vendor_gscan_report_mode - gscan scan results report modes
 * @IWL_MVM_VENDOR_GSCAN_REPORT_BUFFER_FULL: report that scan results are
 *	available only when the scan results buffer reaches the report
 *	threshold. The report threshold is set for each bucket.
 * @IWL_MVM_VENDOR_GSCAN_REPORT_BUFFER_EACH_SCAN: report that scan results are
 *	available when scanning of this bucket is complete.
 * @IWL_MVM_VENDOR_GSCAN_REPORT_BUFFER_FULL_RESULTS: forward scan results
 *	(beacons/probe responses) in real time to userspace.
 * @IWL_MVM_VENDOR_GSCAN_REPORT_HISTORY_RESERVED: reserved.
 * @IWL_MVM_VENDOR_GSCAN_REPORT_NO_BATCH: do not fill scan history buffer.
 * @NUM_IWL_MVM_VENDOR_GSCAN_REPORT: number of report mode attributes.
 *
 * Note that these must match the firmware API.
 */
enum iwl_mvm_vendor_gscan_report_mode {
	IWL_MVM_VENDOR_GSCAN_REPORT_BUFFER_FULL,
	IWL_MVM_VENDOR_GSCAN_REPORT_BUFFER_EACH_SCAN,
	IWL_MVM_VENDOR_GSCAN_REPORT_BUFFER_FULL_RESULTS,
	IWL_MVM_VENDOR_GSCAN_REPORT_HISTORY_RESERVED,
	IWL_MVM_VENDOR_GSCAN_REPORT_NO_BATCH,
	NUM_IWL_MVM_VENDOR_GSCAN_REPORT,
};

/**
 * enum iwl_mvm_vendor_gscan_channel_spec - gscan channel specification
 * @IWL_MVM_VENDOR_CHANNEL_SPEC_INVALID: attribute number 0 is reserved
 * @IWL_MVM_VENDOR_CHANNEL_SPEC_CHANNEL: channel number
 * @IWL_MVM_VENDOR_CHANNEL_SPEC_DWELL_TIME: u16 attribute specifying dwell
 *	time on this channel.
 * @IWL_MVM_VENDOR_CHANNEL_SPEC_PASSIVE: flag attribute. If set, passive
 *	scan should be performed on this channel.
 * @NUM_IWL_MVM_VENDOR_CHANNEL_SPEC: number of channel spec attributes.
 * @MAX_IWL_MVM_VENDOR_CHANNEL_SPEC: highest channel spec attribute number.
 */
enum iwl_mvm_vendor_gscan_channel_spec {
	IWL_MVM_VENDOR_CHANNEL_SPEC_INVALID,
	IWL_MVM_VENDOR_CHANNEL_SPEC_CHANNEL,
	IWL_MVM_VENDOR_CHANNEL_SPEC_DWELL_TIME,
	IWL_MVM_VENDOR_CHANNEL_SPEC_PASSIVE,
	NUM_IWL_MVM_VENDOR_CHANNEL_SPEC,
	MAX_IWL_MVM_VENDOR_CHANNEL_SPEC =
		NUM_IWL_MVM_VENDOR_CHANNEL_SPEC - 1,
};

/**
 * enum iwl_mvm_vendor_gscan_bucket_spec - gscan bucket specification
 * @IWL_MVM_VENDOR_BUCKET_SPEC_INVALID: attribute number 0 is reserved
 * @IWL_MVM_VENDOR_BUCKET_SPEC_INDEX: bucket index
 * @IWL_MVM_VENDOR_BUCKET_SPEC_BAND: band to scan as specified in
 *	&enum iwl_gscan_band. When not set, the channel list is used.
 * @IWL_MVM_VENDOR_BUCKET_SPEC_PERIOD: interval between this bucket scans,
 *	in msecs.
 * @IWL_MVM_VENDOR_BUCKET_SPEC_REPORT_MODE: when to report scan results.
 *	Available modes are specified in &enum iwl_mvm_vendor_report_mode.
 * @IWL_MVM_VENDOR_BUCKET_SPEC_CHANNELS: array of channels to scan for this
 *	bucket. Each channel is specified with a nested attribute of
 *	%IWL_MVM_VENDOR_CHANNEL_SPEC. This channel list is used when
 *	%IWL_MVM_VENDOR_BUCKET_SPEC_BAND is set to
 *	%IWL_MVM_VENDOR_BAND_UNSPECIFIED.
 * @IWL_MVM_VENDOR_BUCKET_SPEC_MAX_PERIOD: maximum scan interval. If it's
 *	non zero or different than period, then this bucket is an exponential
 *	back off bucket and the scan period will grow exponentially.
 * @IWL_MVM_VENDOR_BUCKET_SPEC_EXPONENT: for exponential back off bucket,
 *	scan period calculation should be done according to the following:
 *	new_period = old_period * exponent
 * @IWL_MVM_VENDOR_BUCKET_SPEC_STEP_CNT: for exponential back off bucket:
 *	number of scans to perform at a given period and until the exponent
 *	is applied.
 * @NUM_IWL_MVM_VENDOR_BUCKET_SPEC: number of bucket spec attributes.
 * @MAX_IWL_MVM_VENDOR_BUCKET_SPEC: highest bucket spec attribute number.
 */
enum iwl_mvm_vendor_gscan_bucket_spec {
	IWL_MVM_VENDOR_BUCKET_SPEC_INVALID,
	IWL_MVM_VENDOR_BUCKET_SPEC_INDEX,
	IWL_MVM_VENDOR_BUCKET_SPEC_BAND,
	IWL_MVM_VENDOR_BUCKET_SPEC_PERIOD,
	IWL_MVM_VENDOR_BUCKET_SPEC_REPORT_MODE,
	IWL_MVM_VENDOR_BUCKET_SPEC_CHANNELS,
	IWL_MVM_VENDOR_BUCKET_SPEC_MAX_PERIOD,
	IWL_MVM_VENDOR_BUCKET_SPEC_EXPONENT,
	IWL_MVM_VENDOR_BUCKET_SPEC_STEP_CNT,
	NUM_IWL_MVM_VENDOR_BUCKET_SPEC,
	MAX_IWL_MVM_VENDOR_BUCKET_SPEC =
		NUM_IWL_MVM_VENDOR_BUCKET_SPEC - 1,
};

/**
 * enum iwl_mvm_vendor_results_event_type - scan results available event type
 * @IWL_MVM_VENDOR_RESULTS_NOTIF_BUFFER_FULL: scan results available was
 *	reported because scan results buffer has reached the report threshold.
 * @IWL_MVM_VENDOR_RESULTS_NOTIF_BUCKET_END: scan results available was reported
 *	because scan of a bucket was completed.
 * @NUM_IWL_VENDOR_RESULTS_NOTIF_EVENT_TYPE: number of defined gscan results
 *	notification event types.
 *
 * Note that these must match the firmware API.
 */
enum iwl_mvm_vendor_results_event_type {
	IWL_MVM_VENDOR_RESULTS_NOTIF_BUFFER_FULL,
	IWL_MVM_VENDOR_RESULTS_NOTIF_BUCKET_END,
	NUM_IWL_VENDOR_RESULTS_NOTIF_EVENT_TYPE,
};

/**
 * enum iwl_mvm_vendor_gscan_result - gscan scan result
 * @IWL_MVM_VENDOR_GSCAN_RESULT_INVALID: attribute number 0 is reserved.
 * @IWL_MVM_VENDOR_GSCAN_RESULT_TIMESTAMP: time since boot (in usecs) when
 *	the result was retrieved.
 * @IWL_MVM_VENDOR_GSCAN_RESULT_SSID: SSID.
 * @IWL_MVM_VENDOR_GSCAN_RESULT_BSSID: BSSID of the BSS (6 octets).
 * @IWL_MVM_VENDOR_GSCAN_RESULT_CHANNEL: channel frequency in MHz.
 * @IWL_MVM_VENDOR_GSCAN_RESULT_RSSI: signal strength in dB.
 * @IWL_MVM_VENDOR_GSCAN_RESULT_FRAME: the whole beacon/probe response
 *	frame data including the header.
 * @IWL_MVM_VENDOR_GSCAN_RESULT_BEACON_PERIOD: period advertised in the beacon.
 * @IWL_MVM_VENDOR_GSCAN_RESULT_CAPABILITY: capabilities advertised in the
 *	beacon / probe response.
 * @IWL_MVM_VENDOR_GSCAN_RESULT_PAD: used for padding, ignore
 * @NUM_IWL_MVM_VENDOR_GSCAN_RESULT: number of scan result attributes.
 * @MAX_IWL_MVM_VENDOR_GSCAN_RESULT: highest scan result attribute number.
 */
enum iwl_mvm_vendor_gscan_result {
	IWL_MVM_VENDOR_GSCAN_RESULT_INVALID,
	IWL_MVM_VENDOR_GSCAN_RESULT_TIMESTAMP,
	IWL_MVM_VENDOR_GSCAN_RESULT_SSID,
	IWL_MVM_VENDOR_GSCAN_RESULT_BSSID,
	IWL_MVM_VENDOR_GSCAN_RESULT_CHANNEL,
	IWL_MVM_VENDOR_GSCAN_RESULT_RSSI,
	IWL_MVM_VENDOR_GSCAN_RESULT_FRAME,
	IWL_MVM_VENDOR_GSCAN_RESULT_BEACON_PERIOD,
	IWL_MVM_VENDOR_GSCAN_RESULT_CAPABILITY,
	IWL_MVM_VENDOR_GSCAN_RESULT_PAD,
	NUM_IWL_MVM_VENDOR_GSCAN_RESULT,
	MAX_IWL_MVM_VENDOR_GSCAN_RESULT =
		NUM_IWL_MVM_VENDOR_GSCAN_RESULT - 1,
};

/**
 * enum iwl_mvm_vendor_gscan_cached_scan_res - gscan cached scan result
 * @IWL_MVM_VENDOR_GSCAN_CACHED_RES_INVALID: attribute number 0 is reserved.
 * @IWL_MVM_VENDOR_GSCAN_CACHED_RES_SCAN_ID: unique ID for this cached result.
 * @IWL_MVM_VENDOR_GSCAN_CACHED_RES_FLAGS: additional information about this
 *	scan iteration.
 * @IWL_MVM_VENDOR_GSCAN_CACHED_RES_APS: APs reported in this scan iteration.
 * @NUM_IWL_MVM_VENDOR_GSCAN_CACHED_RES: number of scan result attributes.
 * @MAX_IWL_MVM_VENDOR_GSCAN_CACHED_RES: highest scan result attribute number.
 */
enum iwl_mvm_vendor_gscan_cached_scan_res {
	IWL_MVM_VENDOR_GSCAN_CACHED_RES_INVALID,
	IWL_MVM_VENDOR_GSCAN_CACHED_RES_SCAN_ID,
	IWL_MVM_VENDOR_GSCAN_CACHED_RES_FLAGS,
	IWL_MVM_VENDOR_GSCAN_CACHED_RES_APS,
	NUM_IWL_MVM_VENDOR_GSCAN_CACHED_RES,
	MAX_IWL_MVM_VENDOR_GSCAN_CACHED_RES =
		NUM_IWL_MVM_VENDOR_GSCAN_CACHED_RES - 1,
};

/**
 * enum iwl_mvm_vendor_ap_threshold_param - parameters for tracking AP's RSSI
 * @IWL_MVM_VENDOR_AP_THRESHOLD_PARAM_INVALID: attribute number 0 is reserved.
 * @IWL_MVM_VENDOR_AP_BSSID: BSSID of the BSS (6 octets)
 * @IWL_MVM_VENDOR_AP_LOW_RSSI_THRESHOLD: low RSSI threshold. in dB.
 * @IWL_MVM_VENDOR_AP_HIGH_RSSI_THRESHOLD: high RSSI threshold. in dB.
 * @NUM_IWL_MVM_VENDOR_GSCAN_AP_THRESHOLD_PARAM: number of ap threshold param
 *	attributes.
 * @MAX_IWL_MVM_VENDOR_GSCAN_AP_THRESHOLD_PARAM: highest ap threshold param
 *	attribute number.
 */
enum iwl_mvm_vendor_ap_threshold_param {
	IWL_MVM_VENDOR_AP_THRESHOLD_PARAM_INVALID,
	IWL_MVM_VENDOR_AP_BSSID,
	IWL_MVM_VENDOR_AP_LOW_RSSI_THRESHOLD,
	IWL_MVM_VENDOR_AP_HIGH_RSSI_THRESHOLD,
	NUM_IWL_MVM_VENDOR_GSCAN_AP_THRESHOLD_PARAM,
	MAX_IWL_MVM_VENDOR_GSCAN_AP_THRESHOLD_PARAM =
		NUM_IWL_MVM_VENDOR_GSCAN_AP_THRESHOLD_PARAM - 1,
};

/**
 * enum iwl_mvm_vendor_hotlist_ap_status - whether an AP was found or lost
 * @IWL_MVM_VENDOR_HOTLIST_AP_FOUND: beacon from this AP was received with RSSI
 *	above the configured high threshold.
 * @IWL_MVM_VENDOR_HOTLIST_AP_LOST: beacon from this AP was received with RSSI
 *	below the configured low threshold.
 * @NUM_IWL_MVM_VENDOR_HOTLIST_AP_STATUS: number of defined AP statuses.
 *
 * Note that these must match the firmware API.
 */
enum iwl_mvm_vendor_hotlist_ap_status {
	IWL_MVM_VENDOR_HOTLIST_AP_FOUND,
	IWL_MVM_VENDOR_HOTLIST_AP_LOST,
	NUM_IWL_MVM_VENDOR_HOTLIST_AP_STATUS,
};

/**
 * enum iwl_mvm_vendor_significant_change_result - significant change result
 * @IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_INVALID: attribute number 0 is reserved
 * @IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_CHANNEL: channel number of the reported
 *	AP.
 * @IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_BSSID: BSSID.
 * @IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_RSSI_HISTORY: array of RSSI samples for
 *	the reported AP. in dB.
 * @NUM_IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_RESULT: number of significant change
 *	attriutes.
 * @MAX_IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_RESULT: highest significant change
 *	result attribute number.
 */
enum iwl_mvm_vendor_significant_change_result {
	IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_INVALID,
	IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_CHANNEL,
	IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_BSSID,
	IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_RSSI_HISTORY,
	NUM_IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_RESULT,
	MAX_IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_RESULT =
	NUM_IWL_MVM_VENDOR_SIGNIFICANT_CHANGE_RESULT - 1,
};

/**
 * enum iwl_mvm_vendor_rxfilter_flags - the type of request rxfilter
 *
 * @IWL_MVM_VENDOR_RXFILTER_UNICAST: control unicast Rx filter
 * @IWL_MVM_VENDOR_RXFILTER_MCAST4: control IPv4 multicast Rx filter
 * @IWL_MVM_VENDOR_RXFILTER_MCAST6: control IPv4 multicast Rx filter
 * @IWL_MVM_VENDOR_RXFILTER_EINVAL: no Rx filter command was set
 *
 */
enum iwl_mvm_vendor_rxfilter_flags {
	IWL_MVM_VENDOR_RXFILTER_UNICAST = 1 << 0,
	IWL_MVM_VENDOR_RXFILTER_MCAST4 = 1 << 2,
	IWL_MVM_VENDOR_RXFILTER_MCAST6 = 1 << 3,
	IWL_MVM_VENDOR_RXFILTER_EINVAL = 1 << 7,
};

/**
 * enum iwl_mvm_vendor_rxfilter_op - the operation associated with a filter
 *
 * @IWL_MVM_VENDOR_RXFILTER_OP_PASS: pass frames matching the filter
 * @IWL_MVM_VENDOR_RXFILTER_OP_DROP: drop frames matching the filter
 */
enum iwl_mvm_vendor_rxfilter_op {
	IWL_MVM_VENDOR_RXFILTER_OP_PASS,
	IWL_MVM_VENDOR_RXFILTER_OP_DROP,
};

/*
 * enum iwl_mvm_vendor_nr_chan_width - channel width definitions
 *
 * The values in this enum correspond to the values defined in
 * IEEE802.11-2016, table 9-153.
 */
enum iwl_mvm_vendor_nr_chan_width {
	IWL_MVM_VENDOR_CHAN_WIDTH_20,
	IWL_MVM_VENDOR_CHAN_WIDTH_40,
	IWL_MVM_VENDOR_CHAN_WIDTH_80,
	IWL_MVM_VENDOR_CHAN_WIDTH_160,
	IWL_MVM_VENDOR_CHAN_WIDTH_80P80,
};

/*
 * enum iwl_mvm_vendor_phy_type - neighbor report phy types
 *
 * The values in this enum correspond to the values defined in
 * IEEE802.11-2016, Annex C.
 */
enum iwl_mvm_vendor_phy_type {
	IWL_MVM_VENDOR_PHY_TYPE_UNSPECIFIED,
	IWL_MVM_VENDOR_PHY_TYPE_DSSS = 2,
	IWL_MVM_VENDOR_PHY_TYPE_OFDM = 4,
	IWL_MVM_VENDOR_PHY_TYPE_HRDSSS = 5,
	IWL_MVM_VENDOR_PHY_TYPE_ERP = 6,
	IWL_MVM_VENDOR_PHY_TYPE_HT = 7,
	IWL_MVM_VENDOR_PHY_TYPE_DMG = 8,
	IWL_MVM_VENDOR_PHY_TYPE_VHT = 9,
	IWL_MVM_VENDOR_PHY_TYPE_TVHT = 10,
};

/**
 * enum iwl_mvm_vendor_neighbor_report - Neighbor report for one AP
 *
 * @__IWL_MVM_VENDOR_NEIGHBOR_INVALID: attribute number 0 is reserved
 * @IWL_MVM_VENDOR_NEIGHBOR_BSSID: the BSSID of the neighbor AP.
 * @IWL_MVM_VENDOR_NEIGHBOR_BSSID_INFO: the BSSID information field as
 *	defined in IEEE802.11-2016, figure 9-296 (u32)
 * @IWL_MVM_VENDOR_NEIGHBOR_OPERATING_CLASS: the operating class of the
 *	neighbor AP (u8)
 * @IWL_MVM_VENDOR_NEIGHBOR_CHANNEL: the primary channel number of the
 *	neighbor AP (u8)
 * @IWL_MVM_VENDOR_NEIGHBOR_PHY_TYPE: the phy type of the neighbor AP
 *	as specified in &enum iwl_mvm_vendor_phy_type (u8)
 * @IWL_MVM_VENDOR_NEIGHBOR_CHANNEL_WIDTH: u32 attribute containing one of the
 *	values of &enum iwl_mvm_vendor_nr_chan_width, describing the
 *	channel width.
 * @IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_0: Center frequency of the first
 *	part of the channel, used for anything but 20 MHz bandwidth.
 * @IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_1: Center frequency of the second
 *	part of the channel, used only for 80+80 MHz bandwidth.
 * @IWL_MVM_VENDOR_NEIGHBOR_LCI: the LCI info of the neighbor AP. Optional.
 *	Binary attribute.
 * @IWL_MVM_VENDOR_NEIGHBOR_CIVIC: the CIVIC info of the neighbor AP. Optional.
 *	Binary attribute.
 * @NUM_IWL_MVM_VENDOR_NEIGHBOR_REPORT: num of neighbor report attributes
 * @MAX_IWL_MVM_VENDOR_NEIGHBOR_REPORT: highest neighbor report attribute
 *	number.
 */
enum iwl_mvm_vendor_neighbor_report {
	__IWL_MVM_VENDOR_NEIGHBOR_INVALID,
	IWL_MVM_VENDOR_NEIGHBOR_BSSID,
	IWL_MVM_VENDOR_NEIGHBOR_BSSID_INFO,
	IWL_MVM_VENDOR_NEIGHBOR_OPERATING_CLASS,
	IWL_MVM_VENDOR_NEIGHBOR_CHANNEL,
	IWL_MVM_VENDOR_NEIGHBOR_PHY_TYPE,
	IWL_MVM_VENDOR_NEIGHBOR_CHANNEL_WIDTH,
	IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_0,
	IWL_MVM_VENDOR_NEIGHBOR_CENTER_FREQ_IDX_1,
	IWL_MVM_VENDOR_NEIGHBOR_LCI,
	IWL_MVM_VENDOR_NEIGHBOR_CIVIC,

	NUM_IWL_MVM_VENDOR_NEIGHBOR_REPORT,
	MAX_IWL_MVM_VENDOR_NEIGHBOR_REPORT =
		NUM_IWL_MVM_VENDOR_NEIGHBOR_REPORT - 1,
};

/**
 * enum iwl_vendor_sar_per_chain_geo_table - per chain tx power table
 *
 * @IWL_VENDOR_SAR_GEO_INVALID: attribute number 0 is reserved.
 * @IWL_VENDOR_SAR_GEO_CHAIN_A_OFFSET: allowed offset for chain a (u8).
 * @IWL_VENDOR_SAR_GEO_CHAIN_B_OFFSET: allowed offset for chain b (u8).
 * @IWL_VENDOR_SAR_GEO_MAX_TXP: maximum allowed tx power (u8).
 */
enum iwl_vendor_sar_per_chain_geo_table {
	IWL_VENDOR_SAR_GEO_INVALID,
	IWL_VENDOR_SAR_GEO_CHAIN_A_OFFSET,
	IWL_VENDOR_SAR_GEO_CHAIN_B_OFFSET,
	IWL_VENDOR_SAR_GEO_MAX_TXP,
};

/**
 * enum iwl_vendor_fips_test_vector_sha_type - SHA types for FIPS tests
 *
 * @IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA1: SHA1
 * @IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA256: SHA256
 * @IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA384: SHA384
 */
enum iwl_vendor_fips_test_vector_sha_type {
	IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA1,
	IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA256,
	IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA384,
};

/**
 * enum iwl_vendor_fips_test_vector_sha - test vector for SHA tests
 *
 * @IWL_VENDOR_FIPS_TEST_VECTOR_SHA_INVALID: attribute number 0 is reserved.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE: which SHA function to use. One of
 *	&enum iwl_vendor_fips_test_vector_sha_type.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_SHA_MSG: the message to generate the digest for.
 * @NUM_IWL_VENDOR_FIPS_TEST_VECTOR_SHA: number of SHA test vector attributes.
 * @MAX_IWL_VENDOR_FIPS_TEST_VECTOR_SHA: highest SHA test vector attribute.
 */
enum iwl_vendor_fips_test_vector_sha {
	IWL_VENDOR_FIPS_TEST_VECTOR_SHA_INVALID,
	IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE,
	IWL_VENDOR_FIPS_TEST_VECTOR_SHA_MSG,

	NUM_IWL_VENDOR_FIPS_TEST_VECTOR_SHA,
	MAX_IWL_VENDOR_FIPS_TEST_VECTOR_SHA =
		NUM_IWL_VENDOR_FIPS_TEST_VECTOR_SHA - 1,
};

/**
 * enum iwl_vendor_fips_test_vector_hmac_kdf - test vector for HMAC/KDF tests
 *
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_INVALID: attribute number 0 is
 *	reserved.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_TYPE: which HMAC-SHA function to use.
 *	One of &enum iwl_vendor_fips_test_vector_sha_type.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_KEY: key input for the HMAC-SHA
 *	function.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_MSG: the message to generate the
 *	digest for.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_RES_LEN: the requested digest length in
 *	bytes.
 * @NUM_IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF: number of HMAC/KDF test vector
 *	attributes.
 * @MAX_IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF: highest HMAC/KDF test vector
 *	attribute.
 */
enum iwl_vendor_fips_test_vector_hmac_kdf {
	IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_INVALID,
	IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_TYPE,
	IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_KEY,
	IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_MSG,
	IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_RES_LEN,

	NUM_IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF,
	MAX_IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF =
		NUM_IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF - 1,
};

/**
 * enum iwl_vendor_fips_test_vector_flags - flags for FIPS HW test vector
 * @IWL_VENDOR_FIPS_TEST_VECTOR_FLAGS_ENCRYPT: if this is set, the requested
 *	operation is encryption. Otherwise the requested operation is
 *	decryption.
 */
enum iwl_vendor_fips_test_vector_flags {
	IWL_VENDOR_FIPS_TEST_VECTOR_FLAGS_ENCRYPT = BIT(0),
};

/**
 * enum iwl_vendor_fips_test_vector_hw - test vector for FIPS HW tests
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HW_INVALID: attribute number 0 is reserved.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HW_KEY: the key to use for
 *	encryption/decryption. For CCM, only 128-bit key is supported.
 *	For AES and GCM, 128-bit and 256-bit keys are supported.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HW_NONCE: for CCM use 13 bytes, for GCM only 12
 *	bytes. Not valid for AES tests.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HW_AAD: adata. maximum supported size is 30
 *	bytes. Not valid for AES tests.
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HW_PAYLOAD: for encryption, this is the
 *	plaintext to encrypt. For decryption, this is the ciphertext + MIC (8
 *	bytes of MIC for CCM, 16 bytes for GCM).
 * @IWL_VENDOR_FIPS_TEST_VECTOR_HW_FLAGS: &enum iwl_vendor_fips_test_vector_flags.
 * @NUM_IWL_VENDOR_FIPS_TEST_VECTOR_HW: number of hw test vector attributes.
 * @MAX_IWL_VENDOR_FIPS_TEST_VECTOR_HW: highest hw test vector attribute.
 */
enum iwl_vendor_fips_test_vector_hw {
	IWL_VENDOR_FIPS_TEST_VECTOR_HW_INVALID,
	IWL_VENDOR_FIPS_TEST_VECTOR_HW_KEY,
	IWL_VENDOR_FIPS_TEST_VECTOR_HW_NONCE,
	IWL_VENDOR_FIPS_TEST_VECTOR_HW_AAD,
	IWL_VENDOR_FIPS_TEST_VECTOR_HW_PAYLOAD,
	IWL_VENDOR_FIPS_TEST_VECTOR_HW_FLAGS,

	NUM_IWL_VENDOR_FIPS_TEST_VECTOR_HW,
	MAX_IWL_VENDOR_FIPS_TEST_VECTOR_HW =
		NUM_IWL_VENDOR_FIPS_TEST_VECTOR_HW - 1,
};

enum iwl_vendor_auth_akm_mode {
	IWL_VENDOR_AUTH_OPEN,
	IWL_VENDOR_AUTH_SHARED,
	IWL_VENDOR_AUTH_WPA = 0x3,
	IWL_VENDOR_AUTH_WPA_PSK,
	IWL_VENDOR_AUTH_RSNA = 0x6,
	IWL_VENDOR_AUTH_RSNA_PSK,
	IWL_VENDOR_AUTH_SAE = 0x9,
	IWL_VENDOR_AUTH_MAX,
};

/**
 * enum iwl_mvm_vendor_attr - attributes used in vendor commands
 * @__IWL_MVM_VENDOR_ATTR_INVALID: attribute 0 is invalid
 * @IWL_MVM_VENDOR_ATTR_LOW_LATENCY: low-latency flag attribute
 * @IWL_MVM_VENDOR_ATTR_VIF_ADDR: interface MAC address
 * @IWL_MVM_VENDOR_ATTR_COUNTRY: MCC to set, for regulatory information (u16)
 * @IWL_MVM_VENDOR_ATTR_FILTER_ARP_NA: filter gratuitous ARP and unsolicited
 *	Neighbor Advertisement frames
 * @IWL_MVM_VENDOR_ATTR_FILTER_GTK: filter Filtering Frames Encrypted using
 *	the GTK
 * @IWL_MVM_VENDOR_ATTR_ADDR: MAC address
 * @IWL_MVM_VENDOR_ATTR_TX_BYTES: number of bytes transmitted to peer
 * @IWL_MVM_VENDOR_ATTR_RX_BYTES: number of bytes received from peer
 * @IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24: TX power limit for 2.4 GHz
 *	(s32 in units of 1/8 dBm)
 * @IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L: TX power limit for 5.2 GHz low (as 2.4)
 * @IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H: TX power limit for 5.2 GHz high (as 2.4)
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_SCAN_CACHE_SIZE: scan cache size
 *	(in bytes)
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_SCAN_BUCKETS: maximum number of channel
 *	buckets
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_AP_CACHE_PER_SCAN: maximum number of AP's
 *	that can be stored per scan
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_RSSI_SAMPLE_SIZE: number of RSSI samples
 *	used for averaging RSSI
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_SCAN_REPORTING_THRESHOLD: max possible
 *	report threshold. see %IWL_MVM_VENDOR_ATTR_GSCAN_START_REPORT_THRESHOLD
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_HOTLIST_APS: maximum number of entries for
 *	hotlist AP's
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_SIGNIFICANT_CHANGE_APS: maximum number of
 *	entries for significant change AP's
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_BSSID_HISTORY_ENTRIES: number of
 *	BSSID/RSSI entries that the device can hold
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR: mac address to be used on gscan scans
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR_MASK: mac address mask. Bits set to 0
 *	will be copied from %IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR. Bits set to 1
 *	will be randomized
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_AP_PER_SCAN: number of AP's to store in each
 *	scan in the BSSID/RSSI history buffer (keep the highest RSSI AP's)
 * @IWL_MVM_VENDOR_ATTR_GSCAN_REPORT_THRESHOLD: report that scan results
 *	are available when buffer is that much full. In percentage.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_BUCKET_SPECS: array of bucket specifications for
 *	this gscan start command. Each bucket spec is a nested attribute of
 *	&enum iwl_mvm_vendor_gscan_bucket_spec.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_RESULTS_EVENT_TYPE: gscan results event type as
 *	specified in &enum iwl_mvm_vendor_results_event_type.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_RESULTS: array of gscan results. Each result is a
 *	nested attribute of &enum iwl_mvm_vendor_gscan_result.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_LOST_AP_SAMPLE_SIZE: number of samples to confirm
 *	ap loss.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_AP_LIST: an array of nested attributes of
 *	&enum iwl_mvm_vendor_ap_threshold_param.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_RSSI_SAMPLE_SIZE: number of samples for averaging
 *	RSSI
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MIN_BREACHING: number of APs breaching threshold
 * @IWL_MVM_VENDOR_ATTR_GSCAN_HOTLIST_AP_STATUS: indicates if a reported AP was
 *	lost or found as specified in &enum iwl_mvm_vendor_hotlist_ap_status.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_SIG_CHANGE_RESULTS: array of significant
 *	change results. Each result is a nested attribute of &enum
 *	iwl_mvm_vendor_significant_change_result.
 * @IWL_MVM_VENDOR_ATTR_RXFILTER: u32 attribute.
 *      See %iwl_mvm_vendor_rxfilter_flags.
 * @IWL_MVM_VENDOR_ATTR_RXFILTER_OP: u32 attribute.
 *      See %iwl_mvm_vendor_rxfilter_op.
 * @IWL_MVM_VENDOR_ATTR_DBG_COLLECT_TRIGGER: description of collect debug data
 *	trigger.
 * @IWL_MVM_VENDOR_ATTR_NAN_FAW_FREQ: u32 attribute. Frequency (in MHz) to be
 *	used for NAN further availability.
 * @IWL_MVM_VENDOR_ATTR_NAN_FAW_SLOTS: u8 attribute. Number of 16TU slots
 *	the NAN device will be available on it's FAW between DWs.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_HOTLIST_SSIDS: maximum number of entries for
 *	hotlist SSID's
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_NUM_EPNO_NETWORKS: max number of epno entries
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_NUM_EPNO_NETWORKS_BY_SSID: max number of epno
 *	entries if ssid is specified
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_NUM_WHITE_LISTED_SSID: max number of pass
 *	listed SSIDs
 * @IWL_MVM_VENDOR_ATTR_GSCAN_MAX_NUM_BLACK_LISTED_SSID: max number of block
 *	listed SSIDs
 * @IWL_MVM_VENDOR_ATTR_WIPHY_FREQ: frequency of the selected channel in MHz,
 *	defines the channel together with the attributes
 *	%IWL_MVM_VENDOR_ATTR_CHANNEL_WIDTH and if needed
 *	%IWL_MVM_VENDOR_ATTR_CENTER_FREQ1 and
 *	%IWL_MVM_VENDOR_ATTR_CENTER_FREQ2.
 * @IWL_MVM_VENDOR_ATTR_CHANNEL_WIDTH: u32 attribute containing one of the
 *	values of &enum nl80211_chan_width, describing the channel width.
 *	See the documentation of the enum for more information.
 * @IWL_MVM_VENDOR_ATTR_CENTER_FREQ1: Center frequency of the first part of the
 *	channel, used for anything but 20 MHz bandwidth.
 * @IWL_MVM_VENDOR_ATTR_CENTER_FREQ2: Center frequency of the second part of
 *	the channel, used only for 80+80 MHz bandwidth.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_REPORT_THRESHOLD_NUM: report that scan results
 *	are available when buffer is that much full. In number of scans.
 * @IWL_MVM_VENDOR_ATTR_GSCAN_CACHED_RESULTS: array of gscan cached results.
 *	Each result is a nested attribute of
 *	&enum iwl_mvm_vendor_gscan_cached_scan_res.
 * @IWL_MVM_VENDOR_ATTR_LAST_MSG: Indicates that this message is the last one
 *	in the series of messages. (flag)
 * @IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE: SAR table idx for chain A.
 *	This is a u8.
 * @IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE: SAR table idx for chain B.
 *	This is a u8.
 * @IWL_MVM_VENDOR_ATTR_SAR_ENABLED_PROFILE_NUM: number of enabled SAR profile
 *	This is a u8.
 * @IWL_MVM_VENDOR_ATTR_SSID: SSID (binary attribute, 0..32 octets)
 * @IWL_MVM_VENDOR_ATTR_NEIGHBOR_LCI: Flag attribute specifying that the
 *	neighbor request shall query for LCI information.
 * @IWL_MVM_VENDOR_ATTR_NEIGHBOR_CIVIC: Flag attribute specifying that the
 *	neighbor request shall query for CIVIC information.
 * @IWL_MVM_VENDOR_ATTR_NEIGHBOR_REPORT: A list of neighbor APs as received in a
 *	neighbor report frame. Each AP is a nested attribute of
 *	&enum iwl_mvm_vendor_neighbor_report.
 * @IWL_MVM_VENDOR_ATTR_SAR_GEO_PROFILE: geo profile info.
 *	see &enum iwl_vendor_sar_per_chain_geo_table.
 * @IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_SHA: data vector for FIPS SHA test.
 *	&enum iwl_vendor_fips_test_vector_sha.
 * @IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HMAC: data vector for FIPS HMAC test.
 *	&enum iwl_vendor_fips_test_vector_hmac_kdf.
 * @IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_KDF: data vector for FIPS KDF test.
 *	&enum iwl_vendor_fips_test_vector_hmac_kdf.
 * @IWL_MVM_VENDOR_ATTR_FIPS_TEST_RESULT: FIPS test result. Contains the
 *	output of the requested function.
 * @IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_AES: data vector for FIPS AES HW
 *	test. &enum iwl_vendor_fips_test_vector_hw.
 * @IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_CCM: data vector for FIPS CCM HW
 *	test. &enum iwl_vendor_fips_test_vector_hw.
 * @IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_GCM: data vector for FIPS GCM HW
 *	test. &enum iwl_vendor_fips_test_vector_hw.
 * @IWL_MVM_VENDOR_ATTR_CSI_HDR: CSI header
 * @IWL_MVM_VENDOR_ATTR_CSI_DATA: CSI data
 * @IWL_MVM_VENDOR_ATTR_STA_TK: the TK to use for PMF encryption for the
 *	station with the mac address specified in &IWL_MVM_VENDOR_ATTR_ADDR.
 * @IWL_MVM_VENDOR_ATTR_STA_HLTK: the HLTK to use for secure LTF bits
 *	generation for the station with the mac address specified in
 *	&IWL_MVM_VENDOR_ATTR_ADDR.
 * @IWL_MVM_VENDOR_ATTR_STA_CIPHER: the cipher to use for the station with the
 *	mac address specified in &IWL_MVM_VENDOR_ATTR_ADDR.
 *	One of WLAN_CIPHER_SUITE_*.
 * @IWL_MVM_VENDOR_ATTR_ROAMING_FORBIDDEN: u8 attribute. Indicates whether
 *	roaming is forbidden or not. Value 1 means roaming is forbidden,
 *	0 mean roaming is allowed.
 * @IWL_MVM_VENDOR_ATTR_AUTH_MODE: u32 attribute. Authentication mode type
 *	as specified in &enum iwl_vendor_auth_akm_mode.
 * @IWL_MVM_VENDOR_ATTR_CHANNEL_NUM: u8 attribute. Contains channel number.
 * @IWL_MVM_VENDOR_ATTR_BAND: u8 attribute.
 *	0 for 2.4 GHz band, 1 for 5.2GHz band and 2 for 6GHz band.
 * @IWL_MVM_VENDOR_ATTR_COLLOC_CHANNEL: u32 attribute. Channel number of
 *	collocated AP. Relevant for 6GHz AP info.
 * @IWL_MVM_VENDOR_ATTR_COLLOC_ADDR: MAC address of a collocated AP.
 *	Relevant for 6GHz AP info.
 * @IWL_MVM_VENDOR_ATTR_PPAG_TABLE: nested attribute. Contains a binary
 *	attribute for each chain, each of them contains the ppag
 *	values for all sub-bands.
 * @IWL_MVM_VENDOR_ATTR_PPAG_NUM_SUB_BANDS: u32 attribute. The number of
 *	sub-bands that we have in the ppag table.
 * @IWL_MVM_VENDOR_ATTR_SAR_TABLE: nested attribute. Contains a nested
 *	attribute for each profile, each of them contains binary attribute
 *	for each chain.
 * @IWL_MVM_VENDOR_ATTR_SAR_VER: u32 attribute. Contains the SAR table version.
 * @IWL_MVM_VENDOR_ATTR_GEO_SAR_TABLE: nested attribute. Contains a
 *	nested attribute for each profile, each of them contains
 *	a nested attribute for each band. See &enum
 *	iwl_vendor_sar_per_chain_geo_table.
 * @IWL_MVM_VENDOR_ATTR_GEO_SAR_VER: u32 attribute. Contains the GEO SAR
 *	table version
 * @IWL_MVM_VENDOR_ATTR_SGOM_TABLE: binary attribute.
 * @IWL_MVM_VENDOR_ATTR_RFIM_BANDS: RFIM bands
 * @IWL_MVM_VENDOR_ATTR_RFIM_CAPA: RFIM capabilities (u16)
 * @IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS: RFIM channels
 * @IWL_MVM_VENDOR_ATTR_RFIM_FREQ: RFIM frequency (u16)
 * @IWL_MVM_VENDOR_ATTR_RFIM_INFO: overall RFIM info (nested)
 * @IWL_MVM_VENDOR_ATTR_RFIM_CNVI_MASTER: CNVI master configuration (u32)
 * @IWL_MVM_VENDOR_ATTR_LINKS_INFO: Link information (nested)
 * @IWL_MVM_VENDOR_ATTR_CHANNEL: Operating channel (u8)
 * @IWL_MVM_VENDOR_ATTR_PHY_BAND: Operating band (u8)
 *	&PHY_BAND_5 for 5 GHz band, &PHY_BAND_24 for 2.4 GHz band and
 *	&PHY_BAND_6 for 6 GHz band.
 * @IWL_MVM_VENDOR_ATTR_RSSI: average beacon rssi (u8)
 *
 * @NUM_IWL_MVM_VENDOR_ATTR: number of vendor attributes
 * @MAX_IWL_MVM_VENDOR_ATTR: highest vendor attribute number
 */
enum iwl_mvm_vendor_attr {
	__IWL_MVM_VENDOR_ATTR_INVALID				= 0x00,
	IWL_MVM_VENDOR_ATTR_LOW_LATENCY				= 0x01,
	IWL_MVM_VENDOR_ATTR_VIF_ADDR				= 0x02,
	/* 0x3 is deprecated */
	/* 0x4 is deprecated */
	/* 0x5 is deprecated */
	/* 0x6 is deprecated */
	IWL_MVM_VENDOR_ATTR_COUNTRY				= 0x07,
	IWL_MVM_VENDOR_ATTR_FILTER_ARP_NA			= 0x08,
	IWL_MVM_VENDOR_ATTR_FILTER_GTK				= 0x09,
	IWL_MVM_VENDOR_ATTR_ADDR				= 0x0a,
	IWL_MVM_VENDOR_ATTR_TX_BYTES				= 0x0b,
	IWL_MVM_VENDOR_ATTR_RX_BYTES				= 0x0c,
	IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24			= 0x0d,
	IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L			= 0x0e,
	IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H			= 0x0f,
	/* 0x10 is deprecated */
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_SCAN_CACHE_SIZE		= 0x11,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_SCAN_BUCKETS		= 0x12,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_AP_CACHE_PER_SCAN		= 0x13,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_RSSI_SAMPLE_SIZE		= 0x14,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_SCAN_REPORTING_THRESHOLD	= 0x15,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_HOTLIST_APS		= 0x16,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_SIGNIFICANT_CHANGE_APS	= 0x17,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_BSSID_HISTORY_ENTRIES	= 0x18,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR			= 0x19,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR_MASK			= 0x1a,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_AP_PER_SCAN		= 0x1b,
	IWL_MVM_VENDOR_ATTR_GSCAN_REPORT_THRESHOLD		= 0x1c,
	IWL_MVM_VENDOR_ATTR_GSCAN_BUCKET_SPECS			= 0x1d,
	IWL_MVM_VENDOR_ATTR_GSCAN_RESULTS_EVENT_TYPE		= 0x1e,
	IWL_MVM_VENDOR_ATTR_GSCAN_RESULTS			= 0x1f,
	IWL_MVM_VENDOR_ATTR_GSCAN_LOST_AP_SAMPLE_SIZE		= 0x20,
	IWL_MVM_VENDOR_ATTR_GSCAN_AP_LIST			= 0x21,
	IWL_MVM_VENDOR_ATTR_GSCAN_RSSI_SAMPLE_SIZE		= 0x22,
	IWL_MVM_VENDOR_ATTR_GSCAN_MIN_BREACHING			= 0x23,
	IWL_MVM_VENDOR_ATTR_GSCAN_HOTLIST_AP_STATUS		= 0x24,
	IWL_MVM_VENDOR_ATTR_GSCAN_SIG_CHANGE_RESULTS		= 0x25,
	IWL_MVM_VENDOR_ATTR_RXFILTER				= 0x26,
	IWL_MVM_VENDOR_ATTR_RXFILTER_OP				= 0x27,
	IWL_MVM_VENDOR_ATTR_DBG_COLLECT_TRIGGER			= 0x28,
	IWL_MVM_VENDOR_ATTR_NAN_FAW_FREQ			= 0x29,
	IWL_MVM_VENDOR_ATTR_NAN_FAW_SLOTS			= 0x2a,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_HOTLIST_SSIDS		= 0x2b,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_NUM_EPNO_NETWORKS		= 0x2c,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_NUM_EPNO_NETWORKS_BY_SSID	= 0x2d,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_NUM_WHITE_LISTED_SSID	= 0x2e,
	IWL_MVM_VENDOR_ATTR_GSCAN_MAX_NUM_BLACK_LISTED_SSID	= 0x2f,
	IWL_MVM_VENDOR_ATTR_WIPHY_FREQ				= 0x30,
	IWL_MVM_VENDOR_ATTR_CHANNEL_WIDTH			= 0x31,
	IWL_MVM_VENDOR_ATTR_CENTER_FREQ1			= 0x32,
	IWL_MVM_VENDOR_ATTR_CENTER_FREQ2			= 0x33,
	/* 0x34 is deprecated */
	/* 0x35 is deprecated */
	/* 0x36 is deprecated */
	IWL_MVM_VENDOR_ATTR_GSCAN_REPORT_THRESHOLD_NUM		= 0x37,
	IWL_MVM_VENDOR_ATTR_GSCAN_CACHED_RESULTS		= 0x38,
	IWL_MVM_VENDOR_ATTR_LAST_MSG				= 0x39,
	IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE			= 0x3a,
	IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE			= 0x3b,
	IWL_MVM_VENDOR_ATTR_SAR_ENABLED_PROFILE_NUM		= 0x3c,
	IWL_MVM_VENDOR_ATTR_SSID				= 0x3d,
	IWL_MVM_VENDOR_ATTR_NEIGHBOR_LCI			= 0x3e,
	IWL_MVM_VENDOR_ATTR_NEIGHBOR_CIVIC			= 0x3f,
	IWL_MVM_VENDOR_ATTR_NEIGHBOR_REPORT			= 0x40,
	IWL_MVM_VENDOR_ATTR_SAR_GEO_PROFILE			= 0x41,
	IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_SHA		= 0x42,
	IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HMAC		= 0x43,
	IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_KDF		= 0x44,
	IWL_MVM_VENDOR_ATTR_FIPS_TEST_RESULT			= 0x45,
	IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_AES		= 0x46,
	IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_CCM		= 0x47,
	IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HW_GCM		= 0x48,
	/* 0x49 - 0x4c are reserved */
	IWL_MVM_VENDOR_ATTR_CSI_HDR				= 0x4d,
	IWL_MVM_VENDOR_ATTR_CSI_DATA				= 0x4e,
	IWL_MVM_VENDOR_ATTR_STA_TK				= 0x4f,
	IWL_MVM_VENDOR_ATTR_STA_HLTK				= 0x50,
	IWL_MVM_VENDOR_ATTR_STA_CIPHER				= 0x51,
	IWL_MVM_VENDOR_ATTR_RFIM_INFO				= 0x52,
	IWL_MVM_VENDOR_ATTR_RFIM_FREQ				= 0x53,
	IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS			= 0x54,
	IWL_MVM_VENDOR_ATTR_RFIM_BANDS				= 0x55,
	IWL_MVM_VENDOR_ATTR_RFIM_CAPA				= 0x56,
	/* 0x57 is deprecated */
	/* 0x58 is deprecated */
	/* 0x59 is deprecated */
	/* 0x5a is deprecated */
	/* 0x5b is deprecated */
	/* 0x5c is deprecated */
	/* 0x5d is deprecated */
	/* 0x5e is deprecated */
	/* 0x5f is deprecated */
	/* 0x60 is deprecated */
	/* 0x61 is deprecated */
	/* 0x62 is deprecated */
	/* 0x63 is deprecated */
	IWL_MVM_VENDOR_ATTR_ROAMING_FORBIDDEN			= 0x64,
	IWL_MVM_VENDOR_ATTR_AUTH_MODE				= 0x65,
	IWL_MVM_VENDOR_ATTR_CHANNEL_NUM				= 0x66,
	IWL_MVM_VENDOR_ATTR_BAND				= 0x69,
	IWL_MVM_VENDOR_ATTR_COLLOC_CHANNEL			= 0x70,
	IWL_MVM_VENDOR_ATTR_COLLOC_ADDR				= 0x71,
	IWL_MVM_VENDOR_ATTR_PPAG_TABLE                          = 0x72,
	IWL_MVM_VENDOR_ATTR_PPAG_NUM_SUB_BANDS                  = 0x73,
	IWL_MVM_VENDOR_ATTR_SAR_TABLE                           = 0x74,
	IWL_MVM_VENDOR_ATTR_SAR_VER                             = 0x75,
	IWL_MVM_VENDOR_ATTR_GEO_SAR_TABLE                       = 0x76,
	IWL_MVM_VENDOR_ATTR_GEO_SAR_VER                         = 0x77,
	IWL_MVM_VENDOR_ATTR_SGOM_TABLE				= 0x78,
	IWL_MVM_VENDOR_ATTR_RFIM_CNVI_MASTER			= 0x79,
	IWL_MVM_VENDOR_ATTR_LINKS_INFO				= 0x7a,
	IWL_MVM_VENDOR_ATTR_CHANNEL				= 0x7b,
	IWL_MVM_VENDOR_ATTR_PHY_BAND				= 0x7c,
	IWL_MVM_VENDOR_ATTR_RSSI				= 0x7d,

	NUM_IWL_MVM_VENDOR_ATTR,
	MAX_IWL_MVM_VENDOR_ATTR = NUM_IWL_MVM_VENDOR_ATTR - 1,
};
#define IWL_MVM_VENDOR_FILTER_ARP_NA IWL_MVM_VENDOR_ATTR_FILTER_ARP_NA
#define IWL_MVM_VENDOR_FILTER_GTK IWL_MVM_VENDOR_ATTR_FILTER_GTK
#endif /* __VENDOR_CMD_H__ */
