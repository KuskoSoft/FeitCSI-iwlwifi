// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "mlo.h"

/* Block reasons helper */
#define HANDLE_EMLSR_BLOCKED_REASONS(HOW)	\
	HOW(PREVENTION)			\
	HOW(WOWLAN)			\
	HOW(FW)				\
	HOW(ROC)			\
	HOW(NON_BSS)

static const char *
iwl_mld_get_emlsr_blocked_string(enum iwl_mld_emlsr_blocked blocked)
{
	/* Using switch without "default" will warn about missing entries  */
	switch (blocked) {
#define REASON_CASE(x) case IWL_MLD_EMLSR_BLOCKED_##x: return #x;
	HANDLE_EMLSR_BLOCKED_REASONS(REASON_CASE)
#undef REASON_CASE
	}

	return "ERROR";
}

static void iwl_mld_print_emlsr_blocked(struct iwl_mld *mld, u32 mask)
{
#define NAME_FMT(x) "%s"
#define NAME_PR(x) (mask & IWL_MLD_EMLSR_BLOCKED_##x) ? "[" #x "]" : "",
	IWL_DEBUG_INFO(mld,
		       "EMLSR blocked = " HANDLE_EMLSR_BLOCKED_REASONS(NAME_FMT)
		       " (0x%x)\n",
		       HANDLE_EMLSR_BLOCKED_REASONS(NAME_PR)
		       mask);
#undef NAME_FMT
#undef NAME_PR
}

/* Exit reasons helper */
#define HANDLE_EMLSR_EXIT_REASONS(HOW)	\
	HOW(BLOCK)			\
	HOW(MISSED_BEACON)		\
	HOW(FAIL_ENTRY)			\
	HOW(CSA)			\
	HOW(EQUAL_BAND)			\
	HOW(BANDWIDTH)			\
	HOW(LOW_RSSI)

static const char *
iwl_mld_get_emlsr_exit_string(enum iwl_mld_emlsr_exit exit)
{
	/* Using switch without "default" will warn about missing entries  */
	switch (exit) {
#define REASON_CASE(x) case IWL_MLD_EMLSR_EXIT_##x: return #x;
	HANDLE_EMLSR_EXIT_REASONS(REASON_CASE)
#undef REASON_CASE
	}

	return "ERROR";
}

static void iwl_mld_print_emlsr_exit(struct iwl_mld *mld, u32 mask)
{
#define NAME_FMT(x) "%s"
#define NAME_PR(x) (mask & IWL_MLD_EMLSR_EXIT_##x) ? "[" #x "]" : "",
	IWL_DEBUG_INFO(mld,
		       "EMLSR exit = " HANDLE_EMLSR_EXIT_REASONS(NAME_FMT)
		       " (0x%x)\n",
		       HANDLE_EMLSR_EXIT_REASONS(NAME_PR)
		       mask);
#undef NAME_FMT
#undef NAME_PR
}

void iwl_mld_emlsr_prevent_done_wk(struct wiphy *wiphy, struct wiphy_work *wk)
{
	struct iwl_mld_vif *mld_vif = container_of(wk, struct iwl_mld_vif,
						   emlsr.prevent_done_wk.work);
	struct ieee80211_vif *vif =
		container_of((void *)mld_vif, struct ieee80211_vif, drv_priv);

	if (WARN_ON(!(mld_vif->emlsr.blocked_reasons &
		      IWL_MLD_EMLSR_BLOCKED_PREVENTION)))
		return;

	iwl_mld_unblock_emlsr(mld_vif->mld, vif,
			      IWL_MLD_EMLSR_BLOCKED_PREVENTION);
}

#define IWL_MLD_TRIGGER_LINK_SEL_TIME	(HZ * IWL_MLD_TRIGGER_LINK_SEL_TIME_SEC)

/* Exit reasons that can cause longer EMLSR prevention */
#define IWL_MLD_PREVENT_EMLSR_REASONS	IWL_MLD_EMLSR_EXIT_MISSED_BEACON
#define IWL_MLD_PREVENT_EMLSR_TIMEOUT	(HZ * 400)

#define IWL_MLD_EMLSR_PREVENT_SHORT	(HZ * 300)
#define IWL_MLD_EMLSR_PREVENT_LONG	(HZ * 600)

static void iwl_mld_check_emlsr_prevention(struct iwl_mld *mld,
					   struct iwl_mld_vif *mld_vif,
					   enum iwl_mld_emlsr_exit reason)
{
	unsigned long delay;

	/*
	 * Reset the counter if more than 400 seconds have passed between one
	 * exit and the other, or if we exited due to a different reason.
	 * Will also reset the counter after the long prevention is done.
	 */
	if (time_after(jiffies, mld_vif->emlsr.last_exit_ts +
				IWL_MLD_PREVENT_EMLSR_TIMEOUT) ||
	    mld_vif->emlsr.last_exit_reason != reason)
		mld_vif->emlsr.exit_repeat_count = 0;

	mld_vif->emlsr.last_exit_reason = reason;
	mld_vif->emlsr.last_exit_ts = jiffies;
	mld_vif->emlsr.exit_repeat_count++;

	/*
	 * Do not add a prevention when the reason was a block. For a block,
	 * EMLSR will be enabled again on unblock.
	 */
	if (reason == IWL_MLD_EMLSR_EXIT_BLOCK)
		return;

	/* Set prevention for a minimum of 30 seconds */
	mld_vif->emlsr.blocked_reasons |= IWL_MLD_EMLSR_BLOCKED_PREVENTION;
	delay = IWL_MLD_TRIGGER_LINK_SEL_TIME;

	/* Handle repeats for reasons that can cause long prevention */
	if (mld_vif->emlsr.exit_repeat_count > 1 &&
	    reason & IWL_MLD_PREVENT_EMLSR_REASONS) {
		if (mld_vif->emlsr.exit_repeat_count == 2)
			delay = IWL_MLD_EMLSR_PREVENT_SHORT;
		else
			delay = IWL_MLD_EMLSR_PREVENT_LONG;

		/*
		 * The timeouts are chosen so that this will not happen, i.e.
		 * IWL_MLD_EMLSR_PREVENT_LONG > IWL_MLD_PREVENT_EMLSR_TIMEOUT
		 */
		WARN_ON(mld_vif->emlsr.exit_repeat_count > 3);
	}

	IWL_DEBUG_INFO(mld,
		       "Preventing EMLSR for %ld seconds due to %u exits with the reason = %s (0x%x)\n",
		       delay / HZ, mld_vif->emlsr.exit_repeat_count,
		       iwl_mld_get_emlsr_exit_string(reason), reason);

	wiphy_delayed_work_queue(mld->wiphy,
				 &mld_vif->emlsr.prevent_done_wk, delay);
}

static int _iwl_mld_exit_emlsr(struct iwl_mld *mld, struct ieee80211_vif *vif,
			       enum iwl_mld_emlsr_exit exit, u8 link_to_keep,
			       bool sync)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	u16 new_active_links;
	int ret = 0;

	lockdep_assert_wiphy(mld->wiphy);

	if (!IWL_MLD_AUTO_EML_ENABLE)
		return 0;

	/* Ignore exit request if EMLSR is not active */
	if (!iwl_mld_emlsr_active(vif))
		return 0;

	if (WARN_ON(!ieee80211_vif_is_mld(vif) || !mld_vif->authorized))
		return 0;

	if (WARN_ON(!(vif->active_links & BIT(link_to_keep))))
		link_to_keep = __ffs(vif->active_links);

	new_active_links = BIT(link_to_keep);
	IWL_DEBUG_INFO(mld,
		       "Exiting EMLSR. reason = %s (0x%x). Current active links=0x%x, new active links = 0x%x\n",
		       iwl_mld_get_emlsr_exit_string(exit), exit,
		       vif->active_links, new_active_links);

	if (sync)
		ret = ieee80211_set_active_links(vif, new_active_links);
	else
		ieee80211_set_active_links_async(vif, new_active_links);

	/* Update latest exit reason and check EMLSR prevention */
	iwl_mld_check_emlsr_prevention(mld, mld_vif, exit);

	return ret;
}

void iwl_mld_exit_emlsr(struct iwl_mld *mld, struct ieee80211_vif *vif,
			enum iwl_mld_emlsr_exit exit, u8 link_to_keep)
{
	_iwl_mld_exit_emlsr(mld, vif, exit, link_to_keep, false);
}

static int _iwl_mld_emlsr_block(struct iwl_mld *mld, struct ieee80211_vif *vif,
				enum iwl_mld_emlsr_blocked reason,
				u8 link_to_keep, bool sync)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	lockdep_assert_wiphy(mld->wiphy);

	if (!iwl_mld_vif_has_emlsr(vif))
		return 0;

	if (mld_vif->emlsr.blocked_reasons & reason)
		return 0;

	mld_vif->emlsr.blocked_reasons |= reason;

	IWL_DEBUG_INFO(mld,
		       "Blocking EMLSR mode. reason = %s (0x%x)\n",
		       iwl_mld_get_emlsr_blocked_string(reason), reason);
	iwl_mld_print_emlsr_blocked(mld, mld_vif->emlsr.blocked_reasons);

	return _iwl_mld_exit_emlsr(mld, vif, IWL_MLD_EMLSR_EXIT_BLOCK,
				   link_to_keep, sync);
}

void iwl_mld_block_emlsr(struct iwl_mld *mld, struct ieee80211_vif *vif,
		       enum iwl_mld_emlsr_blocked reason, u8 link_to_keep)
{
	_iwl_mld_emlsr_block(mld, vif, reason, link_to_keep, false);
}

int iwl_mld_block_emlsr_sync(struct iwl_mld *mld, struct ieee80211_vif *vif,
			   enum iwl_mld_emlsr_blocked reason, u8 link_to_keep)
{
	return _iwl_mld_emlsr_block(mld, vif, reason, link_to_keep, true);
}

static void iwl_mld_unblocked_emlsr(struct iwl_mld *mld,
				    struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	bool last_exit_was_recent =
		time_before(jiffies, mld_vif->emlsr.last_exit_ts +
				     IWL_MLD_TRIGGER_LINK_SEL_TIME);

	if (!IWL_MLD_AUTO_EML_ENABLE && iwl_mld_emlsr_active(vif))
		return;

	IWL_DEBUG_INFO(mld, "EMLSR is unblocked\n");

	/*
	 * Take a shortcut if the last exit happened due to a temporary block
	 * that was very recent (i.e. no longer than 30s) and we still have a
	 * valid link selection.
	 * In that case, simply activate the selection.
	 */
	if (mld_vif->emlsr.last_exit_reason == IWL_MLD_EMLSR_EXIT_BLOCK &&
	    last_exit_was_recent &&
	    hweight16(mld_vif->emlsr.selected_links) == 2) {
		IWL_DEBUG_INFO(mld,
			       "Use the latest link selection result: 0x%x\n",
			       mld_vif->emlsr.selected_links);
		ieee80211_set_active_links_async(vif,
						 mld_vif->emlsr.selected_links);

		return;
	}

	IWL_DEBUG_INFO(mld, "Doing link selection after MLO scan\n");
	iwl_mld_int_mlo_scan(mld, vif);
}

void iwl_mld_unblock_emlsr(struct iwl_mld *mld, struct ieee80211_vif *vif,
			 enum iwl_mld_emlsr_blocked reason)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	lockdep_assert_wiphy(mld->wiphy);

	if (!IWL_MLD_AUTO_EML_ENABLE || !iwl_mld_vif_has_emlsr(vif))
		return;

	if (!(mld_vif->emlsr.blocked_reasons & reason))
		return;

	mld_vif->emlsr.blocked_reasons &= ~reason;

	IWL_DEBUG_INFO(mld,
		       "Unblocking EMLSR mode. reason = %s (0x%x)\n",
		       iwl_mld_get_emlsr_blocked_string(reason), reason);
	iwl_mld_print_emlsr_blocked(mld, mld_vif->emlsr.blocked_reasons);

	if (!mld_vif->emlsr.blocked_reasons)
		iwl_mld_unblocked_emlsr(mld, vif);
}

static void
iwl_mld_vif_iter_emlsr_mode_notif(void *data, u8 *mac,
				  struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mvm_esr_mode_notif *notif = (void *)data;

	if (!iwl_mld_vif_has_emlsr(vif))
		return;

	switch (le32_to_cpu(notif->action)) {
	case ESR_RECOMMEND_ENTER:
		iwl_mld_unblock_emlsr(mld_vif->mld, vif,
				      IWL_MLD_EMLSR_BLOCKED_FW);
		break;
	case ESR_RECOMMEND_LEAVE:
		/* FIXME: This should probably be handled in some way */
		IWL_DEBUG_INFO(mld_vif->mld,
			       "Received recommendation to leave EMLSR.\n");
		break;
	case ESR_FORCE_LEAVE:
	default:
		/* ESR_FORCE_LEAVE should not happen at this point */
		IWL_WARN(mld_vif->mld, "Unexpected EMLSR notification: %d\n",
			 le32_to_cpu(notif->action));
	}
}

void iwl_mld_handle_emlsr_mode_notif(struct iwl_mld *mld,
				     struct iwl_rx_packet *pkt)
{
	ieee80211_iterate_active_interfaces_mtx(mld->hw,
						IEEE80211_IFACE_ITER_NORMAL,
						iwl_mld_vif_iter_emlsr_mode_notif,
						pkt->data);
}

static void
iwl_mld_vif_iter_disconnect_emlsr(void *data, u8 *mac,
				  struct ieee80211_vif *vif)
{
	if (!iwl_mld_vif_has_emlsr(vif))
		return;

	ieee80211_connection_loss(vif);
}

void iwl_mld_handle_emlsr_trans_fail_notif(struct iwl_mld *mld,
					   struct iwl_rx_packet *pkt)
{
	const struct iwl_esr_trans_fail_notif *notif = (const void *)pkt->data;
	u32 fw_link_id = le32_to_cpu(notif->link_id);
	struct ieee80211_bss_conf *bss_conf =
		iwl_mld_fw_id_to_link_conf(mld, fw_link_id);

	IWL_DEBUG_INFO(mld, "Failed to %s EMLSR on link %d (FW: %d), reason %d\n",
		       le32_to_cpu(notif->activation) ? "enter" : "exit",
		       bss_conf ? bss_conf->link_id : -1,
		       le32_to_cpu(notif->link_id),
		       le32_to_cpu(notif->err_code));

	if (IWL_FW_CHECK(mld, !bss_conf,
			 "FW reported failure to %sactivate EMLSR on a non-existing link: %d\n",
			 le32_to_cpu(notif->activation) ? "" : "de",
			 fw_link_id)) {
		ieee80211_iterate_active_interfaces_mtx(
			mld->hw, IEEE80211_IFACE_ITER_NORMAL,
			iwl_mld_vif_iter_disconnect_emlsr, NULL);
		return;
	}

	/* Disconnect if we failed to deactivate a link */
	if (!le32_to_cpu(notif->activation)) {
		ieee80211_connection_loss(bss_conf->vif);
		return;
	}

	/*
	 * We failed to activate the second link, go back to the link specified
	 * by the firmware as that is the one that is still valid now.
	 */
	iwl_mld_exit_emlsr(mld, bss_conf->vif, IWL_MLD_EMLSR_EXIT_FAIL_ENTRY,
			   bss_conf->link_id);
}

/* Active non-station link tracking */
static void iwl_mld_count_non_bss_links(void *_data, u8 *mac,
					struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int *count = _data;

	if (ieee80211_vif_type_p2p(vif) == NL80211_IFTYPE_STATION)
		return;

	*count += iwl_mld_count_active_links(mld_vif->mld, vif);
}

struct iwl_mld_update_emlsr_block_data {
	bool block;
	int result;
};

static void iwl_mld_vif_iter_update_emlsr_non_bss_block(void *_data, u8 *mac,
						       struct ieee80211_vif *vif)
{
	struct iwl_mld_update_emlsr_block_data *data = _data;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int ret;

	if (data->block) {
		ret = iwl_mld_block_emlsr_sync(mld_vif->mld, vif,
					       IWL_MLD_EMLSR_BLOCKED_NON_BSS,
					       iwl_mld_get_primary_link(vif));
		if (ret)
			data->result = ret;
	} else {
		iwl_mld_unblock_emlsr(mld_vif->mld, vif,
				      IWL_MLD_EMLSR_BLOCKED_NON_BSS);
	}
}

int iwl_mld_emlsr_check_non_bss_block(struct iwl_mld *mld,
				      int pending_link_changes)
{
	/* An active link of a non-station vif blocks EMLSR. Upon activation
	 * block EMLSR on the bss vif. Upon deactivation, check if this link
	 * was the last non-station link active, and if so unblock the bss vif
	 */
	struct iwl_mld_update_emlsr_block_data block_data = {};
	int count = pending_link_changes;

	/* No need to count if we are activating a non-BSS link */
	if (count <= 0)
		ieee80211_iterate_active_interfaces_mtx(mld->hw,
							IEEE80211_IFACE_ITER_NORMAL,
							iwl_mld_count_non_bss_links,
							&count);

	/*
	 * We could skip updating it if the block change did not change (and
	 * pending_link_changes is non-zero).
	 */
	block_data.block = !!count;

	ieee80211_iterate_active_interfaces_mtx(mld->hw,
						IEEE80211_IFACE_ITER_NORMAL,
						iwl_mld_vif_iter_update_emlsr_non_bss_block,
						&block_data);

	return block_data.result;
}

/*
 * Link selection
 */
struct iwl_mld_link_sel_data {
	u8 link_id;
	const struct cfg80211_chan_def *chandef;
	s32 signal;
	u16 grade;
};

s8 iwl_mld_get_emlsr_rssi_thresh(struct iwl_mld *mld,
				 const struct cfg80211_chan_def *chandef,
				 bool low)
{
	if (WARN_ON(chandef->chan->band != NL80211_BAND_2GHZ &&
		    chandef->chan->band != NL80211_BAND_5GHZ &&
		    chandef->chan->band != NL80211_BAND_6GHZ))
		return S8_MAX;

#define RSSI_THRESHOLD(_low, _bw)			\
	(_low) ? IWL_MLD_LOW_RSSI_THRESH_##_bw##MHZ	\
	       : IWL_MLD_HIGH_RSSI_THRESH_##_bw##MHZ

	switch (chandef->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
	case NL80211_CHAN_WIDTH_20:
	/* 320 MHz has the same thresholds as 20 MHz */
	case NL80211_CHAN_WIDTH_320:
		return RSSI_THRESHOLD(low, 20);
	case NL80211_CHAN_WIDTH_40:
		return RSSI_THRESHOLD(low, 40);
	case NL80211_CHAN_WIDTH_80:
		return RSSI_THRESHOLD(low, 80);
	case NL80211_CHAN_WIDTH_160:
		return RSSI_THRESHOLD(low, 160);
	default:
		WARN_ON(1);
		return S8_MAX;
	}
#undef RSSI_THRESHOLD
}

static u32
iwl_mld_emlsr_disallowed_with_link(struct iwl_mld *mld,
				   struct ieee80211_vif *vif,
				   struct iwl_mld_link_sel_data *link,
				   bool primary)
{
	struct wiphy *wiphy = mld->wiphy;
	struct ieee80211_bss_conf *conf;
	enum iwl_mld_emlsr_exit ret = 0;

	conf = wiphy_dereference(wiphy, vif->link_conf[link->link_id]);
	if (WARN_ON_ONCE(!conf))
		return false;

	/* TODO: handle BT Coex (task=EMLSR, task=coex) */

	if (link->signal <
	    iwl_mld_get_emlsr_rssi_thresh(mld, link->chandef, false))
		ret |= IWL_MLD_EMLSR_EXIT_LOW_RSSI;

	if (conf->csa_active)
		ret |= IWL_MLD_EMLSR_EXIT_CSA;

	if (ret) {
		IWL_DEBUG_INFO(mld,
			       "Link %d is not allowed for EMLSR as %s\n",
			       link->link_id,
			       primary ? "primary" : "secondary");
		iwl_mld_print_emlsr_exit(mld, ret);
	}

	return ret;
}

static u8
iwl_mld_set_link_sel_data(struct ieee80211_vif *vif,
			  struct iwl_mld_link_sel_data *data,
			  unsigned long usable_links,
			  u8 *best_link_idx)
{
	u8 n_data = 0;
	u16 max_grade = 0;
	unsigned long link_id;

	/*
	 * TODO: don't select links that weren't discovered in the last scan
	 * This requires mac80211 (or cfg80211) changes to forward/track when
	 * a BSS was last updated. cfg80211 already tracks this information but
	 * it is not exposed within the kernel.
	 */
	for_each_set_bit(link_id, &usable_links, IEEE80211_MLD_MAX_NUM_LINKS) {
		struct ieee80211_bss_conf *link_conf =
			link_conf_dereference_protected(vif, link_id);

		if (WARN_ON_ONCE(!link_conf))
			continue;

		data[n_data].link_id = link_id;
		data[n_data].chandef = &link_conf->chanreq.oper;
		data[n_data].signal = MBM_TO_DBM(link_conf->bss->signal);
		data[n_data].grade = iwl_mld_get_link_grade(link_conf);

		if (n_data == 0 || data[n_data].grade > max_grade) {
			max_grade = data[n_data].grade;
			*best_link_idx = n_data;
		}
		n_data++;
	}

	return n_data;
}

static bool
iwl_mld_valid_emlsr_pair(struct ieee80211_vif *vif,
			 struct iwl_mld_link_sel_data *a,
			 struct iwl_mld_link_sel_data *b)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld *mld = mld_vif->mld;
	enum iwl_mld_emlsr_exit ret = 0;

	/* Per-link considerations */
	if (iwl_mld_emlsr_disallowed_with_link(mld, vif, a, true) ||
	    iwl_mld_emlsr_disallowed_with_link(mld, vif, b, false))
		return false;

	if (a->chandef->chan->band == b->chandef->chan->band) {
		ret |= IWL_MLD_EMLSR_EXIT_EQUAL_BAND;
	} else if (a->chandef->width != b->chandef->width) {
		/* TODO: task=EMLSR task=statistics
		 * replace BANDWIDTH exit reason with channel load criteria
		 */
		ret |= IWL_MLD_EMLSR_EXIT_BANDWIDTH;
	}

	/* TODO: task=EMLSR task=RFI RFI considerations */

	if (ret) {
		IWL_DEBUG_INFO(mld,
			       "Links %d and %d are not a valid pair for EMLSR\n",
			       a->link_id, b->link_id);
		IWL_DEBUG_INFO(mld,
			       "Links bandwidth are: %d and %d\n",
			       nl80211_chan_width_to_mhz(a->chandef->width),
			       nl80211_chan_width_to_mhz(b->chandef->width));
		iwl_mld_print_emlsr_exit(mld, ret);
		return false;
	}

	return true;
}

/* Calculation is done with fixed-point with a scaling factor of 1/256 */
#define SCALE_FACTOR 256

/*
 * Returns the combined grade of two given links.
 * Returns 0 if EMLSR is not allowed with these 2 links.
 */
static
unsigned int iwl_mld_get_emlsr_grade(struct ieee80211_vif *vif,
				     struct iwl_mld_link_sel_data *a,
				     struct iwl_mld_link_sel_data *b,
				     u8 *primary_id)
{
	struct ieee80211_bss_conf *primary_conf;
	struct wiphy *wiphy = ieee80211_vif_to_wdev(vif)->wiphy;
	unsigned int primary_load;

	lockdep_assert_wiphy(wiphy);

	/* a is always primary, b is always secondary */
	if (b->grade > a->grade)
		swap(a, b);

	*primary_id = a->link_id;

	if (!iwl_mld_valid_emlsr_pair(vif, a, b))
		return 0;

	primary_conf = wiphy_dereference(wiphy, vif->link_conf[*primary_id]);

	if (WARN_ON_ONCE(!primary_conf))
		return 0;

	/*
	 * With EMLSR we can use the secondary channel whenever the primary is
	 * loaded with other traffic. Scale the secondary grade accordingly.
	 */
	/* TODO: task=statistics fetch load */
	primary_load = SCALE_FACTOR / 2;

	return a->grade + ((b->grade * primary_load) / SCALE_FACTOR);
}

static void _iwl_mld_select_links(struct iwl_mld *mld,
				  struct ieee80211_vif *vif)
{
	struct iwl_mld_link_sel_data data[IEEE80211_MLD_MAX_NUM_LINKS];
	struct iwl_mld_link_sel_data *best_link;
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	int max_active_links = iwl_mld_max_active_links(mld, vif);
	u16 new_active, usable_links = ieee80211_vif_usable_links(vif);
	u8 best_idx, new_primary, n_data;
	u16 max_grade;

	lockdep_assert_wiphy(mld->wiphy);

	/* Link selection only works for EMLSR right now */
	if (!iwl_mld_vif_has_emlsr(vif))
		return;

	if (!IWL_MLD_AUTO_EML_ENABLE)
		return;

	/* The logic below is simple and not suited for more than 2 links */
	WARN_ON_ONCE(max_active_links > 2);

	n_data = iwl_mld_set_link_sel_data(vif, data, usable_links, &best_idx);

	if (WARN(!n_data, "Couldn't find a valid grade for any link!\n"))
		return;

	/* Default to selecting the single best link */
	best_link = &data[best_idx];
	new_primary = best_link->link_id;
	new_active = BIT(best_link->link_id);
	max_grade = best_link->grade;

	/* Only one link available (or only one maximum link) */
	if (max_active_links == 1 || n_data == 1)
		goto set_active;

	/* Try to find the best link combination */
	for (u8 a = 0; a < n_data; a++) {
		for (u8 b = a + 1; b < n_data; b++) {
			u8 best_in_pair;
			u16 emlsr_grade =
				iwl_mld_get_emlsr_grade(vif,
							&data[a], &data[b],
							&best_in_pair);

			/*
			 * Prefer (new) EMLSR combination to prefer EMLSR over
			 * a single link.
			 */
			if (emlsr_grade < max_grade)
				continue;

			max_grade = emlsr_grade;
			new_primary = best_in_pair;
			new_active = BIT(data[a].link_id) |
				     BIT(data[b].link_id);
		}
	}

set_active:
	IWL_DEBUG_INFO(mld, "Link selection result: 0x%x. Primary = %d\n",
		       new_active, new_primary);

	mld_vif->emlsr.selected_primary = new_primary;
	mld_vif->emlsr.selected_links = new_active;

	/* If EMLSR is currently blocked, then only use the primary link */
	if (mld_vif->emlsr.blocked_reasons)
		ieee80211_set_active_links_async(vif, BIT(new_primary));
	else
		ieee80211_set_active_links_async(vif, new_active);
}

static void iwl_mld_vif_iter_select_links(void *_data, u8 *mac,
					   struct ieee80211_vif *vif)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_mld *mld = mld_vif->mld;

	_iwl_mld_select_links(mld, vif);
}

void iwl_mld_select_links(struct iwl_mld *mld)
{
	ieee80211_iterate_active_interfaces_mtx(mld->hw,
						IEEE80211_IFACE_ITER_NORMAL,
						iwl_mld_vif_iter_select_links,
						NULL);
}
