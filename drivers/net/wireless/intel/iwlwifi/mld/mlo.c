// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */
#include "mlo.h"

/* Block reasons helper */
#define HANDLE_EMLSR_BLOCKED_REASONS(HOW)	\
	HOW(PREVENTION)

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
	HOW(BLOCK)

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

__always_unused
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

#define IWL_MLD_TRIGGER_LINK_SEL_TIME	(HZ * IWL_MLD_TRIGGER_LINK_SEL_TIME_SEC)

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

	/* TODO: Implement EMLSR prevention */
	mld_vif->emlsr.last_exit_reason = exit;
	mld_vif->emlsr.last_exit_ts = jiffies;

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
	/* TODO: Trigger MLO scan */
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
