/*
 * Regression test for the mod_sofia NULL-session NOTIFY crash.
 *
 * Tracker: coding_trackers 2026-06-22-1_sofia-notify-null-session-crash_P0
 *
 * Bug: a local patch hoisted
 *   switch_channel_get_variable(switch_core_session_get_channel(session), "autodisconnect_refer")
 * to the top of sofia_handle_sip_i_notify(), BEFORE the function's own
 * `if (session)` guards. A NOTIFY dispatched with session == NULL (an in-dialog
 * refer NOTIFY racing in after the call's BYE, or any unsolicited NOTIFY) then
 * dereferenced NULL via switch_core_session_get_channel() -> switch_assert(session->channel).
 *
 * This test drives a single OUT-OF-DIALOG refer-event NOTIFY at the sofia
 * profile via SIPp. mod_sofia has no session for it, so the handler is entered
 * with session == NULL -- the crash condition. Because FST hosts the FreeSWITCH
 * core in-process, an unfixed mod_sofia SIGSEGVs and takes THIS test binary down
 * with it (deterministic crashes-pre-fix proof). A fixed mod_sofia answers
 * 200 OK (RFC 5057: a BYE ends only the INVITE usage; the refer-subscription
 * usage is acknowledged with 200, not 481), SIPp completes, and the assertions
 * below pass.
 */

#include <switch.h>
#include <test/switch_test.h>

FST_CORE_EX_BEGIN("./conf-sipp", SCF_VG | SCF_USE_SQL)

FST_MODULE_BEGIN(mod_sofia, notify_null_session)

FST_SETUP_BEGIN()
{
	/* Give mod_sofia time to spin up its profile threads / bind 5080. */
	switch_sleep(5000 * 1000);
}
FST_SETUP_END()

FST_TEARDOWN_BEGIN()
{
	/* Scope the kill to this test's scenario so parallel SIPp jobs on the host are untouched. */
	switch_system("pkill -f uac_notify_refer.xml", SWITCH_TRUE);
}
FST_TEARDOWN_END()

FST_TEST_BEGIN(notify_refer_null_session_no_crash)
{
	const char *local_ip_v4 = switch_core_get_variable("local_ip_v4");
	char *cmd;
	int sipp_ret;

	fst_requires_module("mod_sofia");

	/* Run SIPp synchronously (no -bg): exit 0 iff it received the expected 200. */
	cmd = switch_mprintf("sipp %s:5080 -nr -p 5066 -m 1 -s notifytest "
						  "-recv_timeout 8000 -timeout 12s "
						  "-sf sipp-scenarios/uac_notify_refer.xml",
						  local_ip_v4);
	printf("Running: %s\n", cmd);
	sipp_ret = switch_system(cmd, SWITCH_TRUE);
	switch_safe_free(cmd);

	if (sipp_ret < 0 || sipp_ret == 127) {
		fst_check(!"sipp not found / failed to launch");
	} else {
		/*
		 * Reaching here at all means mod_sofia did NOT crash on the NULL-session
		 * NOTIFY -- on an unfixed build the in-process core would have SIGSEGV'd
		 * before SIPp's transaction completed, taking this binary down with it.
		 * The core being still alive is the primary regression assertion.
		 */
		fst_requires_module("mod_sofia");

		/* And the wire response must be the single 200 OK the scenario expects. */
		fst_check(sipp_ret == 0);
	}
}
FST_TEST_END()

FST_MODULE_END()

FST_CORE_END()
