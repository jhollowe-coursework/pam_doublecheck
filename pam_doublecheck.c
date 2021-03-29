#include "pam_doublecheck.h"

// GLOBAL CONFIG
char *verifier_group = DC_VERIFIER_GROUP_DEFAULT;
int   sms_timeout    = SMS_RESPONSE_TIMEOUT_DEFAULT;

/* PAM hook: allows modifying the user's credentials */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// We don't need to modify credentials, so just return success
	return PAM_SUCCESS;
}

/* PAM hook: determine if this account can be used at the moment. The main action of this module */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int retval;

	parseArgs(pamh, argc, argv);

	// get the username of the user we are checking
	const char *pUsername;
	validateRetVal(pam_get_user(pamh, &pUsername, NULL));

	// ask for optional reason
	struct pam_message msg = {
			.msg_style = PAM_PROMPT_ECHO_ON,
			.msg       = DC_REASON_PROMPT,
	};
	struct pam_response *resp = NULL;

	// get reason for session from user
	validateRetVal(converseSingle(pamh, &msg, &resp));
	char *reason = "";
	if (resp != NULL && resp->resp != NULL && *resp->resp != '\000') {
		reason = resp->resp;
	}

	int    numVerifiers = 0;
	char **verifierUsernames;
	char **verifierPhoneNumbers;

	struct passwd *pw       = NULL;
	struct group * grp      = NULL;
	char *         phoneNum = NULL;

	// search through all the users, filter if they are in the verifier group, and get phone number from GECOS
	while ((grp = getgrent()) != NULL) {
		if (grp != NULL && grp->gr_name != NULL) {

			// get users in verifier group
			if (!strcmp(grp->gr_name, verifier_group)) {
				verifierUsernames = grp->gr_mem;
			}

			// if there are no users to verify access, just exit
			if (verifierUsernames == NULL) {
				// TODO use some logging tools
				printf("Unable to find users to verify access\n");
				return PAM_AUTH_ERR;
			}

			for (int i = 0; verifierUsernames[i] != NULL; i++) {
				numVerifiers++;
				printf("%s\n", verifierUsernames[i]);
			}

			// TODO parse phone number from GECOS
		}
	}
	// close the group database
	endgrent();

	// verify with each user
	for (int i = 0; i < numVerifiers; i++) {
	}

	printf("DEBUG: user:%s|reason:\"%s\"\n", pUsername, reason);
	return PAM_SUCCESS;
}

static int converse(pam_handle_t *pamh, int nargs, PAM_CONST struct pam_message **message,
                    struct pam_response **response) {

	struct pam_conv *conv = NULL;
	validateRetVal(pam_get_item(pamh, PAM_CONV, (void *)&conv));
	return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static int converseSingle(pam_handle_t *pamh, PAM_CONST struct pam_message *message, struct pam_response **response) {

	return converse(pamh, 1, &message, response);
}

static int parseArgs(pam_handle_t *pamh, int argc, const char **argv) {
	for (int i = 0; i < argc; ++i) {
		if (!strncmp(argv[i], "verifier_group=", 15)) {
			verifier_group = argv[i];
		} else if (!strncmp(argv[i], "sms_timeout=", 13)) {
			sms_timeout = argv[i];
		}
	}
	return 0;
}
