#include "pam_doublecheck.h"

/* PAM hook: allows modifying the user's credentials */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// We don't need to modify credentials, so just return success
	return PAM_SUCCESS;
}

/* PAM hook: determine if this account can be used at the moment. The main action of this module */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int retval;

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

	int   numSudoers          = 0;
	char *sudoerUsernames[]   = NULL;
	char *sudoerPhoneNumber[] = NULL;

	struct passwd *pw       = NULL;
	char *         phoneNum = NULL;

	// search through all the users, filter if they are in the sudo group, and get phone number from GECOS
	while ((pw = getpwent()) != NULL) {
		// TODO check if user is in sudo group
		sscanf(pw->pw_gecos, "%s", phoneNum); // TODO parse phone number from GECOS
	}
	// close the passwd database
	endpwent();

	// verify with each
	for (int i = 0; i < numSudoers; i++) {
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
