#include "pam_doublecheck.h"

// GLOBAL CONFIG
char *verifier_group = DC_VERIFIER_GROUP_DEFAULT;
char *bypass_group   = DC_BYPASS_GROUP_DEFAULT;
int   sms_timeout    = SMS_RESPONSE_TIMEOUT_DEFAULT;

/* PAM hook: allows modifying the user's credentials */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// We don't need to modify credentials, so just return success
	return PAM_SUCCESS;
}

/* PAM hook: determine if this account can be used at the moment. The main action of this module */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int            retval;
	struct passwd *pw  = NULL;
	struct group * grp = NULL;

	parseArgs(pamh, argc, argv);

	// get the username of the user we are checking
	const char *pUsername;
	validateRetVal(pam_get_user(pamh, &pUsername, NULL));

	/* bypass this module if the user is in the bypass group */

	int    ngroups = 1;
	gid_t *groups  = malloc(ngroups * sizeof(gid_t *));
	pw             = getpwnam(pUsername);
	if (pw == NULL) {
		fprintf(stderr, "Unable to find %s in user database\n", pUsername);
		return PAM_USER_UNKNOWN;
	}
	// get the number of groups this user is into ngroups, resize groups, and get groups
	getgrouplist(pUsername, pw->pw_gid, groups, &ngroups);
	groups = realloc(groups, sizeof(*groups) * ngroups);
	getgrouplist(pUsername, pw->pw_gid, groups, &ngroups);
	// get group names from group ID and check for bypass
	for (int i = 0; i < ngroups; i++) {
		grp = getgrgid(groups[i]);
		printf("%s(%d)\n", grp->gr_name, groups[i]);
		if (grp != NULL && !strcmp(grp->gr_name, bypass_group)) {
			return PAM_SUCCESS;
		}
	}

	/* USER HAS NOT BYPASSED */

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

	int    numVerifiers      = 0;
	char **verifierUsernames = malloc(sizeof(char *));
	char **verifierPhoneNumbers;
	char * phoneNum = NULL;

	// get users in verifier group
	grp = getgrnam(verifier_group);
	if (grp == NULL) {
		// TODO use some logging tools
		fprintf(stderr, "Unable to find users to verify access\n");
		return PAM_AUTH_ERR;
	}
	char **members = grp->gr_mem;
	while (members != NULL && *members != NULL) {
		numVerifiers++;
		verifierUsernames = realloc(verifierUsernames, numVerifiers * sizeof(char *));
		printf("%s is in %s\n", *members, verifier_group);
		char *username = malloc(sizeof(char) * USERNAME_NAME_MAX_LENGTH);
		strncpy(username, *members, USERNAME_NAME_MAX_LENGTH);
		verifierUsernames[numVerifiers - 1] = username;
		members++;
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
			sms_timeout = atoi(argv[i]);
		} else if (!strncmp(argv[i], "bypass_group=", 14)) {
			bypass_group = argv[i];
		}
	}
	return 0;
}
