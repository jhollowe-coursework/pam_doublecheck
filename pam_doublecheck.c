#define PAM_SM_ACCOUNT

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
	struct passwd *pw        = NULL;
	struct group * grp       = NULL;
	int            sessionId = (rand() % (1 + DC_ID_MAX - DC_ID_MIN)) + DC_ID_MIN;
	bool           verified  = false;

	// DEBUG
	// flags |= PAM_SILENT;

	parseArgs(pamh, argc, argv);

	// get the username of the user we are checking
	const char *pUsername;
	validateRetVal(pam_get_user(pamh, &pUsername, NULL));

	/* bypass this module if the user is in the bypass group */

	int    ngroups = 1;
	gid_t *groups  = malloc(ngroups * sizeof(gid_t *));
	pw             = getpwnam(pUsername);
	if (pw == NULL) {
		p_fprintf(flags, stderr, "Unable to find %s in user database\n", pUsername);
		return PAM_USER_UNKNOWN;
	}
	// get the number of groups this user is into ngroups, resize groups, and get groups
	getgrouplist(pUsername, pw->pw_gid, groups, &ngroups);
	groups = realloc(groups, sizeof(*groups) * ngroups);
	getgrouplist(pUsername, pw->pw_gid, groups, &ngroups);
	// get group names from group ID and check for bypass
	for (int i = 0; i < ngroups; i++) {
		grp = getgrgid(groups[i]);
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

	// get reason for session from user if allowed
	char *reason = "";
	if (!isSilent(flags)) {
		validateRetVal(converseSingle(pamh, &msg, &resp));
		if (resp != NULL && resp->resp != NULL && *resp->resp != '\000') {
			reason = resp->resp;
		}
	}

	int    numVerifiers         = 0;
	char **verifierUsernames    = malloc(sizeof(char *));
	char **verifierPhoneNumbers = malloc(sizeof(char *));

	// get users in verifier group
	grp = getgrnam(verifier_group);
	if (grp == NULL) {
		// TODO use some logging tools
		p_fprintf(flags, stderr, "Unable to find users to verify access\n");
		return PAM_AUTH_ERR;
	}
	char **members = grp->gr_mem;
	while (members != NULL && *members != NULL) {
		numVerifiers++;

		// get usernames
		verifierUsernames = realloc(verifierUsernames, numVerifiers * sizeof(char *));
		char *username    = malloc(sizeof(char) * USERNAME_MAX_LENGTH);
		strncpy(username, *members, USERNAME_MAX_LENGTH);
		verifierUsernames[numVerifiers - 1] = username;

		// get phone numbers
		verifierPhoneNumbers = realloc(verifierPhoneNumbers, numVerifiers * sizeof(char *));
		pw                   = getpwnam(username);
		char *gecos          = malloc(sizeof(char) * GECOS_MAX_LENGTH);
		// TODO don't assume the only thing in a user's GECOS is a phone number
		strncpy(gecos, pw->pw_gecos, GECOS_MAX_LENGTH);
		verifierPhoneNumbers[numVerifiers - 1] = gecos;

		members++;
	}

	/* send verification code to verifiers */
	char hostname[HOSTNAME_MAX_LENGTH];
	gethostname(hostname, HOSTNAME_MAX_LENGTH);

	char command[GENERIC_STRING_MAX_LENGTH];
	char message[MESSAGE_BASE_LENGTH + strlen(reason)];
	for (int i = 0; i < numVerifiers; i++) {
		int userUuid = (rand() % (1 + DC_ID_MAX - DC_ID_MIN)) + DC_ID_MIN;

		char *reasonClean = !strncmp(reason, "", 1) ? "<no reason given>" : reason;

		sprintf(command, "ssh %s@%s doublecheck %d %d", verifierUsernames[i], hostname, sessionId, userUuid);
		sprintf(message, "%s is attempting to authenticate on %s\nReason: %s\nTo allow this, please run the command\n%s",
		        pUsername, hostname, reasonClean, command);

#if DC_ENABLE_TEXTS == 1
		twilio_send_message(DC_TWILIO_SID, DC_TWILIO_AUTH, message, DC_TWILIO_FROM, verifierPhoneNumbers[i], NULL,
		                    DC_TWILIO_VERBOSE);
#else
		p_printf(flags, "Text to %s:\n\"%s\"\n\n", verifierPhoneNumbers[i], message);
#endif
	}

	/* wait for verification */

	int  fd;
	char filename[GENERIC_STRING_MAX_LENGTH];
	sprintf(filename, "%s_%0*d", DC_COMMUNICATION_FILE_BASE, DC_ID_PAD_LENGTH, sessionId);

	mkfifo(filename, 0666);

	if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) < 0) {
		p_fprintf(flags, stderr, "Unable to access verifier log");
		exit(1);
	}

	char   line[LINE_MAX_LENGTH] = "";
	time_t startTime             = time(NULL);
	while (!verified) {
		// if the timeout is set and expired
		if (sms_timeout > 0 && (time(NULL) - startTime) >= sms_timeout) {
			p_printf(flags, "Verification exceeded max allowed time\n");
			return PAM_ACCT_EXPIRED;
		}

		// if the read failed because there was nothing to read,
		if (read(fd, line, LINE_MAX_LENGTH) > 0) {
			int readId = atoi(line);
			printf("%d\n", readId);
		}

		sleep(1);
	}

	// close and remove the FIFO
	close(fd);
	remove(filename);

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
