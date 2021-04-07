#define PAM_SM_ACCOUNT

#include "pam_doublecheck.h"

// GLOBAL CONFIG
char *verifier_group        = DC_VERIFIER_GROUP_DEFAULT;
char *bypass_group          = DC_BYPASS_GROUP_DEFAULT;
int   timeout               = RESPONSE_TIMEOUT_DEFAULT;
float verified_need_percent = DC_VERIFIED_NEED_PERCENT;
int   verified_need_count   = DC_VERIFIED_NEED_NUM;

/* PAM hook: allows modifying the user's credentials */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// We don't need to modify credentials, so just return success
	return PAM_SUCCESS;
}

/* PAM hook: determine if this account can be used at the moment. The main action of this module */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// set seed for rand() to current timestamp
	srand(time(NULL));

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
		// TODO allow a list of groups to bypass
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

	int          numVerifiers = 0;
	verifier_t **verifiers    = malloc(sizeof(verifier_t *));

	// get users in verifier group
	// TODO allow a list of groups for verifiers
	grp = getgrnam(verifier_group);
	if (grp == NULL) {
		// TODO use some logging tools
		p_fprintf(flags, stderr, "Unable to find users to verify access\n");
		return PAM_AUTH_ERR;
	}
	char **members = grp->gr_mem;
	while (members != NULL && *members != NULL) {
		numVerifiers++;

		// create a new verifier, expand array, and add
		verifiers                   = realloc(verifiers, numVerifiers * sizeof(verifier_t *));
		verifier_t *verifier        = malloc(sizeof(verifier_t));
		verifiers[numVerifiers - 1] = verifier;

		// store username
		strncpy(verifier->username, *members, USERNAME_MAX_LENGTH);

		// store phone numbers
		pw = getpwnam(verifier->username);
		// TODO don't assume the only thing in a user's GECOS is a phone number
		strncpy(verifier->phoneNum, pw->pw_gecos, GECOS_MAX_LENGTH);

		// store userId
		verifier->userId   = (rand() % (1 + DC_ID_MAX - DC_ID_MIN)) + DC_ID_MIN;
		verifier->verified = false;

		members++;
	}

	/* send verification code to verifiers */
	char hostname[HOSTNAME_MAX_LENGTH];
	gethostname(hostname, HOSTNAME_MAX_LENGTH);

	char command[GENERIC_STRING_MAX_LENGTH];
	char message[MESSAGE_BASE_LENGTH + strlen(reason)];
	for (int i = 0; i < numVerifiers; i++) {

		char *reasonClean = !strncmp(reason, "", 1) ? "<no reason given>" : reason;

		sprintf(command, "ssh %s@%s doublecheck %d %d", verifiers[i]->username, hostname, sessionId, verifiers[i]->userId);
		sprintf(message, "%s is attempting to authenticate on %s\nReason: %s\nTo allow this, please run the command\n%s",
		        pUsername, hostname, reasonClean, command);

#if DC_ENABLE_TEXTS == 1
		twilio_send_message(DC_TWILIO_SID, DC_TWILIO_AUTH, message, DC_TWILIO_FROM, verifiers[i]->phoneNum, NULL,
		                    DEBUG >= 2);
#else
		p_printf(flags, "Text to %s:\n\"%s\"\n\n", verifiers[i]->phoneNum, message);
#endif
	}

	/* wait for verification */

	int  fd;
	char filename[GENERIC_STRING_MAX_LENGTH];
	sprintf(filename, "%s_%0*d", DC_COMMUNICATION_FILE_BASE, DC_ID_PAD_LENGTH, sessionId);

	// TODO fix this being create with incorrect permissions
	mkfifo(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) < 0) {
		p_fprintf(flags, stderr, "Unable to access verifier log");
		exit(1);
	}

	char   line[LINE_MAX_LENGTH] = "";
	time_t startTime             = time(NULL);
	while (!verified) {
		// if the timeout is set and expired
		if (timeout > 0 && (time(NULL) - startTime) >= timeout) {
			p_printf(flags, "Verification exceeded max allowed time\n");

			// close and remove the FIFO
			close(fd);
			remove(filename);

			return PAM_PERM_DENIED;
		}

		// if something was read
		if (read(fd, line, LINE_MAX_LENGTH) > 0) {
			int readId = atoi(line);

			for (int i = 0; i < numVerifiers; i++) {
				if (readId == verifiers[i]->userId) {
					verifiers[i]->verified = true;
#if DEBUG >= 1
					p_printf(flags, "User %s has verified\n", verifiers[i]->username);
#endif
				}
			}
		}

		int numVerified = 0;
		for (int i = 0; i < numVerifiers; i++) {
			if (verifiers[i]->verified) {
				numVerified++;
			}
		}

		float percentVerified = numVerified / (float)numVerifiers;
		if (percentVerified >= verified_need_percent && numVerified >= verified_need_count) {
			verified = true;
		}

		sleep(verified ? 0 : 1);
	}
	// if the loop is existed, the user is verified

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
			verifier_group = (char *)(argv[i] + 15);
		} else if (!strncmp(argv[i], "bypass_group=", 13)) {
			bypass_group = (char *)(argv[i] + 13);
		} else if (!strncmp(argv[i], "timeout=", 8)) {
			timeout = atoi(argv[i] + 8);
		} else if (!strncmp(argv[i], "verified_need_percent=", 22)) {
			verified_need_percent = atof(argv[i] + 22);
		} else if (!strncmp(argv[i], "verified_need_count=", 20)) {
			verified_need_count = atoi(argv[i] + 20);
		}
	}

#if DEBUG >= 1
	printf("verifier_group:%s\n", verifier_group);
	printf("bypass_group:%s\n", bypass_group);
	printf("timeout:%d\n", timeout);
	printf("verified_need_percent:%f\n", verified_need_percent);
	printf("verified_need_count:%d\n", verified_need_count);
#endif
	return 0;
}
