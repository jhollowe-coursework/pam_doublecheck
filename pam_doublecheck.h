#include <grp.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifdef sun
#define PAM_CONST
#else
#define PAM_CONST const
#endif

#define validateRetVal(retval) \
	if (retval != PAM_SUCCESS)   \
	return retval

#define DC_PREFIX        "[Doublecheck] "
#define DC_REASON_PROMPT DC_PREFIX "Reason: "

#define SMS_RESPONSE_TIMEOUT 120

static int converse(pam_handle_t *pamh, int nargs, PAM_CONST struct pam_message **message,
                    struct pam_response **response);

static int converseSingle(pam_handle_t *pamh, PAM_CONST struct pam_message *message, struct pam_response **response);
