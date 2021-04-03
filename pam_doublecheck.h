#include "secrets.h"
#include "twilio.h"
#include <grp.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef sun
#define PAM_CONST
#else
#define PAM_CONST const
#endif

#define validateRetVal(retval) \
	if (retval != PAM_SUCCESS)   \
	return retval

#define isSilent(flags) !!(flags & PAM_SILENT)

#define DC_PREFIX                 "[Doublecheck] "
#define DC_REASON_PROMPT          DC_PREFIX "Reason: "
#define DC_REGEX_SMS              "sms="
#define DC_ID_MIN                 100
#define DC_ID_MAX                 999
#define USERNAME_MAX_LENGTH       32
#define GECOS_MAX_LENGTH          256
#define HOSTNAME_MAX_LENGTH       256
#define COMMAND_MAX_LENGTH        18 + 8 + USERNAME_MAX_LENGTH + HOSTNAME_MAX_LENGTH
#define MESSAGE_BASE_LENGTH       90 + USERNAME_MAX_LENGTH + HOSTNAME_MAX_LENGTH + COMMAND_MAX_LENGTH // + strlen(reason)
#define GENERIC_STRING_MAX_LENGTH 1000

#define DC_VERIFIER_GROUP_DEFAULT    "sudo"
#define DC_BYPASS_GROUP_DEFAULT      "sudo"
#define SMS_RESPONSE_TIMEOUT_DEFAULT 120
#define DC_COMMUNICATION_FILE        "/tmp/dc_verify"
#define DC_ENABLE_TEXTS              0

static int converse(pam_handle_t *pamh, int nargs, PAM_CONST struct pam_message **message,
                    struct pam_response **response);

static int converseSingle(pam_handle_t *pamh, PAM_CONST struct pam_message *message, struct pam_response **response);

static int parseArgs(pam_handle_t *pamh, int argc, const char **argv);

/*
 * Takes the PAM flags int and only prints if the PAM_SILENT flag is not set
 */
void p_printf(int flags, const char *restrict format, ...) {
	if (!isSilent(flags)) {
		va_list arg;
		int     done;
		va_start(arg, format);
		done = vprintf(format, arg);
		va_end(arg);
		return done;
	}
}

/*
 * Takes the PAM flags int and only prints if the PAM_SILENT flag is not set
 */
void p_fprintf(int flags, FILE *restrict stream, const char *restrict format, ...) {
	if (!isSilent(flags)) {
		va_list arg;
		int     done;
		va_start(arg, format);
		done = vfprintf(stream, format, arg);
		va_end(arg);
		return done;
	}
}
