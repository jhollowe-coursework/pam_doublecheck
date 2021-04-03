#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DC_COMMUNICATION_FILE_BASE "/tmp/dc_verify"
#define DC_ERROR_MESSAGE           "Unable to communicate with PAM module\n"
#define LINE_MAX_LENGTH            10
#define GENERIC_STRING_MAX_LENGTH  1000
#define DC_ID_PAD_LENGTH           3
