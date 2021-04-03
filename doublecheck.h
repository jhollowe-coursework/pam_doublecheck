#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define DC_COMMUNICATION_FILE "/tmp/dc_verify"
#define DC_ERROR_MESSAGE      "Unable to communicate with PAM module\n"

#define USERNAME_MAX_LENGTH 32
#define LINE_MAX_LENGTH     USERNAME_MAX_LENGTH + 10
