#include "doublecheck.h"

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Please use the command as show in your notification (requires both numbers).\n");
	}

	int sessionId = atoi(argv[1]);
	int userUuid  = atoi(argv[2]);

	int  fd;
	char filename[GENERIC_STRING_MAX_LENGTH];
	sprintf(filename, "%s_%0*d", DC_COMMUNICATION_FILE_BASE, DC_ID_PAD_LENGTH, sessionId);

	if ((fd = open(filename, O_WRONLY | O_APPEND)) < 0) {
		fprintf(stderr, DC_ERROR_MESSAGE);
		exit(1);
	}

	char line[LINE_MAX_LENGTH];
	sprintf(line, "%d\n", userUuid);

	if (write(fd, line, strlen(line)) < 0) {
		fprintf(stderr, DC_ERROR_MESSAGE);
	}

	close(fd);

	return 0;
}
