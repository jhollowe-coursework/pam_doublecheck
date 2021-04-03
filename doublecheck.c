#include "doublecheck.h"

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Please use the command as show in your notification (requires both numbers).\n");
	}
	char *username  = getlogin();
	int   sessionId = atoi(argv[1]);
	int   userUuid  = atoi(argv[1]);

	int fd;
	if ((fd = open(DC_COMMUNICATION_FILE, O_APPEND)) < 0) {
		fprintf(stderr, DC_ERROR_MESSAGE);
		exit(1);
	}

	char line[LINE_MAX_LENGTH];
	sprintf(line, "%s %d %d\n", username, sessionId, userUuid);
	printf("%s", line);

	// keep trying to get the lock
	while (flock(fd, LOCK_EX))
		;

	if (write(fd, line, strlen(line)) < 0) {
		fprintf(stderr, DC_ERROR_MESSAGE);
	}
	flock(fd, LOCK_UN);
	close(fd);

	return 0;
}
