
SOURCES = pam_doublecheck.c
BIN = pam_doublecheck

EXPORT_PATH = /usr/lib/x86_64-linux-gnu/security

link: compile
	ld -x --shared -o $(BIN).so $(BIN).o

exports: compile
	sudo ld -x --shared -o $(EXPORT_PATH)/$(BIN).so $(BIN).o

compile:
	gcc -g -fPIC -fno-stack-protector -o $(BIN).o -c $(SOURCES)

test: exports
	pam_test auth vscode

clean:
	$(RM) -f $(BIN).so $(BIN).o
