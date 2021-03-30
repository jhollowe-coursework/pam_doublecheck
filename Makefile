
SOURCES = pam_doublecheck.c twilio.c
LIBS = -lcurl
BIN = pam_doublecheck

EXPORT_PATH = /usr/lib/x86_64-linux-gnu/security

compile:
	gcc -g -fPIC -shared -fno-stack-protector -o $(BIN).so $(SOURCES) $(LIBS)

exports: compile
	sudo cp $(BIN).so $(EXPORT_PATH)/$(BIN).so
	sudo chown root:root $(EXPORT_PATH)/$(BIN).so
	sudo chmod 644 $(EXPORT_PATH)/$(BIN).so

test: exports
	pam_test auth vscode

clean:
	$(RM) -f $(BIN).so $(BIN).o
