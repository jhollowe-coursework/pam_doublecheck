
PAM_SOURCES = pam_doublecheck.c twilio.c
PAM_LIBS = -lcurl
PAM_BIN = pam_doublecheck
PAM_EXPORT_PATH = /usr/lib/x86_64-linux-gnu/security

SOURCES = doublecheck.c
LIBS =
BIN = doublecheck
EXPORT_PATH = /bin

compile_all: compile_bin compile_pam

.PHONY: compile_all exports test install

compile_bin:
	gcc -Wall -g -o $(BIN) $(SOURCES) $(LIBS)

compile_pam:
	gcc -Wall -g -fPIC -shared -fno-stack-protector -o $(PAM_BIN).so $(PAM_SOURCES) $(PAM_LIBS)


install: exports
exports: export_bin export_pam

export_bin: compile_bin
	@sudo cp $(BIN) $(EXPORT_PATH)/$(BIN)
	@sudo chown root:root $(EXPORT_PATH)/$(BIN)
	@sudo chmod 755 $(EXPORT_PATH)/$(BIN)

export_pam: compile_pam
	@sudo cp $(PAM_BIN).so $(PAM_EXPORT_PATH)/$(PAM_BIN).so
	@sudo chown root:root $(PAM_EXPORT_PATH)/$(PAM_BIN).so
	@sudo chmod 644 $(PAM_EXPORT_PATH)/$(PAM_BIN).so

test: test_pam
test_pam: export_pam
	pam_test auth vscode

test_bin: compile_bin
	./doublecheck 123 456

clean:
	$(RM) -f $(PAM_BIN).so $(BIN)
