
SOURCES = pam_doublecheck.c
BIN = pam_doublecheck

EXPORT_PATH = /exports

link: compile
	ld -x --shared -o $(BIN).so $(BIN).o

exports: compile
	sudo ld -x --shared -o $(EXPORT_PATH)/$(BIN).so $(BIN).o

compile:
	gcc -fPIC -fno-stack-protector -o $(BIN).o -c $(SOURCES)



clean:
	$(RM) -f $(BIN).so $(BIN).o
