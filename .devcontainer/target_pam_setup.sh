#!/usr/bin/env bash

LIB=pam_doublecheck.so

# cp /exports/${LIB} /lib/security/


sudo tee -a /etc/pam.d/base-account > /dev/null << EOF
account required /exports/${LIB}
EOF
