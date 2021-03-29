#!/usr/bin/env bash

LIB=pam_doublecheck.so

echo "adding pam_test PAM config"
sudo tee /etc/pam.d/pam_test > /dev/null << EOF
account required ${LIB}
EOF

echo "adding password for vscode user"
echo "vscode:password" | sudo chpasswd
