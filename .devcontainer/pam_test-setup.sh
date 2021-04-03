#!/usr/bin/env bash

LIB=pam_doublecheck.so

echo "adding pam_test PAM config"
sudo tee /etc/pam.d/pam_test > /dev/null << EOF
account required ${LIB}
EOF

echo "adding password for vscode user"
echo "vscode:password" | sudo chpasswd

echo "creating test users"
sudo useradd -G sudo -c "+19342004168" test1
sudo useradd test2
sudo useradd test3
sudo useradd -G sudo -c "+1 423-218-9620" test4
