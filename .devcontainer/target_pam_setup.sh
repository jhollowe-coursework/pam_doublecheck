#!/usr/bin/env bash

LIB=pam_doublecheck.so

# cp /exports/${LIB} /lib/security/


# echo "adding PAM config to base-account"
# sudo tee -a /etc/pam.d/base-account > /dev/null << EOF
# account required /exports/${LIB}
# EOF

# echo "enabling PAM in sshd_config"
# sudo sed -i 's/#\?UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config


echo "adding pam_test PAM config"
sudo tee -a /etc/pam.d/pam_test > /dev/null << EOF
account required /exports/${LIB}
EOF
