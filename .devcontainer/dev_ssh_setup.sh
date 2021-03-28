#!/usr/bin/env bash

# add config so you can just use `ssh target`
cat >> ~/.ssh/config << EOF
Host target
  User vscode
  Port 2222
EOF
