# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.163.1/containers/cpp/.devcontainer/base.Dockerfile

# [Choice] Debian / Ubuntu version: debian-10, debian-9, ubuntu-20.04, ubuntu-18.04
ARG VARIANT="buster"
FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT} as base

# [Optional] Uncomment this section to install additional packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends libpam0g-dev

#######################################################################

FROM base as builder

RUN git clone https://github.com/pbrezina/pam-test.git pam-test \
    && cd pam-test && make

#######################################################################

FROM base

COPY --from=builder /pam-test/pam_test /bin/

VOLUME "/app/"

# CMD ["/bin/sh", "-c", "while sleep 1000; do :; done"]
