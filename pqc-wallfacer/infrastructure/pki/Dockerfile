# syntax=docker/dockerfile:1.7
# wallfacer/pki — offline CA and artifact signer (PKI-02..PKI-09, PRV-01..PRV-04, MSH-05).
# Runs with no network at all (compose: network_mode: none). Keys live on the /pki volume,
# which should sit on the air-gapped host's encrypted disk, never on an online node.
ARG BASE_IMAGE=wallfacer/base:latest
FROM ${BASE_IMAGE}

USER root
COPY wf-ca wf-sign /usr/local/bin/
RUN chmod 0755 /usr/local/bin/wf-ca /usr/local/bin/wf-sign \
 && install -d -o wf -g wf -m 0700 /pki

USER wf
WORKDIR /pki
VOLUME ["/pki"]
CMD ["wf-ca", "help"]
