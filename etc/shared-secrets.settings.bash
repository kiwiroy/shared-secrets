#!/bin/echo

SCRIPT=$(basename $0)
SS_DIR=$(dirname $(dirname $0))

TARGET_DIRECTORY=$SS_DIR/share
           VAULT=$SS_DIR/vault

PRIVATE_PEM=$SS_DIR/etc/keys/shared-secrets.pem
 PUBLIC_PEM=$SS_DIR/etc/keys/shared-secrets.pem.pub
  SYMMETRIC=$VAULT/symmetric.key.rsa
