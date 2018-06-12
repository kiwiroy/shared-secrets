
#!/bin/echo

##
## Settings and functions file for encrypt-keys and decrypt-keys
##


function message
{
    echo "[$SCRIPT] $@" >&2;
}

function message_exit {
    echo "[$SCRIPT] $@" >&2;
    exit 1
}

function encrypt_sym_key_decrypt
{
    message "+ generating random symmetric key..."
    head -c 32 /dev/urandom                               | \
        openssl enc -base64                               | \
	      openssl rsautl -encrypt -inkey $PUBLIC_PEM -pubin | \
	      tee $SYMMETRIC                                    | \
	      openssl rsautl -inkey $PRIVATE_PEM -decrypt
}

function decrypt_sym_key
{
    message "+ decrypting $SYMMETRIC key file"
    cat $SYMMETRIC | openssl rsautl -inkey $PRIVATE_PEM -decrypt
}

function clean
{
    message "+ cleaning up..."
    tar -tf $VAULT/vault.tar.gz | {
	    cd $VAULT && xargs rm
    }
}
