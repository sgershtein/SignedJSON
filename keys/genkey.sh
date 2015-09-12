#!/bin/sh
#
# Generate keypair for signing files in the api
#

# generate a keypair
openssl genrsa -out private.pem 1024 ; chmod 600 private.pem

# save public key in pem format 
openssl rsa -in private.pem -pubout -outform PEM -out public.pem 

# save public key in der format (this one can be used by SignedJSON.java)
openssl rsa -in private.pem -pubout -outform DER -out public.der

# save private key in PKCS#8 der format (can be used by SignedJSON.java)
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem \
    -out private.der -nocrypt

# generate signature for a file
#openssl dgst -sha256 -binary -sign private.pem data.txt > signature

# verify signature
#openssl dgst -verify public.pem -signature QQQ.signature QQQ


