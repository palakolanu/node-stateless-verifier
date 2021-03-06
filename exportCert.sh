#!/bin/bash
#smof 08/06/15 export cert for alias=test from Java keystore into PEM format - then strip out just the public key using openssl. Outputs to publicKey.pem file

#Certificate alias that you want to export
ALIAS="test" 
#Keystore location
KEYSTORE="/path/to/java/keystore/keystore.jks"
#Location of output file
OUTPUT="$ALIAS-publicKey.pem"

keytool -exportcert -alias $ALIAS -keystore $KEYSTORE -rfc | openssl x509 -pubkey -noout > $OUTPUT
