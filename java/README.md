# SignedJSON java class
Simple way to add digital signature to plain JSON in a backward-compatible way 

## Example usage to verify a signed json
```java
SignedJSON signedJSON = new SignedJSON().setPublicKey(getResources().openRawResource(R.raw.publickey));
byte[] json = someMethodThatReturnsSignedJson(); 

try {
	byte[] jsonWithoutSignature = signedJSON.verify(json,
		SignedJSON.VERIFY_MODE.NO_SIGNATURE_FAIL);

	// signature verified	

} catch(SignedJSON.BadSignatureException e) {

	// signature was not verified

}

```
The code above assumes we put a public key required to verify a signature to `res/raw/publickey.der` file.  Please see below instructions on generating keys with openssl. 

## Example usage to sign a json
```java
SignedJSON signedJSON = new SigneJSON().setPrivateKey(getResources().openRawResource(R.raw.privatekey));
byte[] json = someMethodThatReturnsPlainJson(); 

byte[] jsonWithSignature = signedJSON.sign(json);
```
The code above assumes we put a private key required to sign a json to `res/raw/privatekey.der` file.  Please see below instructions on generating keys with openssl. 

## Why do we keep json in byte[] instead of String?
We do that simply to avoid any locale-based conversions that could alter the characters and possibly broke the signature. It is recommended to get the json (e.g. from the web) as a byte[] array first, verify the signature and only then convert it to String if needed: `jsonString = new String(jsonBytes)`.  
When signing a json it is recommended to convert the json from String to byte[] first, and only then sign it and save or send: `jsonBytes = jsonString.getBytes()`.

## How to generate keys and convert them to the required formats 
To generate a keypair:
```
openssl genrsa -out private.pem 1024
```
To save a public key in a file in der format that can be used by SignedJSON java class:
```
openssl rsa -in private.pem -pubout -outform DER -out publickey.der
```
To save a private key in PKCS#8 der format that can be used by SignedJSON java class:
```
openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem \
    -out privatekey.der -nocrypt
```
Public key is only required to verify a signature that was created with the corresponding private key.  A private key is only required to generate a signature. A typical usage is having a public key with an application to verify signed json downloaded from the server.  The corresponding private key is secretely kept on server and is used to sign json files. 

## License

```
Copyright 2015 Sergey Gershtein

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
