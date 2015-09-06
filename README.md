# SignedJSON
Simple way to add digital signature to plain JSON in a backward-compatible way 

We need a simple way to digitally sing JSON file keeping the signature embedded into the file.
Why embedded?  Because having the signature separately in another file may cause ugly race conditions when either JSON file itself or its signature file gets cached by a proxy, requested a moment later after being updated, etc.  This can easily lead for the client to getting wrong (a future or a past) signature file that does not match the JSON data.  And there would be no easy way to distinguish this kind of race condition from a bad case when the data is indeed compromised.
There are definitely ways to get around the race condition, e.g. we could keep the JSON payload and its signature in a single zip archive.  That's one way to do it.  We've chosen another way.

Our method is similar to the one described here: http://upon2020.com/blog/2014/03/digital-signatures-on-json-payloads-lets-call-it-jsonsig/ albeit more simple.  We only allow one signature per file and only embed the signature itself there as the public key required to verify the signature is already know to the client.

### The process of signing is the following:

 * A binary sha256 signature is calculated for the original JSON file:
```shell
openssl dgst -sha256 -binary -sign private.pem data.json >signature
```
 * The signature is base64 encoded:
```shell
base64 -w 0 signature >signature64
``` 
 * The calculated base64-encoded signature is embedded to the original JSON file immediately after the first opening curly bracket with the key "dgst_sha256_base64".  It is important not to modify in any way the rest of the file. The following perl regular expression can be used:
```perl
s/^(\s*{)/$1"dgst_sha256_base64":"$signature64",/
```

This way the signed file is still absolutely valid JSON file with all the original data in place and only one field added on the top level.  Any original parser of the file can use it as it is simply ignoring the new dgst_sha256_base64 field.  However care now must be taken not to alter the signed file in any way including any whitespace as it would break the signature.

### The process of verifying the signature is the opposite:

 * First we need to extract the signature from JSON-file carefully returning it to the original state it was before we injected the signature there.  This can be done with the following perl code:
```perl
s/^(\s*{)"dgst_sha256_base64":"([^"]+)",/$1/; my $signature64 = $2;
```
 * Then we need to decode the signature from base64
```shell
base64 -d signature64 >signature
```
 * Finally verify the signature with openssl:
```shell
openssl gdst -verify public.pem -signature signature data.json
```

## Perl module

**SignedJSON.pm** perl module in perl subdir does all the work for signing JSON files this way and verifying signatures

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
