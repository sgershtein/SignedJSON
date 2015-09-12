MODULE
------

`SignedJSON.pm` - digitally sign JSON files; verify signature for a signed JSON file

SYNOPSIS
--------

```perl
  use SignedJSON;

  # initialize the object 
  # NB. private key is only required for signing, public key for verifying, 
  # You don't have to specify both when initializing the object 
  $sJSON = new SignedJSON( {
            'privatekey' => '/some/place/private.pem',
            'publickey' => '/some/place/public.pem', 
           } ); 

  # sign a plain json file.
  my $signedjson = $sJSON->sign( $plainjson );

  # verify a signature of a signed json
  # the return value is be the following:
  #  - if verification passed, the function returns plain original JSON without the signature 
  #  - if verification failed an empty string is returned
  #  - if no signature found or wrong format, undef is returned
  my $plainjson = $sJSON->verify( $signedjson ) or die;
```

DESCRIPTION
-----------

The purpose of this module is to create digitally signed JSON file that is
backward-compartible with the original unsigned file. The signature is
embedded into the JSON structure as exactly one additional field that can
be safely ignored by legacy parsers. All the JSON structure of the
original file is kept intact. The field key is "dgst_sha256_base64"

NOTE
----

The module requies openssl and tries to find it in one of the following
places: `/bin`, `/usr/bin`, `/usr/local/bin`

If you have openssl somewhere else, pass its location as an extra key when
initializing SignedJSON object:

```perl
  $sJSON = new SignedJSON( { 'openssl' => '/some/place/openssl', ...} );
```

AUTHOR
------

Sergey Gershtein <http://sergey.gershtein.net/>

## How to generate keys and convert them to the required formats 
To generate a keypair:
```
openssl genrsa -out private.pem 1024
```
To save a public key in a file in pem format that can be used by SignedJSON.pm module:
```
openssl rsa -in private.pem -pubout -outform PEM -out public.pem
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
