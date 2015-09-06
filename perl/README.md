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
            'publickey' => '/some/place/public.key', 
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
original file is kept intact. The field key is [1m"dgst_sha265_base64"[0m

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

