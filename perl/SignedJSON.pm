#!/usr/bin/perl
#
# A module for digitally signing JSON files and verifying signed files
#

#
# object initialization
#

=head1 MODULE

SignedJSON.pm - digitally sign JSON files; verify signature for a signed 
JSON file

=head1 SYNOPSIS

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
  #  if verification passed, the function returns plain original JSON 
  #  without the signature 
  #  if verification failed an empty string is returned
  #  if no signature found or wrong format, undef is returned
  my $plainjson = $sJSON->verify( $signedjson ) or die;

=head1 DESCRIPTION

The purpose of this module is to create digitally signed JSON file that is 
backward-compartible with the original unsigned file.   The signature is
embedded into the JSON structure as exactly one additional field that
can be safely ignored by legacy parsers.  All the JSON structure of the
original file is kept intact. The field key is B<"dgst_sha265_base64">

=head1 NOTE

The module requies openssl and tries to find it in one of the following places:
  /bin
  /usr/bin
  /usr/local/bin

If you have openssl somewhere else, pass its location as an extra key
when initializing SignedJSON object:

  $sJSON = new SignedJSON( { 'openssl' => '/some/place/openssl', ...} );

=head1 AUTHOR

Sergey Gershtein  L<http://sergey.gershtein.net/>

=cut

package SignedJSON;
use strict;
use Carp;
use File::Path qw( remove_tree );
use MIME::Base64;
use vars qw( $SIGNATURE_KEY );

# key that holds the signature in JSON structure
$SIGNATURE_KEY = "dgst_sha256_base64";

# path to search for openssl
my @paths = qw( /bin /usr/bin /usr/local/bin );
# openssl binary name
my $filename = 'openssl';
# directory for temporary files
my $tempDir = "/tmp/sjson.$$";

#my $opensslArgs = {
#	'sign' 		=> [ qw( gdst -sha256 -binary -sign ) ],
#	'verify'	=> [ qw( dgst -verify ) ].
#}

# found openssl location
my $openssl;


# object initialization
sub new {
	my $class = shift;
	my $args = shift;

	croak "The only constructor argument must be a hash reference" 
		unless( ref( $args ) eq 'HASH' );

	# start constructing the object
	my $self = {};

	foreach my $k (keys %$args) {
		if( $k =~ /^(public|private)key$/ ) {

			# check if the file exists and is readable
			if( -r $args->{$k} ) {
				$self->{$k} = $args->{$k};
			} else {
				croak "Key file for $k ".$args->{$k}.
					" does not exist or no read permissions";
			}

		} elsif( $k eq 'openssl' ) {

			# check if the file exists and is executable
			if( -x $args->{$k} ) {
				$self->{$k} = $args->{$k}
			} else {
				carp "Could not execute specified openssl binary ".
					$args->{$k}.
					", will try to check default locations";
			}

		}
	} # foreach

	# look for openssl location if not provided
	unless( $self->{'openssl'} ) {
		if( $openssl ) {
			$self->{'openssl'} = $openssl;
		} else {
			foreach my $p (@paths) {
				if( -x "$p/$filename" ) {
					$self->{'openssl'} = $openssl = "$p/$filename";
					last; 
				}
			}
			croak "$filename not found in any of default locations" unless( $openssl );
		}
	}

	bless $self, $class;
	return $self;
}


#
# sign the provided JSON
#
sub sign {
	my $self = shift;
	my $json = shift;

	# first check it looks like JSON
	croak "Input does not look like JSON" 
		unless( $json =~ /^\s*{/ );

	# do we have a private key?
	croak "Need private key to make a signature"
		unless( $self->{'privatekey'} );

	# create a temporary dir
	$self->make_temp_dir();

	# we don't need line breaks parsing here, so setting local $/ undefined
	local( $/ );

	# remove any whitespace before starting and after ending curly bracket
	$json =~ s/^\s*{/{/;
	$json =~ s/}\s*$/}/;

	# store json to a temp file
	my $datafile = $self->{'tempdir'}.'/data';
	putFile( $datafile, $json );

	# run openssl to sign the file
	my( $f );
	open( $f, "-|", 
		$self->{'openssl'},
		'dgst', '-sha256', '-binary',
		'-sign', $self->{'privatekey'},
		$datafile 
		) || croak "Error running $self->{'openssl'}: $!";
	binmode( $f );
	my $signature = <$f>;
	close( $f );

	# base64-encode the signature
	$signature = encode_base64( $signature, "" );

	# embed the signature into the provided json
	$json =~ s/^(\s*{)/$1"$SIGNATURE_KEY":"$signature",/;

	# remove temp files
	$self->clean_temp_dir();

	return $json;

}

#
# check the signature
#
sub verify {
	my $self = shift;
	my $json = shift;

	my $signature; 

	# check if it's a signed json
	if( $json =~ s/^(\s*{)"$SIGNATURE_KEY":"([^"]+)",/$1/ ) {
		$signature = decode_base64( $2 );
	} else {
		# not a JSON or no signature
		return undef;
	}

	# remove any whitespace before starting and after ending curly bracket
	$json =~ s/^\s*{/{/;
	$json =~ s/}\s*$/}/;

	# do we have a public key?
	croak "Need public key to make a signature"
		unless( $self->{'publickey'} );

	# create a temporary dir
	$self->make_temp_dir();

	# we don't need line breaks parsing here, so setting local $/ undefined
	local( $/ );

	# store signature to a temp file
	my $sfile = $self->{'tempdir'}.'/signature';
	putFile( $sfile, $signature );

	# run openssl to verify the signature
	my $f;
	open( $f, "|-", 
		$self->{'openssl'},
		'dgst', '-sha256',
		'-verify', $self->{'publickey'},
		'-signature', $sfile,
		'-out', $self->{'tempdir'}.'/out'
		) || croak "Error running $self->{'openssl'}: $!";
	binmode( $f );
	print $f $json;
	unless( close( $f ) ) {
		if( $! ) {
			croak "Error closing pipe to openssl: $!"; 
		} else {
			# signature not verified
			$json = "";
		}
	}

	$self->clean_temp_dir();

	return $json;
}

# --------------------------
# "private" internal methods
# --------------------------

# create a temporary directory
sub make_temp_dir {
	my $self = shift;

	# try up to 100 times to find a name that is not yet used
	my $rnd = "";
	for( my $i = 0; $i < 100; $i++ ) {

		if( mkdir( $tempDir.$rnd, 0700 ) ) {
			# success
			$self->{'tempdir'} = $tempDir.$rnd;
			return $self; 
		} 

		# try another random suffix	
		$rnd = int(rand(10000));
	}

	#failed to find a dir we could create
	croak "Unable to create temporary firectory $tempDir";

}

# clean our temporary directory
sub clean_temp_dir {
	my $self = shift;

	confess "Internal error: clean_temp_dir called before make_temp_dir"
		unless( $self->{'tempdir'} );

	remove_tree( $self->{'tempdir'} ) ||
		carp "Error removing temporary dir ".$self->{'tempdir'};

	delete $self->{'tempdir'}
}

# put all data to a file owerwriting it if needed
sub putFile {
	my $path = shift;
	my $content = shift;

	open( my $f, ">", $path ) || 
		carp "Error writing to the file $path: $!";
	print $f $content;
	close( $f );
}
1; 
