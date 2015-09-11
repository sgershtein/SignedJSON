#!/usr/bin/perl
#
# test script for SignedJSON.pm
#

use strict;
use SignedJSON;
use JSON;
use utf8;
use Encode;


my $data = {
	'a' => 'b',
	'c' => [
		{
			'c1' => 'c1-1',
			'c2' => 'c2-1',
			'Русский' => 'ё',
			'中' => '中國的',
		},
		{
			'c1' => 'c1-2',
			'c2' => 'c2-2',
		},
		{
			'c1' => 'c1-3',
			'c2' => 'c2-3',
		},
	]
};

# plain json 
my $plainjson = "  " . 
    encode('UTF-8', JSON->new->utf8(0)->pretty(0)->encode( $data ) );

print "PLAIN JSON:\n$plainjson\n---------------------------\n";

# now let's sign it
my $sJSON = new SignedJSON( {
		'privatekey' => 'private.pem',
		'publickey' => 'public.pem',
	} );

my $signedjson = $sJSON->sign( $plainjson );

print "SIGNED JSON:\n$signedjson\n---------------------------\n";

# let's verify signature

my $result = $sJSON->verify( $signedjson );

if( $result ) {
	print "VERIFICATION PASSED\n";
	if( $plainjson =~ /^\s*\Q$result\E\s*$/ ) {
		print "RESULT EQUAL TO ORIGINAL JSON\n";
	} else {
		print "**** ERROR: RESULT NOT EQUAL TO ORIGINAL JSON\n";
	}
} elsif( defined( $result ) ) {
	print "*** ERROR: SIGNATURE NOT FOUND\n";
} else {
	print "*** ERROR: VERIFICATION FAILED\n";
}

# now let's modify the signed json and try to verify again

$signedjson =~ s/c1-3/c1-4/;

$result = $sJSON->verify( $signedjson );

if( $result ) {
	print "*** ERROR: VERIFICATION PASSED FOR ALTERED JSON\n";
} elsif( !defined( $result ) ) {
	print "*** ERROR: SIGNATURE NOT FOUND\n";
} else {
	print "VERIFICATION FAILED FOR ALTERED JSON\n";
}

# now let's try to verify unsigned json

$result = $sJSON->verify( $plainjson );

if( $result ) {
	print "*** ERROR: VERIFICATION PASSED FOR UNSIGNED JSON\n";
} elsif( !defined( $result ) ) {
	print "SIGNATURE NOT FOUND IN UNSIGNED JSON\n";
} else {
	print "*** ERROR: VERIFICATION FAILED FOR UNSIGNED JSON (should be signature not found)\n";
}
