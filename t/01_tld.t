use Test::More tests => 5;
use Data::Dumper;

use_ok("POE::Component::Client::Whois::TLDList");
my $tld = POE::Component::Client::Whois::TLDList->new();
isa_ok( $tld, "POE::Component::Client::Whois::TLDList" );
my $test = "bingosnet.co.uk";
my @result = $tld->tld( $test );
is( $result[0], 'whois.nic.uk', "TLD Test for $test" );
my $test2 = "bingosnet.com";
my @result2 = $tld->tld( $test2 );
is( $result2[0], 'whois.internic.net', "TLD Test for $test2" );
my $test3 = "bingosnet.ao";
my @result3 = $tld->tld( $test3 );
is( $result3[0], 'NONE', "TLD Test for $test3" );
