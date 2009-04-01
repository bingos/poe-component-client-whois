use Test::More tests => 5;
use Data::Dumper;

use_ok("POE::Component::Client::Whois::TLDList");
my $tld = POE::Component::Client::Whois::TLDList->new();
isa_ok( $tld, "POE::Component::Client::Whois::TLDList" );
my $test = "bingosnet.co.uk";
my @result = $tld->tld( $test );
ok( $result[0] eq 'whois.nic.uk', "TLD Test for $test" );
my $test2 = "bingosnet.com";
my @result2 = $tld->tld( $test2 );
ok( $result2[0] eq 'whois.internic.net', "TLD Test for $test2" );
my $test3 = "bingosnet.ao";
my @result3 = $tld->tld( $test3 );
ok( $result3[0] eq 'NONE', "TLD Test for $test3" );
