use Test::More tests => 5;

use_ok("POE::Component::Client::Whois::IPBlks");
my $tld = POE::Component::Client::Whois::IPBlks->new();
isa_ok( $tld, "POE::Component::Client::Whois::IPBlks" );
my $test = "192.168.1.1";
my @result = $tld->get_server( $test );
ok( $result[0] eq 'whois.arin.net', "TLD Test for $test" );
my $test2 = "211.200.1.55";
my @result2 = $tld->get_server( $test2 );
ok( $result2[0] eq 'whois.apnic.net', "TLD Test for $test2" );
my $test3 = "100.0.0.1";
my @result3 = $tld->get_server( $test3 );
ok( $result3[0] eq 'whois.arin.net', "TLD Test for $test3" );
