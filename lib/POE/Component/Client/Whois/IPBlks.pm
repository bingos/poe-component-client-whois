package POE::Component::Client::Whois::IPBlks;

use strict;
use warnings;
use Net::Netmask;
use vars qw($VERSION);

$VERSION = '1.24';

sub new {
  my $self = bless { }, shift;
  $self->{data} = {
                             '210.120.0.0/14' => 'whois.nic.or.kr',
                             '145.224.0.0/12' => 'whois.ripe.net',
                             '62.0.0.0/8' => 'whois.ripe.net',
                             '202.30.0.0/15' => 'whois.nic.or.kr',
                             '200.18.0.0/15' => 'whois.nic.br',
                             '210.224.0.0/12' => 'whois.nic.ad.jp',
                             '202.23.0.0/16' => 'whois.nic.ad.jp',
                             '192.72.0.0/16' => 'whois.seed.net.tw',
                             '160.48.0.0/12' => 'whois.ripe.net',
                             '211.112.0.0/13' => 'whois.nic.or.kr',
                             '203.35.0.0/16' => 'whois.telstra.net',
                             '164.32.0.0/13' => 'whois.ripe.net',
                             '192.164.0.0/14' => 'whois.ripe.net',
                             '211.32.0.0/11' => 'whois.nic.or.kr',
                             '139.20.0.0/14' => 'whois.ripe.net',
                             '202.15.0.0/16' => 'whois.nic.ad.jp',
                             '171.16.0.0/12' => 'whois.ripe.net',
                             '145.252.0.0/15' => 'whois.ripe.net',
                             '211.0.0.0/12' => 'whois.nic.ad.jp',
                             '211.104.0.0/13' => 'whois.nic.or.kr',
                             '151.100.0.0/16' => 'whois.ripe.net',
                             '203.36.0.0/14' => 'whois.telstra.net',
                             '145.240.0.0/13' => 'whois.ripe.net',
                             '149.202.0.0/15' => 'whois.ripe.net',
                             '210.61.0.0/16' => 'whois.twnic.net',
                             '163.160.0.0/12' => 'whois.ripe.net',
                             '210.71.128.0/16' => 'whois.twnic.net',
                             '24.192.0.0/14' => 'whois.apnic.net',
                             '210.204.0.0/14' => 'whois.nic.or.kr',
                             '0.0.0.0/2' => 'whois.arin.net',
                             '61.0.0.0/8' => 'whois.apnic.net',
                             '210.96.0.0/13' => 'whois.nic.or.kr',
                             '203.74.0.0/15' => 'whois.twnic.net',
                             '216.0.0.0/8' => 'whois.arin.net',
                             '210.128.0.0/11' => 'whois.nic.ad.jp',
                             '164.128.0.0/12' => 'whois.ripe.net',
                             '210.112.0.0/13' => 'whois.nic.or.kr',
                             '210.65.0.0/16' => 'whois.twnic.net',
                             '149.208.0.0/12' => 'whois.ripe.net',
                             '202.224.0.0/11' => 'whois.nic.ad.jp',
                             '210.92.0.0/14' => 'whois.nic.or.kr',
                             '218.216.0.0/13' => 'whois.apnic.net',
                             '210.180.0.0/14' => 'whois.nic.or.kr',
                             '203.66.0.0/16' => 'whois.twnic.net',
                             '220.0.0.0/8' => 'whois.apnic.net',
                             '61.192.0.0/12' => 'whois.nic.ad.jp',
                             '139.24.0.0/14' => 'whois.ripe.net',
                             '210.241.224.0/19' => 'whois.twnic.net',
                             '202.16.0.0/14' => 'whois.nic.ad.jp',
                             '141.80.0.0/14' => 'whois.ripe.net',
                             '149.224.0.0/12' => 'whois.ripe.net',
                             '133.0.0.0/8' => 'whois.nic.ad.jp',
                             '211.128.0.0/13' => 'whois.nic.ad.jp',
                             '202.24.0.0/15' => 'whois.nic.ad.jp',
                             '203.178.0.0/15' => 'whois.nic.ad.jp',
                             '203.136.0.0/14' => 'whois.nic.ad.jp',
                             '141.0.0.0/10' => 'whois.ripe.net',
                             '211.20.0.0/15' => 'whois.twnic.net',
                             '203.58.128.0/17' => 'whois.telstra.net',
                             '149.206.0.0/15' => 'whois.ripe.net',
                             '203.40.0.0/13' => 'whois.telstra.net',
                             '151.64.0.0/11' => 'whois.ripe.net',
                             '145.254.0.0/16' => 'whois.ripe.net',
                             '203.48.0.0/14' => 'whois.telstra.net',
                             '218.0.0.0/7' => 'whois.apnic.net',
                             '202.11.0.0/16' => 'whois.nic.ad.jp',
                             '210.0.0.0/7' => 'whois.apnic.net',
                             '203.58.32.0/19' => 'whois.telstra.net',
                             '210.62.252.0/22' => 'whois.twnic.net',
                             '149.204.0.0/16' => 'whois.ripe.net',
                             '61.208.0.0/13' => 'whois.nic.ad.jp',
                             '203.232.0.0/13' => 'whois.nic.or.kr',
                             '141.64.0.0/12' => 'whois.ripe.net',
                             '210.188.0.0/14' => 'whois.nic.ad.jp',
                             '196.0.0.0/6' => 'whois.arin.net',
                             '61.112.0.0/12' => 'whois.nic.ad.jp',
                             '200.20.0.0/16' => 'whois.nic.br',
                             '200.17.0.0/16' => 'whois.nic.br',
                             '202.13.0.0/16' => 'whois.nic.ad.jp',
                             '204.0.0.0/6' => 'whois.arin.net',
                             '211.120.0.0/13' => 'whois.nic.ad.jp',
                             '150.254.0.0/16' => 'whois.ripe.net',
                             '211.168.0.0/13' => 'whois.nic.or.kr',
                             '192.0.0.0/8' => 'whois.arin.net',
                             '202.208.0.0/12' => 'whois.nic.ad.jp',
                             '146.48.0.0/16' => 'whois.ripe.net',
                             '160.220.0.0/16' => 'whois.ripe.net',
                             '194.0.0.0/7' => 'whois.ripe.net',
                             '202.39.128.0/17' => 'whois.twnic.net',
                             '198.17.117.0/24' => 'whois.ripe.net',
                             '210.196.0.0/14' => 'whois.nic.ad.jp',
                             '163.156.0.0/14' => 'whois.ripe.net',
                             '203.27.128.0/18' => 'whois.telstra.net',
                             '151.0.0.0/10' => 'whois.ripe.net',
                             '164.0.0.0/11' => 'whois.ripe.net',
                             '211.176.0.0/12' => 'whois.nic.or.kr',
                             '200.0.0.0/7' => 'whois.arin.net',
                             '211.192.0.0/10' => 'whois.nic.or.kr',
                             '200.128.0.0/9' => 'whois.nic.br',
                             '211.22.0.0/16' => 'whois.twnic.net',
                             '208.0.0.0/7' => 'whois.arin.net',
                             '149.248.0.0/14' => 'whois.ripe.net',
                             '139.28.0.0/15' => 'whois.ripe.net',
                             '80.0.0.0/7' => 'whois.ripe.net',
                             '218.224.0.0/13' => 'whois.apnic.net',
                             '203.180.0.0/14' => 'whois.nic.ad.jp',
                             '210.90.0.0/15' => 'whois.nic.or.kr',
                             '171.32.0.0/15' => 'whois.ripe.net',
                             '203.52.0.0/15' => 'whois.telstra.net',
                             '193.0.0.0/8' => 'whois.ripe.net',
                             '212.0.0.0/7' => 'whois.ripe.net',
                             '214.0.0.0/7' => 'whois.arin.net',
                             '202.26.0.0/16' => 'whois.nic.ad.jp',
                             '217.0.0.0/8' => 'whois.ripe.net',
                             '211.16.0.0/14' => 'whois.nic.ad.jp',
                             '149.240.0.0/13' => 'whois.ripe.net',
                             '203.69.0.0/16' => 'whois.twnic.net',
                             '210.248.0.0/13' => 'whois.nic.ad.jp',
                             '210.160.0.0/12' => 'whois.nic.ad.jp',
                             '24.132.0.0/14' => 'whois.ripe.net',
                             '160.44.0.0/14' => 'whois.ripe.net',
                             '211.75.0.0/16' => 'whois.twnic.net',
                             '145.248.0.0/14' => 'whois.ripe.net',
                             '203.140.0.0/15' => 'whois.nic.ad.jp',
                             '218.47.0.0/13' => 'whois.nic.or.kr',
                             '218.40.0.0/13' => 'whois.nic.ad.jp',
                             '210.59.128.0/17' => 'whois.twnic.net',
                             '210.241.0.0/15' => 'whois.twnic.net',
                             '203.0.0.0/10' => 'whois.apnic.net',
                             '192.71.0.0/16' => 'whois.ripe.net',
                             '211.72.0.0/16' => 'whois.twnic.net',
                             '210.216.0.0/13' => 'whois.nic.or.kr',
                             '203.54.0.0/16' => 'whois.telstra.net',
                             '202.0.0.0/7' => 'whois.apnic.net',
                             '210.240.0.0/16' => 'whois.twnic.net',
                             '192.106.0.0/16' => 'whois.ripe.net',
                             '203.58.64.0/19' => 'whois.telstra.net',
                             '141.84.0.0/15' => 'whois.ripe.net',
                             '151.96.0.0/14' => 'whois.ripe.net',
                             '202.32.0.0/14' => 'whois.nic.ad.jp',
                             '192.162.0.0/16' => 'whois.ripe.net',
                             '169.208.0.0/12' => 'whois.apnic.net',
                             '202.48.0.0/16' => 'whois.nic.ad.jp',
                             '210.178.0.0/15' => 'whois.nic.or.kr',
                             '210.242.0.0/15' => 'whois.twnic.net',
                             '164.40.0.0/16' => 'whois.ripe.net',
                             '210.104.0.0/13' => 'whois.nic.or.kr',
                             '160.216.0.0/14' => 'whois.ripe.net',
			     '58.0.0.0/8' => 'whois.apnic.net',
                           };
  return $self;
}

sub get_server {
  my $self = shift;
  my $ip = shift || return undef;

  foreach my $range ( keys %{ $self->{data} } ) {
	if ( $range eq '0.0.0.0/2' ) {
		foreach my $cls_a ( 1 .. 126 ) {
		  my $block2 = Net::Netmask->new( "$cls_a.0.0.0/8" );
		  if ( $block2->match( $ip ) ) {
			return ( $self->{data}->{ $range }, $range );
		  }
		}
	}
	my $block = Net::Netmask->new( $range );
	if ( $block->match( $ip ) ) {
		return ( $self->{data}->{ $range }, $range );
	}
  }
  return undef;
}

1;

__END__

=head1 NAME

POE::Component::Client::Whois::IPBlks - determine which whois server is responsible for a network address.

=head1 SYNOPSIS

  use strict;
  use POE::Component::Client::Whois::IPBlks;

  my $ipblks = POE::Component::Client::Whois::IPBlks->new();

  my $whois_server = $ipblks->get_server('192.168.1.12');

=head1 DESCRIPTION

POE::Component::Client::Whois::IPBlks provides the ability to determine which whois server is responsible for a network address. It has a list of network ranges mapped to whois servers and uses L<Net::Netmask> to determine the appropriate Whois server for the given address.

=head1 CONSTRUCTOR

=over

=item C<new>

Returns a POE::Component::Client::Whois::IPBlks object.

=back

=head1 METHODS

=over

=item C<get_server>

Takes a single argument, an IP address to lookup the Whois for. Returns the applicable whois server or undef on failure.

=back

=head1 AUTHOR

Chris C<BinGOs> Williams

=head1 LICENSE

Copyright E<copy> Chris Williams

This module may be used, modified, and distributed under the same terms as Perl itself. Please see the license that came with your Perl distribution for details.

=head1 SEE ALSO 

L<Net::Netmask>
