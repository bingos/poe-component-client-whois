package POE::Component::Client::Whois::IPBlks;

use strict;
use warnings;
use Net::Netmask;
use vars qw($VERSION);

$VERSION = '1.28';

sub new {
  my $self = bless { }, shift;
  $self->{data} = {
  '175.0.0.0/8' => 'whois.apnic.net',
  '170.0.0.0/8' => 'whois.arin.net',
  '66.0.0.0/8' => 'whois.arin.net',
  '184.0.0.0/8' => 'whois.arin.net',
  '90.0.0.0/8' => 'whois.ripe.net',
  '132.0.0.0/8' => 'whois.arin.net',
  '15.0.0.0/8' => 'whois.arin.net',
  '163.0.0.0/8' => 'whois.apnic.net',
  '97.0.0.0/8' => 'whois.arin.net',
  '129.0.0.0/8' => 'whois.arin.net',
  '100.0.0.0/8' => 'whois.arin.net',
  '111.0.0.0/8' => 'whois.apnic.net',
  '188.0.0.0/8' => 'whois.ripe.net',
  '209.0.0.0/8' => 'whois.arin.net',
  '27.0.0.0/8' => 'whois.apnic.net',
  '139.0.0.0/8' => 'whois.arin.net',
  '171.0.0.0/8' => 'whois.apnic.net',
  '48.0.0.0/8' => 'whois.arin.net',
  '1.0.0.0/8' => 'whois.apnic.net',
  '14.0.0.0/8' => 'whois.apnic.net',
  '183.0.0.0/8' => 'whois.apnic.net',
  '4.0.0.0/8' => 'whois.arin.net',
  '61.0.0.0/8' => 'whois.apnic.net',
  '8.0.0.0/8' => 'whois.arin.net',
  '108.0.0.0/8' => 'whois.arin.net',
  '81.0.0.0/8' => 'whois.ripe.net',
  '189.0.0.0/8' => 'whois.lacnic.net',
  '43.0.0.0/8' => 'whois.apnic.net',
  '37.0.0.0/8' => 'whois.ripe.net',
  '223.0.0.0/8' => 'whois.apnic.net',
  '74.0.0.0/8' => 'whois.arin.net',
  '92.0.0.0/8' => 'whois.ripe.net',
  '105.0.0.0/8' => 'whois.afrinic.net',
  '12.0.0.0/8' => 'whois.arin.net',
  '176.0.0.0/8' => 'whois.ripe.net',
  '98.0.0.0/8' => 'whois.arin.net',
  '218.0.0.0/8' => 'whois.apnic.net',
  '145.0.0.0/8' => 'whois.ripe.net',
  '164.0.0.0/8' => 'whois.arin.net',
  '24.0.0.0/8' => 'whois.arin.net',
  '16.0.0.0/8' => 'whois.arin.net',
  '185.0.0.0/8' => 'whois.ripe.net',
  '178.0.0.0/8' => 'whois.ripe.net',
  '89.0.0.0/8' => 'whois.ripe.net',
  '130.0.0.0/8' => 'whois.arin.net',
  '124.0.0.0/8' => 'whois.apnic.net',
  '67.0.0.0/8' => 'whois.arin.net',
  '88.0.0.0/8' => 'whois.ripe.net',
  '155.0.0.0/8' => 'whois.arin.net',
  '109.0.0.0/8' => 'whois.ripe.net',
  '220.0.0.0/8' => 'whois.apnic.net',
  '204.0.0.0/8' => 'whois.arin.net',
  '116.0.0.0/8' => 'whois.apnic.net',
  '115.0.0.0/8' => 'whois.apnic.net',
  '112.0.0.0/8' => 'whois.apnic.net',
  '144.0.0.0/8' => 'whois.arin.net',
  '36.0.0.0/8' => 'whois.apnic.net',
  '207.0.0.0/8' => 'whois.arin.net',
  '172.0.0.0/8' => 'whois.arin.net',
  '5.0.0.0/8' => 'whois.ripe.net',
  '77.0.0.0/8' => 'whois.ripe.net',
  '153.0.0.0/8' => 'whois.apnic.net',
  '47.0.0.0/8' => 'whois.arin.net',
  '211.0.0.0/8' => 'whois.apnic.net',
  '56.0.0.0/8' => 'whois.arin.net',
  '146.0.0.0/8' => 'whois.arin.net',
  '198.0.0.0/8' => 'whois.arin.net',
  '136.0.0.0/8' => 'whois.arin.net',
  '168.0.0.0/8' => 'whois.arin.net',
  '65.0.0.0/8' => 'whois.arin.net',
  '20.0.0.0/8' => 'whois.arin.net',
  '72.0.0.0/8' => 'whois.arin.net',
  '197.0.0.0/8' => 'whois.afrinic.net',
  '119.0.0.0/8' => 'whois.apnic.net',
  '191.0.0.0/8' => 'whois.lacnic.net',
  '125.0.0.0/8' => 'whois.apnic.net',
  '84.0.0.0/8' => 'whois.ripe.net',
  '181.0.0.0/8' => 'whois.lacnic.net',
  '203.0.0.0/8' => 'whois.apnic.net',
  '142.0.0.0/8' => 'whois.arin.net',
  '210.0.0.0/8' => 'whois.apnic.net',
  '52.0.0.0/8' => 'whois.arin.net',
  '138.0.0.0/8' => 'whois.arin.net',
  '194.0.0.0/8' => 'whois.ripe.net',
  '154.0.0.0/8' => 'whois.afrinic.net',
  '93.0.0.0/8' => 'whois.ripe.net',
  '200.0.0.0/8' => 'whois.lacnic.net',
  '205.0.0.0/8' => 'whois.arin.net',
  '157.0.0.0/8' => 'whois.arin.net',
  '31.0.0.0/8' => 'whois.ripe.net',
  '19.0.0.0/8' => 'whois.arin.net',
  '147.0.0.0/8' => 'whois.arin.net',
  '160.0.0.0/8' => 'whois.arin.net',
  '18.0.0.0/8' => 'whois.arin.net',
  '222.0.0.0/8' => 'whois.apnic.net',
  '41.0.0.0/8' => 'whois.afrinic.net',
  '195.0.0.0/8' => 'whois.ripe.net',
  '217.0.0.0/8' => 'whois.ripe.net',
  '114.0.0.0/8' => 'whois.apnic.net',
  '102.0.0.0/8' => 'whois.afrinic.net',
  '75.0.0.0/8' => 'whois.arin.net',
  '50.0.0.0/8' => 'whois.arin.net',
  '51.0.0.0/8' => 'whois.ripe.net',
  '180.0.0.0/8' => 'whois.apnic.net',
  '69.0.0.0/8' => 'whois.arin.net',
  '58.0.0.0/8' => 'whois.apnic.net',
  '158.0.0.0/8' => 'whois.arin.net',
  '182.0.0.0/8' => 'whois.apnic.net',
  '174.0.0.0/8' => 'whois.arin.net',
  '177.0.0.0/8' => 'whois.lacnic.net',
  '2.0.0.0/8' => 'whois.ripe.net',
  '169.0.0.0/8' => 'whois.arin.net',
  '95.0.0.0/8' => 'whois.ripe.net',
  '76.0.0.0/8' => 'whois.arin.net',
  '121.0.0.0/8' => 'whois.apnic.net',
  '213.0.0.0/8' => 'whois.ripe.net',
  '179.0.0.0/8' => 'whois.lacnic.net',
  '40.0.0.0/8' => 'whois.arin.net',
  '143.0.0.0/8' => 'whois.arin.net',
  '120.0.0.0/8' => 'whois.apnic.net',
  '113.0.0.0/8' => 'whois.apnic.net',
  '64.0.0.0/8' => 'whois.arin.net',
  '122.0.0.0/8' => 'whois.apnic.net',
  '199.0.0.0/8' => 'whois.arin.net',
  '133.0.0.0/8' => 'whois.apnic.net',
  '208.0.0.0/8' => 'whois.arin.net',
  '62.0.0.0/8' => 'whois.ripe.net',
  '13.0.0.0/8' => 'whois.arin.net',
  '38.0.0.0/8' => 'whois.arin.net',
  '118.0.0.0/8' => 'whois.apnic.net',
  '167.0.0.0/8' => 'whois.arin.net',
  '190.0.0.0/8' => 'whois.lacnic.net',
  '86.0.0.0/8' => 'whois.ripe.net',
  '193.0.0.0/8' => 'whois.ripe.net',
  '126.0.0.0/8' => 'whois.apnic.net',
  '137.0.0.0/8' => 'whois.arin.net',
  '106.0.0.0/8' => 'whois.apnic.net',
  '148.0.0.0/8' => 'whois.arin.net',
  '73.0.0.0/8' => 'whois.arin.net',
  '9.0.0.0/8' => 'whois.arin.net',
  '150.0.0.0/8' => 'whois.apnic.net',
  '131.0.0.0/8' => 'whois.arin.net',
  '196.0.0.0/8' => 'whois.afrinic.net',
  '134.0.0.0/8' => 'whois.arin.net',
  '46.0.0.0/8' => 'whois.ripe.net',
  '202.0.0.0/8' => 'whois.apnic.net',
  '96.0.0.0/8' => 'whois.arin.net',
  '206.0.0.0/8' => 'whois.arin.net',
  '135.0.0.0/8' => 'whois.arin.net',
  '59.0.0.0/8' => 'whois.apnic.net',
  '99.0.0.0/8' => 'whois.arin.net',
  '201.0.0.0/8' => 'whois.lacnic.net',
  '3.0.0.0/8' => 'whois.arin.net',
  '173.0.0.0/8' => 'whois.arin.net',
  '94.0.0.0/8' => 'whois.ripe.net',
  '80.0.0.0/8' => 'whois.ripe.net',
  '161.0.0.0/8' => 'whois.arin.net',
  '117.0.0.0/8' => 'whois.apnic.net',
  '60.0.0.0/8' => 'whois.apnic.net',
  '42.0.0.0/8' => 'whois.apnic.net',
  '212.0.0.0/8' => 'whois.ripe.net',
  '216.0.0.0/8' => 'whois.arin.net',
  '34.0.0.0/8' => 'whois.arin.net',
  '141.0.0.0/8' => 'whois.ripe.net',
  '44.0.0.0/8' => 'whois.arin.net',
  '39.0.0.0/8' => 'whois.apnic.net',
  '87.0.0.0/8' => 'whois.ripe.net',
  '156.0.0.0/8' => 'whois.arin.net',
  '140.0.0.0/8' => 'whois.arin.net',
  '70.0.0.0/8' => 'whois.arin.net',
  '54.0.0.0/8' => 'whois.arin.net',
  '101.0.0.0/8' => 'whois.apnic.net',
  '82.0.0.0/8' => 'whois.ripe.net',
  '152.0.0.0/8' => 'whois.arin.net',
  '107.0.0.0/8' => 'whois.arin.net',
  '110.0.0.0/8' => 'whois.apnic.net',
  '49.0.0.0/8' => 'whois.apnic.net',
  '45.0.0.0/8' => 'whois.arin.net',
  '17.0.0.0/8' => 'whois.arin.net',
  '104.0.0.0/8' => 'whois.arin.net',
  '123.0.0.0/8' => 'whois.apnic.net',
  '71.0.0.0/8' => 'whois.arin.net',
  '32.0.0.0/8' => 'whois.arin.net',
  '162.0.0.0/8' => 'whois.arin.net',
  '166.0.0.0/8' => 'whois.arin.net',
  '23.0.0.0/8' => 'whois.arin.net',
  '7.0.0.0/8' => 'whois.arin.net',
  '186.0.0.0/8' => 'whois.lacnic.net',
  '91.0.0.0/8' => 'whois.ripe.net',
  '221.0.0.0/8' => 'whois.apnic.net',
  '219.0.0.0/8' => 'whois.apnic.net',
  '159.0.0.0/8' => 'whois.arin.net',
  '83.0.0.0/8' => 'whois.ripe.net',
  '192.0.0.0/8' => 'whois.arin.net',
  '68.0.0.0/8' => 'whois.arin.net',
  '165.0.0.0/8' => 'whois.arin.net',
  '187.0.0.0/8' => 'whois.lacnic.net',
  '151.0.0.0/8' => 'whois.ripe.net',
  '149.0.0.0/8' => 'whois.arin.net',
  '103.0.0.0/8' => 'whois.apnic.net',
  '79.0.0.0/8' => 'whois.ripe.net',
  '78.0.0.0/8' => 'whois.ripe.net',
  '63.0.0.0/8' => 'whois.arin.net',
  '35.0.0.0/8' => 'whois.arin.net',
  '85.0.0.0/8' => 'whois.ripe.net',
  '128.0.0.0/8' => 'whois.arin.net',
  '25.0.0.0/8' => 'whois.ripe.net'
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
