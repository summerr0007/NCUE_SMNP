use strict;
use warnings;
 
use Net::SNMP qw(:snmp);
 
my $OID_arpTable = '1.3.6.1.4.1.890.1.5.8.19.18.1';
my $OID_arpIpAddr = '1.3.6.1.4.1.890.1.5.8.19.18.1.1.2';
my $OID_arpMacAddr = '1.3.6.1.4.1.890.1.5.8.19.18.1.1.3';
 
my ($session, $error) = Net::SNMP->session(
   -hostname    => shift || '192.168.44.113',
   -community   => shift || 'public',
   -nonblocking => 1,
   -translate   => [-octetstring => 0],
   -version     => 'snmpv2c',
);
 
if (!defined $session) {
   printf "ERROR: %s.\n", $error;
   exit 1;
}
 
my %table; # Hash to store the results
 
my $result = $session->get_bulk_request(
   -varbindlist    => [ $OID_arpTable ],
   -callback       => [ \&table_callback, \%table ],
   -maxrepetitions => 10,
);
 
if (!defined $result) {
   printf "ERROR: %s\n", $session->error();
   $session->close();
   exit 1;
}
 
# Now initiate the SNMP message exchange.
 
snmp_dispatcher();
 
$session->close();
 
# Print the results, specifically formatting ifPhysAddress.
 
for my $oid (oid_lex_sort(keys %table)) {
    if (!oid_base_match($OID_arpMacAddr, $oid)) {
      printf "%s = %s\n", $oid, $table{$oid};
   } else {
      printf "%s = %s\n", $oid, unpack( 'H*', $table{$oid});
   }
}
 
exit 0;
 
sub table_callback
{
   my ($session, $table) = @_;
 
   my $list = $session->var_bind_list();
 
   if (!defined $list) {
      printf "ERROR: %s\n", $session->error();
      return;
   }
 
   # Loop through each of the OIDs in the response and assign
   # the key/value pairs to the reference that was passed with
   # the callback.  Make sure that we are still in the table
   # before assigning the key/values.
 
   my @names = $session->var_bind_names();
   my $next  = undef;
 
   while (@names) {
      $next = shift @names;
      if (!oid_base_match($OID_arpTable, $next)) {
         return; # Table is done.
      }
      $table->{$next} = $list->{$next};
   }
 
   # Table is not done, send another request, starting at the last
   # OBJECT IDENTIFIER in the response.  No need to include the
   # calback argument, the same callback that was specified for the
   # original request will be used.
 
   my $result = $session->get_bulk_request(
      -varbindlist    => [ $next ],
      -maxrepetitions => 10,
   );
 
   if (!defined $result) {
      printf "ERROR: %s.\n", $session->error();
   }
 
   return;
}