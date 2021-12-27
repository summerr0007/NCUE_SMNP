use strict;
use warnings;
 
use Net::SNMP;

printf "請輸入IP : ";
my $IP;
chomp($IP = <STDIN>);
my $i = 5;


my $OID_sysUpTime = '1.3.6.1.2.1.1.3.0';
#  '192.168.44.113'
my ($session, $error) = Net::SNMP->session(
   -hostname  => shift || $IP ,
   -community => shift || 'public',
);
 
if (!defined $session) {
   printf "ERROR: %s.\n", $error;
   exit 1;
}
 
my $result = $session->get_request(-varbindlist => [ $OID_sysUpTime ],);
 
if (!defined $result) {
   printf "ERROR: %s.\n", $session->error();
   $session->close();
   exit 1;
}
 
printf "The sysUpTime for host '%s' is %s.\a\n",
       $session->hostname(), $result->{$OID_sysUpTime};
 

my $result2 = $session->get_request(-varbindlist => [ $OID_sysUpTime ],);

printf "The sysUpTime for host '%s' is %s.\a\n",
       $session->hostname(), $result2;

$session->close();
 
exit 0;