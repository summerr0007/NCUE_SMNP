# .1.3.6.1.2.1.2.2.1.7 (.*) disable port
# 1.3.6.1.4.1.890.1.5.8.19.18.1.1 arptable

# my $OID_ifPhysAddress = '1.3.6.1.4.1.890.1.5.8.19.18.1.1.3';
use threads;
use strict;
use warnings;
 
use Net::SNMP qw(:snmp);

STDOUT->autoflush(1);
printf("請輸入IP: \n");
chomp(my $IP = <STDIN>);
# chomp(my $IP = '192.168.44.113');
#  '192.168.44.113'
my $OID_sysUpTime = '1.3.6.1.2.1.1.3.0';
my $OID_sysDescr = '1.3.6.1.2.1.1.1.0';
my $OID_ifTable = '1.3.6.1.2.1.2.2';
my $OID_ifPhysAddress = '1.3.6.1.2.1.2.2.1.6';
my $OID_ifAdminStatus = '1.3.6.1.2.1.2.2.1.7';
my $OID_arpTable = '1.3.6.1.4.1.890.1.5.8.19.18.1';
my $OID_arpIpAddr = '1.3.6.1.4.1.890.1.5.8.19.18.1.1.2';
my $OID_arpMacAddr = '1.3.6.1.4.1.890.1.5.8.19.18.1.1.3';

while(1){
    printf("--"x15 . "\n");
    printf("1.查看系統情況\n");
    printf("2.查看iftables\n");
    printf("3.arp spoofing 偵測\n");
    printf("3A.查看arp table\n");
    printf("4.port 開關\n");
    printf("5.port 定時開關\n");
    printf("88.EXIT\n");
    chomp(my $op1 = <STDIN>);
    if($op1 eq 1){      
        my ($session, $error) = Net::SNMP->session(
            -hostname  => shift || $IP ,
            -community => shift || 'public',
        );

        if (!defined $session) {
            printf "ERROR: %s.\n", $error;
            exit 1;
        }


        my $result = $session->get_request(-varbindlist => [ $OID_sysDescr ],); 
        if (!defined $result) {
            printf "ERROR: %s.\n", $session->error();
            $session->close();
            exit 1;
        }
        printf "The sysDescr for host '%s' is %s.\n",
        $session->hostname(), $result->{$OID_sysDescr};

        $result = $session->get_request(-varbindlist => [ $OID_sysUpTime ],); 
        if (!defined $result) {
            printf "ERROR: %s.\n", $session->error();
            $session->close();
            exit 1;
        }
        printf "The sysUpTime for host '%s' is %s.\n",
        $session->hostname(), $result->{$OID_sysUpTime};     
        $session->close();
    }elsif($op1 eq 2){
        my ($session, $error) = Net::SNMP->session(
            -hostname  => shift || $IP ,
            -community => shift || 'public',
            -nonblocking => 1,
            -translate   => [-octetstring => 0],
            -version     => 'snmpv2c',
        );

        if (!defined $session) {
            printf "ERROR: %s.\n", $error;
            exit 1;
        }
        my %table; 
        my $result = $session->get_bulk_request(
            -varbindlist    => [ $OID_ifTable ],
            -callback       => [ \&table_callback_if, \%table ],
            -maxrepetitions => 10,
        );
        
        if (!defined $result) {
            printf "ERROR: %s\n", $session->error();
            $session->close();
            exit 1;
        }    
        snmp_dispatcher();
        
        
        
        for my $oid ((keys %table)) {
            if (!oid_base_match($OID_ifPhysAddress, $oid)) {
                printf "%s = %s\n", $oid, $table{$oid};
            } else {
                printf "%s = %s\n", $oid, unpack 'H*', $table{$oid};
            }
        }
        $session->close();
    }elsif($op1 eq 3 || $op1 eq "3A"){
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
        
        my %table; 

        my @iparr;
        my @macarr;
        
        my $result = $session->get_bulk_request(
            -varbindlist    => [ $OID_arpTable ],
            -callback       => [ \&table_callback_arp, \%table ],
            -maxrepetitions => 10,
        );
        
        if (!defined $result) {
            printf "ERROR: %s\n", $session->error();
            $session->close();
            exit 1;
        }
        
        
        
        snmp_dispatcher();
        
        $session->close();
        
        
        if($op1 eq 3){
            for my $oid (oid_lex_sort(keys %table)) {
                if (oid_base_match($OID_arpIpAddr, $oid)) {
                    # printf "%s = %s\n", $oid, $table{$oid};
                    push @iparr , $table{$oid};
                }
                if (oid_base_match($OID_arpMacAddr, $oid)) {
                    # printf "%s = %s\n", $oid, unpack( 'H*', $table{$oid});
                    push @macarr,unpack( 'H*', $table{$oid});
                }
            }
            # print @iparr;
            # print @macarr;
            my @i;
            foreach my $rr (@macarr){
                @i = grep { $macarr[$_] eq $rr } 0 .. $#macarr;
            } 
            if(scalar @i > 1){
                printf("可疑行為:\n");
                foreach my $ind (@i){
                    printf(" %s ",$iparr[$ind]);
                }
                printf("\n mac=> %s",$macarr[$i[0]]);
            }else{
                printf("無可疑行為\n");
            }
        }else{
            for my $oid (oid_lex_sort(keys %table)) {
                if (oid_base_match($OID_arpIpAddr, $oid)) {
                    printf "%s = %s\n", $oid, $table{$oid};

                }
                if (oid_base_match($OID_arpMacAddr, $oid)) {
                    printf "%s = %s\n", $oid, unpack( 'H*', $table{$oid});

                }
            }
        }

    }elsif($op1 eq 4){
        my ($session, $error) = Net::SNMP->session(
            -hostname  => shift || $IP ,
            -community => shift || 'public',
        );
        
        if (!defined $session) {
            printf "ERROR: %s.\n", $error;
            exit 1;
        }
        
        printf("請輸入PORT : ");
        chomp(my $port = <STDIN>);
        printf("1.開 \n2.關 : ");
        chomp(my $able = <STDIN>);
        chomp(my $stmt = $OID_ifAdminStatus.".".$port);


        my @arr = ($stmt,  Net::SNMP::INTEGER , $able);
        my $result = $session->set_request(
            -varbindlist =>\@arr,
        );

        if (!defined $result) {
            printf "ERROR: %s.\n", $session->error();
            $session->close();
            exit 1;
        }
        
        printf "The ifAdminStatus for host '%s' was set to '%s'.\n",
            $session->hostname(), $result->{$stmt};        
        $session->close();

    }elsif($op1 eq 5){

    }elsif($op1 eq 88){
        printf("bye bye\n");
        exit 1;
    }else{
        printf("errorinput\n");
    }
}

sub table_callback_if
{
   my ($session, $table) = @_;
 
   my $list = $session->var_bind_list();
 
   if (!defined $list) {
      printf "ERROR: %s\n", $session->error();
      return;
   }
 

 
   my @names = $session->var_bind_names();
   my $next  = undef;
 
   while (@names) {
      $next = shift @names;
      if (!oid_base_match($OID_ifTable, $next)) {
         return; 
      }
      $table->{$next} = $list->{$next};
   }
 

 
   my $result = $session->get_bulk_request(
      -varbindlist    => [ $next ],
      -maxrepetitions => 10,
   );
 
   if (!defined $result) {
      printf "ERROR: %s.\n", $session->error();
   }
 
   return;
}


sub table_callback_arp
{
   my ($session, $table) = @_;
 
   my $list = $session->var_bind_list();
 
   if (!defined $list) {
      printf "ERROR: %s\n", $session->error();
      return;
   }
 

 
   my @names = $session->var_bind_names();
   my $next  = undef;
 
   while (@names) {
      $next = shift @names;
      if (!oid_base_match($OID_arpTable, $next)) {
         return; 
      }
      $table->{$next} = $list->{$next};
   }

   my $result = $session->get_bulk_request(
      -varbindlist    => [ $next ],
      -maxrepetitions => 10,
   );
 
   if (!defined $result) {
      printf "ERROR: %s.\n", $session->error();
   }
 
   return;
}