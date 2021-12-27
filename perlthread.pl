
use strict;
use warnings;

use threads;
use Thread::Queue; 

my $input_q = Thread::Queue -> new();
my $success_q = Thread::Queue -> new(); 
my $failure_q = Thread::Queue -> new();

my $thread_count = 4; 

sub spinoff_thread {
    while ( my $target = $input_q -> dequeue() )
    {
       #do something to $target
       my @results = `echo  $target`;
       if ( $? ) { 
           $failure_q -> enqueue ( $target );
       }
       else {
           $success_q -> enqueue ( $target );
       }
    } 
}

#main bit

for ( 1..$thread_count ) {
    my $thr = threads -> create ( \&spinoff_thread );
}

foreach my $server ( "server1", "server2", "server3", "server4", "server5" ) {
  $input_q -> enqueue ( $server );
}

$input_q -> end(); #will cause threads to 'bail out' because that while loop will go 'undef'); 

 #wait for threads to complete. 
foreach my $thr ( threads -> list() ) {
   $thr -> join();
}


print "Fail:\n", join ("\n", $failure_q -> dequeue() ), "\n";
print "Success:\n", join ( "\n", $success_q -> dequeue() ), "\n";