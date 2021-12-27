use IO::Async::Timer::Countdown;
 
use IO::Async::Loop;
my $loop = IO::Async::Loop->new;
 
my $timer = IO::Async::Timer::Countdown->new(
   delay => 10,
 
   on_expire => sub {
      print "Sorry, your time's up\n";
      $loop->stop;
   },
);
 
$timer->start;
 
$loop->add( $timer );
 
$loop->run;