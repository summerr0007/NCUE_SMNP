
use strict;
use warnings;

my @x = ( 1, 2, 3, 3, 2, 1, 1, 2, 3, 3, 2, 1 );

foreach my $rr (@x){
   my @i = grep { $x[$_] == $rr } 0 .. $#x;
   print "$rr\n";
   print "@i\n";
} 
