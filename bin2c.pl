#!/usr/bin/perl -w

use strict;
use warnings;

my ($file_name) = @ARGV;
if (!$file_name) {
  die "usage: bin2c.pl <local file name>";
}

open(my $fh, "<", $file_name) || die "$file_name: $!";
binmode($fh) || die "$file_name: binmode(): $!";
my $data;
{
  local $/;
  $data = <$fh>;
}
close($fh);

my $var_name = $file_name;
$var_name =~ s/[^A-Za-z0-9_]/_/g;

my $hfile = "$var_name.h";
open($fh, ">", $hfile) || die "$hfile: $!";
binmode($fh) || die "$hfile: binmode(): $!";

print $fh "char $var_name\[\] = { ";
while ($data =~ s/^(.)//ms) {
  my $char = $1;
  print $fh sprintf("0x%02hx", ord($char));
  if ($data ne "") {
    print $fh ",";
    print $fh "\n" if ($char eq "\n");
  }
}
print $fh " };\n";

close($fh);
