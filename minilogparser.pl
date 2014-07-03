#!/usr/bin/perl -w 
#
# This is a simple and probably broken log parser used to get 
# Sonicwall log files from a local syslog server and parse such logfile
# to select some fields to use in another external reporting tool.
#
# Luciano Coutinho <lucianocoutinho@live.com> - 03 jul 2014
#

use strict;
use warnings;
use Getopt::Long;

# put options in a generic hash
my %options;

# get command line options
GetOptions(\%options, "logfile=s", "outfile=s", "sn=s", "help") or &show_help();
		

# check if all options are set or show help message.
if ($options{'sn'} and $options{'logfile'} and $options{'outfile'}) {
	exit &parse_files($options{'sn'}, $options{'logfile'}, $options{'outfile'});

} else {
	&show_help;
};


#
# read each file from selected logfile and send parsed data to
# selected output file
#
sub parse_files() {

	# got options
	my $sn = shift;
	my $logfile = shift;
	my $outfile = shift;

	# open files
	open LOG_FILE, $logfile or die $!;
	open OUT_FILE, '>',  $outfile or die $!;

	# iterate over each line of the log file
	while (<LOG_FILE>) {
		
		# remove "new lines"
		chomp;
	
		# skip lines without the required information..
		next if ! /m=(14|16|17|97) /;
	
		# cleanup quotes
		s/"//g;
	
		# discard any (unused) data before the firewall serial number
		my (undef, $line) = split("sn=$sn", $_, 2);
	
		#
		# select the required data from log
		#
		my ($date, $hour, $timezone) = $line =~ /time=(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\w{3})/;
	
		my $user = "";
		  ($user) = $line =~ /usr=([^\s]+) / if /usr=/;
	
		my ($source_f) = $line =~ /src=([^\s]+) /;
		my ($source_ip, $source_port, $source_intf, $source_hostname) = split(":", $source_f);
	
		my ($url_h) = $line =~ /dstname=([^\s]+) /;
	
		my $url_a = "";
		  ($url_a) = $line =~ /arg=([^\s]+) / if ! /arg= /;
	
		my $url = sprintf("%s%s", $url_h, $url_a);
	
		my ($category) = $line =~ /Category=(.*) /;
	           $category =~ s/\s/_/g;
	
		my $method = "";
		  ($method) = $line =~ /op=(\w+) / if /op=/;
	
	
		my $size = 0;
		  ($size) = $line =~ /rcvd=(\d+) / if /rcvd=/;
	
		my $action = ( $_ =~ /m=14/ ) ? "DENY" : "ALLOW";
	
		# store parsed data into the new logfile
		printf OUT_FILE "%s %s %s %s %s %s %s %s %s %s\n",
			$date, $hour, $timezone, $user, $action, $source_ip,
			$category, $url, $method, $size;
	
	}

	# close file descriptors
	close LOG_FILE;
	close OUT_FILE;

	return 0;
}


sub show_help() {
	printf "\nUsage:\n";
	printf "\n %s --sn=<serial number> ", $0;
	printf "--logfile=<log files to parse> --outfile=<output parsed file>\n\n";
	
	printf "\n\n";
	printf "serial number: Sonicwall Serial Number\n";
	printf "logfile:      List of log files from syslog\n";
        printf "outfile:       Output file with parsed log entries\n";
	printf "\n\n";
	exit 0;
}
# EOF
