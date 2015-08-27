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
use Socket;

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

		# if we cannot get serial number to select our data, then skip to the next line
		next if not $line;

		#
		# select the required data from log
		#
		my ($date, $hour, $timezone) = $line =~ /time=(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\w{3})/;

		# create a placeholder for user
		my $user = "none";
		  ($user) = $line =~ /usr=([^\s]+) / if /usr=/;

		my ($source_f) = $line =~ /src=([^\s]+) /;
		my ($source_ip, undef) = split(":", $source_f, 2);

		my $url_h = "";

		# search for dstname or dst to get the host name
		if ( (/dstname=/) && ( ! /dstname= /)) {
			($url_h) = $line =~ /dstname=([^\s]+) /;

		} elsif ( ($line =~ /dst=/) && ( $line !~ /dst= /) ) {
			my ($dst) = $line =~ /dst=([^\s]+) /;
			my ($ipaddr, undef) = split(":", $dst, 2);

			# keep the ip address if cannot resolve hostname
			$url_h = gethostbyaddr(inet_aton($ipaddr), AF_INET) || $ipaddr;
		};

		my $url_a = "";
		  ($url_a) = $line =~ /arg=([^\s]+) / if (/arg=/) && (! /arg= /);

		my $url = sprintf("%s%s", $url_h, $url_a);

		my ($category, undef) = $line =~ /Category=(.*)$/;
		   $category =~ s/\s/_/g;

		# set method to GET by default
		my $method = "1";
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
	printf "logfile:       List of log files from syslog\n";
        printf "outfile:       Output file with parsed log entries\n";
	printf "\n\n";
	exit 0;
}
# EOF
