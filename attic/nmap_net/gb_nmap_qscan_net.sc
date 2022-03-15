if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104158" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: qscan" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Repeatedly probe open and/or closed ports on a host to obtain a series         of round-
trip time values for each port.  These values are used to         group collections of ports which
are statistically different from other         groups.  Ports being in different groups (or
'families') may be due to         network mechanisms such as port forwarding to machines behind a
NAT.

        In order to group these ports into different families, some statistical         values must
be computed.  Among these values are the mean and standard         deviation of the round-trip times
for each port.  Once all of the times         have been recorded and these values have been
computed, the Student's         t-test is used to test the statistical significance of the
differences         between each port's data.  Ports which have round-trip times that are
statistically the same are grouped together in the same family.

        This script is based on Doug Hoyte's Qscan documentation and patches         for Nmap.

SYNTAX:

delay:  Average delay between packet sends. This is a number followed by 'ms' for milliseconds or 's' for seconds. ('m' and 'h' are also supported but are too long for timeouts.) The actual delay will randomly vary between 50% and 150% of the time specified. Default:'200ms'.


numtrips:  Number of round-trip times to try to get.


confidence:  Confidence level:'0.75', '0.9', '0.95', '0.975', '0.99', '0.995', or '0.9995'.


numclosed:  Maximum number of closed ports to probe (default 1). A negative number disables the limit.



numopen:  Maximum number of open ports to probe (default 8). A negative number disables the limit." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

