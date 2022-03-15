if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104024" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Nmap NSE net: dns-fuzz" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "This script launches a DNS fuzzing attack against any DNS server.

The script induces errors into randomly generated but valid DNS packets. The packet template that we
use includes one uncompressed and one compressed name.

Use the 'dns-fuzz.timelimit' argument to control how long the fuzzing lasts. This script
should be run for a long time. It will send a very large quantity of packets and thus it's pretty
invasive, so it should only be used against private DNS servers as part of a software development
lifecycle.

SYNTAX:

dns-fuzz.timelimit:  How long to run the fuzz attack. This is a
number followed by a suffix:'s' for seconds,
'm' for minutes, and 'h' for hours. Use
'0' for an unlimited amount of time. Default:
'10m'." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

