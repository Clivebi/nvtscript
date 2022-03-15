if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803542" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:31 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: snmp-brute" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Attempts to find an SNMP community string by brute force guessing.

This script opens a sending socket and a sniffing pcap socket in parallel  threads. The sending
socket sends the SNMP probes with the community strings, while the pcap socket sniffs the network
for an answer to the probes. If  valid community strings are found, they are added to the creds
database and reported in the output.

The script takes the 'snmp-brute.communitiesdb' argument that allows the user to define
the file that contains the community strings to be used. If not defined, the default wordlist used
to bruteforce the SNMP community strings is 'nselib/data/snmpcommunities.lst'. In case
this wordlist does not exist, the script falls back to 'nselib/data/passwords.lst'

No output is reported if no valid account is found.

SYNTAX:

userdb:  The filename of an alternate username database.

snmpcommunity:  The community string to use. If not given, it is
''public'', or whatever is passed to 'buildPacket'.

passdb:  The filename of an alternate password database.

snmp-brute.communitiesdb:  The filename of a list of community strings to try.

unpwdb.passlimit:  The maximum number of passwords
'passwords' will return (default unlimited).

unpwdb.userlimit:  The maximum number of usernames
'usernames' will return (default unlimited).

unpwdb.timelimit:  The maximum amount of time that any iterator will run
before stopping. The value is in seconds by default and you can follow it
with 'ms', 's', 'm', or 'h' for
milliseconds, seconds, minutes, or hours. For example,
'unpwdb.timelimit=30m' or 'unpwdb.timelimit=.5h' for
30 minutes. The default depends on the timing template level (see the module
description). Use the value '0' to disable the time limit." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

