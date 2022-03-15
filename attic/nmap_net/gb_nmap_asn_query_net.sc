if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104046" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: asn-query" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Maps IP addresses to autonomous system (AS) numbers.

The script works by sending DNS TXT queries to a DNS server which in turn queries a third-party
service provided by Team Cymru (team-cymru.org) using an in-addr.arpa style zone set up especially
for use by Nmap. The responses to these queries contain both Origin and Peer ASNs and their
descriptions, displayed along with the BGP Prefix and Country Code. The script caches results to
reduce the number of queries and should perform a single query for all scanned targets in a BGP
Prefix present in Team Cymru's database.

Be aware that any targets against which this script is run will be sent to and potentially recorded
by one or more DNS servers and Team Cymru. In addition your IP address will be sent along with the
ASN to a DNS server (your default DNS server, or whichever one you specified with the
'dns' script argument).

SYNTAX:

dns:  The address of a recursive nameserver to use (optional)." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

