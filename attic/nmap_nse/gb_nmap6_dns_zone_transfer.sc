if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803507" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 18:59:56 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: dns-zone-transfer" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_xref( name: "URL", value: "http://www.zytrax.com/books/dns/" );
	script_xref( name: "URL", value: "http://cr.yp.to/djbdns/axfr-notes.html" );
	script_tag( name: "summary", value: "Requests a zone transfer (AXFR)from a DNS server.

The script sends an AXFR query to a DNS server. The domain to query is determined by examining the
name given on the command line, the DNS server's hostname, or it can be specified with the <code
>dns-zone-transfer.domain' script argument. If the query is successful all domains and domain
types are returned along with common type specific data (SOA/MX/NS/PTR/A).

This script can run at different phases of an Nmap scan:

  * Script Pre-scanning: in this phase the script will run before any Nmap scan and use the defined DNS server in the arguments. The script
arguments in this phase are:'dns-zone-transfer.server' the DNS server to use, can be a
hostname or an IP address and must be specified. The 'dns-zone-transfer.port' argument is
optional and can be used to specify the DNS server port.

  * Script scanning: in this phase the script will run after the other Nmap phases and against an Nmap discovered DNS server. If we don't have the
'true' hostname for the DNS server we cannot determine a likely zone to perform the transfer on.

SYNTAX:

dns-zone-transfer.server:  DNS server. If set, this argument will
enable the script for the 'Script Pre-scanning phase'.

dns-zone-transfer.addall:   If specified, adds all IP addresses
including private ones onto Nmap scanning queue when the
script argument 'newtargets' is given. The default
behavior is to skip private IPs (non-routable).

dns-zone-transfer.port:  DNS server port, this argument concerns
the 'Script Pre-scanning phase' and it's optional, the default
value is '53'.

dns-zone-transfer.domain:  Domain to transfer." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

