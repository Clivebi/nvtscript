if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104068" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: hostmap" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_xref( name: "URL", value: "http://www.bfk.de/bfk_dnslogger.html" );
	script_tag( name: "summary", value: "Tries to find hostnames that resolve to the target's IP address by querying the online database at
the linked reference.

The script is in the 'external' category because it sends target IPs to a third party in order to
query their database.

SYNTAX:

hostmap.prefix:  If set, saves the output for each host in a file
called '<prefix><target>'. The file contains one entry per line.

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

http-max-cache-size:  The maximum memory size (in bytes) of the cache." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

