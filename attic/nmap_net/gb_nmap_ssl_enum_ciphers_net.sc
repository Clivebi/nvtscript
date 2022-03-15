if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104167" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: ssl-enum-ciphers" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "This script repeatedly initiates SSL/TLS connections, each time trying a new cipher or compressor
while recording whether a host accepts or rejects it. The end result is a list of all the ciphers
and compressors that a server accepts.

SSLv3/TLSv1 requires more effort to determine which ciphers and compression methods a server
supports than SSLv2. A client lists the ciphers and compressors that it is capable of supporting,
and the server will respond with a single cipher and compressor chosen, or a rejection notice.

This script is intrusive since it must initiate many connections to a server, and therefore is quite
noisy." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

