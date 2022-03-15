if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803512" );
	script_version( "2020-07-07T14:13:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2013-02-28 19:00:01 +0530 (Thu, 28 Feb 2013)" );
	script_name( "Nmap NSE 6.01: http-headers" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE" );
	script_tag( name: "summary", value: "Performs a GET request for the root folder ('/')of a web server and displays the HTTP headers
returned.

SYNTAX:

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

path:  The path to request, such as '/index.php'. Default '/'.

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

useget:  Set to force GET requests instead of HEAD." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

