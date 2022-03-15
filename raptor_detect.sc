if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10730" );
	script_version( "2021-01-20T14:57:47+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 14:57:47 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Raptor FW Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Holm Diening" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "By sending an invalid HTTP request to an
  webserver behind Raptor firewall, the http proxy itself will respond." );
	script_tag( name: "insight", value: "The server banner of Raptor FW version 6.5 is always
  'Simple, Secure Web Server 1.1'." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
teststring = NASLString( "some invalid request\\r\\n\\r\\n" );
testpattern = NASLString( "Simple, Secure Web Server 1." );
recv = http_send_recv( port: port, data: teststring );
if(ContainsString( recv, testpattern )){
	log_message( port: port, data: "The remote WWW host is very likely behind Raptor FW Version 6.5." );
	http_set_is_marked_embedded( port: port );
}
exit( 0 );

