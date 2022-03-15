if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18178" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Trend Micro TMCM Console Management Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Filter incoming traffic to this port." );
	script_tag( name: "summary", value: "The remote host appears to run Trend Micro Control Manager, connections
  are allowed to the web console management." );
	script_tag( name: "impact", value: "Letting attackers know that you are using this software will help them to
  focus their attack or will make them change their strategy." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/ControlManager/default.htm";
rep = http_get_cache( item: url, port: port );
if(!rep){
	exit( 0 );
}
if(egrep( pattern: "Trend Micro Control Manager.+</title>", string: rep, icase: TRUE )){
	log_message( port: port );
	http_set_is_marked_embedded( port: port );
}
exit( 0 );

