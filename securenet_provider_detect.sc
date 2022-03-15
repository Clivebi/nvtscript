if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18533" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Intrusion.com SecureNet Provider Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host appears to run the Intrusion.com SecureNet provider on this port." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
rep = http_get_cache( item: "/", port: port );
if(!rep){
	exit( 0 );
}
if(ContainsString( rep, " - SecureNet Provider WBI</title>" )){
	log_message( port: port );
	http_set_is_marked_embedded( port: port );
}
exit( 0 );

