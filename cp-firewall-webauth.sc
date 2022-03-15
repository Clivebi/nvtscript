if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10676" );
	script_version( "2021-01-20T14:57:47+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 14:57:47 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "CheckPoint Firewall-1 Web Authentication Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 900 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "A Firewall-1 web server is running on this port and serves web
  authentication requests." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 900 );
re = http_get_cache( item: "/", port: port );
if(ContainsString( re, "Authentication Form" ) && ContainsString( re, "Client Authentication Remote" ) && ContainsString( re, "FireWall-1 message" )){
	log_message( port: port );
	exit( 0 );
}
exit( 99 );

