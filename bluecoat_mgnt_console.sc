if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16363" );
	script_version( "2021-01-20T14:57:47+0000" );
	script_tag( name: "last_modification", value: "2021-01-20 14:57:47 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "BlueCoat ProxySG Console Management Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 8082 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host appears to be a BlueCoat ProxySG, connections are
  allowed to the web console management." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
port = 8082;
if(!get_port_state( port )){
	exit( 0 );
}
url = "/Secure/Local/console/logout.htm";
req = http_get( item: url, port: port );
res = http_send_recv( data: req, port: port );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "<title>Blue Coat Systems  - Logout</title>" )){
	log_message( port: port );
}
exit( 0 );

