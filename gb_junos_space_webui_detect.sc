if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105411" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-10-19 11:11:38 +0200 (Mon, 19 Oct 2015)" );
	script_name( "Junos Space Web-UI Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of the Junos Space Web-UI." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = "/mainui/";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "Junos Space Login</title>" ) || !ContainsString( buf, "j_username" )){
	exit( 0 );
}
set_kb_item( name: "junos_space_webui/installed", value: TRUE );
register_product( cpe: "cpe:/a:juniper:junos_space", location: url, port: port, service: "www" );
log_message( data: "The Junos Space Web-UI is running at this port.\nCPE: cpe:/a:juniper:junos_space", port: port );
exit( 0 );

