if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140002" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-28 16:19:24 +0200 (Wed, 28 Sep 2016)" );
	script_name( "Netman 204 Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Netman 204" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( port: port, item: "/" );
if(!ContainsString( buf, "<title>Netman 204 login</title>" ) || !ContainsString( buf, "cgi-bin/login.cgi" ) || !ContainsString( buf, "cgi-bin/view.cgi" )){
	exit( 0 );
}
set_kb_item( name: "netman_204/detected", value: TRUE );
register_product( cpe: "cpe:/a:riello:netman_204", location: "/", port: port, service: "www" );
log_message( port: port, data: "The remote host is a Riello NetMan 204 network card" );
exit( 0 );

