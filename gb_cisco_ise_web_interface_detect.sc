if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105472" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-12-01 15:47:56 +0100 (Tue, 01 Dec 2015)" );
	script_name( "Cisco Identity Services Engine Web Interface Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of the Cisco Identity Services Engine Web Interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = "/admin/login.jsp";
buf = http_get_cache( item: url, port: port );
if(ContainsString( buf, "<title>Identity Services Engine</title>" ) && ContainsString( buf, "Cisco Systems" ) && ContainsString( buf, "productName=\"Identity Services Engine\"" )){
	register_product( cpe: "cpe:/a:cisco:identity_services_engine", location: "/", port: port, service: "www" );
	set_kb_item( name: "cisco_ise/webgui_installed", value: TRUE );
	set_kb_item( name: "cisco_ise/webgui_port", value: port );
	log_message( port: port, data: "The Cisco Identity Services Engine Web Interface is running at this port." );
	exit( 0 );
}
exit( 0 );

