if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140244" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-11 13:15:09 +0200 (Tue, 11 Apr 2017)" );
	script_name( "Moxa MXview Detection" );
	script_tag( name: "summary", value: "This script performs http based detection of Moxa MXview." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 81 );
url = "/index_en.htm";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "<title>MXview</title>" ) && ContainsString( buf, "MXviewClientSetup" ) && ContainsString( buf, "Moxa Inc." )){
	cpe = "cpe:/a:moxa:mxview";
	set_kb_item( name: "moxa/mxviev/installed", value: TRUE );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( port: port, data: "The Moxa MXview Webinterface is running at this port.\n\nVersion: Unknown\nCPE:     " + cpe );
	exit( 0 );
}
exit( 0 );

