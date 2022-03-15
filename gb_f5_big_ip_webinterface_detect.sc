if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105162" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-09 16:07:09 +0100 (Fri, 09 Jan 2015)" );
	script_name( "F5 Networks BIG-IP Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the BIG-IP Webinterface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
url = "/";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "<title>BIG-IP" ) || !ContainsString( buf, "F5 Networks" ) || !ContainsString( buf, "/tmui/" )){
	exit( 0 );
}
set_kb_item( name: "f5/big_ip/web_management/installed", value: TRUE );
set_kb_item( name: "f5/big_ip/web_management/port", value: port );
register_product( cpe: "cpe:/h:f5:big-ip", location: "/", port: port, service: "www" );
log_message( port: port );
exit( 0 );

