if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143255" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-16 07:45:56 +0000 (Mon, 16 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Inim SmartLAN Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Inim SmartLAN devices.

  HTTP based detection of Inim SmartLAN devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/" );
if(!ContainsString( res, "<title>SmartLAN" ) || !ContainsString( res, "smartlang.appcache" )){
	exit( 0 );
}
set_kb_item( name: "inim/smartlan/detected", value: TRUE );
set_kb_item( name: "inim/smartlan/http/detected", value: TRUE );
set_kb_item( name: "inim/smartlan/http/port", value: port );
version = "unknown";
url = "/version.html";
res = http_get_cache( port: port, item: url );
vers = eregmatch( pattern: "SmartLAN[^v]+v\\. ([0-9.]+)", string: res );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "inim/smartlan/http/" + port + "/concluded", value: vers[0] );
	set_kb_item( name: "inim/smartlan/http/" + port + "/concUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
}
set_kb_item( name: "inim/smartlan/http/" + port + "/version", value: version );
exit( 0 );

