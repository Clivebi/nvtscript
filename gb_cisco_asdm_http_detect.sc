if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105193" );
	script_version( "2021-07-08T06:14:58+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 06:14:58 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2015-02-03 11:47:01 +0100 (Tue, 03 Feb 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco Adaptive Security Device Manager (ASDM) Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Cisco Adaptive Security Device Manager (ASDM)." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/admin/public/index.html";
install = "/admin";
res = http_get_cache( port: port, item: url );
if(!ContainsString( res, "<title>Cisco ASDM" ) || !ContainsString( res, "Cisco Systems" )){
	exit( 0 );
}
version = "unknown";
vers = eregmatch( pattern: "<title>Cisco ASDM ([^<]+)</title>", string: res );
if(!isnull( vers[1] )){
	version = vers[1];
	concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	cpe_version = ereg_replace( string: version, pattern: "\\(([0-9.]+)\\)", replace: ".\\1" );
}
set_kb_item( name: "cisco/asdm/detected", value: TRUE );
set_kb_item( name: "cisco/asdm/http/detected", value: TRUE );
cpe = build_cpe( value: cpe_version, exp: "^([0-9.()]+)", base: "cpe:/a:cisco:adaptive_security_device_manager:" );
if(!cpe){
	cpe = "cpe:/a:cisco:adaptive_security_device_manager";
}
register_product( cpe: cpe, location: install, port: port, service: "www" );
log_message( data: build_detection_report( app: "Cisco Adaptive Security Device Manager (ASDM)", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
exit( 0 );

