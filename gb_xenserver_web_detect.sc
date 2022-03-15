if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105763" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-14 12:25:04 +0200 (Tue, 14 Jun 2016)" );
	script_name( "Citrix Xenserver Web Detection" );
	script_tag( name: "summary", value: "This script detects the Citrix Xenserver Webinterface" );
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
if(( !ContainsString( buf, "<title>Welcome to Citrix XenServer" ) && !IsMatchRegexp( buf, "<title>XenServer [0-9.]+</title>" ) ) || !ContainsString( buf, "XenCenter.iso" ) || !ContainsString( buf, "Citrix Systems, Inc" )){
	exit( 0 );
}
set_kb_item( name: "citrix_xenserver/webgui/detected", value: TRUE );
vers = "unknown";
cpe = "cpe:/a:citrix:xenserver";
version = eregmatch( pattern: "XenServer ([0-9.]+)", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
report = build_detection_report( app: "Citrix Xenserver (Webinterface)", version: vers, install: "/", cpe: cpe, concluded: version[0] );
log_message( port: port, data: report );
exit( 0 );

