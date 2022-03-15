if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800297" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "WampServer Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the installed WampServer version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
wampPort = http_get_port( default: 80 );
if(!http_can_host_php( port: wampPort )){
	exit( 0 );
}
rcvRes = http_get_cache( item: "/index.php", port: wampPort );
if(!ContainsString( rcvRes, "title>WAMPSERVER" )){
	exit( 0 );
}
wv = "unknown";
cpe = "cpe:/a:wampserver:wampserver";
wampVer = eregmatch( pattern: ">[vV]ersion ([0-9.a-z]+)", string: rcvRes );
if(wampVer[1] != NULL){
	wv = wampVer[1];
	cpe += ":" + wv;
}
set_kb_item( name: "www/" + wampPort + "/WampServer", value: wv );
set_kb_item( name: "wampserver/installed", value: TRUE );
register_product( cpe: cpe, location: "/", port: wampPort, service: "www" );
report = build_detection_report( app: "WampServer", version: wv, install: "/", cpe: cpe, concluded: wampVer[0], concludedUrl: "/index.php" );
log_message( port: wampPort, data: report );
exit( 0 );

