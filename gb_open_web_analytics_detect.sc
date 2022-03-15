if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803794" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-01-21 13:04:26 +0530 (Tue, 21 Jan 2014)" );
	script_name( "Open Web Analytics Version Detection" );
	script_tag( name: "summary", value: "Detection of Open Web Analytics version.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
owaPort = http_get_port( default: 80 );
if(!http_can_host_php( port: owaPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/owa", "/analytics", http_cgi_dirs( port: owaPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	owaReq = http_get( item: dir + "/index.php?owa_do=base.loginForm", port: owaPort );
	owaRes = http_keepalive_send_recv( port: owaPort, data: owaReq );
	if(ContainsString( owaRes, "Open Web Analytics</" )){
		ver = "unknown";
		owaVer = eregmatch( pattern: "v: ([0-9.]+)([a-zA-Z0-9.]+)?", string: owaRes );
		if(owaVer[1] != NULL){
			if( owaVer[2] == NULL ){
				ver = owaVer[1];
			}
			else {
				ver = owaVer[1] + "." + owaVer[2];
			}
		}
		set_kb_item( name: "www/" + owaPort + "/OWA", value: ver + " under " + install );
		set_kb_item( name: "OpenWebAnalytics/installed", value: TRUE );
		cpe = build_cpe( value: ver, exp: "^([0-9.]+)([a-zA-Z0-9.]+)?", base: "cpe:/a:openwebanalytics:open_web_analytics:" );
		if(!cpe){
			cpe = "cpe:/a:openwebanalytics:open_web_analytics";
		}
		register_product( cpe: cpe, location: install, port: owaPort, service: "www" );
		log_message( data: build_detection_report( app: "Open Web Analytics", version: ver, install: install, cpe: cpe, concluded: owaVer[0] ), port: owaPort );
	}
}
exit( 0 );

