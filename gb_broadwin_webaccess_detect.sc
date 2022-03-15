if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105327" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-08-20 17:37:34 +0200 (Thu, 20 Aug 2015)" );
	script_name( "BroadWin WebAccess Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of BroadWin WebAccess.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
awPort = http_get_port( default: 80 );
if(!http_can_host_asp( port: awPort )){
	exit( 0 );
}
awRes = http_get_cache( item: "/broadWeb/bwRoot.asp", port: awPort );
if(!ContainsString( awRes, "<title>BroadWin WebAccess" ) && !ContainsString( awRes, " BroadWin Technology, Inc." )){
	exit( 0 );
}
vers = "unknown";
cpe = "cpe:/a:broadwin:webaccess";
awVer = eregmatch( pattern: "Software Build : ([0-9.-]+)", string: awRes );
if(!isnull( awVer[1] )){
	vers = str_replace( string: awVer[1], find: "-", replace: "." );
	cpe += ":" + vers;
}
set_kb_item( name: "www/" + awPort + "/BroadWin/WebAccess", value: vers );
set_kb_item( name: "BroadWin/WebAccess/installed", value: TRUE );
register_product( cpe: cpe, location: awPort + "/tcp", port: awPort, service: "www" );
log_message( data: build_detection_report( app: "BroadWin WebAccess", version: vers, install: "/broadWeb/", cpe: cpe, concluded: awVer[0] ), port: awPort );

