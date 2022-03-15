if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813320" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-02 16:58:59 +0530 (Wed, 02 May 2018)" );
	script_name( "IBM Endpoint Manager for Remote Control Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
 IBM Endpoint Manager for Remote Control.

 This script sends an HTTP GET request and tries to detect the presence of
 IBM Endpoint Manager for Remote Control from the response." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
trcport = http_get_port( default: 80 );
res = http_get_cache( item: "/trc/", port: trcport );
if(IsMatchRegexp( res, "<title>Tivoli Endpoint Manager for Remote Control.*</title>" ) && ContainsString( res, ">User ID:" ) && ContainsString( res, ">Password:" )){
	version = "unknown";
	set_kb_item( name: "ibm_endpoint_manager_for_remote_control/installed", value: TRUE );
	vers = eregmatch( pattern: "<title>Tivoli Endpoint Manager for Remote Control ([0-9.]+)", string: res );
	if(!vers[1]){
		vers = eregmatch( pattern: "js_about_version=\"([0-9.]+)\"", string: res );
	}
	if(vers[1]){
		version = vers[1];
		set_kb_item( name: "ibm_endpoint_manager_for_remote_control/version", value: version );
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:endpoint_manager_for_remote_control:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:ibm:endpoint_manager_for_remote_control";
	}
	register_product( cpe: cpe, location: "/", port: trcport, service: "www" );
	log_message( data: build_detection_report( app: "IBM Endpoint Manager for Remote Control", version: version, install: "/", cpe: cpe, concluded: version ), port: trcport );
	exit( 0 );
}
exit( 0 );

