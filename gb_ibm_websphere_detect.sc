if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100564" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-01 13:43:26 +0200 (Thu, 01 Apr 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "IBM WebSphere Application Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "gb_ibm_websphere_detect_giop.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running the IBM WebSphere Application Server." );
	script_xref( name: "URL", value: "http://www-01.ibm.com/software/webservers/appserv/was/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(!res){
	exit( 0 );
}
vers = "unknown";
if(egrep( pattern: "WASRemoteRuntimeVersion", string: res, icase: TRUE )){
	version = eregmatch( pattern: "WASRemoteRuntimeVersion=\"([^\"]+)\"", string: res );
	if(version[1]){
		vers = version[1];
		install = TRUE;
	}
}
if(!install){
	if(ContainsString( res, "title\">Welcome to the WebSphere Application Server" ) || ContainsString( res, "<title>WebSphere Application Server" )){
		version = eregmatch( pattern: "WebSphere Application Server V([0-9.]+)", string: res );
		if(version[1]){
			vers = version[1];
		}
		install = TRUE;
	}
}
banner = http_get_remote_headers( port: port );
if(ContainsString( banner, "Server: WebSphere Application Server/" )){
	install = TRUE;
}
if(install){
	if( ContainsString( res, "Liberty Profile<" ) || ContainsString( res, ">Welcome to Liberty<" ) ){
		appName = "WebSphere Application Server Liberty Profile";
		set_kb_item( name: "ibm_websphere_application_server/liberty/profile/installed", value: TRUE );
	}
	else {
		appName = "WebSphere Application Server";
	}
	set_kb_item( name: "www/" + port + "/websphere_application_server", value: vers );
	set_kb_item( name: "ibm_websphere_application_server/installed", value: TRUE );
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:ibm:websphere_application_server:" );
	if(!cpe){
		cpe = "cpe:/a:ibm:websphere_application_server";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: appName, version: vers, install: "/", cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

