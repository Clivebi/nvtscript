if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105864" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-12 11:45:40 +0200 (Fri, 12 Aug 2016)" );
	script_name( "VMware vRealize Orchestrator Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8281 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8281 );
url = "/vco/";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>VMware vRealize Orchestrator</title>" ) || !ContainsString( buf, "Orchestrator Control Center" )){
	exit( 0 );
}
set_kb_item( name: "vmware/vrealize/orchestrator/installed", value: TRUE );
vers = "unknown";
cpe = "cpe:/a:vmware:vrealize_orchestrator";
version = eregmatch( pattern: "<div id=\"appliance-info\">[\n ]*VMware vRealize Orchestrator ([0-9.]+)", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	set_kb_item( name: "vmware/vrealize/orchestrator/version", value: vers );
}
register_product( cpe: cpe, location: url, port: port, service: "www" );
report = build_detection_report( app: "VMware vRealize Orchestrator", version: vers, install: url, cpe: cpe, concluded: version[0] );
log_message( port: port, data: report );
exit( 0 );

