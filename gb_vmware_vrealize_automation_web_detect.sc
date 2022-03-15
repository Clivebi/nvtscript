if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105863" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-11 17:10:02 +0200 (Thu, 11 Aug 2016)" );
	script_name( "VMware vRealize Automation Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( port: port, item: "/" );
if(!ContainsString( buf, "title>VMware vRealize Automation" ) || !ContainsString( buf, ">VMware<" ) || !ContainsString( buf, "vRealize Automation console" )){
	exit( 0 );
}
set_kb_item( name: "vmware/vrealize/automation/installed", value: TRUE );
vers = "unknown";
rep_vers = vers;
cpe = "cpe:/a:vmware:vrealize_automation";
v_b = eregmatch( pattern: "VMware vRealize Automation( Appliance)? ([0-9.]+)-([0-9]+)", string: buf );
if(isnull( v_b )){
	v_b = eregmatch( pattern: "VMware vRealize Automation( Appliance)? version ([0-9.]+) \\(build ([0-9]+)\\)", string: buf );
}
if(!isnull( v_b[2] )){
	vers = v_b[2];
	rep_vers = vers;
	set_kb_item( name: "vmware/vrealize/automation/version", value: vers );
	cpe += ":" + vers;
}
if(!isnull( v_b[3] )){
	build = v_b[3];
	rep_vers += " (Build: " + build + ")";
	set_kb_item( name: "vmware/vrealize/automation/build", value: build );
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
report = build_detection_report( app: "VMware vRealize Automation", version: rep_vers, install: "/", cpe: cpe, concluded: v_b[0] );
log_message( port: port, data: report );
exit( 0 );

