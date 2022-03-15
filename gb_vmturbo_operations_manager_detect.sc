if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105066" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-08-18 13:58:41 +0200 (Mon, 18 Aug 2014)" );
	script_name( "VMTurbo Operations Manager Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to extract the version number from the reply." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/cgi-bin/vmtadmin.cgi?callType=ACTION&actionType=VERSIONS";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req );
if(!buf){
	exit( 0 );
}
if(ContainsString( buf, "vmtbuild:" ) && ContainsString( buf, "vmtrelease:" )){
	install = url;
	vers = "unknown";
	version = eregmatch( string: buf, pattern: "vmtrelease:([^,]+)", icase: TRUE );
	if(!isnull( version[1] )){
		vers = version[1];
	}
	set_kb_item( name: "vmturbo/installed", value: TRUE );
	build = eregmatch( string: buf, pattern: "vmtbuild:([^,]+)", icase: TRUE );
	if(!isnull( build[1] )){
		buildNR = build[1];
		set_kb_item( name: "vmturbo/" + port + "/build", value: buildNR );
	}
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:vmturbo:operations_manager:" );
	if(!cpe){
		cpe = "cpe:/a:vmturbo:operations_manager";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "VMTurbo Operations Manager", version: vers + " Build: " + buildNR, install: install, cpe: cpe, concluded: version[0] ), port: port );
}
exit( 0 );

