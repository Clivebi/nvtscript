if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105766" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-06-15 21:09:20 +0200 (Wed, 15 Jun 2016)" );
	script_name( "SolarWinds Virtualization Manager Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
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
url = "/swvm/ConsoleContainer.jsp";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>SolarWinds Virtualization Manager</title>" )){
	exit( 0 );
}
cpe = "cpe:/a:solarwinds:virtualization_manager";
vers = "unknown";
set_kb_item( name: "solarwinds/virtualization_manager/installed", value: TRUE );
version = eregmatch( pattern: "src=\"ConsoleContainer.swf\\?version=([0-9.]+[^\"]+)\"", string: buf );
if(!isnull( version[1] )){
	parts = split( buffer: version[1], sep: ".", keep: FALSE );
	vers = parts[0] + "." + parts[1] + "." + parts[2];
	rep_vers = vers;
	if(parts[3]){
		build = parts[3];
		set_kb_item( name: "solarwinds/virtualization_manager/build", value: build );
		rep_vers += " Build " + build;
	}
	set_kb_item( name: "solarwinds/virtualization_manager/version", value: vers );
}
register_product( cpe: cpe, location: "/swvm/", port: port, service: "www" );
report = build_detection_report( app: "SolarWinds Virtualization Manager", version: rep_vers, install: "/swvm/", cpe: cpe, concluded: version[0] );
log_message( port: port, data: report );
exit( 0 );

