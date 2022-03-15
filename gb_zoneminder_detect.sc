if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106520" );
	script_version( "2021-09-09T10:20:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:20:36 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-17 13:28:38 +0700 (Tue, 17 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ZoneMinder Detection" );
	script_tag( name: "summary", value: "Detection of ZoneMinder

The script sends a HTTP connection request to the server and attempts to detect the presence of ZoneMinder." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/zm", "/zoneminder", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/index.php" );
	if(( ContainsString( res, "<h1>ZoneMinder Login</h1>" ) || IsMatchRegexp( res, "<title>Zone[mM]inder - Console</title>" ) ) && ContainsString( res, "var skinPath" )){
		version = "unknown";
		req = http_get( port: port, item: dir + "/index.php?view=version" );
		res = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "ZoneMinder, v([0-9]+\\.[0-9]+\\.[0-9]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "zoneminder/version", value: version );
		}
		set_kb_item( name: "zoneminder/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:zoneminder:zoneminder:" );
		if(!cpe){
			cpe = "cpe:/a:zoneminder:zoneminder";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "ZoneMinder", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

