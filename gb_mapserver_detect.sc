if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800547" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)" );
	script_name( "MapServer Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of the MapServer and its installed version.

  This script sends a HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
if( os_host_runs( "Windows" ) == "yes" ) {
	files = make_list( "/cgi-bin/mapserv.exe" );
}
else {
	if( os_host_runs( "Linux" ) == "yes" ) {
		files = make_list( "/cgi-bin/mapserv" );
	}
	else {
		files = make_list( "/cgi-bin/mapserv",
			 "/cgi-bin/mapserv.exe" );
	}
}
port = http_get_port( default: 80 );
for file in files {
	url = file + "?map=";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!ContainsString( res, "MapServer" )){
		continue;
	}
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	version = "unknown";
	install = "/";
	mapVer = eregmatch( pattern: "MapServer version ([0-9]\\.[0-9.]+)", string: res );
	if(mapVer[1]){
		version = mapVer[1];
		set_kb_item( name: "MapServer/ver", value: version );
	}
	set_kb_item( name: "MapServer/Installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:umn:mapserver:" );
	if(!cpe){
		cpe = "cpe:/a:umn:mapserver";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "MapServer", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: version ), port: port );
	exit( 0 );
}
exit( 0 );

