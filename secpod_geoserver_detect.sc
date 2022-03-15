if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900945" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "GeoServer Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://geoserver.org/" );
	script_tag( name: "summary", value: "This script detects the installed version of GeoServer." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
func register_and_report( ver, dir, port, cpe, concluded, conclUrl ){
	set_kb_item( name: "www/" + port + "/GeoServer", value: ver + " under " + dir );
	set_kb_item( name: "GeoServer/installed", value: TRUE );
	register_product( cpe: cpe, location: dir, port: port, service: "www" );
	log_message( data: build_detection_report( app: "GeoServer", version: ver, install: dir, cpe: cpe, concludedUrl: conclUrl, concluded: concluded ), port: port );
	exit( 0 );
}
geoPort = http_get_port( default: 80 );
cpe = "cpe:/a:geoserver:geoserver";
dirs = nasl_make_list_unique( "/", "/geoserver", http_cgi_dirs( port: geoPort ) );
for dir in dirs {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	path = dir + "/welcome.do";
	sndReq = http_get( item: path, port: geoPort );
	rcvRes = http_keepalive_send_recv( port: geoPort, data: sndReq, bodyonly: FALSE );
	if(( ContainsString( rcvRes, "My GeoServer" ) ) && ( ContainsString( rcvRes, "Welcome to GeoServer" ) )){
		geoVer = eregmatch( pattern: "Welcome to GeoServer ([0-9.]+(-[a-zA-Z0-9]+)?)", string: rcvRes );
		if( !isnull( geoVer[1] ) ){
			concluded = geoVer[0];
			geoVer = ereg_replace( pattern: "([0-9]\\.[0-9]\\.[0-9])\\.", string: geoVer[1], replace: "\\1" );
			geoVer = ereg_replace( pattern: "-", replace: ".", string: geoVer );
			cpe = cpe + ":" + geoVer;
		}
		else {
			geoVer = "unknown";
		}
		register_and_report( ver: geoVer, dir: install, port: geoPort, cpe: cpe, concluded: concluded );
	}
}
for dir in dirs {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	path = dir + "/web/?wicket:bookmarkablePage=:org.geoserver.web.AboutGeoServerPage";
	conclUrl = http_report_vuln_url( port: geoPort, url: path, url_only: TRUE );
	sndReq = http_get( item: path, port: geoPort );
	rcvRes = http_keepalive_send_recv( port: geoPort, data: sndReq );
	if(( ContainsString( rcvRes, "<title>GeoServer: About GeoServer" ) )){
		geoVer = eregmatch( pattern: ">GeoServer ([0-9]\\.[0-9]\\.[0-9](-[a-zA-Z0-9]+)?)<", string: rcvRes );
		if(isnull( geoVer[1] )){
			geoVer = eregmatch( pattern: "span id=\"version\">([^<]+)<", string: rcvRes );
		}
		if( !isnull( geoVer[1] ) ){
			concluded = geoVer[0];
			geoVer = ereg_replace( pattern: "([0-9]\\.[0-9]\\.[0-9])\\.", string: geoVer[1], replace: "\\1" );
			geoVer = ereg_replace( pattern: "-", replace: ".", string: geoVer );
			cpe = cpe + ":" + geoVer;
		}
		else {
			geoVer = "unknown";
		}
		register_and_report( ver: geoVer, dir: install, port: geoPort, cpe: cpe, concluded: concluded, conclUrl: conclUrl );
	}
}
exit( 0 );

