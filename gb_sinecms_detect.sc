if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800941" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SineCMS Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of SineCMS." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sinePort = http_get_port( default: 80 );
if(!http_can_host_php( port: sinePort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/sinecms", "/sine", http_cgi_dirs( port: sinePort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: sinePort );
	if(ContainsString( rcvRes, "SineCMS" )){
		version = "unknown";
		sineVer = eregmatch( pattern: "SineCms Version: ([0-9.]+)", string: rcvRes );
		if(sineVer[1] != NULL){
			version = sineVer[1];
		}
		tmp_version = version + " under " + dir;
		set_kb_item( name: "www/" + sinePort + "/SineCMS", value: tmp_version );
		set_kb_item( name: "sinecms/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sinecms:sinecms:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:sinecms:sinecms";
		}
		register_product( cpe: cpe, location: install, port: sinePort, service: "www" );
		log_message( data: build_detection_report( app: "SineCMS", version: version, install: install, cpe: cpe, concluded: sineVer[0] ), port: sinePort );
	}
}

