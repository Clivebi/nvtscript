if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901084" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "AlefMentor Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the running AlefMentor version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
amPort = http_get_port( default: 80 );
if(!http_can_host_php( port: amPort )){
	exit( 0 );
}
for path in nasl_make_list_unique( "/", "/am", "/AM", http_cgi_dirs( port: amPort ) ) {
	install = path;
	if(path == "/"){
		path = "";
	}
	rcvRes = http_get_cache( item: path + "/index.php", port: amPort );
	if(ContainsString( rcvRes, "AlefMentor" )){
		version = "unknown";
		amVer = eregmatch( pattern: "AlefMentor ([0-9.]+)", string: rcvRes );
		if(amVer[1] != NULL){
			version = amVer[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + amPort + "/AlefMentor", value: tmp_version );
		set_kb_item( name: "alefmentor/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:findmysoft:alefmentor:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:findmysoft:alefmentor";
		}
		register_product( cpe: cpe, location: install, port: amPort, service: "www" );
		log_message( data: build_detection_report( app: "AlefMentor", version: version, install: install, cpe: cpe, concluded: amVer[0] ), port: amPort );
	}
}

