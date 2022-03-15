if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900884" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "OpenDocMan Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed OpenDocMan version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
docmanPort = http_get_port( default: 80 );
if(!http_can_host_php( port: docmanPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/docman", "/opendocman", http_cgi_dirs( port: docmanPort ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: docmanPort );
	if(!ContainsString( rcvRes, "Welcome to OpenDocMan" )){
		rcvRes = http_get_cache( item: dir + "/admin.php", port: docmanPort );
	}
	if(ContainsString( rcvRes, "Welcome to OpenDocMan" ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: rcvRes )){
		version = "unknown";
		docmanVer = eregmatch( pattern: "OpenDocMan v([0-9.]+)([a-z]+[0-9])?", string: rcvRes );
		if(docmanVer[1]){
			if( docmanVer[2] ){
				version = docmanVer[1] + "." + docmanVer[2];
			}
			else {
				version = docmanVer[1];
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + docmanPort + "/OpenDocMan", value: tmp_version );
		set_kb_item( name: "OpenDocMan/installed", value: TRUE );
		cpe = build_cpe( value: docmanVer, exp: "^([0-9.]+)", base: "cpe:/a:opendocman:opendocman:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:opendocman:opendocman";
		}
		register_product( cpe: cpe, location: install, port: docmanPort, service: "www" );
		log_message( data: build_detection_report( app: "OpenDocMan", version: version, install: install, cpe: cpe, concluded: docmanVer[0] ), port: docmanPort );
	}
}

