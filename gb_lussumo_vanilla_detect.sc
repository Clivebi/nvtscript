if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800622" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Vanilla Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the installed Vanilla version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/Vanilla117", "/Vanilla118", "/Vanilla113rc1", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(isnull( res )){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">Vanilla" )){
		version = "unknown";
		ver = eregmatch( pattern: ">Vanilla ([0-9.a-z]+)", string: res );
		if(ver[1]){
			version = ver[1];
		}
		set_kb_item( name: "www/" + port + "/Lussumo/Vanilla", value: version + " under " + install );
		set_kb_item( name: "Lussumo/Vanilla/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+\\.[0-9])\\.?([a-z0-9]+)?", base: "cpe:/a:lussumo:vanilla:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:lussumo:vanilla";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Vanilla", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

