if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801217" );
	script_version( "2021-01-13T07:27:23+0000" );
	script_tag( name: "last_modification", value: "2021-01-13 07:27:23 +0000 (Wed, 13 Jan 2021)" );
	script_tag( name: "creation_date", value: "2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Snipe Gallery Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Snipe Gallery." );
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
for dir in nasl_make_list_unique( "/", "/snipegallery", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">Snipe Gallery" )){
		version = "unknown";
		ver = eregmatch( pattern: ">Snipe Gallery v.([0-9].[0-9.]+) +- +Galleries", string: res );
		if(ver[1]){
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/snipegallery", value: tmp_version );
		set_kb_item( name: "snipegallery/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:snipegallery:snipe_gallery:" );
		if(!cpe){
			cpe = "cpe:/a:snipegallery:snipe_gallery";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Snipe Gallery", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

