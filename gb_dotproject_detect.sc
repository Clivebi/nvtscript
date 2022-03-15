if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800564" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)" );
	script_name( "dotProject Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the installed version
  of dotProject." );
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
for dir in nasl_make_list_unique( "/dotproject", "/dotProject", "/Dotproject", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "dotProject" )){
		version = eregmatch( pattern: "Version ([0-9.]+)(rc[0-9])?", string: res );
		if(version[1] != NULL){
			if( version[2] != NULL ){
				vers = version[1] + "." + version[2];
			}
			else {
				vers = version[1];
			}
			tmp_version = vers + " under " + install;
			set_kb_item( name: "www/" + port + "/dotProject", value: tmp_version );
			set_kb_item( name: "dotproject/detected", value: TRUE );
			cpe = build_cpe( value: vers, exp: "^([0-9.]+\\.[0-9])\\.?([a-z0-9]+)?", base: "cpe:/a:dotproject:dotproject:" );
			if(cpe){
				register_product( cpe: cpe, location: install, port: port, service: "www" );
				log_message( data: build_detection_report( app: "dotProject", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

