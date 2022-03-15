if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106089" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-05-31 08:10:56 +0700 (Tue, 31 May 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "phpLiteAdmin Detection" );
	script_tag( name: "summary", value: "Detection of phpLiteAdmin

The script sends a connection request to the server and attempts to detect phpLiteAdmin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.phpliteadmin.org/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/phpliteadmin", "/phplite", http_cgi_dirs( port: port ) ) {
	for file in make_list( "/",
		 "/phpliteadmin.php",
		 "/index.php" ) {
		install = dir;
		if(dir == "/"){
			dir = "";
		}
		res = http_get_cache( item: dir + file, port: port );
		if(ContainsString( res, "phpLiteAdmin" )){
			version = "unknown";
			ver = eregmatch( pattern: "'version'>v([0-9.]+)<", string: res );
			if(ver[1] != NULL){
				version = ver[1];
			}
			set_kb_item( name: NASLString( "www/", port, "/phpliteadmin" ), value: version );
			set_kb_item( name: "phpliteadmin/installed", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:phpliteadmin_project:phpliteadmin:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:phpliteadmin_project:phpliteadmin";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "phpLiteAdmin", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
			exit( 0 );
		}
	}
}
exit( 0 );

