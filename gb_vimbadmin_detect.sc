if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106871" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-06-14 10:53:56 +0700 (Wed, 14 Jun 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ViMbAdmin Detection" );
	script_tag( name: "summary", value: "Detection of ViMbAdmin.

The script sends a connection request to the server and attempts to detect ViMbAdmin and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.vimbadmin.net/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/vimbadmin", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	req = http_get( port: port, item: dir + "/auth/login" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "keywords\" content=\"ViMbAdmin" ) && ContainsString( res, "Login to ViMbAdmin" )){
		version = "unknown";
		vers = eregmatch( pattern: "releases\">V([0-9.]+)", string: res );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			set_kb_item( name: "vimbadmin/version", value: version );
		}
		else {
			vers = eregmatch( pattern: "ViMbAdmin V([0-9.]+)", string: res );
			if(!isnull( vers[1] )){
				version = vers[1];
				set_kb_item( name: "vimbadmin/version", value: version );
			}
		}
		set_kb_item( name: "vimbadmin/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:vimbadmin:vimbadmin:" );
		if(!cpe){
			cpe = "cpe:/a:vimbadmin:vimbadmin";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "ViMbAdmin", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
	}
}
exit( 0 );

