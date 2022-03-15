if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100864" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-10-21 13:52:26 +0200 (Thu, 21 Oct 2010)" );
	script_name( "FishEye Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of FishEye.

The script sends a connection request to the server and attempts to
extract the version number from the reply." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/fisheye", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/admin/login-default.do" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "<h3>Administration log in to FishEye" )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "(\\(Version:([0-9.]+))" );
		if(!isnull( version[2] )){
			vers = chomp( version[2] );
		}
		set_kb_item( name: NASLString( "www/", port, "/FishEye" ), value: NASLString( vers ) );
		set_kb_item( name: "FishEye/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:fisheye:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:atlassian:fisheye";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "FishEye", version: vers, install: install, cpe: cpe, concluded: version[1] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

