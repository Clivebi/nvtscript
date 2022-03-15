if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140326" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-08-25 14:18:37 +0700 (Fri, 25 Aug 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Atlassian FishEye and Crucible Detection" );
	script_tag( name: "summary", value: "Detection of Atlassian FishEye and Crucible.

The script sends a connection request to the server and attempts to detect Atlasian FishEye and Crucible and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.atlassian.com/software/fisheye" );
	script_xref( name: "URL", value: "https://www.atlassian.com/software/crucible" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", "/crucible", "/fisheye", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/" );
	if(( ContainsString( res, "display-name=\"FishEye and Crucible\"" ) || ContainsString( res, "<title>Log in to FishEye and Crucible" ) ) && IsMatchRegexp( res, "Page generated [0-9]{4}-" )){
		version = "unknown";
		vers = eregmatch( pattern: "\\(Version:([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "atlassian_fisheye_crucible/version", value: version );
		}
		set_kb_item( name: "atlassian_fisheye_crucible/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:fisheye:" );
		if(!cpe){
			cpe = "cpe:/a:atlassian:fisheye";
		}
		cpe2 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:crucible:" );
		if(!cpe){
			cpe = "cpe:/a:atlassian:crucible";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		register_product( cpe: cpe2, location: install, port: port );
		log_message( data: build_detection_report( app: "Atlassian FishEye and Crucible", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

