if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106637" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-03-08 12:16:59 +0700 (Wed, 08 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "NagVis Detection" );
	script_tag( name: "summary", value: "Detection of NagVis

The script sends a HTTP connection request to the server and attempts to detect the presence of NagVis and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.nagvis.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/nagvis", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	req = http_get( port: port, item: dir + "/frontend/nagvis-js/index.php" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "\\/nagvis\\/userfiles\\/sounds\\/" ) && ContainsString( res, "Log In</title>" )){
		version = "unknown";
		vers = eregmatch( pattern: "title=\"NagVis ([0-9b.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "nagvis/version", value: version );
		}
		set_kb_item( name: "nagvis/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9b.]+)", base: "cpe:/a:nagvis:nagvis:" );
		if(!cpe){
			cpe = "cpe:/a:nagvis:nagvis";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "NagVis", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

