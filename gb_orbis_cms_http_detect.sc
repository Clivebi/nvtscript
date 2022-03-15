if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801403" );
	script_version( "2021-08-02T13:28:43+0000" );
	script_tag( name: "last_modification", value: "2021-08-02 13:28:43 +0000 (Mon, 02 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Orbis CMS Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Orbis CMS." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for path in nasl_make_list_unique( "/orbis", "/Orbis", "/", http_cgi_dirs( port: port ) ) {
	install = path;
	if(path == "/"){
		path = "";
	}
	res = http_get_cache( port: port, item: path + "/admin/login.php" );
	if(ContainsString( res, ">Powered by Orbis CMS<" )){
		req = http_get( item: path + "/CHANGELOG.txt", port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		version = "unknown";
		vers = eregmatch( pattern: "Version ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "orbis/cms/detected", value: TRUE );
		set_kb_item( name: "orbis/cms/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:novo-ws:orbis_cms:" );
		if(!cpe){
			cpe = "cpe:/a:novo-ws:orbis_cms";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Orbis CMS", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

