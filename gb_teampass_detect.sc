if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106165" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-03 11:33:48 +0700 (Wed, 03 Aug 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "TeamPass Detection" );
	script_tag( name: "summary", value: "Detection of TeamPass

The script sends a connection request to the server and attempts to detect the presence of TeamPass and
to extract its version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://teampass.net/" );
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
for dir in nasl_make_list_unique( "/teampass", "/TeamPass", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "<title>Teampass</title>" ) || ContainsString( res, "<title>Collaborative Passwords Manager</title>" ) && ContainsString( res, "teampass.net/about" )){
		version = "unknown";
		vers = eregmatch( pattern: "color:#F0F0F0;\">TeamPass&nbsp;([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "teampass/installed", value: TRUE );
		if(version != "unknown"){
			set_kb_item( name: "teampass/version", value: version );
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:teampass:teampass:" );
		if(!cpe){
			cpe = "cpe:/a:teampass:teampass";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "TeamPass", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

