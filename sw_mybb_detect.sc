if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111023" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-07-20 13:14:40 +0200 (Mon, 20 Jul 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "MyBB Forum Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of a MyBB Forum." );
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
for dir in nasl_make_list_unique( "/", "/forum", "/forums", "/mybb", "/MyBB", "/board", "/boards", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">MyBB" ) && ContainsString( res, ">MyBB Group<" )){
		vers = "unknown";
		extra = NULL;
		version = eregmatch( pattern: ">MyBB ([0-9.]+).?<", string: res );
		if( !isnull( version[1] ) ){
			vers = version[1];
		}
		else {
			version = eregmatch( pattern: "general\\.js\\?ver=([0-9]+)", string: res );
			if(!isnull( version[1] )){
				ver = version[1];
				if( strlen( ver ) > 3 && ver[2] == 0 ) {
					i = 3;
				}
				else {
					i = 2;
				}
				vers = ver[0] + "." + ver[1] + "." + substr( ver, i );
				if(vers == "1.8.21"){
					vers = "1.8.22";
					extra = "Version 1.8.22 had also reported itself as Version 1.8.21.";
					extra += " To avoid false positives 1.8.22 is assumed for this case.";
				}
			}
		}
		set_kb_item( name: "MyBB/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:mybb:mybb:" );
		if(!cpe){
			cpe = "cpe:/a:mybb:mybb";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "MyBB Forum", version: vers, install: install, cpe: cpe, extra: extra, concluded: version[0] ), port: port );
	}
}
exit( 0 );

