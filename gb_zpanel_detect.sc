if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105414" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-10-21 11:00:30 +0200 (Wed, 21 Oct 2015)" );
	script_name( "Zpanel Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Zpanel" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
cpe = "cpe:/a:zpanel:zpanel";
for dir in nasl_make_list_unique( "/", "/zpanel", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(( ContainsString( buf, "title>Control Panel - Login</title>" ) || ContainsString( buf, "<title>ZPanel" ) ) && ( egrep( pattern: "Powered By: .*>ZPanel([ 0-9.]+)?", string: buf, icase: TRUE ) || ContainsString( buf, "This server is running: ZPanel" ) )){
		if(install == "/"){
			root_install = TRUE;
		}
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "(: |>)ZPanel ([0-9.]+)</(a|p)>", icase: TRUE );
		if(!isnull( version[2] )){
			vers = chomp( version[2] );
			cpe += ":" + vers;
		}
		set_kb_item( name: "zpanel/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Zpanel", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		if(root_install){
			exit( 0 );
		}
	}
}
exit( 0 );

