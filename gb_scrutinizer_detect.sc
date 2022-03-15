if(description){
	script_tag( name: "cvss_base", value: "0.0" );
	script_oid( "1.3.6.1.4.1.25623.1.0.103532" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-08-08 12:07:31 +0200 (Wed, 08 Aug 2012)" );
	script_name( "Scrutinizer Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Scrutinizer

The script sends a connection request to the server and attempts to
extract the version number from the reply." );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.html";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "<title>Scrutinizer</title>", string: buf, icase: TRUE )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "<div id='testAlertDivTitle'>Scrutinizer ([0-9.]+)</div>", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		set_kb_item( name: NASLString( "www/", port, "/scrutinizer" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "scrutinizer/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:dell:sonicwall_scrutinizer:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:dell:sonicwall_scrutinizer";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Scrutinizer", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

