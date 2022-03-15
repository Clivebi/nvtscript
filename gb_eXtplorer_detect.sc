if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103640" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-01-10 12:49:27 +0100 (Thu, 10 Jan 2013)" );
	script_name( "eXtplorer Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of eXtplorer.

The script sends a connection request to the server and attempts to
extract the version number from the reply." );
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
for dir in nasl_make_list_unique( "/eXtplorer", "/extplorer", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/extplorer.xml";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "<name>eXtplorer</name>" )){
		vers = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "<version>([^<]+)</version>", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		set_kb_item( name: NASLString( "www/", port, "/eXtplorer" ), value: NASLString( vers, " under ", install ) );
		set_kb_item( name: "eXtplorer/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)(RC[0-9])?", base: "cpe:/a:extplorer:extplorer:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:extplorer:extplorer";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "eXtplorer", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

