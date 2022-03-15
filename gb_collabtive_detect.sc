if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100854" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-10-13 18:51:23 +0200 (Wed, 13 Oct 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Collabtive Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running Collabtive, a Project Management and Open Source
  Groupware." );
	script_xref( name: "URL", value: "http://collabtive.o-dyn.de" );
	exit( 0 );
}
CPE = "cpe:/a:collabtive:collabtive:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/collabtive", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(IsMatchRegexp( buf, "Open Source project management" ) && IsMatchRegexp( buf, "collabtive" ) && IsMatchRegexp( buf, "<title>Login" )){
		set_kb_item( name: "collabtive/detected", value: TRUE );
		url = NASLString( dir, "/changelog.txt" );
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		version = "unknown";
		vers = eregmatch( string: buf, pattern: "Collabtive ([0-9.]+)", icase: TRUE );
		if(!isnull( vers[1] )){
			version = chomp( vers[1] );
		}
		set_kb_item( name: NASLString( "www/", port, "/collabtive" ), value: NASLString( version, " under ", install ) );
		register_and_report_cpe( app: "Collabtive", ver: version, concluded: vers[0], base: CPE, expr: "([0-9.]+)", insloc: install, regPort: port, conclUrl: dir );
		exit( 0 );
	}
}
exit( 0 );

