if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103742" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-20 11:43:29 +0200 (Thu, 20 Jun 2013)" );
	script_name( "GLPI Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of GLPI.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	exit( 0 );
}
CPE = "cpe:/a:glpi-project:glpi:";
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
version = "unknown";
for dir in nasl_make_list_unique( "/glpi", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		url = dir + "/index.php";
		buf = http_get_cache( item: url, port: port );
		if(!buf){
			continue;
		}
	}
	if(IsMatchRegexp( buf, "<title>GLPI - Auth?enti" ) && IsMatchRegexp( buf, "Powered By (Indepnet|Teclib)" )){
		vers = eregmatch( string: buf, pattern: "GLPI version[ ]+([0-9.]+) ", icase: TRUE );
		if( !isnull( vers[1] ) ){
			version = chomp( vers[1] );
		}
		else {
			vers = eregmatch( string: buf, pattern: "src=\"[^\"]+?v=([0-9.]+)\"", icase: TRUE );
			if(!isnull( vers[1] )){
				version = vers[1];
			}
		}
		set_kb_item( name: NASLString( "www/", port, "/glpi" ), value: NASLString( version, " under ", install ) );
		set_kb_item( name: "glpi/detected", value: TRUE );
		register_and_report_cpe( app: "GLPI", ver: version, concluded: vers[0], base: CPE, expr: "([0-9.]+)", insloc: install, regPort: port, regService: "www", conclUrl: url );
	}
}
exit( 0 );

