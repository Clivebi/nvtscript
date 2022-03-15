if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112482" );
	script_version( "2021-06-17T10:24:47+0000" );
	script_tag( name: "last_modification", value: "2021-06-17 10:24:47 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-01-14 10:51:11 +0100 (Mon, 14 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Traccar Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Traccar." );
	script_xref( name: "URL", value: "https://www.traccar.org/" );
	exit( 0 );
}
CPE = "cpe:/a:traccar:traccar:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for location in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	dir = location;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( buf, "<div id=\"attribution\">Powered by <a href=\"https://www.traccar.org/\">Traccar GPS Tracking System</a></div>" )){
		set_kb_item( name: "traccar/detected", value: TRUE );
		set_kb_item( name: "traccar/http/detected", value: TRUE );
		set_kb_item( name: "traccar/port", value: port );
		set_kb_item( name: "traccar/location", value: location );
		version = "unknown";
		vers_url = dir + "/api/server";
		vers_buf = http_get_cache( item: vers_url, port: port );
		vers = eregmatch( string: vers_buf, pattern: "version\":\"([0-9.]+)" );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		register_and_report_cpe( app: "Traccar", ver: version, concluded: vers[0], base: CPE, expr: "([0-9.]+)", insloc: location, regService: "www", regPort: port, conclUrl: dir );
		exit( 0 );
	}
}
exit( 0 );

