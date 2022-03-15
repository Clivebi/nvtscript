if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113315" );
	script_version( "2021-06-17T10:24:47+0000" );
	script_tag( name: "last_modification", value: "2021-06-17 10:24:47 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-12 12:55:55 +0100 (Wed, 12 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Adiscon LogAnalyzer Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Adiscon LogAnalyzer." );
	script_xref( name: "URL", value: "https://loganalyzer.adiscon.com/" );
	exit( 0 );
}
CPE = "cpe:/a:adiscon:log_analyzer:";
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
for location in nasl_make_list_unique( "/", "/loganalyzer", http_cgi_dirs( port: port ) ) {
	dir = location;
	if(dir == "/"){
		dir = "";
	}
	dir = dir + "/login.php";
	buf = http_get_cache( item: dir, port: port );
	if(IsMatchRegexp( buf, "<strong>Use this form to login into LogAnalyzer" ) || IsMatchRegexp( buf, "<title>Adiscon LogAnalyzer" )){
		set_kb_item( name: "adiscon/log_analyzer/detected", value: TRUE );
		set_kb_item( name: "adiscon/log_analyzer/http/detected", value: TRUE );
		set_kb_item( name: "adiscon/log_analyzer/port", value: port );
		set_kb_item( name: "adiscon/log_analyzer/location", value: location );
		version = "unknown";
		ver = eregmatch( string: buf, pattern: "LogAnalyzer</A> Version ([0-9.]+)" );
		if(!isnull( ver[1] )){
			version = ver[1];
			set_kb_item( name: "adiscon/log_analyzer/version", value: version );
		}
		register_and_report_cpe( app: "Adiscon LogAnalyzer", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: location, regPort: port, conclUrl: dir );
		exit( 0 );
	}
}
exit( 0 );

