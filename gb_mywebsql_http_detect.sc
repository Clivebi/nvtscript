if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113333" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-13 10:36:44 +0100 (Wed, 13 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "MyWebSQL Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether MyWebSQL is present on the
  target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "http://mywebsql.net/" );
	exit( 0 );
}
CPE = "cpe:/a:mywebsql:mywebsql:";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for location in nasl_make_list_unique( "/", "/mywebsql", http_cgi_dirs( port: port ) ) {
	buf = http_get_cache( port: port, item: location );
	if(!IsMatchRegexp( buf, "<title>MyWebSQL</title>" )){
		continue;
	}
	set_kb_item( name: "mywebsql/detected", value: TRUE );
	version = "unknown";
	ver = eregmatch( string: buf, pattern: "<span class=\"version\">version ([0-9.]+)</span>", icase: TRUE );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	register_and_report_cpe( app: "MyWebSQL", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: location, regPort: port, conclUrl: location );
	if(location == "/"){
		exit( 0 );
	}
}
exit( 0 );

