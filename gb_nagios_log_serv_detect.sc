if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107058" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-12 13:26:09 +0700 (Wed, 12 Oct 2016)" );
	script_name( "Nagios Log Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Nagios Log Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.nagios.com/products/nagios-log-server/" );
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
for dir in nasl_make_list_unique( "/nagioslogserver", "/nagios", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login";
	buf = http_get_cache( port: port, item: url );
	if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "Nagios Log Server" ) && ContainsString( buf, "Nagios Enterprises" ) && ContainsString( buf, "var LS_USER_ID" ) && ( ContainsString( buf, "<div class=\"demosplash\"></div>" ) || ContainsString( buf, "<div class=\"loginsplash\"></div>" ) )){
		set_kb_item( name: "nagios/log_server/detected", value: TRUE );
		if(ContainsString( buf, "<div class=\"demosplash\"></div>" )){
			extra = "Demo Version";
		}
		version = "unknown";
		vers = eregmatch( string: buf, pattern: "var LS_VERSION = \"([0-9.]+)\"", icase: TRUE );
		if(isnull( vers[1] )){
			vers = eregmatch( string: buf, pattern: "ver=([0-9.]+)\">" );
		}
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:nagios:log_server:" );
		if(!cpe){
			cpe = "cpe:/a:nagios:log_server";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Nagios Log Server", version: version, install: install, cpe: cpe, concluded: vers[0], extra: extra ), port: port );
	}
}
exit( 0 );

