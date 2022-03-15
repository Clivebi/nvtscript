if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107062" );
	script_version( "2021-05-27T04:37:21+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 04:37:21 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2016-10-19 13:26:09 +0700 (Wed, 19 Oct 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Nagios Network Analyzer Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Nagios Network Analyzer." );
	script_xref( name: "URL", value: "https://www.nagios.com/products/nagios-network-analyzer/" );
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
for dir in nasl_make_list_unique( "/nagiosna", "/nagios", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php/login";
	res = http_get_cache( port: port, item: url );
	if(ContainsString( res, "<title>Login &bull; Nagios Network Analyzer</title>" ) && ContainsString( res, "nnalogo_small.png" )){
		version = "unknown";
		set_kb_item( name: "nagios/network_analyzer/detected", value: TRUE );
		vers = eregmatch( pattern: "var NA_VERSION = \"([0-9.]+)\"", string: res, icase: TRUE );
		if(isnull( vers[1] )){
			vers = eregmatch( pattern: "ver=([0-9.]+)\">", string: res );
		}
		if(!isnull( vers[1] )){
			vers = vers[1];
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:nagios:network_analyzer:" );
		if(!cpe){
			cpe = "cpe:/a:nagios:network_analyzer";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Nagios Network Analyzer", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

