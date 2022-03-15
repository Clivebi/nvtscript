if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813251" );
	script_version( "2021-05-27T05:26:55+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 05:26:55 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-18 13:05:09 +0530 (Mon, 18 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Nagios Fusion Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Nagios Fusion." );
	script_xref( name: "URL", value: "https://www.nagios.com/products/nagios-fusion/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/Nagios", "/nagiosfusion", "/fusion", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.php";
	res = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( res, ">Login.*Nagios Fusion</title" ) && ContainsString( res, "\"product\" value=\"nagiosfusion\">" )){
		version = "unknown";
		set_kb_item( name: "nagios/fusion/detected", value: TRUE );
		vers = eregmatch( pattern: "name=\"version\" value=\"([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:nagios:fusion:" );
		if(!cpe){
			cpe = "cpe:/a:nagios:fusion";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Nagios Fusion", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

